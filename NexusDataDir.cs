using System.Security.AccessControl;
using System.Security.Principal;

namespace NexusAV.Engine;

/// <summary>
/// Single owner of the %ProgramData%\NexusXDR tree: every module gets its directory from here
/// instead of calling Directory.CreateDirectory on its own.
///
/// Why the ACL is part of that: ProgramData hands BUILTIN\Users write-data/append-data on the
/// folder, so any other standard account on this machine can plant a file exactly where the engine
/// later reads its whitelist, quarantine database, fingerprints or module baseline. Removing that
/// one ACE is the difference between "our state" and "whoever got here first".
///
/// Safety rails — this runs unelevated on the operator's daily-driver machine:
///  - the signed-in user keeps FullControl, so an unelevated engine never locks itself out
///    (a SYSTEM/Administrators-only DACL would);
///  - the change is verified with a real write probe and the previous DACL is put back if it fails;
///  - any failure is logged and swallowed: a directory we cannot lock is still a directory we can use.
/// </summary>
public static class NexusDataDir
{
    private static readonly object Gate = new();
    private static readonly HashSet<string> Locked = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Absolute path of the shared Nexus data root.</summary>
    public static string Root { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "NexusXDR");

    /// <summary>
    /// Creates the data root (or <paramref name="sub"/> inside it) and locks its ACL once per run.
    /// Returns the directory that now exists.
    /// </summary>
    public static string Ensure(string sub = "")
    {
        string dir = sub.Length == 0 ? Root : Path.Combine(Root, sub);
        Directory.CreateDirectory(dir);
        if (sub.Length != 0) Harden(Root);
        Harden(dir);
        return dir;
    }

    private static void Harden(string dir)
    {
        lock (Gate)
        {
            if (Locked.Contains(dir)) return;
            Locked.Add(dir);
        }

        try
        {
            var info = new DirectoryInfo(dir);
            DirectorySecurity current = info.GetAccessControl(AccessControlSections.Access);
            if (!GrantsUsersWrite(current))
            {
                Console.WriteLine($"[DATADIR] {dir}: no Users write ACE — ACL left untouched");
                EventBus.Status($"datadir_acl_clean path={Safe(dir)}");
                return;
            }

            using WindowsIdentity self = WindowsIdentity.GetCurrent();
            string me = self.Name;

            // Built from scratch rather than edited: RemoveAccessRule matching is fuzzy enough that
            // a partial removal would leave AppendData behind, and AppendData is all it takes to
            // create a file. This way the resulting DACL is exactly the five ACEs below.
            var acl = new DirectorySecurity();
            acl.SetAccessRuleProtection(true, false);
            Allow(acl, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, inheritOnly: false);
            Allow(acl, new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, inheritOnly: false);
            Allow(acl, self.User!, FileSystemRights.FullControl, inheritOnly: false);
            // Inherit-only: files created here belong to whoever wrote them, including an elevated
            // run under a different account.
            Allow(acl, new SecurityIdentifier(WellKnownSidType.CreatorOwnerSid, null), FileSystemRights.FullControl, inheritOnly: true);
            Allow(acl, new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.ReadAndExecute, inheritOnly: false);

            info.SetAccessControl(acl);

            if (!ProbeWritable(dir))
            {
                info.SetAccessControl(current);
                Console.WriteLine($"[DATADIR] write probe failed after locking {dir} — previous ACL restored, engine keeps running");
                EventBus.Status($"datadir_acl_rolled_back path={Safe(dir)}");
                return;
            }

            Console.WriteLine($"[DATADIR] {dir} locked — other local users can read but no longer create files here (SYSTEM, Administrators and {me} keep full control)");
            EventBus.Status($"datadir_acl_hardened path={Safe(dir)} owner={Safe(me)}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[DATADIR] ACL of {dir} not changed ({ex.GetType().Name}: {ex.Message}) — data stays usable, other local users may still write here");
            EventBus.Status($"datadir_acl_skipped path={Safe(dir)} reason={ex.GetType().Name}");
        }
    }

    private static void Allow(DirectorySecurity acl, SecurityIdentifier who, FileSystemRights rights, bool inheritOnly)
    {
        acl.AddAccessRule(new FileSystemAccessRule(
            who,
            rights,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            inheritOnly ? PropagationFlags.InheritOnly : PropagationFlags.None,
            AccessControlType.Allow));
    }

    private static bool GrantsUsersWrite(DirectorySecurity acl)
    {
        string users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null).Value;
        const FileSystemRights anyWrite =
            FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Write |
            FileSystemRights.Modify | FileSystemRights.FullControl;

        foreach (AuthorizationRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule is not FileSystemAccessRule ace) continue;
            if (ace.AccessControlType != AccessControlType.Allow) continue;
            if (!string.Equals(ace.IdentityReference.Value, users, StringComparison.OrdinalIgnoreCase)) continue;
            if ((ace.FileSystemRights & anyWrite) != 0) return true;
        }
        return false;
    }

    private static bool ProbeWritable(string dir)
    {
        string probe = Path.Combine(dir, ".acl-probe");
        try
        {
            File.WriteAllText(probe, "ok");
            File.Delete(probe);
            return true;
        }
        catch
        {
            try { if (File.Exists(probe)) File.Delete(probe); } catch { }
            return false;
        }
    }

    private static string Safe(string s) => s.Replace('\\', '/').Replace(' ', '_');
}
