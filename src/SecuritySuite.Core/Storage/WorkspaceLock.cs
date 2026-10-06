using System.Diagnostics;
using System.Text;

namespace SecuritySuite.Storage;

/// <summary>
/// One monitoring process per workspace, enforced by the filesystem.
/// </summary>
/// <remarks>
/// <para>
/// Two instances sharing a findings log both sweep the same watch paths and
/// both append to the same NDJSON, so every new file is detected twice and the
/// dashboard shows duplicate findings with identical hashes seconds apart. The
/// CLI already tried to prevent this by probing for a running instance, but it
/// probed <em>by port</em>: a second instance on a different port shares the
/// workspace and is never found.
/// </para>
/// <para>
/// The port is not what has to be unique; the workspace is. A lock file beside
/// the findings log, held open for the life of the process, makes that true
/// regardless of how the second instance was started. The OS releases it if the
/// process dies, so a crash cannot leave a workspace permanently locked.
/// </para>
/// <para>
/// This guards the <em>monitor</em>, not every operation. A one-shot
/// <c>--scan</c> appending a line while a monitor runs is fine and useful; two
/// monitors double-scanning is not.
/// </para>
/// </remarks>
public sealed class WorkspaceLock : IDisposable
{
    private FileStream? _handle;

    public string Path { get; }

    /// <summary>True when this process owns the workspace.</summary>
    public bool Held => _handle is not null;

    /// <summary>What the owning process recorded, when the lock could not be taken.</summary>
    public string? HeldBy { get; private set; }

    private WorkspaceLock(string path) => Path = path;

    /// <summary>
    /// Try to take the workspace lock.
    /// </summary>
    /// <remarks>
    /// Returns a lock either way: check <see cref="Held"/>. Failing to lock is
    /// a normal outcome the caller reports, not an exception, because "another
    /// instance is already running" is information rather than a fault.
    /// </remarks>
    public static WorkspaceLock Acquire(string findingsLog)
    {
        var directory = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(findingsLog));
        if (string.IsNullOrEmpty(directory)) directory = ".";

        var path = System.IO.Path.Combine(directory, ".monitor.lock");
        var instance = new WorkspaceLock(path);

        try
        {
            Directory.CreateDirectory(directory);

            // FileShare.Read, not None: a second instance asking for write
            // access is still refused, which is the lock, but a reader can see
            // who holds it. With None the conflict message could not name the
            // process the operator needs to stop.
            //
            // DeleteOnClose tidies up on a clean exit; on a hard kill the OS
            // still releases the handle, which is what actually matters.
            instance._handle = new FileStream(path, FileMode.Create, FileAccess.ReadWrite,
                FileShare.Read, 1024, FileOptions.DeleteOnClose);

            var owner = Encoding.UTF8.GetBytes(
                "pid=" + Environment.ProcessId +
                " started=" + EventStore.NowIso() +
                " exe=" + (Environment.ProcessPath ?? "?") + "\n");

            instance._handle.Write(owner);
            instance._handle.Flush();
        }
        catch (IOException)
        {
            // Held by someone else. Read who, best effort: the owner opened it
            // with FileShare.None, so this usually fails too, and the absence
            // of a name must not stop us reporting the conflict.
            instance.HeldBy = ReadOwner(path);
        }
        catch (UnauthorizedAccessException)
        {
            instance.HeldBy = "another process (lock file not readable)";
        }
        return instance;
    }

    private static string? ReadOwner(string path)
    {
        try
        {
            // FileShare.Delete is required as well as ReadWrite: the owner
            // opened the file with DeleteOnClose, and an opener that does not
            // tolerate a pending delete is refused, which is why this read
            // silently failed and the conflict could not name its owner.
            using var reader = new StreamReader(
                new FileStream(path, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete));
            var line = reader.ReadLine();
            return string.IsNullOrWhiteSpace(line) ? null : line.Trim();
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// Whether the recorded owner is still alive.
    /// </summary>
    /// <remarks>
    /// Only meaningful alongside <see cref="HeldBy"/>. A stale lock file with a
    /// dead owner should not happen, because the OS releases the handle, but
    /// saying so plainly beats leaving an operator to guess.
    /// </remarks>
    public bool OwnerIsAlive()
    {
        if (HeldBy is null) return false;

        var marker = HeldBy.Split(' ').FirstOrDefault(p => p.StartsWith("pid=", StringComparison.Ordinal));
        if (marker is null || !int.TryParse(marker[4..], out var pid)) return false;

        try
        {
            using var process = Process.GetProcessById(pid);
            return !process.HasExited;
        }
        catch (Exception exc) when (exc is ArgumentException or InvalidOperationException)
        {
            return false;
        }
    }

    public void Dispose()
    {
        _handle?.Dispose();
        _handle = null;
    }
}
