using System.Threading.Channels;

namespace SecuritySuite.Storage;

/// <summary>
/// One live event-stream client.
/// </summary>
/// <remarks>
/// <para>
/// Wraps the channel so the store can record that a reader fell behind.
/// Without that flag the only options are to drop the subscriber, which leaves
/// its stream open and delivering stats frames so the dashboard shows a live
/// dot and a ticking uptime while receiving no findings, or to drop events,
/// which has the same effect for the same reason.
/// </para>
/// <para>
/// With it, the stream handler can tell the client it fell behind and close,
/// and the browser's <c>EventSource</c> reconnects onto a fresh subscription
/// and resyncs. Missing events is acceptable; not knowing you missed them is
/// not.
/// </para>
/// </remarks>
public sealed class Subscription(Channel<SuiteEvent> channel)
{
    private int _overflowed;

    public Channel<SuiteEvent> Channel { get; } = channel;

    /// <summary>
    /// Set once the store could not hand this reader an event because its
    /// buffer was full. Never reset: the stream is closed instead.
    /// </summary>
    public bool Overflowed => Volatile.Read(ref _overflowed) != 0;

    internal void MarkOverflowed() => Interlocked.Exchange(ref _overflowed, 1);

    public ChannelReader<SuiteEvent> Reader => Channel.Reader;
}
