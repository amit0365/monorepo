Proposed Solution
Design Approach
I propose adding a send_vectored method to the Sink trait that accepts multiple buffer slices. Here's my plan:

Add send_vectored to the Sink trait (runtime/src/lib.rs)
pub trait Sink: Sync + Send + 'static {
/// Send a message to the sink.
fn send(
&mut self,
msg: impl Into<StableBuf> + Send,
) -> impl Future<Output = Result<(), Error>> + Send;

/// Send multiple buffers in a single operation (vectored/scatter-gather I/O).
/// This allows sending data without copying by referencing multiple separate buffers.
fn send_vectored(
&mut self,
bufs: &[&[u8]],
) -> impl Future<Output = Result<(), Error>> + Send;
}

Implement for Tokio runtime (runtime/src/network/tokio.rs)
use tokio::io::AsyncWriteExt;
use std::io::IoSlice;

impl crate::Sink for Sink {
async fn send(&mut self, msg: impl Into<StableBuf> + Send) -> Result<(), Error> {
// Existing implementation...
}

async fn send_vectored(&mut self, bufs: &[&[u8]]) -> Result<(), Error> {
    // Convert to IoSlice for tokio
    let io_slices: Vec<IoSlice> = bufs.iter().map(|b| IoSlice::new(b)).collect();
    
    // Write all buffers with timeout
    timeout(
        self.write_timeout,
        self.sink.write_all_vectored(&io_slices)
    )
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(|_| Error::SendFailed)?;
    
    Ok(())
}
}
3. Implement for deterministic/mocks (fallback to copying)
For runtimes that don't support true vectored I/O (mocks, deterministic), fall back to copying into a single buffer:
async fn send_vectored(&mut self, bufs: &[&[u8]]) -> Result<(), Error> {
// Calculate total length
let total_len: usize = bufs.iter().map(|b| b.len()).sum();

// Allocate single buffer and copy
let mut combined = Vec::with_capacity(total_len);
for buf in bufs {
    combined.extend_from_slice(buf);
}

// Use existing send implementation
self.send(combined).await
}
4. Update send_frame (stream/src/utils/codec.rs)
pub async fn send_frame<S: Sink>(
sink: &mut S,
buf: &[u8],
max_message_size: usize,
) -> Result<(), Error> {
// Validate frame size
let n = buf.len();
if n > max_message_size {
return Err(Error::SendTooLarge(n));
}

// Create length prefix (on stack, no heap allocation)
let len: u32 = n.try_into().map_err(|_| Error::SendTooLarge(n))?;
let len_bytes = len.to_be_bytes();

// Send both buffers in a single vectored write (no copy!)
sink.send_vectored(&[&len_bytes, buf])
    .await
    .map_err(Error::SendFailed)
}
Key Benefits
Zero-copy for Tokio: Uses native write_all_vectored with IoSlice
Backward compatible: Mocks/deterministic still work (with copy fallback)
Simple API: Just &[&[u8]] - easy to use
Minimal changes: Only touches Sink trait and send_frame
Trade-offs
Lifetime challenges: send_vectored takes &[&[u8]] which requires buffers to outlive the call
Allocates Vec of IoSlice: Small allocation for the slice array (but avoids copying actual data) -- what are challenges? is this the best way forward


Here’s a focused review of your proposal, what to watch out for, and a recommendation.

What Works Well

Reduces copies in hot path: Moving send_frame away from building a fresh BytesMut avoids copying large payloads. Using two buffers (4‑byte prefix + payload) is a good fit for the current framing code in stream/src/utils/codec.rs:1.
Localizes change: A single trait addition in runtime/src/lib.rs:423 and one call site in stream/src/utils/codec.rs keeps churn low.
Backward compatibility: With a sensible default on the trait, existing runtimes continue to work.
Key Challenges

API and lifetimes across runtimes
Borrowed slices across .await: fn send_vectored(&mut self, bufs: &[&[u8]]) -> impl Future<...> returns a future that must hold references to bufs. This is fine for async code that completes before the await returns (Tokio), but must be carefully implemented for runtimes that enqueue ops to an event loop (io_uring).
StableBuf invariants: The repo uses StableBuf (utils/src/stable_buf.rs:12) to guarantee stable memory across async boundaries and low‑level I/O. A borrowed &[u8] is safe if the future holding the borrow doesn’t hand the raw pointer to a kernel op that outlives the borrow. For io_uring, the current design explicitly retains an owned buffer (runtime/src/iouring/mod.rs:204) with each op so the memory stays alive.
io_uring integration
The existing io_uring network sink uses Send with a single contiguous buffer (runtime/src/network/iouring.rs:226). True vectored I/O there would need SendMsg + msghdr/iovecs and a way to retain all parts’ lifetimes (e.g., store them in the Op like it currently stores a single StableBuf). That’s extra complexity.
If we add send_vectored with &[&[u8]], io_uring must either copy (combine) or grow new support for SendMsg.
Wrapper layers (metered/audited)
The wrappers at runtime/src/network/metered.rs and runtime/src/network/audited.rs currently only override send. If you add send_vectored, you either:
rely on a default implementation that copies/combines and then calls send (metrics + auditing continue to work as‑is), or
override send_vectored in wrappers to forward to the inner send_vectored (to preserve vectored benefits) and update metrics/auditing to sum/hash across slices.
Tokio API surface
Using AsyncWrite vectored I/O: Tokio 1.43 is recent, but write_all_vectored may not be available on all versions/targets. If not, we must implement a “write all vectored” loop using write_vectored that handles partial writes, and fall back to a single write when vectored isn’t supported.
Semantics and error mapping
Partial writes: a correct implementation must loop until all slices are fully written (or time out), updating the slices to reflect consumption across iterations. This is subtle and easy to get wrong.
Timeouts and mapping to Error::Timeout/Error::SendFailed must match existing behavior in runtime/src/network/tokio.rs:20.
Recommended Design

Add a default send_vectored implementation on the trait
In runtime/src/lib.rs:423, add:
A default send_vectored(&mut self, bufs: &[&[u8]]) -> impl Future<Output = Result<(), Error>> + Send that combines into a single buffer and calls self.send(...).
This preserves backwards compatibility for all existing sinks, wrappers, and mocks while enabling immediate use from stream.
Override in Tokio sink for zero‑copy (and ideally vectored syscall)
In runtime/src/network/tokio.rs:20, implement send_vectored to:
Build IoSlice array from bufs.
Loop with write_vectored until all bytes are written, honoring the existing timeout semantics (like send).
If write_vectored isn’t available or is_write_vectored() returns false, fallback to two writes (or a small loop) to avoid copying the payload.
Wrappers forward to inner
runtime/src/network/metered.rs:57 and runtime/src/network/audited.rs:13 should override send_vectored to call the inner sink’s send_vectored so we don’t lose the benefit. Update metrics by summing bufs.iter().map(|b| b.len()). For auditing, hash all slices in order.
Keep io_uring on default
Let io_uring use the default (copy/concat) for now. If needed later, we can add a SendMsg path and store a small owned list of StableBuf parts in the Op to keep memory alive safely.
Update codec to use it
In stream/src/utils/codec.rs:1, change send_frame to:
Bound check payload size.
Create len_bytes = u32::to_be_bytes(...).
Call sink.send_vectored(&[&len_bytes, buf]) and map errors to Error::SendFailed.
Why this is the best balanced path

Safety: Default impl keeps semantics identical and respects StableBuf guarantees across runtimes that need ownership (io_uring).
Performance where it matters: Tokio path gets zero‑copy (big payload avoids extra allocation/copy). Even if we end up with two writes instead of a single vectored write, it still removes the big copy made by BytesMut.
Minimal churn: Only one trait addition, small focused impls, and a straightforward change to send_frame.
Forward‑compatible: We can later add a send_vectored_owned(Vec<StableBuf>) or a send_buf<B: bytes::Buf> if we want to support more advanced chaining without copying, and add SendMsg for io_uring.
Trade-offs to note

Borrowed lifetime requirement: Callers must guarantee the slices live until the future resolves. Document this clearly in the trait docs at runtime/src/lib.rs:423.
IoSlice allocation: Converting &[&[u8]] to Vec<IoSlice> allocates a tiny vector (2 for framing). Negligible compared to payload sizes.
Not truly single syscall everywhere: Without write_all_vectored or SendMsg, some paths will loop or do two writes, which is still a big improvement over copying.
Good alternative (if you want even less surface change)

Keep the trait as-is and modify send_frame to do two writes via a “specialized” sink method, e.g. send_prefix_and_body(&[u8;4], &[u8]) implemented only for Tokio. But this leaks codec concerns into the runtime abstraction and feels less general than send_vectored.
If you want, I can implement:

Trait + default method in runtime/src/lib.rs,
Tokio impl with robust partial-write loop and timeout,
Metered/Audited forwarding + metrics/auditing updates,
send_frame change in stream/src/utils/codec.rs,
A small test that ensures the length prefix and payload are delivered correctly.
Shall I proceed with that implementation?

can we improve this -- Borrowed lifetime requirement: Callers must guarantee the slices live until the future resolves. Document this clearly in the trait docs at runtime/src/lib.rs:423.
IoSlice allocation: Converting &[&[u8]] to Vec<IoSlice> allocates a tiny vector (2 for framing). Negligible compared to payload sizes.
Not truly single syscall everywhere: Without write_all_vectored or SendMsg, some paths will loop or do two writes, which is still a big improvement over copying. -- just resaech and explore


Here are concrete ways to improve each trade‑off, with minimal churn and clear upgrade paths.

Borrowed Lifetimes

Add an owned variant to eliminate borrower lifetime constraints.
Trait addition in runtime/src/lib.rs:423:
fn send_vectored_owned(&mut self, bufs: Vec<StableBuf>) -> impl Future<Output = Result<(), Error>> + Send;
Default impl: concatenate and call send (keeps BC). Tokio/iouring can override to truly zero‑copy across awaits.
Codec change: allocate the 4‑byte length prefix as a tiny owned buffer and keep body borrowed for the borrowed API, or switch to owned for both only when needed (e.g., non‑Tokio).
Keep the borrowed API but document the rule precisely.
Note: “The slices must remain valid until this future resolves; do not await unrelated work that might free them.”
This mirrors how many async writers handle vectored writes with borrowed slices.
Avoiding IoSlice Allocation

Use stack arrays for the common case (2 parts) in the Tokio impl.
Build [IoSlice::new(&len_bytes), IoSlice::new(body)] on the stack and loop with write_vectored until fully written; no heap allocation.
For N > small threshold, fall back to a temporary Vec<IoSlice<'_>> or a SmallVec.
Optional: add a small‑N helper to the trait to make this obvious without per‑impl branching:
fn send_vectored_2(&mut self, a: &[u8], b: &[u8]) -> impl Future<Output = Result<(), Error>> + Send;
Implement in terms of send_vectored by default; Tokio can specialize to avoid heap allocs entirely.
“Single Syscall” Reality

On Tokio (TcpStream), write_vectored generally maps to writev on Unix, so small prefix+body often emits a single syscall; partial writes are handled by looping.
On io_uring, we can upgrade later to true scatter‑gather:
Implement send_vectored_owned using IORING_OP_WRITEV or IORING_OP_SENDMSG with an msghdr + iovec array.
Store both the Vec<StableBuf> and a heap‑allocated Vec<iovec> inside the Op (runtime/src/iouring/mod.rs:204) so pointers remain valid until completion.
This yields “true” vectored I/O without copying on Linux, matching Tokio’s best case.
Short‑term: keep io_uring on the default copy path via send_vectored → concat → send. The tiny 4‑byte header copy is trivial; the large body remains single‑buffer.
Alternative API Shapes (trade‑offs)

bytes::Buf variant:
fn send_buf(&mut self, buf: impl bytes::Buf + Send) lets callers pass Buf::chain(Bytes::from(len_bytes), Bytes::from(body)). Tokio can leverage write_buf and may use vectored internally; io_uring still needs an owned backing. This is flexible but shifts the lifetime/copy decisions to the caller.
Special‑case framing helper:
fn send_with_prefix(&mut self, prefix: [u8; 4], body: impl Into<StableBuf> + Send) optimizes the common case (no heap for header; owned body). It’s simple and avoids vectors, but is narrowly tailored.
Recommended Path

Keep your borrowed send_vectored(&[&[u8]]) with a clear lifetime doc in runtime/src/lib.rs:423.
Add send_vectored_owned(Vec<StableBuf>) to provide a no‑borrow path for runtimes that enqueue ops and for callers that prefer safety over borrowing.
In Tokio:
Implement send_vectored with an on‑stack [IoSlice; 2] fast path and a robust partial‑write loop under timeout.
Implement send_vectored_owned by borrowing slices from the owned StableBufs; the future owns them, so lifetimes are safe.
In wrappers (metered/audited):
Forward both methods to the inner sink and update metrics/auditing by summing/hashing all parts.
Later (Linux only): upgrade io_uring to WRITEV/SENDMSG for send_vectored_owned, storing Vec<StableBuf> + Vec<iovec> in Op for true scatter‑gather.
This gives:

Safety: Owned path removes lifetime pitfalls entirely.
Zero‑copy where it matters: Tokio is immediate; io_uring gets a clear upgrade path.
No extra allocs for the common framing case: stack IoSlice array in Tokio.
Minimal public surface churn while enabling future performance work.
why we need this -- Later (Linux only): upgrade io_uring to WRITEV/SENDMSG for send_vectored_owned, storing Vec<StableBuf> + Vec<iovec> in Op for true scatter‑gather.


Here’s why the io_uring upgrade to WRITEV/SENDMSG for send_vectored_owned is worth doing, and what it buys us.

Why It Matters

Reduce copies on hot paths: Without vectored I/O, the default path concatenates header+body into a new buffer before a single send. For large frames, that extra copy dominates CPU and memory bandwidth.
One op per frame, not two: Using a single vectored send avoids submitting separate header/body ops. That lowers ring pressure, halves completions for framed writes, and reduces scheduler overhead.
Better write coalescing: A single writev/sendmsg tends to keep the 4‑byte length prefix and body adjacent in the TCP send queue, reducing chances of interleaving with other writes from the same fd under load.
Parity with Tokio path: Tokio can already benefit from write_vectored to avoid the extra copy. Matching that capability in io_uring preserves performance on Linux deployments that choose the io_uring backend.
Aligns with repo principles: “Performance Sensitive” and “Avoid allocations in hot paths” from AGENTS.md strongly favor true scatter‑gather on the data plane.
Why Owned Vectors Specifically

Async lifetime safety: io_uring requires the iovecs and backing memory to remain valid until the CQE arrives. Borrowed &[u8] isn’t safe across that boundary. An owned Vec<StableBuf> solves this by pinning memory for the op’s lifetime.
Kernel ABI requires stable pointers: We must keep both the iovec array and the underlying buffers alive across the async boundary; owning them inside the in-flight Op guarantees that.
What It Requires

Use WRITEV or SENDMSG: For sockets, IORING_OP_SENDMSG (or IORING_OP_WRITEV) lets us submit multiple slices at once. It maps to the same kernel machinery as writev(2)/sendmsg(2).
Retain buffers + iovecs in Op: Instead of Op { buffer: Option<StableBuf> } (runtime/src/iouring/mod.rs:204), a vectored op needs to own:
Vec<StableBuf>: keeps each slice’s memory alive.
Vec<iovec> (or equivalent): stable array of scatter‑gather descriptors pointing into those buffers.
Partial writes handled by kernel: writev/sendmsg returns the number of bytes written; the op either completes fully or we resubmit with the remaining tail (same logic as the current single‑buffer send loop, but over iovecs).
When It Helps Most

Large or frequent frames: Eliminates a full copy of the payload per send. For 64 KiB messages at high QPS, this is a measurable CPU and memory bandwidth win.
Busy connections: Fewer ring ops/completions and better batching can translate into lower latency and higher throughput under load.
Alternatives (and Why They’re Weaker)

Keep copy-on-send: Simple, but pays an O(n) copy per message forever on Linux, contradicting our zero‑copy goals.
Do two ops (header, body): Avoids the big copy but doubles ring traffic and increases interleaving risk versus a single vectored op.
Only use borrowed slices: Not safe for io_uring’s async lifetime across CQE without owning the memory; risks UAF.
Risks/Costs

Slightly more complex Op plumbing: We need an enum or struct to carry multiple buffers and their iovecs for the duration of the op.
Linux‑only path: This optimization only applies to the io_uring backend. That’s fine—Tokio already covers other platforms.
In short: implementing WRITEV/SENDMSG for send_vectored_owned gives true scatter‑gather on Linux io_uring, eliminating per‑message copies, reducing ring/completion load, and aligning with the runtime’s performance goals while preserving async safety via owned memory.

but why we need this -- fn send_vectored_owned(&mut self, bufs: Vec<StableBuf>) -> impl Future<Output = Result<(), Error>> + Send;?


Here’s why adding an owned variant like fn send_vectored_owned(&mut self, bufs: Vec<StableBuf>) -> impl Future<Output = Result<(), Error>> + Send is needed and useful.

Safety across async boundaries: io_uring submissions complete later on CQE; the kernel must see valid pointers the whole time. Owned StableBufs let the future own memory until completion, avoiding use‑after‑free risks inherent with borrowed &[u8] over .await (see runtime/src/iouring/mod.rs:204 for how ops retain buffers today).

Enables true scatter‑gather on io_uring: To implement WRITEV/SENDMSG, we must keep both the iovec array and backing buffers alive in the in‑flight op. Owned Vec<StableBuf> is the natural way to store these until the CQE (runtime/src/network/iouring.rs:226 currently only supports a single contiguous buffer).

Zero‑copy without concatenation: The current fallback concatenates header+body and calls send, incurring an O(n) copy per message (stream/src/utils/codec.rs:1). Owned vectored avoids that copy while still being safe.

Portable API with runtime‑specific benefits: Tokio can still use borrowed send_vectored(&[&[u8]]) efficiently; io_uring needs the owned form to be both safe and zero‑copy. Having both methods lets each backend optimize without forcing copying or risky lifetimes on the other.

Clear ownership semantics: The signature communicates that the sink takes ownership of the buffers until the send completes, matching how low‑level async I/O works and reducing caller footguns.

Keeps wrappers correct and efficient: Metered/audited sinks can forward the owned vectors, sum lengths for metrics, and hash contents for audit without reallocation (runtime/src/network/metered.rs:57, runtime/src/network/audited.rs:13).

Aligns with StableBuf design: StableBuf exists to provide memory stability across async I/O (utils/src/stable_buf.rs:12). An owned vectored API leverages that type exactly where it matters most.

Backwards compatible: Provide a default impl that concatenates and calls send, so existing sinks still work; backends can override to unlock zero‑copy.

In short, the owned variant is the safe, portable enabler for true scatter‑gather on io_uring (and consistent semantics elsewhere) without forcing callers into risky borrowing patterns or extra copies.

does agent.md provide any guidlines that can help determine if we need thw owned verwison


Yes — several AGENTS.md guidelines push toward adding an owned vectored API when designing cross‑runtime I/O:

Performance Sensitive / Avoid allocations in hot paths
Owned Vec<StableBuf> enables true zero‑copy in io_uring via WRITEV/SENDMSG, avoiding per‑message concatenation copies that send_vectored(&[&[u8]]) may force in non‑Tokio backends.
Prefer Bytes over Vec<u8> for zero‑copy
StableBuf wraps BytesMut/Vec and is designed for zero‑copy; an owned API lets the runtime hold these buffers safely until completion.
Adversarial Safety / Safety Guidelines
Borrowed slices across .await are footguns for runtimes that outlive the call site (io_uring). Owning the buffers eliminates lifetime hazards and UAF risks without extra unsafe.
Abstract Runtime
The trait should express capabilities that all backends can implement safely and efficiently. Owned vectored buffers are the portable way to support scatter‑gather across Tokio and io_uring.
Always Commit Complete Code
If we introduce vectored sending, providing both borrowed and owned paths makes the feature complete across all supported runtimes, not just Tokio.
Rule of thumb from these guidelines:

If targeting multiple backends (Tokio + io_uring), sending large frames, or requiring zero‑copy and safe cross‑await semantics, add send_vectored_owned(Vec<StableBuf>).
If only Tokio matters and payloads are small, the borrowed send_vectored(&[&[u8]]) can suffice, but the repo’s performance and safety principles still favor offering the owned variant for completeness and portability.
instead of using two mehots send_vectored and the owned. can we have a single version that woreks with both tokio and uring? should we change the params type


Short answer: yes, you can unify to a single method — the cleanest choices are either “owned vectored” or “owned Buf.” Here’s how to pick.

Option A: Owned Vectored

Signature: fn send_vectored(&mut self, bufs: Vec<StableBuf>) -> impl Future<Output = Result<(), Error>> + Send;
Why it works across Tokio + io_uring:
Ownership guarantees memory stays valid across awaits (required by io_uring).
Tokio can still do zero-copy by borrowing from the owned buffers into IoSlice on the stack (no heap for the iovec in the 2-slice fast path).
Pros:
Simple to implement now (minimal runtime churn).
Aligns with StableBuf (utils/src/stable_buf.rs) and current io_uring Op ownership model.
Cons:
Callers with only borrowed slices must allocate (e.g., body is &[u8]), so avoiding the big body copy depends on callers passing owned buffers (Vec or BytesMut).
Option B: Single “Buf”-based API

Signature: fn send_buf<B: bytes::Buf + Send + 'static>(&mut self, buf: B) -> impl Future<Output = Result<(), Error>> + Send;
Why it works across Tokio + io_uring:
Tokio: use write_all_buf; it internally exploits vectored writes.
io_uring: store the Buf in the in‑flight Op; build iovecs from buf.chunks()/chunks_vectored, submit WRITEV/SENDMSG, advance the Buf on partial writes.
Pros:
One API, very flexible: callers can chain buffers (Bytes::from(len).chain(Bytes::from(vec))) and keep it zero‑copy when they already have owned bodies (Vec/Bytes/BytesMut).
No need to expose vectors explicitly; the backend can decide how many iovecs to materialize.
Cons:
io_uring implementation is more involved (maintain Buf across submits, handle partial writes, rebuild iovecs as you advance).
What to pass from send_frame

With Option A (owned vectored):
Keep header as small owned buffer (BytesMut::from(&len_bytes[..])).
If callers can pass owned body (Vec/BytesMut), zero‑copy; if they only have &[u8], you’ll copy (no worse than today).
With Option B (Buf):
Build a Buf chain: Bytes::copy_from_slice(&len_bytes).chain(Bytes::from(body_vec)).
Zero‑copy for body if encode() returns Vec/BytesMut (Vec→Bytes is zero‑copy); only the 4‑byte header is copied.
Recommendation

If you want a single method now with minimal churn and safe portability: choose Owned Vectored (Vec<StableBuf>). It meshes perfectly with StableBuf and the io_uring Op model, and Tokio can still be fully efficient.
If you’re willing to implement the io_uring Buf path: choose send_buf<B: Buf>. It’s the most general, future‑proof API and still efficient on Tokio today. It also lets you keep send_frame zero‑copy for bodies where encode returns Vec/BytesMut by using a Buf chain.
Either way, you can keep the existing send for backward compatibility, and wrappers (metered/audited) can simply sum lengths and forward.

If you’d like, I can sketch the exact Tokio impl for either choice and a small adapter for send_frame that keeps header zero‑alloc and body zero‑copy when owned.

is this correct? -- Based on my analysis of the codebase, here's what I found regarding whether callers can pass owned Vec/BytesMut buffers with Option A (owned vectored):
Key Findings
Current Situation:
send_frame currently accepts buf: &[u8] (borrowed slice)
All actual data being sent comes from already-owned buffers:
Caller Patterns
stream/src/lib.rs:289-297 - Encrypted messages:
let c = self.cipher.send(msg)?; // Returns Vec<u8>
send_frame(&mut self.sink, &c, ...).await?;
cipher.send() returns Vec<u8> (owned)
Currently borrowed immediately for send_frame
examples/sync/src/bin/server.rs:343-344 - Encoded responses:
let response_data = response.encode().to_vec(); // BytesMut -> Vec
send_frame(&mut sink, &response_data, MAX_MESSAGE_SIZE).await
encode() returns BytesMut (owned)
.to_vec() converts to Vec<u8> (owned)
p2p/src/simulated/network.rs:869-873 - Network messages:
let mut data = bytes::BytesMut::with_capacity(...);
data.extend_from_slice(&channel.to_be_bytes());
data.extend_from_slice(&message);
let data = data.freeze(); // BytesMut -> Bytes
send_frame(&mut sink, &data, max_size).await;
BytesMut::freeze() returns Bytes (owned, reference-counted)
stream/src/lib.rs:174-192 - Handshake messages:
send_frame(&mut sink, config.signing_key.public_key().encode().as_ref(), ...);
send_frame(&mut sink, &syn.encode(), ...);
send_frame(&mut sink, &ack.encode(), ...);
encode() returns BytesMut (owned)
Recommendation: Option A is Viable with API Change
All callers already have owned buffers (Vec<u8>, BytesMut, or Bytes). They only borrow them because the current API requires &[u8]. Proposed Changes:
Change send_frame signature to accept owned buffers:
pub async fn send_frame<S: Sink>(
sink: &mut S,
buf: impl Into<Vec<u8>>, // Accept Vec, BytesMut, Bytes, etc.
max_message_size: usize,
) -> Result<(), Error>
Change send_vectored to owned:
fn send_vectored(&mut self, bufs: Vec<StableBuf>)
-> impl Future<Output = Result<(), Error>> + Send;
Benefits:
✅ Zero-copy for io_uring (ownership guarantees memory validity)
✅ Zero-copy for Tokio (can borrow from owned buffers into IoSlice on stack)
✅ No caller impact - all callers already have owned data
✅ Simple implementation - minimal runtime churn
Implementation in send_frame:
pub async fn send_frame<S: Sink>(
sink: &mut S,
buf: impl Into<Vec<u8>>,
max_message_size: usize,
) -> Result<(), Error> {
let buf = buf.into();
let n = buf.len();
if n > max_message_size {
return Err(Error::SendTooLarge(n));
}

let len: u32 = n.try_into().map_err(|_| Error::SendTooLarge(n))?;
let len_bytes = len.to_be_bytes().to_vec();

sink.send_vectored(vec![
    StableBuf::from(len_bytes),
    StableBuf::from(buf),
]).await.map_err(Error::SendFailed)
}
Conclusion
Yes, callers can pass owned buffers - in fact, they already have them! The current API just forces unnecessary borrowing. Option A (owned vectored) is the right choice and will provide zero-copy benefits for both Tokio and io_uring without impacting any callers negatively. -- willl changing api violate principles laid out in agents.md


Short answer: your high‑level conclusion (callers often have owned data) is mostly right, but the specific API change to Into<Vec<u8>> is not aligned with the codebase or AGENTS.md.

What’s correct

encode() returns BytesMut (codec/src/codec.rs:76), so many call sites already materialize owned buffers.
Handshake and ciphertext paths in stream/src/lib.rs pass owned data (BytesMut or Vec) but then borrow because send_frame expects &[u8].
Some sites produce Bytes via freeze, which is owned and zero‑copy.
What breaks or regresses

Into<Vec<u8>> forces extra copies:
BytesMut → Vec copies. You’d regress hot paths that currently avoid copies until framing.
Bytes → Vec copies. p2p simulated path freezes to Bytes; converting that to Vec would copy the whole payload.
StableBuf is the project’s zero‑copy ownership vehicle. Bypassing it in favor of Vec<u8> conflicts with existing runtime APIs (Sink::send takes Into<StableBuf>) and design.
AGENTS.md alignment

Performance Sensitive / Avoid allocations in hot paths: Into<Vec<u8>> adds copies for BytesMut/Bytes.
Prefer Bytes over Vec<u8>: Using Vec in the public API pushes callers toward Vec.
Own Core Mechanisms / Abstract Runtime: StableBuf is the house abstraction for safe, stable ownership across async I/O; the API should lean on it, not Vec.
Better unification

Single owned vectored API:
fn send_vectored(&mut self, bufs: Vec<StableBuf>) -> impl Future<Output = Result<(), Error>> + Send;
Tokio: borrow IoSlice from StableBufs on the stack (no heap for the iovec in the 2‑slice fast path), loop on partials with timeout.
io_uring (later): true scatter‑gather via WRITEV/SENDMSG by storing Vec<StableBuf> + iovecs in Op.
Keep send_frame’s input flexible without copies:
Accept Into<StableBuf> (not Into<Vec<u8>>), so BytesMut and Vec stay zero‑copy. For Bytes, you either:
keep the current borrowed path (and use borrowed send_vectored for Tokio), or
avoid freezing to Bytes in the few places that do it before send_frame.
If you must have one method only: consider a Buf‑based API (fn send_buf<B: bytes::Buf + Send + 'static>(...)), but it’s a heavier io_uring implementation.
Recommendation

Do not switch send_frame to Into<Vec<u8>>; it adds unnecessary copies and conflicts with AGENTS.md.
If you unify, prefer Vec<StableBuf> for the owned vectored method and keep the current borrowed send_frame signature, updating it to call send_vectored where available. This preserves zero‑copy for BytesMut/Vec today and sets you up for true scatter‑gather on io_uring later.
what do yiou mean? sets you up for true scatter‑gather on io_uring later. -- currently this wont benefit on uring backend


Here’s what “sets you up for true scatter‑gather on io_uring later” means.

What it means

Choosing a single owned‑vectored API now (e.g., send_vectored(Vec<StableBuf>)) gives the io_uring backend the ownership it needs to safely implement WRITEV/SENDMSG later without changing the public API again.
Why no immediate io_uring gain

Today, the io_uring sink only sends a single contiguous buffer (runtime/src/network/iouring.rs:226). With the owned‑vectored API but no io_uring work, we’d still concatenate and send one buffer (i.e., no vectored win yet).
What you’d do later (io_uring)

Extend the op payload to hold multiple buffers + iovecs safely across the CQE:
Replace Op { buffer: Option<StableBuf> } with a form that can store Vec<StableBuf> and a heap‑allocated Box<[libc::iovec]> (runtime/src/iouring/mod.rs:204).
Implement send_vectored in runtime/src/network/iouring.rs using IORING_OP_WRITEV (or SENDMSG):
Build iovecs from the owned StableBufs, submit once.
On partial completion, adjust iovecs (advance base/len) and resubmit until all bytes are sent.
Keep existing timeout/error mapping consistent with current send.
This yields real scatter‑gather (no payload copy, one op per frame), matching Tokio’s vectored behavior.
Why choose this shape now

Safety: io_uring requires buffers live until CQE; owned StableBuf guarantees that.
Stability: adopting the owned‑vectored signature now avoids a future breaking change when we add the io_uring writev path.
Alignment: uses the repo’s StableBuf (utils/src/stable_buf.rs) and performance principles in AGENTS.md.
Practical next step

Add the owned‑vectored method and implement it in Tokio immediately (stack IoSlice fast path).
Forward in audited/metered wrappers.
Keep io_uring on the concat fallback for now; upgrade to WRITEV/SENDMSG when ready without touching call sites.
but earlier you said uring would work for option A of owning with work with uring natively -- Short answer: yes, you can unify to a single method — the cleanest choices are either “owned vectored” or “owned Buf.” Here’s how to pick.

Option A: Owned Vectored

Signature: fn send_vectored(&mut self, bufs: Vec<StableBuf>) -> impl Future<Output = Result<(), Error>> + Send;
Why it works across Tokio + io_uring:
Ownership guarantees memory stays valid across awaits (required by io_uring).
Tokio can still do zero-copy by borrowing from the owned buffers into IoSlice on the stack (no heap for the iovec in the 2-slice fast path).
Pros:
Simple to implement now (minimal runtime churn).
Aligns with StableBuf (utils/src/stable_buf.rs) and current io_uring Op ownership model.
Cons:
Callers with only borrowed slices must allocate (e.g., body is &[u8]), so avoiding the big body copy depends on callers passing owned buffers (Vec or BytesMut).


You’re right to call out the nuance. When I said “Option A works across Tokio + io_uring,” I meant the API shape is correct and safe for both backends — not that the io_uring backend already does vectored sends today.

What “works” means: Owned Vec<StableBuf> gives io_uring the ownership it needs to safely submit vectored writes (buffers live until the CQE). That’s necessary groundwork.
Current state: io_uring’s sink only supports a single contiguous buffer (runtime/src/network/iouring.rs:226). With the new API but no backend change, it will still concatenate and send — no immediate perf gain on io_uring.
How to get native io_uring benefits: implement vectored send in the backend:
Extend op payload to hold multiple buffers + iovecs (runtime/src/iouring/mod.rs:204).
Build iovec array and submit IORING_OP_WRITEV (or SENDMSG), handle partial writes and timeouts.
Why keep Option A: It avoids another future API change. You can implement Tokio’s fast path now and add io_uring’s writev/sendmsg later without touching call sites.
If you want the io_uring win immediately, I can sketch the exact changes to:

Op struct (store Vec<StableBuf> and Box<[libc::iovec]>), and
a new Sink::send_vectored in runtime/src/network/iouring.rs with a partial‑write loop.
Short answer: yes, you can unify to a single method — the cleanest choices are either “owned vectored” or “owned Buf.” Here’s how to pick.

Option A: Owned Vectored

Signature: fn send_vectored(&mut self, bufs: Vec<StableBuf>) -> impl Future<Output = Result<(), Error>> + Send;
Why it works across Tokio + io_uring:
Ownership guarantees memory stays valid across awaits (required by io_uring).
Tokio can still do zero-copy by borrowing from the owned buffers into IoSlice on the stack (no heap for the iovec in the 2-slice fast path).
Pros:
Simple to implement now (minimal runtime churn).
Aligns with StableBuf (utils/src/stable_buf.rs) and current io_uring Op ownership model.
Cons:
Callers with only borrowed slices must allocate (e.g., body is &[u8]), so avoiding the big body copy depends on callers passing owned buffers (Vec or BytesMut).
Option B: Single “Buf”-based API

Signature: fn send_buf<B: bytes::Buf + Send + 'static>(&mut self, buf: B) -> impl Future<Output = Result<(), Error>> + Send;
Why it works across Tokio + io_uring:
Tokio: use write_all_buf; it internally exploits vectored writes.
io_uring: store the Buf in the in‑flight Op; build iovecs from buf.chunks()/chunks_vectored, submit WRITEV/SENDMSG, advance the Buf on partial writes.
Pros:
One API, very flexible: callers can chain buffers (Bytes::from(len).chain(Bytes::from(vec))) and keep it zero‑copy when they already have owned bodies (Vec/Bytes/BytesMut).
No need to expose vectors explicitly; the backend can decide how many iovecs to materialize.
Cons:
io_uring implementation is more involved (maintain Buf across submits, handle partial writes, rebuild iovecs as you advance).
What to pass from send_frame

With Option A (owned vectored):
Keep header as small owned buffer (BytesMut::from(&len_bytes[..])).
If callers can pass owned body (Vec/BytesMut), zero‑copy; if they only have &[u8], you’ll copy (no worse than today).
With Option B (Buf):
Build a Buf chain: Bytes::copy_from_slice(&len_bytes).chain(Bytes::from(body_vec)).
Zero‑copy for body if encode() returns Vec/BytesMut (Vec→Bytes is zero‑copy); only the 4‑byte header is copied.
Recommendation

If you want a single method now with minimal churn and safe portability: choose Owned Vectored (Vec<StableBuf>). It meshes perfectly with StableBuf and the io_uring Op model, and Tokio can still be fully efficient.
If you’re willing to implement the io_uring Buf path: choose send_buf<B: Buf>. It’s the most general, future‑proof API and still efficient on Tokio today. It also lets you keep send_frame zero‑copy for bodies where encode returns Vec/BytesMut by using a Buf chain.
Either way, you can keep the existing send for backward compatibility, and wrappers (metered/audited) can simply sum lengths and forward.

If you’d like, I can sketch the exact Tokio impl for either choice and a small adapter for send_frame that keeps header zero‑alloc and body zero‑copy when owned. -- which option is more aligned to -- which option is more aligned with aligned with the codebase or AGENTS.md


Option A (owned vectored with Vec<StableBuf>) is more aligned with this codebase and AGENTS.md.

Matches existing abstractions: StableBuf is already the runtime’s ownership primitive (runtime/src/lib.rs, utils/src/stable_buf.rs). Extending the trait to take Vec<StableBuf> keeps types consistent across tokio, deterministic, metered, audited, and io_uring.
Simpler by design: Fewer generics and less state to juggle than a Buf-based API. Aligns with “The Simpler The Better.”
Performance-focused, portable: Unlocks immediate zero-copy benefits on Tokio; gives io_uring the ownership it needs for a later WRITEV/SENDMSG path without another API break. Fits “Performance Sensitive” and “Abstract Runtime.”
Avoids unintended copies: Unlike Into<Vec<u8>>, it doesn’t push callers toward Vec and respects “Prefer Bytes over Vec<u8>.”
One refinement to fully align with “Prefer Bytes”:

Consider adding a StableBuf::Bytes variant (plus impl Frombytes::Bytes) so callers that currently freeze to Bytes can pass ownership without copying. This keeps send_frame and p2p paths zero-copy when they already have Bytes.
Practical shape:

Single method: fn send_vectored(&mut self, bufs: Vec<StableBuf>) -> impl Future<Output = Result<(), Error>> + Send;
Tokio impl: borrow IoSlice from StableBufs on stack (2-slice fast path), loop on partial writes with timeout.
Wrappers: forward and sum lengths/hash contents.
io_uring: keep concat fallback now; later implement WRITEV/SENDMSG using owned Vec<StableBuf> + iovecs in Op for true scatter-gather.
Net: Option A honors current design patterns, minimizes complexity, and positions io_uring for a zero-copy upgrade when you’re ready.

give full implementation plan


Here’s a precise, end‑to‑end plan to add a single owned‑vectored send that works cleanly with Tokio now and positions io_uring for a later true scatter‑gather upgrade.

Plan

Extend Sink trait with owned‑vectored
Implement Tokio fast path (vectored)
Override wrappers (metered/audited)
Keep deterministic/io_uring on fallback
Update StableBuf conversions
Update send_frame to use owned‑vectored
Adjust call sites and tests
Document + validation
Details

Extend Sink trait with owned‑vectored
File: runtime/src/lib.rs:423
Change:
Add: fn send_vectored(&mut self, bufs: Vec<StableBuf>) -> impl Future<Output = Result<(), Error>> + Send;
Provide a default implementation:
Validate bufs not empty; if empty, return Ok.
Compute total_len, allocate a combined buffer (BytesMut::with_capacity(total_len)), extend from each buf.as_ref(), and call self.send(combined).
Doc comments:
Ownership semantics: the sink owns buffers until completion.
Guarantees: ordered send of concatenation of slices.
Error mapping consistent with send (Timeout → Error::Timeout, I/O → Error::SendFailed).
Implement Tokio fast path (vectored)
File: runtime/src/network/tokio.rs:20
Add impl method:
async fn send_vectored(&mut self, bufs: Vec<StableBuf>) -> Result<(), Error>
If total_len == 0: return Ok.
Use a loop with timeout(self.write_timeout, async move { ... }):
Track (slice_index, offset_in_slice) and remaining bytes.
Build IoSlice<'_> vector referencing the remaining parts:
For typical 2‑slice (header + body), this allocates a tiny Vec; acceptable for now.
Call self.sink.write_vectored(&iovecs).await:
If 0: return Err(Error::SendFailed).
Advance indices and continue until all bytes sent.
Map timeout to Error::Timeout; I/O errors to Error::SendFailed.
Keep existing send() unchanged.
Override wrappers to forward vectored
Metered
File: runtime/src/network/metered.rs:57
Add async fn send_vectored(&mut self, bufs: Vec<StableBuf>) -> Result<(), crate::Error>:
Sum total_len = bufs.iter().map(|b| b.len()).sum::<usize>();
self.inner.send_vectored(bufs).await?;
self.metrics.outbound_bandwidth.inc_by(total_len as u64);
Ok(())
Audited
File: runtime/src/network/audited.rs:13
Add async fn send_vectored(&mut self, bufs: Vec<StableBuf>) -> Result<(), Error>:
Emit “send_attempt” event with remote_addr (same as send()).
Optionally include a per‑slice hash/update (to parallel send()’s hashing over the full buffer) by iterating slices.
Forward to inner.send_vectored(bufs).await, on error emit “send_failure”; on success emit “send_success”.
Deterministic + io_uring: keep fallback for now
Deterministic
File: runtime/src/network/deterministic.rs:18
No changes needed; it inherits the trait’s default.
io_uring
File: runtime/src/network/iouring.rs:226
No changes now; it will use the default (concat + single send).
Future (not in this change): upgrade to WRITEV/SENDMSG by storing Vec<StableBuf> + iovecs in Op.
StableBuf conversions (to ease call sites)
File: utils/src/stable_buf.rs
Add:
impl Frombytes::Bytes for StableBuf { fn from(b: bytes::Bytes) -> Self { StableBuf::BytesMut(bytes::BytesMut::from(&b[..])) } }
Rationale: lets current Bytes callers (e.g., p2p) pass ownership into send_frame without changing their data shape; this copies today, but is acceptable for simulated/test paths.
Update send_frame to use owned‑vectored
File: stream/src/utils/codec.rs:1
Change signature:
From: pub async fn send_frame<S: Sink>(sink: &mut S, buf: &[u8], max_message_size: usize) -> Result<(), Error>
To: pub async fn send_frame<S: Sink>(sink: &mut S, buf: impl Into<StableBuf>, max_message_size: usize) -> Result<(), Error>
Body:
let buf = buf.into();
let n = buf.len(); bounds check as before.
let len_bytes = (n as u32).to_be_bytes().to_vec(); // tiny owned header
sink.send_vectored(vec![StableBuf::from(len_bytes), buf]).await.map_err(Error::SendFailed)
Notes:
This keeps zero‑copy for bodies that are Vec<u8> or BytesMut.
Bytes callers will copy into BytesMut via the new From<Bytes>.
Adjust call sites and tests
File: stream/src/lib.rs:174,186,192,252,291
Replace borrowed usage with owned:
pass encode() directly (drop as_ref())
pass ciphertext Vec<u8> by value.
File: p2p/src/simulated/network.rs: outbox path
At send_frame(&mut sink, &data, max_size).await → send_frame(&mut sink, data, max_size).await (move Bytes into call; conversion handled by From<Bytes>).
File: examples/sync/src/bin/server.rs:343
pass response_data by value (Vec/BytesMut) into send_frame.
File: stream/src/utils/codec.rs tests
Replace borrowed slices with owned Vec where needed, or pass BytesMut/Vec directly:
E.g., send_frame(&mut sink, buf.to_vec(), MAX_MESSAGE_SIZE).await
Where tests used manual framing, keep as is or update to StableBuf friendly forms.
Documentation + validation
Trait docs (runtime/src/lib.rs:423): explain ownership, ordering, error mapping, and that default path concatenates.
Optional in tokio sink docs: mention vectored write loop and timeout semantics matching send.
Run local checks (when ready):
Format/lint: just lint
Tests: just test --workspace
If you want me to, I can implement and then run a targeted cargo check for runtime + stream to validate signatures compile.
Notes on scope and alignment

The plan keeps the existing send API for compatibility.
It aligns with AGENTS.md:
Performance Sensitive: avoids large copies for owned bodies; Tokio benefits immediately.
Abstract Runtime: one API that works across runtimes; io_uring gets a clean upgrade path later.
Prefer Bytes over Vec<u8>: StableBuf preserves zero‑copy for Vec/BytesMut; Bytes callers can be adjusted later to avoid freeze if desired.
Want me to implement these changes and update the affected call sites now?

but why are we concating in send vectored? Instead, we could concatenate the data together and send once in order to make a single syscall, but this would require copying the memory, which is especially undesirable for large messages.

Instead, it's probably best to simply support tokio's write_vectored() function which takes in a slice of slices and will send them all without having to do copying (besides the references)


You’re right: we should not concatenate in Tokio’s send_vectored. The concat fallback was only to provide a portable baseline across all runtimes. Better approach:

Tokio: implement true vectored writes with write_vectored and a partial-write loop. No copying of payloads, just references.
Default (other backends): avoid copying by sequentially calling send on each slice. This preserves semantics without O(n) payload copies. io_uring can later switch to writev/sendmsg for a single-op, zero‑copy path.
What to change

Trait shape (single, owned API)

Keep one method: fn send_vectored(&mut self, bufs: Vec<StableBuf>) -> impl Future<Output = Result<(), Error>> + Send;
Rationale: owned buffers are safe across awaits (needed by io_uring and consistent with StableBuf).
Tokio implementation (no concat)

Build IoSlice references from the supplied StableBuf parts.
Loop with write_vectored until all bytes are written.
Honor existing write timeout and map errors like send.
If vectored isn’t supported, fall back to a small loop of write_all on each part (still no copying).
Default fallback (no concat)

Implement send_vectored by iterating bufs and calling self.send(part).await for each. This avoids big copies on runtimes that don’t support vectored yet (deterministic/io_uring today). It makes multiple syscalls/ops, but is typically better than copying large messages.
Wrappers (metered/audited)

Forward send_vectored to inner, summing part lengths for metrics and hashing each part for auditing.
Why this is better

No extra copies on Tokio: exactly what you want — use write_vectored.
No big copies elsewhere: sequential send avoids the cost you called out.
Consistent semantics: byte stream order is preserved (prefix then body), as expected by recv_frame.
Future‑proof: io_uring can later implement writev/sendmsg (keeping the same API) for single-op scatter‑gather.
Tokio skeleton

In runtime/src/network/tokio.rs:
use tokio::io::AsyncWrite;
Implement:
Calculate total remaining.
While remaining > 0:
Build IoSlice list from current (slice_index, offset_in_slice).
let wrote = self.sink.write_vectored(&iovecs).await?;
if wrote == 0 -> Err(Error::SendFailed)
Advance indices accordingly.
Wrap the whole loop in timeout(self.write_timeout, async { ... }).
Default skeleton

In runtime/src/lib.rs for the trait default:
async fn send_vectored(&mut self, bufs: Vec<StableBuf>) -> Result<(), Error> {
for b in bufs { self.send(b).await?; }
Ok(())
}
This replaces previous “concat then send” idea.
Net: No concatenation on Tokio; no concatenation in the generic default either. You get zero‑copy (Tokio) now, no big copies on others, and a smooth path to io_uring writev/sendmsg later without changing the API.

what is send refrecning here -- async fn send_vectored(&mut self, bufs: Vec<StableBuf>) -> Result<(), Error> {
for b in bufs { self.send(b).await?; }
Ok(())
} -- should this be send vectoired


What send refers to

It’s the existing single-buffer method on the same Sink trait: fn send(&mut self, msg: impl Into<StableBuf> + Send) -> ...
In the default send_vectored implementation, calling self.send(b).await? dispatches to the concrete type’s send, sending each part sequentially.
Should it be send_vectored instead?

No. Calling send_vectored from inside the default send_vectored would recurse and never progress.
The intent of the default is a safe, portable fallback: send each StableBuf part one-by-one using send. Backends that can do true scatter-gather (Tokio today, io_uring later) should override send_vectored with a specialized implementation.
Summary

The default implementation should call send for each buffer:
async fn send_vectored(&mut self, bufs: Vec<StableBuf>) -> Result<(), Error> {
for b in bufs {
self.send(b).await?;
}
Ok(())
}
Specialized runtimes override send_vectored to avoid multiple writes (e.g., Tokio uses write_vectored). Wrappers (metered/audited) should also override to forward to inner.send_vectored to retain the optimization.
i dont inuderstand how does it override when we have send vector that does send internally -- Specialized runtimes override send_vectored to avoid multiple writes (e.g., Tokio uses write_vectored). Wrappers (metered/audited) should also override to forward to inner.send_vectored to retain the optimization.


Great question — this is just Rust trait default-method semantics.

What the default does

In the trait (runtime/src/lib.rs:423), you add a default:
async fn send_vectored(&mut self, bufs: Vec<StableBuf>) -> Result<(), Error> {
for b in bufs { self.send(b).await?; }
Ok(())
}
This runs only if the concrete impl does not provide its own send_vectored.
How Tokio “overrides” it

In runtime/src/network/tokio.rs:20, you implement the trait for the Tokio sink and provide your own method:
impl crate::Sink for Sink {
async fn send(&mut self, msg: impl Into<StableBuf> + Send) -> Result<(), Error> { ... }
async fn send_vectored(&mut self, bufs: Vec<StableBuf>) -> Result<(), Error> {
// Tokio-specific fast path: build IoSlice[] and loop write_vectored
}
}
Because this impl defines send_vectored, the default is ignored for Tokio’s Sink — your method is called instead.
Why the default calling send doesn’t block overriding

The default calls self.send(...) (not self.send_vectored(...)), so it’s just a fallback behavior for types that don’t implement the optimized method. Once a type implements send_vectored itself, that local method is what the compiler dispatches to.
Wrappers must forward to inner to keep the optimization

Metered/audited define their own Sink impls (runtime/src/network/metered.rs:57, runtime/src/network/audited.rs:13). If they don’t override send_vectored, the default will run on the wrapper type (iterating and calling wrapper.send per part).
To preserve the vectored benefit, override and forward:
async fn send_vectored(&mut self, bufs: Vec<StableBuf>) -> Result<(), Error> {
let total = bufs.iter().map(|b| b.len()).sum::<usize>();
self.inner.send_vectored(bufs).await?;
self.metrics.outbound_bandwidth.inc_by(total as u64);
Ok(())
}
That calls the inner sink’s send_vectored — which, for Tokio, uses write_vectored.
Summary

Default method = safe fallback (send each part) used only when a concrete impl doesn’t provide send_vectored.
Tokio provides its own send_vectored, so it bypasses the default and uses write_vectored.
Wrappers should override and forward to inner.send_vectored to retain the optimization.
is this correct --
async fn send_vectored(&mut self, bufs: Vec<StableBuf>) -> Result<(), Error> {
use std::io::IoSlice;

    if bufs.is_empty() {
        return Ok(());
    }

    let total_len: usize = bufs.iter().map(|b| b.len()).sum();
    if total_len == 0 {
        return Ok(());
    }

    let write_op = async {
        let mut slice_index = 0;
        let mut offset_in_slice = 0;
        let mut remaining = total_len;

        while remaining > 0 {
            let mut iovecs = Vec::new();

            for i in slice_index..bufs.len() {
                let buf = &bufs[i];
                let start = if i == slice_index { offset_in_slice } else { 0 };
                let slice = &buf.as_ref()[start..];
                if !slice.is_empty() {
                    iovecs.push(IoSlice::new(slice));
                }
            }

            if iovecs.is_empty() {
                break;
            }

            let wrote = self
                .sink
                .write_vectored(&iovecs)
                .await
                .map_err(|_| Error::SendFailed)?;
            if wrote == 0 {
                return Err(Error::SendFailed);
            }

            remaining -= wrote;
            let mut advance = wrote;

            while advance > 0 && slice_index < bufs.len() {
                let buf_len = bufs[slice_index].len();
                let available = buf_len - offset_in_slice;

                if advance >= available {
                    advance -= available;
                    slice_index += 1;
                    offset_in_slice = 0;
                } else {
                    offset_in_slice += advance;
                    advance = 0;
                }
            }
        }

        Ok(())
    };

    timeout(self.write_timeout, write_op)
        .await
        .map_err(|_| Error::Timeout)?
}
}


Yes, that Tokio implementation is functionally correct and matches the intended behavior:

Uses true vectored I/O via write_vectored (no payload copies).
Handles partial writes by tracking slice_index and offset_in_slice.
Detects closed/failed writes (wrote == 0 → SendFailed).
Preserves timeout semantics by wrapping the whole loop in timeout(...).
A few small improvements you can make:

Pre‑allocate iovec capacity to avoid tiny re-allocs in the loop:
let mut iovecs = Vec::with_capacity(bufs.len() - slice_index);
Then iovecs.clear() each iteration and reuse.
Early return on all‑empty input is fine (total_len == 0).
Optional: check is_write_vectored() and fallback to sequential write_all per part if false; usually not needed on Tokio’s TCP.
Optional: cap iovecs length to IOV_MAX (unlikely to matter here since framing uses 2 slices).
Semantics and error mapping are consistent with send():

Timeout → Error::Timeout (outer map_err).
I/O failure or closed → Error::SendFailed (inner mapping and wrote == 0 guard).
So you can keep this implementation as-is, with the small capacity tweak for fewer allocs.





Auto context


Local

Agent

gpt-5
high
