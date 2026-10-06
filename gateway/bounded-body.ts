// The streaming body cap for gateway/, which compiles and ships as its own
// Worker and imports nothing from src/. Twin: src/bounded-body.ts. Before
// this file the gateway had two disciplines rather than one: activity.ts
// reimplemented the loop inline, and storage.ts's readJson had no cap at all.
//
// The two copies are held to the same OUTPUT rather than the same source
// text, by test/constant-parity.node.test.ts, the same way the
// groupsVisibleToApp twins are.

/**
 * Why the bytes stopped arriving, not just that they did. The gateway's two
 * callers answer an over-cap body differently: activity.ts counts it as work
 * (a large POST /mcp under a real user token is almost certainly a tools/call
 * payload), storage.ts refuses it. An unreadable body is also a different
 * event from an oversized one, so neither caller should have to infer which
 * happened from a single null.
 */
export type BoundedRead =
  | { ok: true; bytes: Uint8Array }
  | { ok: false; reason: "over-cap" | "unreadable" };

/**
 * Read a body as BYTES, counting them as they arrive and aborting the moment
 * the running total passes `maxBytes`. An absent body reads as zero bytes.
 *
 * The declared Content-Length is checked FIRST because it is free, but it is
 * never the only check: a chunked body carries none, which is precisely how
 * activity.ts's peek cap was bypassable before the streaming form existed.
 *
 * Takes anything with a body stream and headers rather than a Request, so a
 * clone, the original, and a Response all fit the same seam.
 */
export async function readBoundedResultFrom(
  source: { body: ReadableStream<Uint8Array> | null; headers: Headers }, maxBytes: number,
): Promise<BoundedRead> {
  const declared = Number(source.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    // Same discipline as the in-loop cancel below, one step earlier. Giving
    // up on a body without releasing it is not free when the caller handed
    // us a CLONE: clone() tees, and a branch nobody reads forces the runtime
    // to buffer the whole body for the branch that IS read, until it fails
    // with "ReadableStream.tee() buffer limit exceeded". activity.ts peeks a
    // clone of a forwarded request, so this return is exactly that shape.
    await source.body?.cancel().catch(() => {});
    return { ok: false, reason: "over-cap" };
  }
  const body = source.body;
  if (!body) return { ok: true, bytes: new Uint8Array(0) };
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    const reader = body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        // cancel() drops the rest of the stream on the floor rather than
        // draining it: the whole point is not to buffer what we refuse.
        await reader.cancel().catch(() => {});
        return { ok: false, reason: "over-cap" };
      }
      chunks.push(value);
    }
  } catch {
    return { ok: false, reason: "unreadable" };
  }
  const merged = new Uint8Array(total);
  let off = 0;
  for (const ch of chunks) { merged.set(ch, off); off += ch.byteLength; }
  return { ok: true, bytes: merged };
}

/**
 * The twin's exact signature: bytes, or null for an oversized or unreadable
 * body. For the callers that have one answer for both, and the form the
 * parity test compares against src/bounded-body.ts's `readBoundedBytesFrom`.
 */
export async function readBoundedBytesFrom(
  source: { body: ReadableStream<Uint8Array> | null; headers: Headers }, maxBytes: number,
): Promise<Uint8Array | null> {
  const read = await readBoundedResultFrom(source, maxBytes);
  return read.ok ? read.bytes : null;
}
