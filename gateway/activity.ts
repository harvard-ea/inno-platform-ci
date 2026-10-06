// Human-activity touch (spec 2026-08-18-human-activity-idle-clock): when an
// authenticated request is real human use, tell the platform so the app's
// idle clock advances. Wired in index.ts after each perimeter's auth.
import { readBoundedResultFrom } from "./bounded-body";
import { errLine } from "./log-text";
import { PLATFORM_ORIGIN } from "./platform";

// gateway/ builds separately from src/ and cannot import it — TOUCH_PATH is a
// deliberately duplicated constant (twin: src/routes/activity.ts), pinned by
// test/constant-parity.node.test.ts.
export const TOUCH_PATH = "/_activity/touch";

// JSON-RPC methods that are real work. Protocol chatter (initialize, ping,
// */list, notifications/*) is deliberately absent: a connected-but-unused MCP
// client must not keep its app alive.
//
// This Set is the CODE; its prose twin is src/lifecycle/deadlines.ts's
// keepsAliveClause (and keepsAliveNeutral beside it), which is what an owner
// is actually told on app_status, in the panel and in the idle-warning email.
// gateway/ builds separately from src/, so neither can import the other: a
// method added or removed here has to be said there in the same breath, or the
// platform promises owners something this file does not do.
const WORK_METHODS = new Set(["tools/call", "resources/read", "prompts/get", "completion/complete"]);

// Peeking means buffering a clone of the body; past this size skip the parse
// and count the request as work — a large POST /mcp under a real user token
// is almost certainly a tools/call payload.
const PEEK_MAX_BYTES = 262_144;

// At most one send per host per window. Module-scope is per-isolate, and each
// app's gateway is its own Worker, so the key space is one host; isolate
// recycling just causes an occasional extra send against an idempotent write.
const TOUCH_DEBOUNCE_MS = 60 * 60_000;
const lastSentAt = new Map<string, number>();

export function shouldTouch(host: string, nowMs: number): boolean {
  const last = lastSentAt.get(host);
  return last === undefined || nowMs - last >= TOUCH_DEBOUNCE_MS;
}

export function markTouched(host: string, nowMs: number): void {
  lastSentAt.set(host, nowMs);
}

// Does this POST /mcp carry a work method? Parses a CLONE so the forwarded
// body is untouched. Unparseable → false (the app will reject it anyway).
//
// The clone read is byte-counted and abandoned past PEEK_MAX_BYTES: the old
// form checked the declared Content-Length and then buffered the clone whole,
// so a chunked body of any size was peeked in full (its own comment said so).
// That loop now lives once, in bounded-body.ts, because storage.ts needs the
// same discipline and had none.
export async function mcpWorkRequest(req: Request): Promise<boolean> {
  const read = await readBoundedResultFrom(req.clone(), PEEK_MAX_BYTES);
  // The two give-up reasons get OPPOSITE answers here, which is why the
  // reader reports which one it was. Over the cap still counts as WORK: a
  // large POST /mcp under a real user token is almost certainly a tools/call
  // payload. A body we could not read is not work (the app will reject it
  // anyway), the same answer an unparseable one gets below.
  if (!read.ok) return read.reason === "over-cap";
  let parsed: unknown;
  try { parsed = JSON.parse(new TextDecoder().decode(read.bytes)); } catch { return false; }
  const items = Array.isArray(parsed) ? parsed : [parsed];
  return items.some((m) => WORK_METHODS.has((m as { method?: string })?.method ?? ""));
}

// Fire-and-forget: a touch failure must never affect the user's request.
export async function sendTouch(platform: Fetcher, payload: Record<string, string>): Promise<void> {
  try {
    const res = await platform.fetch(`${PLATFORM_ORIGIN}${TOUCH_PATH}`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload),
    });
    if (!res.ok) console.warn(`gateway: activity touch refused (${res.status})`);
  } catch (e) {
    console.warn(`gateway: activity touch failed: ${errLine(e, 120)}`);
  }
}
