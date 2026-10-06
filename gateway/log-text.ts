// The gateway's one way to turn a caught exception into log text, and (at the
// end of the file) its one bytes-to-hex helper.
// Twin: src/util.ts (errText, flattenControl, errLine, toHex). gateway/
// compiles and ships as its own Worker and imports nothing from src/, so the
// two copies are held to the same OUTPUT rather than the same source text, by
// test/constant-parity.node.test.ts. Same discipline as gateway/bounded-body.ts
// and the groupsVisibleToApp twins.
//
// Before this file the gateway hand-wrote a bounded `String(e)` at seven call
// sites and had neither of the twin's two behaviours. Coercing an Error with
// `String` prefixes its class name, so one failure reaches the logs in two
// shapes depending on where it was caught; and nothing stripped a control byte
// out of text the gateway did not write (a fetch failure interpolates an
// upstream body, a D1 error carries back the text it choked on), so an
// embedded newline forged a clean-looking second log line. gateway/storage.ts's
// copy also fed the `detail` of a 500 body returned to app code.

// The C0 range plus DEL, written as ESCAPES and never as the bytes themselves:
// test/control-bytes.node.test.ts records the incident that makes that a rule.
// U+2028/U+2029 are deliberately NOT stripped, matching the twin: they are
// legal in the JSON envelopes this output lands in.
function flattenControl(s: string): string {
  return s.replace(/[\u0000-\u001f\u007f]+/g, " ");
}

// An Error's message rather than `String(e)`'s "Error: message", anything else
// stringified, cut to `max`. A value whose own toString throws yields a fixed
// placeholder rather than becoming the reason a failure goes unrecorded.
function errText(e: unknown, max: number): string {
  let s: string;
  try { s = e instanceof Error ? e.message : String(e); } catch { s = "unstringifiable"; }
  return s.slice(0, max);
}

/**
 * A caught exception, ready for ONE log line: bounded first, then flattened.
 * The order is the whole point and it is not interchangeable. errText first,
 * because it gives the message rather than the class name (one failure, one
 * shape) and survives a value whose own toString throws. flattenControl LAST,
 * because a cut can land inside a run of control bytes: flattening before the
 * slice would leave the tail of that run at the end of the bounded string, and
 * a newline surviving there is precisely the forged log line the flattening
 * exists to prevent.
 */
export function errLine(e: unknown, n = 200): string {
  return flattenControl(errText(e, n));
}

/**
 * Bytes as lowercase hex. Twin of src/util.ts's `toHex`, held to the same
 * OUTPUT like everything else in this file, and living here for the same
 * reason errLine does: this file is the gateway's copy of src/util.ts's small
 * helpers, so the second one joins the first rather than opening a third home.
 *
 * Two call sites wrote this loop out by hand: mcp-auth.ts's introspection
 * cache key (a whole SHA-256) and red.ts's caller bucket (its first four
 * bytes). Both feed values that are compared or stored, so the two spellings
 * had to stay byte-identical by hand; now they cannot differ. Takes a view or
 * a raw buffer, exactly like the twin, because a `crypto.subtle.digest` result
 * is the latter.
 */
export function hex(bytes: Uint8Array | ArrayBuffer): string {
  const u = ArrayBuffer.isView(bytes) ? bytes : new Uint8Array(bytes);
  return [...u].map((b) => b.toString(16).padStart(2, "0")).join("");
}
