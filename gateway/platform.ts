// The gateway's seam to the platform. Every call the gateway makes over the
// PLATFORM service binding (token introspection, activity touches, link
// checks, credential fetches) is addressed to one pseudo-origin and, where
// the platform must know the caller is a gateway, carries one header. Both
// live here so a seam added later cannot spell either differently.
//
// gateway/ builds separately from src/ and cannot import it, which is why the
// header is a hand-written twin of src/routes/mcp-introspect.ts's
// GATEWAY_KEY_HEADER, pinned by test/constant-parity.node.test.ts. The
// separate build justifies ONE twin per platform constant inside gateway/,
// not one per file: this is that one.

// A service binding routes on the binding, not on the host, so the origin is
// a placeholder that only has to parse as a URL. Nothing resolves it.
export const PLATFORM_ORIGIN = "https://platform.internal";

// Proof that the caller is a gateway. The platform mints a caller_assertion
// on /app-introspect, and answers /_links/check at all, only for a caller
// presenting the shared secret under this header, because both seams are
// publicly reachable and the service binding is routing, not authentication.
export const GATEWAY_KEY_HEADER = "x-inno-gateway-key";
