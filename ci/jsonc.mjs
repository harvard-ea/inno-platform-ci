// The one home of JSONC comment stripping. It lives apart from check-config.mjs
// so template-wrangler.mjs (the deploy-time templater) need not import the
// whole config gate for a comment stripper. Zero dependencies, like its callers.

/**
 * Strip `//` and `/* *\/` comments from a JSONC string, without touching
 * `//` or `/*` sequences that appear inside string literals.
 */
export function stripJsonComments(text) {
  let out = "";
  let inString = false;
  let inLineComment = false;
  let inBlockComment = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const next = text[i + 1];

    if (inLineComment) {
      if (ch === "\n") {
        inLineComment = false;
        out += ch;
      }
      continue;
    }

    if (inBlockComment) {
      if (ch === "*" && next === "/") {
        inBlockComment = false;
        i++;
      }
      continue;
    }

    if (inString) {
      out += ch;
      if (ch === "\\") {
        // preserve the escaped character verbatim (e.g. \" or \\)
        out += next;
        i++;
        continue;
      }
      if (ch === '"') inString = false;
      continue;
    }

    if (ch === '"') {
      inString = true;
      out += ch;
      continue;
    }
    if (ch === "/" && next === "/") {
      inLineComment = true;
      i++;
      continue;
    }
    if (ch === "/" && next === "*") {
      inBlockComment = true;
      i++;
      continue;
    }
    out += ch;
  }

  return out;
}
