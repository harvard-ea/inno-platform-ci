#!/usr/bin/env node
// The annotation rule (ci/cli.mjs annotationLine) for a workflow step's own
// shell, so a gate written inline in the reusable workflow ends the way every
// ci/ script's does: one `::<level> title=<gate>[,file=<path>]::<what
// failed>; <how to fix>` line, every value flattened by logSafe and bounded,
// at most ten a step.
//
// Usage:
//   node ci/annotate.mjs [--level <error|warning|notice>] --title <t> --what <w> [--fix <f>] [--file <p>]
//   node ci/annotate.mjs [--level <error|warning|notice>] --title <t> [--fix <f>] [--file <p>] --each
// The first form prints one annotation. The second reads one item per line
// of stdin (blank lines skipped) and prints them through annotateAll: every
// one when there are ten or fewer, else nine and a line counting the rest,
// which the step's own log must list. --level defaults to error and --fix to
// none. Exit 0 once printed; 1, with the usage, on any other argument.
//
// Who calls it: the steps whose message carries a value the author or the
// platform wrote, which a literal line in the workflow could not escape
// safely. The container job's "Assert non-root user + EXPOSE 8080" and
// "Smoke test /healthz" (it copies this file and cli.mjs out of its mirror
// checkout, beside registry-mirror.sh, before the build context is read), the
// app-build job's symlink guard (one call per link, with the link as
// --file, for the first ten; the rest are named in one plain line), and the
// deploy job's image check and finalize answer, all with --what. No step
// uses --each today: it is the form for a step that has a list under one
// title and one file. A step whose annotation is a fixed
// sentence prints it as a literal line, which
// test/annotate-parity.node.test.ts holds equal to annotationLine.
//
// Why stderr: Actions reads workflow commands off either stream, and a step
// that captures a command's stdout (`x="$(...)"`) would swallow a line
// printed there. Every ci/ script annotates on stderr for the same reason,
// except the accessibility scanner (ci/a11y-scan.mjs): it prints its
// annotations on stdout, which nothing captures.

import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { annotate, annotateAll, isMainModule } from "./cli.mjs";

const USAGE = [
  "Usage: node ci/annotate.mjs [--level <error|warning|notice>] --title <t> --what <w> [--fix <f>] [--file <p>]",
  "       node ci/annotate.mjs [--level <error|warning|notice>] --title <t> [--fix <f>] [--file <p>] --each  (items on stdin, one a line)",
].join("\n");

/**
 * The CLI's arguments, checked: a title, and exactly one of --what and
 * --each. Throws the usage on anything else.
 *
 * @param {string[]} argv
 * @returns {{ level: "error"|"warning"|"notice", title: string, what?: string, fix: string, file?: string, each: boolean }}
 */
export function parseAnnotateArgs(argv) {
  let values;
  try {
    ({ values } = parseArgs({
      args: argv,
      options: {
        level: { type: "string", default: "error" },
        title: { type: "string" },
        what: { type: "string" },
        fix: { type: "string", default: "" },
        file: { type: "string" },
        each: { type: "boolean", default: false },
      },
      strict: true,
      allowPositionals: false,
    }));
  } catch {
    throw new Error(USAGE);
  }
  const { level, title, what, fix, file, each } = values;
  if (!["error", "warning", "notice"].includes(level) || !title || (what === undefined) === !each) throw new Error(USAGE);
  return { level: /** @type {"error"|"warning"|"notice"} */ (level), title, what, fix, file, each };
}

if (isMainModule(import.meta.url)) {
  let args;
  try {
    args = parseAnnotateArgs(process.argv.slice(2));
  } catch (err) {
    console.error(String(err?.message ?? err));
    process.exitCode = 1;
  }
  if (args) {
    const { level, title, what, fix, file, each } = args;
    if (each) {
      const items = readFileSync(0, "utf8").split("\n").filter((l) => l.trim() !== "").map((l) => ({ what: l, file }));
      annotateAll({ level, title, fix, items });
    } else {
      annotate({ level, title, what, fix, file });
    }
  }
}
