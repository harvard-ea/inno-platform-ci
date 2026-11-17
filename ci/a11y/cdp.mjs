// The accessibility scanner's browser (ci/a11y-scan.mjs, split in v0.18.16,
// CI-08): where the image keeps Chromium (findChrome), the headless browser
// started with its DevTools protocol on --remote-debugging-pipe
// (launchChrome), the protocol's client over that pipe (Cdp), and the
// teardown that stops the browser and removes its throwaway profile
// (closeBrowser). It knows nothing of pages, axe-core or verdicts:
// ci/a11y/scan.mjs drives it.
//
// Node builtins and ../cli.mjs only, like every ci/ script: the mirror
// publishes ci/ to third-party runners, where no npm package is installed.

import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { logSafe } from "../cli.mjs";

/**
 * Locate a Chromium binary inside the Playwright image (the directory name
 * carries the browser revision and, on some builds, the CPU architecture).
 *
 * @param {string} [root]
 * @returns {string|null}
 */
export function findChrome(root = "/ms-playwright") {
  if (!existsSync(root)) return null;
  const candidates = [];
  for (const d of readdirSync(root).sort()) {
    if (d.startsWith("chromium_headless_shell-")) {
      for (const sub of safeList(join(root, d))) {
        if (!sub.startsWith("chrome-")) continue;
        candidates.push({ rank: 0, path: join(root, d, sub, "headless_shell") });
        candidates.push({ rank: 0, path: join(root, d, sub, "chrome-headless-shell") });
      }
    } else if (d.startsWith("chromium-")) {
      for (const sub of safeList(join(root, d))) {
        if (sub.startsWith("chrome-")) candidates.push({ rank: 1, path: join(root, d, sub, "chrome") });
      }
    }
  }
  candidates.sort((a, b) => a.rank - b.rank);
  const hit = candidates.find((c) => existsSync(c.path));
  return hit ? hit.path : null;
}

function safeList(dir) {
  try { return readdirSync(dir); } catch { return []; }
}

export class Cdp {
  constructor(proc) {
    this.proc = proc;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Set();
    this.buf = Buffer.alloc(0);
    this.closed = false;
    proc.stdio[4].on("data", (chunk) => this.onData(chunk));
    // A browser that fails to start (ENOENT, missing libraries) or dies mid-run
    // surfaces as 'error' events; unhandled, they would crash the scanner
    // instead of producing a "did not run" report.
    proc.on("error", (e) => this.fail(e));
    proc.stdio[3].on("error", (e) => this.fail(e));
    proc.stdio[4].on("error", (e) => this.fail(e));
    proc.on("exit", () => this.fail(new Error("browser exited")));
  }

  fail(err) {
    this.closed = true;
    for (const { reject } of this.pending.values()) reject(err instanceof Error ? err : new Error(String(err)));
    this.pending.clear();
  }

  onData(chunk) {
    this.buf = Buffer.concat([this.buf, chunk]);
    let i;
    while ((i = this.buf.indexOf(0)) !== -1) {
      const raw = this.buf.subarray(0, i).toString("utf8");
      this.buf = this.buf.subarray(i + 1);
      let msg;
      try { msg = JSON.parse(raw); } catch { continue; }
      if (msg.id !== undefined && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) reject(new Error(`${msg.error.message ?? "CDP error"}`));
        else resolve(msg.result ?? {});
      } else if (msg.method) {
        for (const fn of this.listeners) fn(msg);
      }
    }
  }

  send(method, params = {}, sessionId, timeoutMs = 30_000) {
    if (this.closed) return Promise.reject(new Error("browser exited"));
    const id = this.nextId++;
    const msg = { id, method, params };
    if (sessionId) msg.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(`${method} timed out`));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (v) => { clearTimeout(t); resolve(v); },
        reject: (e) => { clearTimeout(t); reject(e); },
      });
      this.proc.stdio[3].write(JSON.stringify(msg) + "\0");
    });
  }

  on(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); }
}

export function launchChrome(binary) {
  const profile = mkdtempSync(join(tmpdir(), "a11y-profile-"));
  const proc = spawn(binary, [
    "--headless",
    "--remote-debugging-pipe",
    "--no-sandbox",
    "--disable-gpu",
    "--disable-dev-shm-usage",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    "--disable-background-networking",
    "--window-size=1280,900",
    `--user-data-dir=${profile}`,
    "about:blank",
  ], {
    stdio: ["ignore", "ignore", "pipe", "pipe", "pipe"],
    // The CI container has a read-only root: point every per-user write
    // (profile, caches, crash reports) at the throwaway profile under /tmp.
    env: { ...process.env, HOME: profile, XDG_CONFIG_HOME: profile, XDG_CACHE_HOME: profile },
  });
  proc.stderr.on("data", () => {});
  return { proc, profile };
}

// How long the scanner waits for the browser it killed to exit before it
// removes the throwaway profile, and how that removal retries what a child
// process still writing leaves behind (an ENOTEMPTY): up to
// PROFILE_REMOVE_TRIES tries, pausing PROFILE_REMOVE_DELAY_MS times the try's
// number after each failed one (2 s in all). The retry is the scanner's own:
// rmSync's maxRetries and retryDelay do not pause as Node documents them on
// the Node versions probed. A profile still left after that is one line,
// never a crash: it sits under the scanner container's /tmp, which goes with
// the container.
export const BROWSER_EXIT_WAIT_MS = 5_000;
export const PROFILE_REMOVE_TRIES = 5;
export const PROFILE_REMOVE_DELAY_MS = 200;

/**
 * Kill the browser and remove its throwaway profile. Never throws: scan()
 * calls it from its `finally`, where a throw would replace the scan's result.
 * A browser that started and has not exited is sent SIGKILL and waited for
 * until it exits or `waitMs` passes, whichever comes first; one that never
 * started (a spawn error has no exit to wait for) or already exited is not
 * waited for. The removal is tried up to PROFILE_REMOVE_TRIES times, with a
 * longer pause after each failed try; only when every try failed is it one
 * line on stderr.
 */
export async function closeBrowser(proc, profile, { remove = (dir) => rmSync(dir, { recursive: true, force: true }), waitMs = BROWSER_EXIT_WAIT_MS } = {}) {
  if (proc.pid !== undefined && proc.exitCode === null && proc.signalCode === null) {
    let timer;
    const exited = new Promise((resolve) => {
      timer = setTimeout(resolve, waitMs);
      proc.once("exit", resolve);
    });
    proc.kill("SIGKILL");
    await exited;
    clearTimeout(timer);
  }
  for (let attempt = 1; ; attempt++) {
    try {
      remove(profile);
      return;
    } catch (e) {
      if (attempt >= PROFILE_REMOVE_TRIES) {
        console.error(`a11y-scan: the browser's throwaway profile was not removed (${logSafe(e && e.message ? e.message : e, 160)}); it goes with the scanner's container`);
        return;
      }
    }
    await sleep(PROFILE_REMOVE_DELAY_MS * attempt);
  }
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
