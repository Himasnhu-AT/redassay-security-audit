// The JavaScript half of the control fixture. Safe forms only.
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";

const DATA_ROOT = path.resolve("/var/data");
const ALLOWED_HOSTS = new Set(["api.internal.example"]);

export function lookup(domain, done) {
  // Argument array, never a shell string.
  execFile("dig", ["+short", domain], done);
}

export async function readDataFile(name) {
  const target = path.resolve(DATA_ROOT, name);
  if (target !== DATA_ROOT && !target.startsWith(DATA_ROOT + path.sep)) {
    throw new Error("outside the data root");
  }
  return readFile(target, "utf8");
}

export async function proxy(rawUrl) {
  const url = new URL(rawUrl);
  if (!ALLOWED_HOSTS.has(url.hostname)) throw new Error("host not allowed");
  const response = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(5000) });
  return response.text();
}

export function setSessionCookie(res, token) {
  res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "lax" });
}

export function renderName(element, name) {
  // textContent, not innerHTML.
  element.textContent = name;
}
