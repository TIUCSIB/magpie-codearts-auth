#!/usr/bin/env node
// Scan a binary for ASCII and UTF-16LE strings matching a regex.
// usage: node strings.mjs <file> <regex> [minLen]
import fs from "node:fs";

const [, , file, pattern, minLenArg] = process.argv;
const re = new RegExp(pattern, "i");
const minLen = Number(minLenArg ?? 6);
const buf = fs.readFileSync(file);

function scan(bytes, enc) {
  const out = [];
  let cur = "";
  const push = () => {
    if (cur.length >= minLen && re.test(cur)) out.push(cur);
    cur = "";
  };
  if (enc === 1) {
    for (let i = 0; i + 1 < bytes.length; i += 2) {
      const c = bytes[i];
      if (bytes[i + 1] === 0 && c >= 0x20 && c < 0x7f) cur += String.fromCharCode(c);
      else push();
    }
  } else {
    for (const b of bytes) {
      if (b >= 0x20 && b < 0x7f) cur += String.fromCharCode(b);
      else push();
    }
  }
  push();
  return out;
}

const seen = new Set();
for (const s of [...scan(buf, 0), ...scan(buf, 1)]) {
  if (seen.has(s)) continue;
  seen.add(s);
  console.log(s);
}
console.error(`# ${seen.size} unique matches, ${buf.length} bytes scanned`);
