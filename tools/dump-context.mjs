#!/usr/bin/env node
// Dump printable context around each occurrence of a byte pattern.
// usage: node dump-context.mjs <file> <literal> [radius]
import fs from "node:fs";

const [, , file, literal, radiusArg] = process.argv;
const radius = Number(radiusArg ?? 160);
const buf = fs.readFileSync(file);
const needle = Buffer.from(literal, "utf8");

let idx = 0;
let n = 0;
while ((idx = buf.indexOf(needle, idx)) !== -1) {
  n++;
  const start = Math.max(0, idx - radius);
  const end = Math.min(buf.length, idx + needle.length + radius);
  const chunk = buf.subarray(start, end);
  let text = "";
  for (const b of chunk) text += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".";
  console.log(`--- #${n} @0x${idx.toString(16)} ---`);
  console.log(text);
  idx += needle.length;
  if (n >= 40) break;
}
console.error(`# ${n} occurrences`);
