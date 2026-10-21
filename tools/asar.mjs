#!/usr/bin/env node
// Minimal ASAR reader: list / extract / grep without installing @electron/asar.
// usage:
//   node asar.mjs <archive> list [regex]
//   node asar.mjs <archive> extract <innerPath> <outFile>
//   node asar.mjs <archive> grep <regex> [fileRegex] [maxHits]
//   node asar.mjs <archive> cat <innerPath> [maxBytes]
import fs from "node:fs";
import path from "node:path";

const [, , archive, mode, ...rest] = process.argv;

function readHeader(archive) {
  const fd = fs.openSync(archive, "r");
  try {
    const b = Buffer.alloc(16);
    fs.readSync(fd, b, 0, 16, 0);
    const headerPickleSize = b.readUInt32LE(4);
    const hb = Buffer.alloc(headerPickleSize);
    fs.readSync(fd, hb, 0, headerPickleSize, 8);
    const jsonSize = hb.readUInt32LE(4);
    const json = hb.subarray(8, 8 + jsonSize).toString("utf8");
    const dataOffset = 8 + headerPickleSize;
    return { header: JSON.parse(json), dataOffset };
  } finally {
    fs.closeSync(fd);
  }
}

function walk(node, prefix, out) {
  for (const [name, entry] of Object.entries(node.files ?? {})) {
    const p = prefix ? `${prefix}/${name}` : name;
    if (entry.files) walk(entry, p, out);
    else out.push({ path: p, size: entry.size ?? 0, offset: Number(entry.offset ?? 0) });
  }
}

const { header, dataOffset } = readHeader(archive);
const files = [];
walk(header, "", files);

if (mode === "list") {
  const re = rest[0] ? new RegExp(rest[0], "i") : null;
  const hit = files.filter((f) => !re || re.test(f.path));
  console.log(`# ${files.length} entries, ${hit.length} matching`);
  for (const f of hit.sort((a, b) => b.size - a.size)) {
    console.log(`${String(f.size).padStart(10)}  ${f.path}`);
  }
} else if (mode === "extract") {
  const [inner, outFile] = rest;
  const f = files.find((x) => x.path === inner);
  if (!f) throw new Error(`not found: ${inner}`);
  const fd = fs.openSync(archive, "r");
  const buf = Buffer.alloc(f.size);
  fs.readSync(fd, buf, 0, f.size, dataOffset + f.offset);
  fs.closeSync(fd);
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, buf);
  console.log(`extracted ${f.size} bytes -> ${outFile}`);
} else if (mode === "cat") {
  const [inner] = rest;
  const maxBytes = Number(rest[1] ?? 200000);
  const f = files.find((x) => x.path === inner);
  if (!f) throw new Error(`not found: ${inner}`);
  const fd = fs.openSync(archive, "r");
  const n = Math.min(f.size, maxBytes);
  const buf = Buffer.alloc(n);
  fs.readSync(fd, buf, 0, n, dataOffset + f.offset);
  fs.closeSync(fd);
  process.stdout.write(buf.toString("utf8"));
} else if (mode === "grep") {
  const re = new RegExp(rest[0]);
  const fileRe = rest[1] ? new RegExp(rest[1], "i") : /\.(js|mjs|cjs|ts|json|html|css|md|yaml|yml|txt)$/i;
  const maxHits = Number(rest[2] ?? 400);
  const fd = fs.openSync(archive, "r");
  let hits = 0;
  for (const f of files) {
    if (hits >= maxHits) break;
    if (!fileRe.test(f.path)) continue;
    if (f.size > 40 * 1024 * 1024) continue;
    const buf = Buffer.alloc(f.size);
    fs.readSync(fd, buf, 0, f.size, dataOffset + f.offset);
    const text = buf.toString("utf8");
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (re.test(lines[i])) {
        const line = lines[i].slice(0, 400);
        console.log(`${f.path}:${i + 1}: ${line}`);
        if (++hits >= maxHits) break;
      }
    }
  }
  fs.closeSync(fd);
  console.log(`# ${hits} hits`);
} else {
  console.error("modes: list | extract | cat | grep");
  process.exit(2);
}
