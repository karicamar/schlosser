// Reads the SARIF file the C# compiler writes (-p:ErrorLog=...) and prints the Schlosser findings as
//   <rule> <file>:<line>
// sorted, with paths relative to a base folder. Used by the sample check and the WebGoat.NET contract test.
//
//   node tools/findings.mjs <file.sarif> <base folder> [--check expected.txt] [--all]
//
// With --check the list is compared with the expected file and the exit code is 1 if they differ.
// Without --all, notes (SL002) are left out: only warnings count.
import { readFileSync } from "node:fs";
import { relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const [sarifPath, baseFolder, ...rest] = process.argv.slice(2);
if (!sarifPath || !baseFolder) {
  console.error("usage: node tools/findings.mjs <file.sarif> <base folder> [--check expected.txt] [--all]");
  process.exit(2);
}

const all = rest.includes("--all");
const checkIndex = rest.indexOf("--check");
const expectedPath = checkIndex >= 0 ? rest[checkIndex + 1] : null;

const sarif = JSON.parse(readFileSync(sarifPath, "utf8").replace(/^﻿/, ""));
const findings = new Set();
for (const run of sarif.runs ?? []) {
  for (const result of run.results ?? []) {
    if (!/^SL\d{3}$/.test(result.ruleId ?? "")) continue;
    if (!all && result.level === "note") continue;
    const location = result.locations?.[0]?.physicalLocation;
    if (!location) continue;
    const uri = location.artifactLocation.uri;
    const file = uri.startsWith("file:") ? fileURLToPath(uri) : uri;
    const path = relative(resolve(baseFolder), resolve(file)).replaceAll("\\", "/");
    findings.add(`${result.ruleId} ${path}:${location.region.startLine}`);
  }
}

const actual = [...findings].sort();
if (!expectedPath) {
  console.log(actual.join("\n"));
  process.exit(0);
}

const expected = readFileSync(expectedPath, "utf8")
  .split(/\r?\n/)
  .map((line) => line.replace(/#.*/, "").trim())
  .filter(Boolean)
  .sort();

const missing = expected.filter((line) => !actual.includes(line));
const unexpected = actual.filter((line) => !expected.includes(line));
if (missing.length === 0 && unexpected.length === 0) {
  console.log(`OK: ${actual.length} findings, exactly as expected.`);
  process.exit(0);
}

if (missing.length > 0) console.error("Expected but not found:\n  " + missing.join("\n  "));
if (unexpected.length > 0) console.error("Found but not expected:\n  " + unexpected.join("\n  "));
process.exit(1);
