"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { scanRepository } = require("../src/scanner");

function scan(files, options = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vg-"));
  for (const [name, body] of Object.entries(files)) {
    const full = path.join(dir, name);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, body);
  }
  return scanRepository(dir, options).findings.map((f) => f.ruleId);
}

test("method calls named eval/exec are not dynamic execution", () => {
  assert.deepEqual(scan({ "a.go": "r, err := e.eval()\n" }), []);
  assert.deepEqual(scan({ "a.php": "<?php $this->exec(sql: $sql);\n" }), []);
});

test("exec with a constant string is ignored, interpolated exec is kept", () => {
  assert.deepEqual(scan({ "a.php": "<?php exec('command -v yq', $out);\n" }), []);
  assert.deepEqual(scan({ "b.php": "<?php exec('rm ' . $_GET['f']);\n" }), ["VG001"]);
  assert.deepEqual(scan({ "c.js": "eval(userInput);\n" }), ["VG001"]);
});

test("placeholder and identifier-like secrets are ignored", () => {
  assert.deepEqual(scan({ "a.ts": "const password = 'hashed_password_here';\n" }), []);
  assert.deepEqual(scan({ "b.py": "secret = 'AKIAIOSFODNN7EXAMPLE'\n" }), []);
  assert.deepEqual(scan({ "c.php": "<?php const CONFIG_HMAC_SECRET = 'dso_pki_hmac_secret';\n" }), []);
});

test("real-looking secrets are kept", () => {
  assert.deepEqual(scan({ "a.js": "const apiKey = 'sk_live_9fA2kQ7xLmP4tRz8Vb1N';\n" }), ["VG004"]);
  assert.deepEqual(scan({ "b.js": "const k = 'AKIA4QZ7XKJ2MNB8PLRT';\n" }), ["VG004"]);
});

test("innerHTML with only escaped interpolations is ignored", () => {
  const safe = "row.innerHTML = `<span>${esc(ev.message)}</span><b>${escapeHtml(x.name)}</b>`;\n";
  assert.deepEqual(scan({ "a.js": safe }), []);
  const unsafe = "row.innerHTML = `<span>${ev.message}</span>`;\n";
  assert.deepEqual(scan({ "b.js": unsafe }), ["VG007"]);
  assert.deepEqual(scan({ "c.js": "el.innerHTML = userHtml;\n" }), ["VG007"]);
});

test("JSON-LD script blocks are ignored", () => {
  const jsonLd =
    '<script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }} />\n';
  assert.deepEqual(scan({ "a.tsx": jsonLd }), []);
  assert.deepEqual(scan({ "b.tsx": "<div dangerouslySetInnerHTML={{ __html: html }} />\n" }), ["VG007"]);
});

test("vendored and test files are skipped by default", () => {
  const body = "eval(userInput);\n";
  assert.deepEqual(
    scan({ "vendor/lib/a.js": body, "pkg/a_test.go": "e := eval(x)\n", "tests/test_a.py": body, "static/chart.umd.js": body }),
    [],
  );
  assert.deepEqual(scan({ "vendor/lib/a.js": body }, { defaultIgnore: false }), ["VG001"]);
});

test("the filter can be turned off", () => {
  assert.deepEqual(scan({ "a.go": "e.eval()\n" }, { filterFalsePositives: false }), ["VG001"]);
});

test("method definitions named exec are ignored", () => {
  assert.deepEqual(scan({ "a.php": "<?php private function exec(string $sql): bool {}\n" }), []);
});

test("SQL rule needs SQL structure, not the English word select", () => {
  assert.deepEqual(scan({ "a.js": "x = `<div aria-label=\"Select model ${name}\">`;\n" }), []);
  assert.deepEqual(scan({ "b.js": "db.run(`SELECT * FROM users WHERE id = ${id}`);\n" }), ["VG003"]);
  assert.deepEqual(scan({ "c.js": "sql = `DELETE FROM t WHERE id = ${id}`;\n" }), ["VG003"]);
});

test("explicit eslint no-unsanitized suppression is honoured", () => {
  const body = "// eslint-disable-next-line no-unsanitized/property\nbtn.innerHTML = originalHTML;\n";
  assert.deepEqual(scan({ "a.js": body }), []);
});
