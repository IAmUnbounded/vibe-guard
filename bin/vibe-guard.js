#!/usr/bin/env node
"use strict";

const path = require("node:path");
const { scanRepository, severityRank, severities } = require("../src/scanner");

const COLORS = {
  reset: "\x1b[0m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  gray: "\x1b[90m",
};

function printHelp() {
  process.stdout.write(`vibe-guard - scan repositories for high-risk patterns from rushed AI-generated code\n\n`);
  process.stdout.write(`Usage:\n`);
  process.stdout.write(`  vibe-guard scan [path] [options]\n\n`);
  process.stdout.write(`Options:\n`);
  process.stdout.write(`  --json                       Print machine-readable JSON output\n`);
  process.stdout.write(`  --min-severity <level>       low|medium|high|critical (default: low)\n`);
  process.stdout.write(`  --fail-on <level>            Exit non-zero if finding >= level exists\n`);
  process.stdout.write(`  --max-file-size-kb <number>  Skip files larger than given KB (default: 512)\n`);
  process.stdout.write(`  --include-tests              Include test/spec files in scan\n`);
  process.stdout.write(`  --no-dataflow               Disable taint/dataflow heuristics\n`);
  process.stdout.write(`  --no-default-ignore          Scan hidden/build directories as well\n`);
  process.stdout.write(`  -h, --help                   Show this help\n\n`);
  process.stdout.write(`Examples:\n`);
  process.stdout.write(`  vibe-guard scan .\n`);
  process.stdout.write(`  vibe-guard scan ./services/api --min-severity high --fail-on medium\n`);
  process.stdout.write(`  vibe-guard scan . --json\n`);
}

function parseArgs(argv) {
  const result = {
    command: null,
    target: ".",
    json: false,
    minSeverity: "low",
    failOn: null,
    includeTests: false,
    includeDataflow: true,
    defaultIgnore: true,
    maxFileSizeBytes: 512 * 1024,
  };

  if (argv.length === 0 || argv.includes("-h") || argv.includes("--help")) {
    return { help: true, ...result };
  }

  const [command, ...rest] = argv;
  result.command = command;

  let i = 0;
  while (i < rest.length) {
    const token = rest[i];

    if (!token.startsWith("-")) {
      result.target = token;
      i += 1;
      continue;
    }

    if (token === "--json") {
      result.json = true;
      i += 1;
      continue;
    }

    if (token === "--include-tests") {
      result.includeTests = true;
      i += 1;
      continue;
    }

    if (token === "--no-default-ignore") {
      result.defaultIgnore = false;
      i += 1;
      continue;
    }

    if (token === "--no-dataflow") {
      result.includeDataflow = false;
      i += 1;
      continue;
    }

    if (token === "--min-severity") {
      result.minSeverity = rest[i + 1];
      i += 2;
      continue;
    }

    if (token === "--fail-on") {
      result.failOn = rest[i + 1];
      i += 2;
      continue;
    }

    if (token === "--max-file-size-kb") {
      const value = Number(rest[i + 1]);
      if (!Number.isFinite(value) || value <= 0) {
        throw new Error("--max-file-size-kb expects a positive number.");
      }
      result.maxFileSizeBytes = Math.round(value * 1024);
      i += 2;
      continue;
    }

    throw new Error(`Unknown option: ${token}`);
  }

  return result;
}

function colorizeSeverity(severity, text) {
  if (!process.stdout.isTTY) {
    return text;
  }

  if (severity === "critical") {
    return `${COLORS.magenta}${text}${COLORS.reset}`;
  }
  if (severity === "high") {
    return `${COLORS.red}${text}${COLORS.reset}`;
  }
  if (severity === "medium") {
    return `${COLORS.yellow}${text}${COLORS.reset}`;
  }
  return `${COLORS.cyan}${text}${COLORS.reset}`;
}

function run() {
  let parsed;

  try {
    parsed = parseArgs(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`Error: ${error.message}\n`);
    process.stderr.write(`Run \"vibe-guard --help\" for usage.\n`);
    process.exitCode = 1;
    return;
  }

  if (parsed.help) {
    printHelp();
    return;
  }

  if (parsed.command !== "scan") {
    process.stderr.write(`Unknown command: ${parsed.command}\n`);
    process.stderr.write(`Only \"scan\" is supported.\n`);
    process.exitCode = 1;
    return;
  }

  let report;
  try {
    report = scanRepository(parsed.target, {
      includeTests: parsed.includeTests,
      includeDataflow: parsed.includeDataflow,
      minSeverity: parsed.minSeverity,
      defaultIgnore: parsed.defaultIgnore,
      maxFileSizeBytes: parsed.maxFileSizeBytes,
    });
  } catch (error) {
    process.stderr.write(`Scan failed: ${error.message}\n`);
    process.exitCode = 1;
    return;
  }

  if (parsed.json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    const relativeTarget = path.relative(process.cwd(), report.scannedPath) || ".";
    process.stdout.write(`\nVibe Guard Scan Report\n`);
    process.stdout.write(`Target: ${relativeTarget}\n`);
    process.stdout.write(`Files scanned: ${report.scannedFiles}\n`);
    process.stdout.write(
      `Findings: ${report.summary.total} (critical: ${report.summary.critical}, high: ${report.summary.high}, medium: ${report.summary.medium}, low: ${report.summary.low})\n\n`,
    );

    if (report.findings.length === 0) {
      process.stdout.write("No matching high-risk patterns were found.\n");
    } else {
      for (const finding of report.findings) {
        const severityLabel = colorizeSeverity(
          finding.severity,
          finding.severity.toUpperCase(),
        );

        const location = `${path.relative(process.cwd(), finding.file) || finding.file}:${finding.line}`;
        process.stdout.write(
          `[${severityLabel}] ${finding.ruleId} ${finding.title} (${finding.confidence})\n`,
        );
        process.stdout.write(`  at ${location}\n`);
        process.stdout.write(`  ${finding.description}\n`);
        process.stdout.write(`  hint: ${finding.recommendation}\n`);
        if (finding.snippet) {
          const snippetText = process.stdout.isTTY
            ? `${COLORS.gray}${finding.snippet}${COLORS.reset}`
            : finding.snippet;
          process.stdout.write(`  code: ${snippetText}\n`);
        }
        process.stdout.write("\n");
      }
    }
  }

  if (parsed.failOn) {
    const level = String(parsed.failOn).toLowerCase();
    if (!severityRank.hasOwnProperty(level)) {
      process.stderr.write(
        `Invalid --fail-on value. Use one of: ${severities.join(", ")}\n`,
      );
      process.exitCode = 1;
      return;
    }

    const matched = report.findings.some(
      (finding) => severityRank[finding.severity] >= severityRank[level],
    );

    if (matched) {
      process.exitCode = 2;
    }
  }
}

run();
