"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { rules, severities } = require("./rules");
const { analyzeDataflow } = require("./dataflow");

const DEFAULT_IGNORED_DIRS = new Set([
  ".git",
  "node_modules",
  ".next",
  "dist",
  "build",
  "coverage",
  ".cache",
  ".turbo",
]);

const DEFAULT_EXTENSIONS = new Set([
  ".js",
  ".mjs",
  ".cjs",
  ".ts",
  ".tsx",
  ".jsx",
  ".py",
  ".go",
  ".java",
  ".rb",
  ".php",
  ".cs",
  ".rs",
  ".kt",
  ".swift",
  ".scala",
  ".sql",
  ".sh",
  ".bash",
  ".zsh",
  ".ps1",
  ".yaml",
  ".yml",
  ".json",
  ".toml",
  ".ini",
  ".env",
  ".vue",
  ".svelte",
  ".html",
]);

const severityRank = severities.reduce((acc, level, index) => {
  acc[level] = index;
  return acc;
}, {});

function normalizeSeverity(input) {
  if (!input) {
    return "low";
  }

  const normalized = String(input).toLowerCase();
  if (!severityRank.hasOwnProperty(normalized)) {
    throw new Error(
      `Invalid severity \"${input}\". Use one of: ${severities.join(", ")}.`,
    );
  }

  return normalized;
}

function shouldScanFile(filePath, options) {
  const ext = path.extname(filePath).toLowerCase();

  if (!options.includeTests) {
    const lower = filePath.toLowerCase();
    if (
      lower.includes("/test/") ||
      lower.includes("/tests/") ||
      lower.includes("/__tests__/") ||
      lower.endsWith(".test.js") ||
      lower.endsWith(".spec.js") ||
      lower.endsWith(".test.ts") ||
      lower.endsWith(".spec.ts")
    ) {
      return false;
    }
  }

  return DEFAULT_EXTENSIONS.has(ext) || filePath.endsWith(".env");
}

function isLikelyText(content) {
  const sample = content.subarray(0, 512);
  let suspicious = 0;

  for (let i = 0; i < sample.length; i += 1) {
    const value = sample[i];
    if (value === 0) {
      return false;
    }
    if (value < 9 || (value > 13 && value < 32)) {
      suspicious += 1;
    }
  }

  return suspicious < 10;
}

function collectFiles(rootDir, options, result = []) {
  let entries;

  try {
    entries = fs.readdirSync(rootDir, { withFileTypes: true });
  } catch (_error) {
    return result;
  }

  for (const entry of entries) {
    const fullPath = path.join(rootDir, entry.name);

    if (entry.isDirectory()) {
      if (
        options.defaultIgnore &&
        (DEFAULT_IGNORED_DIRS.has(entry.name) || entry.name.startsWith("."))
      ) {
        continue;
      }

      collectFiles(fullPath, options, result);
      continue;
    }

    if (!entry.isFile() || !shouldScanFile(fullPath, options)) {
      continue;
    }

    let stat;
    try {
      stat = fs.statSync(fullPath);
    } catch (_error) {
      continue;
    }

    if (stat.size > options.maxFileSizeBytes) {
      continue;
    }

    result.push(fullPath);
  }

  return result;
}

function lineNumberAt(content, index) {
  let line = 1;
  for (let i = 0; i < index; i += 1) {
    if (content.charCodeAt(i) === 10) {
      line += 1;
    }
  }
  return line;
}

function scanFile(filePath, options) {
  let buffer;

  try {
    buffer = fs.readFileSync(filePath);
  } catch (_error) {
    return [];
  }

  if (!isLikelyText(buffer)) {
    return [];
  }

  const content = buffer.toString("utf8");
  const findings = [];
  const seen = new Set();
  const fileExtension = path.extname(filePath).toLowerCase();

  for (const rule of rules) {
    for (const pattern of rule.patterns) {
      const regex = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`);
      let match;

      while ((match = regex.exec(content)) !== null) {
        const snippet = content
          .slice(Math.max(0, match.index - 45), Math.min(content.length, match.index + 120))
          .replace(/\s+/g, " ")
          .trim();

        const finding = {
          ruleId: rule.id,
          title: rule.title,
          severity: rule.severity,
          confidence: rule.confidence,
          description: rule.description,
          recommendation: rule.recommendation,
          file: filePath,
          line: lineNumberAt(content, match.index),
          snippet,
          pattern: pattern.source,
        };

        const key = `${finding.file}:${finding.line}:${finding.ruleId}`;
        if (seen.has(key)) {
          continue;
        }

        seen.add(key);
        findings.push(finding);
      }
    }
  }

  if (options.includeDataflow) {
    const flowFindings = analyzeDataflow(filePath, fileExtension, content);
    for (const finding of flowFindings) {
      const key = `${finding.file}:${finding.line}:${finding.ruleId}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      findings.push(finding);
    }
  }

  const minSeverity = normalizeSeverity(options.minSeverity);
  return findings.filter(
    (finding) => severityRank[finding.severity] >= severityRank[minSeverity],
  );
}

function summarize(findings) {
  const summary = {
    total: findings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  for (const finding of findings) {
    summary[finding.severity] += 1;
  }

  return summary;
}

function scanRepository(targetPath, options = {}) {
  const absoluteTarget = path.resolve(targetPath || ".");
  const normalizedOptions = {
    includeTests: Boolean(options.includeTests),
    maxFileSizeBytes:
      Number.isFinite(options.maxFileSizeBytes) && options.maxFileSizeBytes > 0
        ? options.maxFileSizeBytes
        : 512 * 1024,
    minSeverity: normalizeSeverity(options.minSeverity || "low"),
    includeDataflow:
      options.includeDataflow === undefined
        ? true
        : Boolean(options.includeDataflow),
    defaultIgnore:
      options.defaultIgnore === undefined ? true : Boolean(options.defaultIgnore),
  };

  const files = collectFiles(absoluteTarget, normalizedOptions);
  const findings = files.flatMap((filePath) => scanFile(filePath, normalizedOptions));

  findings.sort((a, b) => {
    const severityDiff = severityRank[b.severity] - severityRank[a.severity];
    if (severityDiff !== 0) {
      return severityDiff;
    }
    if (a.file !== b.file) {
      return a.file.localeCompare(b.file);
    }
    return a.line - b.line;
  });

  return {
    scannedPath: absoluteTarget,
    scannedFiles: files.length,
    findings,
    summary: summarize(findings),
  };
}

module.exports = {
  scanRepository,
  severityRank,
  severities,
};
