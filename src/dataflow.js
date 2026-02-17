"use strict";

const JS_LIKE_EXTENSIONS = new Set([
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".mjs",
  ".cjs",
]);

const PYTHON_EXTENSIONS = new Set([".py"]);

const SOURCE_PATTERNS = [
  /\b(req|request)\.(query|params|body)\b/,
  /\b(req|request)\.(get|header)s?\s*\(/,
  /\bURLSearchParams\s*\(/,
  /\b(window|document)\.location\b/,
  /\brequest\.(args|form|get_json)\b/,
  /\bflask\.request\.(args|form|get_json)\b/,
  /\binput\s*\(/,
];

const FLOW_RULES = [
  {
    id: "VG201",
    title: "Tainted data reaches dynamic execution",
    severity: "critical",
    confidence: "medium",
    description:
      "User-controlled data appears to flow into dynamic code execution.",
    recommendation:
      "Remove dynamic execution paths or strictly allowlist executable operations.",
    jsSink: /\b(eval|Function)\s*\(([^)]*)\)/g,
    pySink: /\beval\s*\(([^)]*)\)/g,
  },
  {
    id: "VG202",
    title: "Tainted data reaches command execution",
    severity: "critical",
    confidence: "medium",
    description:
      "User-controlled data appears to flow into OS command execution.",
    recommendation:
      "Use non-shell parameterized APIs and validate/allowlist all command inputs.",
    jsSink:
      /\b(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(([^)]*)\)/g,
    pySink: /\b(subprocess\.(run|Popen|call)|os\.system)\s*\(([^)]*)\)/g,
  },
  {
    id: "VG203",
    title: "Tainted data reaches SQL execution",
    severity: "high",
    confidence: "medium",
    description:
      "Potential SQL injection path detected from input sources to query execution.",
    recommendation:
      "Use parameterized queries and bind variables instead of dynamic query strings.",
    jsSink: /\b(query|execute|run)\s*\(([^)]*)\)/g,
    pySink: /\b(cursor\.)?(execute|executemany)\s*\(([^)]*)\)/g,
  },
  {
    id: "VG204",
    title: "Tainted data reaches redirect sink",
    severity: "medium",
    confidence: "medium",
    description:
      "User-controlled data appears to flow into redirects, risking open redirect behavior.",
    recommendation:
      "Allowlist destinations and restrict redirects to trusted relative paths.",
    jsSink: /\bres\.redirect\s*\(([^)]*)\)/g,
    pySink: /\bredirect\s*\(([^)]*)\)/g,
  },
  {
    id: "VG205",
    title: "Tainted data reaches file path sink",
    severity: "high",
    confidence: "medium",
    description:
      "User-controlled data appears to flow into filesystem path operations.",
    recommendation:
      "Normalize path input and enforce base-directory boundaries before file access.",
    jsSink:
      /\b(readFile|readFileSync|open|createReadStream|sendFile|writeFile|writeFileSync)\s*\(([^)]*)\)/g,
    pySink: /\b(open|send_file)\s*\(([^)]*)\)/g,
  },
];

function stripLineComments(line) {
  return line.replace(/\/\/.*$/, "").replace(/#.*$/, "").trim();
}

function expressionHasSource(expression) {
  return SOURCE_PATTERNS.some((pattern) => pattern.test(expression));
}

function expressionUsesTaintedVar(expression, taintedVars) {
  for (const variable of taintedVars) {
    const variablePattern = new RegExp(`\\b${variable}\\b`);
    if (variablePattern.test(expression)) {
      return true;
    }
  }

  return false;
}

function expressionIsTainted(expression, taintedVars) {
  return (
    expressionHasSource(expression) || expressionUsesTaintedVar(expression, taintedVars)
  );
}

function updateTaintFromAssignment(line, taintedVars) {
  const assignment = line.match(
    /^(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*(.+?);?$/,
  );

  if (!assignment) {
    return;
  }

  const variable = assignment[1];
  const expression = assignment[2];

  if (expressionIsTainted(expression, taintedVars)) {
    taintedVars.add(variable);
  }
}

function sinkArgument(rule, match, fileExtension) {
  if (PYTHON_EXTENSIONS.has(fileExtension)) {
    return match[3] || match[1] || "";
  }

  return match[2] || match[1] || "";
}

function analyzeDataflow(filePath, fileExtension, content) {
  if (
    !JS_LIKE_EXTENSIONS.has(fileExtension) &&
    !PYTHON_EXTENSIONS.has(fileExtension)
  ) {
    return [];
  }

  const lines = content.split(/\r?\n/);
  const taintedVars = new Set();
  const findings = [];
  const dedupe = new Set();

  for (let index = 0; index < lines.length; index += 1) {
    const originalLine = lines[index];
    const line = stripLineComments(originalLine);

    if (!line) {
      continue;
    }

    updateTaintFromAssignment(line, taintedVars);

    for (const rule of FLOW_RULES) {
      const sink = PYTHON_EXTENSIONS.has(fileExtension) ? rule.pySink : rule.jsSink;
      if (!sink) {
        continue;
      }

      const localSink = new RegExp(sink.source, sink.flags);
      let match;

      while ((match = localSink.exec(line)) !== null) {
        const argument = sinkArgument(rule, match, fileExtension);
        if (!expressionIsTainted(argument, taintedVars)) {
          continue;
        }

        const finding = {
          ruleId: rule.id,
          title: rule.title,
          severity: rule.severity,
          confidence: rule.confidence,
          description: rule.description,
          recommendation: rule.recommendation,
          file: filePath,
          line: index + 1,
          snippet: originalLine.trim().slice(0, 240),
          pattern: sink.source,
        };

        const findingKey = `${finding.ruleId}:${finding.file}:${finding.line}`;
        if (dedupe.has(findingKey)) {
          continue;
        }

        dedupe.add(findingKey);
        findings.push(finding);
      }
    }
  }

  return findings;
}

module.exports = {
  analyzeDataflow,
};
