"use strict";

// Heuristics that suppress pattern matches which are almost never real issues.
// Each check looks only at the match and the statement around it.

const PLACEHOLDER_SECRET =
  /(example|placeholder|changeme|change_me|your[_-]|dummy|fake|sample|xxxx|here|redacted|todo|<|\$\{|\{\{)/i;

const ESCAPE_CALL = /^\s*(esc|escape|escapeHtml|escapeHTML|sanitize|sanitizeHtml|DOMPurify\.sanitize|encodeURIComponent|he\.encode|_\.escape)\s*\(/;

function lineAt(content, index) {
  const start = content.lastIndexOf("\n", index - 1) + 1;
  const end = content.indexOf("\n", index);
  return content.slice(start, end === -1 ? content.length : end);
}

function charBefore(content, index) {
  return index > 0 ? content[index - 1] : "";
}

function shannonEntropy(value) {
  const counts = new Map();
  for (const char of value) {
    counts.set(char, (counts.get(char) || 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// eval( / exec( called as a method (obj.eval(, $this->exec(, Foo::exec() is not
// language-level dynamic execution. Neither is exec() with a constant string.
function isBenignDynamicExecution(match, content) {
  const before = content.slice(Math.max(0, match.index - 2), match.index);
  if (/\bfunction\s+$/.test(content.slice(Math.max(0, match.index - 12), match.index))) {
    return true;
  }
  if (/(\.|->|::)$/.test(before) || /[.\w]$/.test(charBefore(content, match.index))) {
    return true;
  }

  const after = content.slice(match.index + match[0].length, match.index + match[0].length + 200);
  const literalOnly = /^\s*(['"])([^'"$`{}]*)\1\s*[,)]/.exec(after);
  return Boolean(literalOnly);
}

function isPlaceholderSecret(match) {
  const quoted = /["']([^"']+)["']/.exec(match[0]);
  const value = quoted ? quoted[1] : match[0];

  if (PLACEHOLDER_SECRET.test(value)) {
    return true;
  }

  // Config key names such as "dso_pki_hmac_secret" are identifiers, not secrets.
  if (/^[a-z]+(?:[_.-][a-z]+)+$/.test(value)) {
    return true;
  }

  return value.length >= 16 && shannonEntropy(value) < 3;
}

// Returns the right-hand side of an innerHTML assignment up to the end of the
// statement, following a template literal across lines.
function assignedExpression(match, content) {
  const start = content.indexOf("=", match.index) + 1;
  const rest = content.slice(start, start + 4000).trimStart();
  if (rest.startsWith("`")) {
    let depth = 0;
    for (let i = 1; i < rest.length; i += 1) {
      const char = rest[i];
      if (char === "\\") {
        i += 1;
      } else if (char === "$" && rest[i + 1] === "{") {
        depth += 1;
        i += 1;
      } else if (char === "}" && depth > 0) {
        depth -= 1;
      } else if (char === "`" && depth === 0) {
        return rest.slice(0, i + 1);
      }
    }
    return rest;
  }
  const end = rest.search(/;|\n/);
  return end === -1 ? rest : rest.slice(0, end);
}

function templateInterpolations(expression) {
  const parts = [];
  let i = 0;
  while ((i = expression.indexOf("${", i)) !== -1) {
    let depth = 1;
    let j = i + 2;
    while (j < expression.length && depth > 0) {
      if (expression[j] === "{") depth += 1;
      if (expression[j] === "}") depth -= 1;
      j += 1;
    }
    parts.push(expression.slice(i + 2, j - 1));
    i = j;
  }
  return parts;
}

function previousLine(content, index) {
  const lineStart = content.lastIndexOf("\n", index - 1);
  return lineStart <= 0 ? "" : lineAt(content, lineStart);
}

function isSafeHtmlSink(match, content) {
  const line = lineAt(content, match.index);
  const suppression = /eslint-disable[^\n]*no-unsanitized/;
  if (suppression.test(line) || suppression.test(previousLine(content, match.index))) {
    return true;
  }

  // JSON-LD blocks render JSON.stringify output into a non-executable script type.
  if (/dangerouslySetInnerHTML/.test(match[0])) {
    const context = content.slice(Math.max(0, match.index - 200), match.index + 200);
    return /application\/ld\+json/.test(context) && /JSON\.stringify\s*\(/.test(context);
  }

  const expression = assignedExpression(match, content);
  if (!expression.startsWith("`")) {
    return /^\s*['"]/.test(expression);
  }

  const interpolations = templateInterpolations(expression);
  return interpolations.every(
    (part) =>
      ESCAPE_CALL.test(part) ||
      /^\s*[\w.]*(safe|escaped|sanitized)\w*\s*$/i.test(part) ||
      /^\s*-?\d+(\.\d+)?\s*$/.test(part),
  );
}

function isLikelyFalsePositive(ruleId, match, content) {
  switch (ruleId) {
    case "VG001":
      return isBenignDynamicExecution(match, content);
    case "VG004":
      return !/PRIVATE KEY/.test(match[0]) && isPlaceholderSecret(match);
    case "VG007":
      return isSafeHtmlSink(match, content);
    default:
      return false;
  }
}

module.exports = {
  isLikelyFalsePositive,
  shannonEntropy,
};
