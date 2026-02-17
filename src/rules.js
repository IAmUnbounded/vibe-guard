"use strict";

const rules = [
  {
    id: "VG001",
    title: "Dynamic code execution",
    severity: "critical",
    confidence: "high",
    description:
      "Dynamic execution primitives can enable remote code execution when user input is passed through.",
    recommendation:
      "Remove eval-style execution. Use strict allowlists and structured dispatch instead.",
    patterns: [/\beval\s*\(/, /\bnew\s+Function\s*\(/, /(?<!\.)\bexec\s*\(/],
  },
  {
    id: "VG002",
    title: "OS command execution",
    severity: "critical",
    confidence: "high",
    description:
      "Command execution APIs are dangerous in AI-generated glue code and often miss input sanitization.",
    recommendation:
      "Use parameterized APIs (spawn/execFile) and avoid shell invocation where possible.",
    patterns: [
      /child_process\.(exec|execSync)\s*\(/,
      /subprocess\.(run|Popen|call)\s*\(.*shell\s*=\s*True/,
      /os\.system\s*\(/,
    ],
  },
  {
    id: "VG003",
    title: "Potential SQL injection",
    severity: "high",
    confidence: "medium",
    description:
      "String interpolation in SQL statements can allow attacker-controlled query manipulation.",
    recommendation:
      "Use parameterized queries or query builders with bound parameters.",
    patterns: [
      /SELECT\s+.+\$\{.+\}/i,
      /INSERT\s+.+\$\{.+\}/i,
      /UPDATE\s+.+\$\{.+\}/i,
      /DELETE\s+.+\$\{.+\}/i,
      /cursor\.execute\s*\(\s*f["'][^"']*\{/i,
      /query\s*\(\s*`[^`]*\$\{/i,
    ],
  },
  {
    id: "VG004",
    title: "Hardcoded secret",
    severity: "high",
    confidence: "medium",
    description:
      "AI scaffolds often leave test tokens and credentials directly in source files.",
    recommendation:
      "Move secrets to a vault or environment variables and rotate exposed keys.",
    patterns: [
      /(api[_-]?key|secret|token|password)\s*[:=]\s*["'][A-Za-z0-9_\-\.]{16,}["']/i,
      /AKIA[0-9A-Z]{16}/,
      /-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----/,
    ],
  },
  {
    id: "VG005",
    title: "TLS verification disabled",
    severity: "high",
    confidence: "high",
    description:
      "Disabling certificate validation creates trivial man-in-the-middle risk.",
    recommendation:
      "Enable certificate verification and trust only known CAs/certificates.",
    patterns: [
      /rejectUnauthorized\s*:\s*false/,
      /verify\s*=\s*False/,
      /InsecureSkipVerify\s*:\s*true/,
      /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0["']?/,
    ],
  },
  {
    id: "VG006",
    title: "Unsafe deserialization",
    severity: "critical",
    confidence: "high",
    description:
      "Unsafe loaders can deserialize attacker-controlled payloads into code execution.",
    recommendation:
      "Use safe parsing APIs and strict schemas for untrusted input.",
    patterns: [/yaml\.load\s*\(/, /pickle\.loads\s*\(/, /marshal\.loads\s*\(/],
  },
  {
    id: "VG007",
    title: "Potential XSS sink",
    severity: "high",
    confidence: "medium",
    description:
      "Direct HTML injection is common in generated frontend code and can expose script execution.",
    recommendation:
      "Use textContent or trusted sanitization before writing HTML.",
    patterns: [/innerHTML\s*=\s*[^\s"']/, /dangerouslySetInnerHTML\s*=\s*\{\{/],
  },
  {
    id: "VG008",
    title: "Weak hashing algorithm",
    severity: "medium",
    confidence: "high",
    description:
      "MD5 and SHA1 are not safe for security-sensitive hashing.",
    recommendation:
      "Use modern algorithms (SHA-256+, Argon2, scrypt, bcrypt depending on use case).",
    patterns: [/\bmd5\b/i, /\bsha1\b/i],
  },
  {
    id: "VG009",
    title: "Insecure CORS wildcard",
    severity: "high",
    confidence: "medium",
    description:
      "Wildcard CORS with credentials can expose authenticated data cross-origin.",
    recommendation:
      "Use explicit trusted origins and avoid credentialed wildcard policies.",
    patterns: [
      /Access-Control-Allow-Origin\s*[:=]\s*["']\*["']/i,
      /cors\s*\(\s*\{[^}]*origin\s*:\s*["']\*["'][^}]*credentials\s*:\s*true/i,
    ],
  },
  {
    id: "VG010",
    title: "Authentication bypass marker",
    severity: "medium",
    confidence: "low",
    description:
      "Temporary bypass switches in generated code can reach production by accident.",
    recommendation:
      "Remove bypass toggles and enforce auth checks in all environments.",
    patterns: [
      /bypass(auth|Auth)/,
      /skip(auth|Auth)/,
      /if\s*\(\s*process\.env\.(DEV|DEBUG|LOCAL)/,
      /TODO\s*:\s*(remove|fix).*(auth|security)/i,
    ],
  },
  {
    id: "VG011",
    title: "JWT verification disabled",
    severity: "critical",
    confidence: "high",
    description:
      "Disabling JWT signature verification allows token forgery.",
    recommendation:
      "Always verify signature, issuer, audience, and expiration with strict options.",
    patterns: [
      /jwt\.decode\s*\(.*verify\s*[:=]\s*false/i,
      /verify_signature\s*=\s*False/,
      /algorithms\s*=\s*\[["']none["']\]/i,
    ],
  },
  {
    id: "VG012",
    title: "Open redirect candidate",
    severity: "medium",
    confidence: "low",
    description:
      "Directly redirecting from request parameters can be abused for phishing flows.",
    recommendation:
      "Only redirect to allowlisted relative paths or trusted hostnames.",
    patterns: [
      /res\.redirect\s*\(\s*req\.(query|body|params)\./,
      /window\.location\s*=\s*.*(searchParams|get\()/,
    ],
  },
  {
    id: "VG013",
    title: "Path traversal candidate",
    severity: "high",
    confidence: "medium",
    description:
      "Joining file paths with request input can expose arbitrary file read/write.",
    recommendation:
      "Normalize paths and enforce base-directory containment.",
    patterns: [
      /path\.join\s*\(\s*[^,]+,\s*req\.(params|query|body)\./,
      /open\s*\(\s*.*request\.(args|get_json|form)/,
      /sendFile\s*\(\s*req\.(params|query|body)\./,
    ],
  },
  {
    id: "VG014",
    title: "Prototype pollution merge",
    severity: "high",
    confidence: "medium",
    description:
      "Unsafe deep merge of untrusted objects can mutate runtime prototypes.",
    recommendation:
      "Block __proto__/constructor/prototype keys and use hardened merge utilities.",
    patterns: [/lodash\.merge\s*\(/, /deepmerge\s*\(/, /Object\.assign\s*\(\s*\{\}\s*,\s*req\./],
  },
];

const severities = ["low", "medium", "high", "critical"];

module.exports = {
  rules,
  severities,
};
