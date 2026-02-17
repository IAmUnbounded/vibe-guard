# Vibe Guard

Vibe Guard is a security-focused CLI that scans source code for risky patterns often introduced by fast AI-assisted coding.

This repository includes:
- A CLI scanner (`vibe-guard`) for local and CI workflows
- A static product/landing page in `public/`

## Features

- Pattern-based detection for common security anti-patterns
- Lightweight taint/dataflow checks for JavaScript/TypeScript and Python
- Severity filtering (`low`, `medium`, `high`, `critical`)
- CI-friendly exit behavior with `--fail-on`
- JSON output for automation pipelines

## Requirements

- Node.js `>=18`
- npm

## Install

```bash
npm install
```

## Quick Start

```bash
# Scan current directory
npm run scan

# JSON output
npm run scan:json

# Strict mode example
npm run scan:strict
```

## CLI Usage

```bash
vibe-guard scan [path] [options]
```

If running from source without global install:

```bash
node ./bin/vibe-guard.js scan [path] [options]
```

### Options

- `--json` Print machine-readable JSON output
- `--min-severity <level>` `low|medium|high|critical` (default: `low`)
- `--fail-on <level>` Exit with code `2` if any finding at or above level exists
- `--max-file-size-kb <number>` Skip files larger than this size (default: `512`)
- `--include-tests` Include test/spec files
- `--no-dataflow` Disable taint/dataflow heuristics
- `--no-default-ignore` Also scan hidden/build directories
- `-h, --help` Show help

### Examples

```bash
# Scan current repository
node ./bin/vibe-guard.js scan .

# CI-style: show only high+ findings, fail if medium+ exists
node ./bin/vibe-guard.js scan . --min-severity high --fail-on medium

# JSON output for automation
node ./bin/vibe-guard.js scan ./services/api --json

# Pattern matching only (disable dataflow checks)
node ./bin/vibe-guard.js scan . --no-dataflow
```

## Exit Codes

- `0` Scan completed (and no `--fail-on` threshold triggered)
- `1` Invalid arguments or runtime/scan error
- `2` `--fail-on` threshold matched

## Default Scan Behavior

By default, Vibe Guard:
- Skips common generated/build folders such as `.git`, `node_modules`, `.next`, `dist`, `build`, and `coverage`
- Skips hidden directories unless `--no-default-ignore` is used
- Excludes test/spec files unless `--include-tests` is set
- Scans common source/config extensions (for example `.js`, `.ts`, `.py`, `.go`, `.sql`, `.yaml`, `.env`, `.html`)

## Local Landing Page

Run the static site server:

```bash
npm run site
```

Then open:

`http://127.0.0.1:4173`

## Project Structure

```text
bin/vibe-guard.js   CLI entrypoint
src/scanner.js      File traversal and rule execution
src/rules.js        Pattern-based detection rules
src/dataflow.js     Lightweight taint/dataflow analyzer
public/             Landing page assets
web/server.js       Static file server for public/
```

## Limitations

This tool is heuristic by design. Findings should be treated as triage candidates and validated in context before remediation.

## License

MIT. See `LICENSE`.
