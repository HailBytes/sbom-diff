# @hailbytes/sbom-diff
![npm](https://img.shields.io/npm/dt/@hailbytes/sbom-diff)


> Diff two CycloneDX or SPDX SBOMs and produce human-readable change reports. Highlights added, removed, upgraded dependencies and new CVEs.

[![npm version](https://img.shields.io/npm/v/%40hailbytes%2Fsbom-diff.svg)](https://www.npmjs.com/package/%40hailbytes%2Fsbom-diff)
[![npm downloads](https://img.shields.io/npm/dw/%40hailbytes%2Fsbom-diff.svg)](https://www.npmjs.com/package/@hailbytes/sbom-diff)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Bundle Size](https://img.shields.io/bundlephobia/minzip/%40hailbytes%2Fsbom-diff)](https://bundlephobia.com/package/@hailbytes/sbom-diff)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-davidhailbytes-blue?logo=linkedin&style=flat)](https://www.linkedin.com/in/davidhailbytes/)

---

## What it does

Compare two CycloneDX or SPDX SBOM files and instantly see what changed: added packages, removed packages, version upgrades, license changes (e.g. a dependency that switched from MIT to GPL-3.0), and newly introduced CVEs. Output as human-readable text, JSON, or Markdown — perfect for CI/CD gates and audit trails.

---

## Install

```bash
npm install @hailbytes/sbom-diff
# or use directly via npx
npx @hailbytes/sbom-diff old.json new.json
```

---

## Quick Start

### CLI
```bash
# Compare two SBOMs and print a human-readable report
npx @hailbytes/sbom-diff old.json new.json

# Output as JSON
npx @hailbytes/sbom-diff old.json new.json --format json

# Output as Markdown (great for PR comments)
npx @hailbytes/sbom-diff old.json new.json --format markdown

# Fail the build (exit code 3) if any new high or critical CVE appears
npx @hailbytes/sbom-diff old.json new.json --fail-on high
```

### CI/CD gate

Use `--fail-on` to turn the diff into a pass/fail gate. When the policy is
triggered, the report is still printed and the process exits with code `3`, so
your pipeline stops on risky changes:

| `--fail-on` | Fails when… |
|-------------|-------------|
| `none` *(default)* | never — always exits `0` |
| `any` | any new CVE is introduced |
| `low` / `medium` / `high` / `critical` | a new CVE appears at or above that severity |

```yaml
# GitHub Actions example
- name: Gate on new high-severity CVEs
  run: npx @hailbytes/sbom-diff sbom.base.json sbom.pr.json --fail-on high
```

> **Note:** the gate can only see vulnerabilities that are **embedded in the
> SBOMs** you compare. SPDX 2.x has no vulnerability field, and the default
> output of common CycloneDX generators omits one, so `--fail-on` has nothing to
> evaluate for those inputs and will pass. When a gate is armed but neither SBOM
> carries vulnerability data, the CLI prints a warning to `stderr` so a green
> result is never mistaken for "no new CVEs". To enable CVE gating, feed SBOMs
> that include a CycloneDX 1.4+ `vulnerabilities` list (e.g. from a scan/VEX
> step).

### Programmatic
```ts
import { readFile } from 'node:fs/promises';
import { parse, diff, renderReport } from '@hailbytes/sbom-diff';

// parse() accepts a JSON string (or already-parsed object) and auto-detects
// the CycloneDX/SPDX format. diff() compares two parsed SBOMs synchronously.
const oldSBOM = parse(await readFile('old.cdx.json', 'utf-8'));
const newSBOM = parse(await readFile('new.cdx.json', 'utf-8'));

const report = diff(oldSBOM, newSBOM);

console.log(report.added);          // Component[]     — newly added packages
console.log(report.removed);        // Component[]     — packages removed
console.log(report.upgraded);       // VersionChange[] — { component, from, to, isMajorBump }
console.log(report.licenseChanges); // LicenseChange[] — { component, from, to } (e.g. MIT → GPL-3.0)
console.log(report.newCVEs);        // CVEEntry[]      — vulnerabilities new in the latest SBOM

// Or render a ready-made report in text, JSON, or markdown:
console.log(renderReport(report, 'markdown'));
```

---

## Who Is This For

Security engineers, DevSecOps teams, and supply-chain risk analysts who need to track dependency changes between software releases, detect newly introduced CVEs, and produce auditable SBOM diff reports for compliance evidence.

---

## See Also

- [`@hailbytes/caiq-lite`](https://github.com/HailBytes/caiq-lite) — CSA CAIQ-Lite schema and validator
- [`@hailbytes/asm-scope-parser`](https://github.com/HailBytes/asm-scope-parser) — Attack surface scope parsing
- [HailBytes](https://hailbytes.com)

---

*Part of the [HailBytes](https://hailbytes.com) open-source security toolkit.*