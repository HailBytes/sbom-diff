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

Compare two CycloneDX or SPDX SBOM files and instantly see what changed: added packages, removed packages, version upgrades, and newly introduced CVEs. Output as human-readable text, JSON, or Markdown — perfect for CI/CD gates and audit trails.

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
```

### CI/CD gate

Use `--fail-on` to exit with a non-zero status when the diff matches one or
more conditions — turning the diff into a build gate. Conditions are
comma-separated:

| Condition | Fails when… |
|-----------|-------------|
| `any` | any component is added, removed, or upgraded, or any new CVE appears |
| `added` / `removed` / `upgraded` | any component is added / removed / upgraded |
| `major` | any major version bump occurs |
| `new-cves` | any new CVE is introduced |
| `low` / `medium` / `high` / `critical` | any new CVE at or above that severity |

```bash
# Fail the pipeline if a new critical CVE or a major version bump appears
npx @hailbytes/sbom-diff old.json new.json --fail-on critical,major
```

Exit codes: `0` = no gated changes, `1` = gate triggered (or invalid input).

### Programmatic
```ts
import { diff } from '@hailbytes/sbom-diff';

const report = await diff('old.cdx.json', 'new.cdx.json');

console.log(report.added);    // Component[] — newly added packages
console.log(report.removed);  // Component[] — packages removed
console.log(report.upgraded); // { from: Component, to: Component }[]
console.log(report.newCVEs);  // CVE[] — vulnerabilities in new packages
```

```ts
import { parse, diff, evaluateGate } from '@hailbytes/sbom-diff';

const report = diff(parse(oldJSON), parse(newJSON));
const gate = evaluateGate(report, ['critical', 'major']);
if (gate.shouldFail) {
  throw new Error(`SBOM gate failed: ${gate.reasons.join('; ')}`);
}
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