# @hailbytes/sbom-diff

> Diff two CycloneDX or SPDX SBOMs and produce human-readable change reports. Highlights added, removed, upgraded dependencies and new CVEs.

[![npm version](https://img.shields.io/npm/v/%40hailbytes%2Fsbom-diff.svg)](https://www.npmjs.com/package/%40hailbytes%2Fsbom-diff)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Bundle Size](https://img.shields.io/bundlephobia/minzip/%40hailbytes%2Fsbom-diff)](https://bundlephobia.com/package/@hailbytes/sbom-diff)

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

### Programmatic
```ts
import { diff } from '@hailbytes/sbom-diff';

const report = await diff('old.cdx.json', 'new.cdx.json');

console.log(report.added);    // Component[] — newly added packages
console.log(report.removed);  // Component[] — packages removed
console.log(report.upgraded); // { from: Component, to: Component }[]
console.log(report.newCVEs);  // CVE[] — vulnerabilities in new packages
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
