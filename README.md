# sbom-diff

> Diff two CycloneDX or SPDX SBOMs and produce human-readable change reports. Highlights added, removed, upgraded dependencies and new CVEs.

[![npm version](https://img.shields.io/npm/v/%40hailbytes%2Fsbom-diff.svg)](https://www.npmjs.com/package/%40hailbytes%2Fsbom-diff)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Who Is This For

Security engineers, DevSecOps teams, and supply-chain risk analysts who need to track dependency changes between software releases, detect newly introduced CVEs, and produce auditable SBOM diff reports.

## API

### CLI
```bash
# Compare two SBOMs and print a human-readable report
npx @hailbytes/sbom-diff old.json new.json

# Output as JSON
npx @hailbytes/sbom-diff old.json new.json --format json

# Output as Markdown
npx @hailbytes/sbom-diff old.json new.json --format markdown
```

### Programmatic
```ts
import { diff } from '@hailbytes/sbom-diff';

const report = await diff(oldSBOM, newSBOM);
// report: ChangeReport
// {
//   added: Component[],
//   removed: Component[],
//   upgraded: { from: Component, to: Component }[],
//   newCVEs: CVE[]
// }
```

## See Also

- [`@hailbytes/caiq-lite`](https://github.com/HailBytes/caiq-lite) — CSA CAIQ-Lite schema and validator
- [`@hailbytes/asm-scope-parser`](https://github.com/HailBytes/asm-scope-parser) — Attack surface management scope parsing
- [HailBytes](https://hailbytes.com)
