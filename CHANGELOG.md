# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- Real devDependencies: `typescript`, `vitest`, `@vitest/coverage-v8`, `typescript-eslint`, `@types/node`
- `src/types.ts` — Full domain model: `SBOM`, `Component`, `CVEEntry`, `ChangeReport`, `VersionChange`, `SBOMFormat`, `ReportFormat`
- `src/parser.ts` — `parse()` / `parseCycloneDX()` / `parseSPDX()`: auto-detect and parse CycloneDX + SPDX JSON SBOMs, extracts purls, ecosystems, licenses, suppliers, CVEs
- `src/diff.ts` — `diff()`: purl-first component matching (falls back to name), detects added/removed/upgraded deps, major version bump detection, CVE diff (new + fixed)
- `src/reporter.ts` — `renderReport()`: text, JSON, and Markdown output formats
- `src/cli.ts` — CLI entry point (`bin: sbom-diff`), `--format` flag support
- `src/index.ts` — Full public API re-exports replacing stub
- Unit test suite: 20 tests across parser, diff, and reporter modules (all passing)
- `eslint.config.js` — Flat config using `typescript-eslint`
- `vitest.config.ts` — Node environment, v8 coverage provider
- `tsconfig.build.json` — Separate build config excluding test files from `dist/`
- Updated `package.json`: real scripts (`build`, `typecheck`, `lint`, `test`, `test:watch`, `test:coverage`, `cli`), `exports`, `bin`, `files` fields
- Updated `.gitignore`: exclude compiled JS artifacts from `src/`

### Initial scaffold
- Repository structure, README, LICENSE, CONTRIBUTING.md
