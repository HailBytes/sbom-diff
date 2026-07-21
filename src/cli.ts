#!/usr/bin/env node
/**
 * @hailbytes/sbom-diff CLI
 *
 * Usage:
 *   npx @hailbytes/sbom-diff <old.json> <new.json> [--format text|json|markdown] [--fail-on <level>]
 */

import { readFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { parse } from './parser.js';
import { diff } from './diff.js';
import { renderReport } from './reporter.js';
import type { ChangeReport, CVEEntry, ReportFormat, SBOM } from './types.js';

const USAGE =
  'Usage: sbom-diff <old.json> <new.json> [--format text|json|markdown] [--fail-on none|any|low|medium|high|critical]';
const VALID_FORMATS: ReportFormat[] = ['text', 'json', 'markdown'];

/**
 * CI/CD gate policy. Determines whether the CLI exits non-zero.
 * - `none`: never fail (default; preserves prior behaviour)
 * - `any`: fail if any new CVE is introduced, regardless of severity
 * - a severity: fail if any new CVE meets or exceeds that severity
 */
export type FailOn = 'none' | 'any' | 'low' | 'medium' | 'high' | 'critical';
const VALID_FAIL_ON: FailOn[] = ['none', 'any', 'low', 'medium', 'high', 'critical'];

/** Exit code used when a `--fail-on` gate is triggered (distinct from usage/runtime errors). */
export const GATE_FAILURE_EXIT_CODE = 3;

/** Severity ordering, lowest to highest, for threshold comparisons. */
const SEVERITY_RANK: Record<NonNullable<CVEEntry['severity']>, number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const HELP = `sbom-diff — diff two CycloneDX or SPDX SBOMs into a change report.

${USAGE}

Arguments:
  <old.json>   Baseline SBOM (the "before" document)
  <new.json>   Updated SBOM (the "after" document)

Options:
  --format <fmt>   Output format: text (default), json, or markdown
  -h, --help       Show this help and exit
  -v, --version    Print the installed version and exit

Examples:
  sbom-diff old.json new.json
  sbom-diff old.json new.json --format json
  sbom-diff old.json new.json --format markdown`;

export interface ParsedArgs {
  positional: string[];
  format: ReportFormat;
  failOn: FailOn;
  /** true when -h/--help was requested */
  help: boolean;
  /** true when -v/--version was requested */
  version: boolean;
}

/**
 * Parse CLI arguments into positional paths, the requested output format, and
 * the CI/CD gate policy.
 *
 * Supports `--format text`, `--format=text`, `--fail-on high`, `--fail-on=high`,
 * and flags appearing in any position relative to the positional file paths.
 * Defaults to `text` format and a `none` gate policy.
 *
 * `-h`/`--help` and `-v`/`--version` short-circuit parsing so they always
 * work — even alongside otherwise-invalid arguments — and never throw.
 *
 * @throws if an unknown flag or unsupported format value is supplied.
 */
export function parseArgs(argv: string[]): ParsedArgs {
  if (argv.some(a => a === '-h' || a === '--help')) {
    return { positional: [], format: 'text', failOn: 'none', help: true, version: false };
  }
  if (argv.some(a => a === '-v' || a === '-V' || a === '--version')) {
    return { positional: [], format: 'text', failOn: 'none', help: false, version: true };
  }

  const positional: string[] = [];
  let format: ReportFormat = 'text';
  let failOn: FailOn = 'none';

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--format') {
      format = assertFormat(argv[++i]);
    } else if (arg.startsWith('--format=')) {
      format = assertFormat(arg.slice('--format='.length));
    } else if (arg === '--fail-on') {
      failOn = assertFailOn(argv[++i]);
    } else if (arg.startsWith('--fail-on=')) {
      failOn = assertFailOn(arg.slice('--fail-on='.length));
    } else if (arg.startsWith('-')) {
      throw new Error(`Unknown option: ${arg}\n${USAGE}`);
    } else {
      positional.push(arg);
    }
  }

  return { positional, format, failOn, help: false, version: false };
}

/**
 * Read the package version from the shipped package.json, resolved relative to
 * this module so it works whether invoked from `dist/` or via `npx`.
 */
export function resolveVersion(): string {
  try {
    const pkgUrl = new URL('../package.json', import.meta.url);
    const pkg = JSON.parse(readFileSync(pkgUrl, 'utf-8')) as { version?: string };
    return typeof pkg.version === 'string' ? pkg.version : '0.0.0';
  } catch {
    return '0.0.0';
  }
}

function assertFormat(value: string | undefined): ReportFormat {
  if (value !== undefined && (VALID_FORMATS as string[]).includes(value)) {
    return value as ReportFormat;
  }
  throw new Error(
    `Invalid --format value: ${value ?? '(none)'}. Expected one of: ${VALID_FORMATS.join(', ')}`,
  );
}

function assertFailOn(value: string | undefined): FailOn {
  if (value !== undefined && (VALID_FAIL_ON as string[]).includes(value)) {
    return value as FailOn;
  }
  throw new Error(
    `Invalid --fail-on value: ${value ?? '(none)'}. Expected one of: ${VALID_FAIL_ON.join(', ')}`,
  );
}

/**
 * CycloneDX VEX analysis states that explicitly declare the product is not
 * impacted by a vulnerability. A CVE carrying one of these is a documented
 * suppression, not an active finding, so it must never fail the CI gate —
 * that is the entire purpose of VEX. See CycloneDX `vulnerabilities[].analysis.state`.
 */
const SUPPRESSED_ANALYSIS_STATES = new Set(['not_affected', 'false_positive']);

/**
 * True when a vulnerability carries a VEX analysis state that declares the
 * product unaffected, so the gate should ignore it.
 */
export function isSuppressed(v: CVEEntry): boolean {
  return v.analysisState !== undefined && SUPPRESSED_ANALYSIS_STATES.has(v.analysisState);
}

/**
 * Evaluate the CI/CD gate against a diff. Returns the new CVEs that trip the
 * gate (empty when the gate passes). A new CVE with an unknown severity only
 * trips the `any` gate, since it cannot be compared against a severity threshold.
 *
 * Vulnerabilities suppressed by a VEX `not_affected` / `false_positive` analysis
 * state are excluded before the policy is applied, so an SBOM's own assessment
 * that it is not impacted cannot produce a false gate failure.
 */
export function gateFailures(report: ChangeReport, failOn: FailOn): CVEEntry[] {
  if (failOn === 'none') return [];
  const actionable = report.newCVEs.filter(v => !isSuppressed(v));
  if (failOn === 'any') return actionable;
  const threshold = SEVERITY_RANK[failOn];
  return actionable.filter(
    v => v.severity !== undefined && SEVERITY_RANK[v.severity] >= threshold,
  );
}

/**
 * Guard against a silently fail-open CVE gate.
 *
 * `--fail-on` can only trip on vulnerabilities that are *embedded in the SBOMs*
 * being compared (`diff()` derives `newCVEs` from each SBOM's `vulnerabilities`
 * list). Most SBOMs carry no such data: SPDX 2.x has no vulnerability field at
 * all, and the default output of common CycloneDX generators omits it —
 * vulnerabilities are usually attached by a separate scan/VEX step. When a gate
 * is armed but neither input carries vulnerability data, the gate has nothing to
 * evaluate and always passes, which in CI reads as "no new CVEs" when the truth
 * is "CVEs were never checked".
 *
 * Returns a human-readable warning for that fail-open case, or `null` when the
 * gate is off (`none`) or at least one SBOM actually carries vulnerability data.
 */
export function gateWarning(oldSBOM: SBOM, newSBOM: SBOM, failOn: FailOn): string | null {
  if (failOn === 'none') return null;
  const hasVulnData =
    (oldSBOM.vulnerabilities?.length ?? 0) > 0 || (newSBOM.vulnerabilities?.length ?? 0) > 0;
  if (hasVulnData) return null;
  return (
    `Warning: --fail-on "${failOn}" is set, but neither SBOM contains vulnerability data, ` +
    'so the CVE gate has nothing to evaluate and will pass. Most SBOMs do not embed ' +
    'vulnerabilities (all SPDX 2.x, and the default output of common CycloneDX generators); ' +
    'attach a scan/VEX step that emits a CycloneDX 1.4+ "vulnerabilities" list to enable CVE gating.'
  );
}
function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Read and parse an SBOM file, attaching the file path and role to any failure.
 *
 * The underlying `readFile`/`JSON.parse` errors (e.g. `ENOENT` or
 * `Expected property name or '}' in JSON at position 2`) don't say which of the
 * two inputs failed or that the SBOM-load step is where it broke. In a CI gate a
 * wrong or corrupt artifact is a common misconfiguration, so surface the path and
 * whether the read or the parse failed instead of a bare low-level message.
 *
 * @param label human-readable role of the file, e.g. `old` or `new`.
 * @throws if the file cannot be read or is not valid JSON / SBOM.
 */
export async function loadSbom(path: string, label: string): Promise<SBOM> {
  let raw: string;
  try {
    raw = await readFile(path, 'utf-8');
  } catch (err) {
    throw new Error(`Failed to read ${label} SBOM '${path}': ${errorMessage(err)}`);
  }
  try {
    return parse(raw);
  } catch (err) {
    throw new Error(`Failed to parse ${label} SBOM '${path}': ${errorMessage(err)}`);
  }
}

async function main(): Promise<void> {
  const { positional, format, failOn, help, version } = parseArgs(process.argv.slice(2));

  if (help) {
    console.log(HELP);
    return;
  }

  if (version) {
    console.log(resolveVersion());
    return;
  }

  if (positional.length < 2) {
    console.error(USAGE);
    process.exit(1);
  }

  const [oldPath, newPath] = positional;

  const [oldSBOM, newSBOM] = await Promise.all([
    loadSbom(oldPath, 'old'),
    loadSbom(newPath, 'new'),
  ]);

  const report = diff(oldSBOM, newSBOM);

  console.log(renderReport(report, format));

  const warning = gateWarning(oldSBOM, newSBOM, failOn);
  if (warning) console.error(warning);

  const failures = gateFailures(report, failOn);
  if (failures.length > 0) {
    const label = failOn === 'any' ? 'new CVE(s)' : `new CVE(s) at or above "${failOn}" severity`;
    console.error(
      `\nGate failed: ${failures.length} ${label}: ${failures.map(v => v.id).join(', ')}`,
    );
    process.exit(GATE_FAILURE_EXIT_CODE);
  }
}

// Only run when invoked directly (not when imported by tests).
const invokedPath = process.argv[1];
if (invokedPath && import.meta.url === pathToFileURL(invokedPath).href) {
  main().catch(err => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  });
}
