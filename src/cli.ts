#!/usr/bin/env node
/**
 * @hailbytes/sbom-diff CLI
 *
 * Usage:
 *   npx @hailbytes/sbom-diff <old.json> <new.json> [--format text|json|markdown] [--fail-on <level>]
 */

import { readFile } from 'node:fs/promises';
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

export interface ParsedArgs {
  positional: string[];
  format: ReportFormat;
  failOn: FailOn;
}

/**
 * Parse CLI arguments into positional paths, the requested output format, and
 * the CI/CD gate policy.
 *
 * Supports `--format text`, `--format=text`, `--fail-on high`, `--fail-on=high`,
 * and flags appearing in any position relative to the positional file paths.
 * Defaults to `text` format and a `none` gate policy.
 *
 * @throws if an unknown flag or unsupported flag value is supplied.
 */
export function parseArgs(argv: string[]): ParsedArgs {
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

  return { positional, format, failOn };
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
 * Evaluate the CI/CD gate against a diff. Returns the new CVEs that trip the
 * gate (empty when the gate passes). A new CVE with an unknown severity only
 * trips the `any` gate, since it cannot be compared against a severity threshold.
 */
export function gateFailures(report: ChangeReport, failOn: FailOn): CVEEntry[] {
  if (failOn === 'none') return [];
  if (failOn === 'any') return report.newCVEs;
  const threshold = SEVERITY_RANK[failOn];
  return report.newCVEs.filter(
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

async function main(): Promise<void> {
  const { positional, format, failOn } = parseArgs(process.argv.slice(2));

  if (positional.length < 2) {
    console.error(USAGE);
    process.exit(1);
  }

  const [oldPath, newPath] = positional;

  const [oldRaw, newRaw] = await Promise.all([
    readFile(oldPath, 'utf-8'),
    readFile(newPath, 'utf-8'),
  ]);

  const oldSBOM = parse(oldRaw);
  const newSBOM = parse(newRaw);
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
