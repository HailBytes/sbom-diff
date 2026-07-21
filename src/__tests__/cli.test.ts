import { describe, it, expect } from 'vitest';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs, loadSbom, gateFailures, gateWarning, isSuppressed } from '../cli.js';
import type { ChangeReport, CVEEntry, SBOM } from '../types.js';

describe('parseArgs', () => {
  it('defaults to text format when no flag is given', () => {
    const { positional, format, failOn } = parseArgs(['old.json', 'new.json']);
    expect(positional).toEqual(['old.json', 'new.json']);
    expect(format).toBe('text');
    expect(failOn).toBe('none');
  });

  it('parses --format=json', () => {
    const { positional, format } = parseArgs(['old.json', 'new.json', '--format=json']);
    expect(positional).toEqual(['old.json', 'new.json']);
    expect(format).toBe('json');
  });

  it('parses space-separated --format markdown', () => {
    const { positional, format } = parseArgs(['old.json', 'new.json', '--format', 'markdown']);
    expect(positional).toEqual(['old.json', 'new.json']);
    expect(format).toBe('markdown');
  });

  it('handles the flag appearing before positional paths', () => {
    const { positional, format } = parseArgs(['--format', 'json', 'old.json', 'new.json']);
    expect(positional).toEqual(['old.json', 'new.json']);
    expect(format).toBe('json');
  });

  it('throws on an unsupported format value', () => {
    expect(() => parseArgs(['old.json', 'new.json', '--format=yaml'])).toThrow(/Invalid --format/);
  });

  it('throws when --format is given without a value', () => {
    expect(() => parseArgs(['old.json', 'new.json', '--format'])).toThrow(/Invalid --format/);
  });

  it('throws on an unknown option', () => {
    expect(() => parseArgs(['old.json', 'new.json', '--bogus'])).toThrow(/Unknown option/);
  });

  it('parses --fail-on high', () => {
    const { failOn } = parseArgs(['old.json', 'new.json', '--fail-on', 'high']);
    expect(failOn).toBe('high');
  });

  it('parses --fail-on=any', () => {
    const { failOn } = parseArgs(['old.json', 'new.json', '--fail-on=any']);
    expect(failOn).toBe('any');
  });

  it('throws on an unsupported --fail-on value', () => {
    expect(() => parseArgs(['old.json', 'new.json', '--fail-on=sometimes'])).toThrow(
      /Invalid --fail-on/,
    );
  });

  it('throws when --fail-on is given without a value', () => {
    expect(() => parseArgs(['old.json', 'new.json', '--fail-on'])).toThrow(/Invalid --fail-on/);
  });
});

describe('gateFailures', () => {
  const cve = (
    id: string,
    severity?: CVEEntry['severity'],
    analysisState?: string,
  ): CVEEntry => ({
    id,
    affects: 'pkg:npm/example',
    severity,
    analysisState,
  });

  const reportWith = (newCVEs: CVEEntry[]): ChangeReport => ({
    added: [],
    removed: [],
    upgraded: [],
    licenseChanges: [],
    newCVEs,
    fixedCVEs: [],
    summary: {
      totalAdded: 0,
      totalRemoved: 0,
      totalUpgraded: 0,
      totalLicenseChanges: 0,
      totalDowngraded: 0,
      totalNewCVEs: newCVEs.length,
      totalFixedCVEs: 0,
    },
  });

  it('never fails under the "none" policy, even with new CVEs', () => {
    const report = reportWith([cve('CVE-1', 'critical')]);
    expect(gateFailures(report, 'none')).toEqual([]);
  });

  it('fails on any new CVE under the "any" policy', () => {
    const report = reportWith([cve('CVE-1', 'low'), cve('CVE-2')]);
    expect(gateFailures(report, 'any').map(v => v.id)).toEqual(['CVE-1', 'CVE-2']);
  });

  it('passes when there are no new CVEs', () => {
    expect(gateFailures(reportWith([]), 'any')).toEqual([]);
    expect(gateFailures(reportWith([]), 'critical')).toEqual([]);
  });

  it('fails only on new CVEs at or above the severity threshold', () => {
    const report = reportWith([
      cve('CVE-low', 'low'),
      cve('CVE-med', 'medium'),
      cve('CVE-high', 'high'),
      cve('CVE-crit', 'critical'),
    ]);
    expect(gateFailures(report, 'high').map(v => v.id)).toEqual(['CVE-high', 'CVE-crit']);
    expect(gateFailures(report, 'medium').map(v => v.id)).toEqual([
      'CVE-med',
      'CVE-high',
      'CVE-crit',
    ]);
  });

  it('does not trip a severity threshold on unknown-severity CVEs', () => {
    const report = reportWith([cve('CVE-unknown')]);
    expect(gateFailures(report, 'critical')).toEqual([]);
    // ...but "any" still catches them.
    expect(gateFailures(report, 'any').map(v => v.id)).toEqual(['CVE-unknown']);
  });

  it('ignores VEX-suppressed CVEs (not_affected / false_positive) under every policy', () => {
    const report = reportWith([
      cve('CVE-not-affected', 'critical', 'not_affected'),
      cve('CVE-false-pos', 'critical', 'false_positive'),
    ]);
    expect(gateFailures(report, 'any')).toEqual([]);
    expect(gateFailures(report, 'critical')).toEqual([]);
  });

  it('still fails on actionable CVEs alongside suppressed ones', () => {
    const report = reportWith([
      cve('CVE-suppressed', 'critical', 'not_affected'),
      cve('CVE-real', 'high'),
      cve('CVE-triage', 'critical', 'in_triage'),
    ]);
    // The suppressed one drops out; the real and still-under-triage ones remain.
    expect(gateFailures(report, 'high').map(v => v.id)).toEqual(['CVE-real', 'CVE-triage']);
  });
});

describe('isSuppressed', () => {
  const withState = (analysisState?: string): CVEEntry => ({
    id: 'CVE-x',
    affects: 'pkg:npm/example',
    analysisState,
  });

  it('is true only for not_affected and false_positive', () => {
    expect(isSuppressed(withState('not_affected'))).toBe(true);
    expect(isSuppressed(withState('false_positive'))).toBe(true);
  });

  it('is false for active, in-progress, or absent states', () => {
    expect(isSuppressed(withState('exploitable'))).toBe(false);
    expect(isSuppressed(withState('in_triage'))).toBe(false);
    expect(isSuppressed(withState('resolved'))).toBe(false);
    expect(isSuppressed(withState(undefined))).toBe(false);
  });
});

describe('gateWarning', () => {
  const sbom = (vulnerabilities: SBOM['vulnerabilities'] = []): SBOM => ({
    format: 'cyclonedx',
    components: [],
    vulnerabilities,
  });
  const withCve: SBOM = sbom([{ id: 'CVE-1', affects: 'pkg:npm/example', severity: 'high' }]);

  it('returns null when the gate is off, even without vulnerability data', () => {
    expect(gateWarning(sbom(), sbom(), 'none')).toBeNull();
  });

  it('warns when a gate is armed but neither SBOM carries vulnerability data', () => {
    const warning = gateWarning(sbom(), sbom(), 'high');
    expect(warning).toMatch(/--fail-on "high"/);
    expect(warning).toMatch(/neither SBOM contains vulnerability data/);
  });

  it('warns for the "any" policy too', () => {
    expect(gateWarning(sbom(), sbom(), 'any')).toMatch(/neither SBOM contains vulnerability data/);
  });

  it('stays silent when the old SBOM carries vulnerability data', () => {
    expect(gateWarning(withCve, sbom(), 'critical')).toBeNull();
  });

  it('stays silent when the new SBOM carries vulnerability data', () => {
    expect(gateWarning(sbom(), withCve, 'critical')).toBeNull();
  });

  it('treats a missing vulnerabilities field as no data', () => {
    const noField: SBOM = { format: 'spdx', components: [] };
    expect(gateWarning(noField, noField, 'medium')).toMatch(
      /neither SBOM contains vulnerability data/,
    );
  });
});

describe('loadSbom', () => {
  it('wraps a missing file with its path and role', async () => {
    await expect(loadSbom('/no/such/sbom-diff-missing.json', 'old')).rejects.toThrowError(
      "Failed to read old SBOM '/no/such/sbom-diff-missing.json'",
    );
  });

  it('wraps malformed JSON with its path and role', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'sbom-diff-'));
    const path = join(dir, 'bad.json');
    await writeFile(path, '{ not valid json');
    try {
      await expect(loadSbom(path, 'new')).rejects.toThrowError(
        `Failed to parse new SBOM '${path}'`,
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('parses a valid SBOM file', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'sbom-diff-'));
    const path = join(dir, 'good.json');
    await writeFile(
      path,
      JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.5', components: [] }),
    );
    try {
      const sbom = await loadSbom(path, 'old');
      expect(sbom.format).toBe('cyclonedx');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('parseArgs help/version', () => {
  it('sets help for --help and -h', () => {
    expect(parseArgs(['--help']).help).toBe(true);
    expect(parseArgs(['-h']).help).toBe(true);
  });

  it('sets version for --version and -v', () => {
    expect(parseArgs(['--version']).version).toBe(true);
    expect(parseArgs(['-v']).version).toBe(true);
  });

  it('short-circuits --help even alongside otherwise-invalid args', () => {
    // Would normally throw on the bad --format value; --help wins instead.
    expect(() => parseArgs(['--help', '--format=yaml'])).not.toThrow();
    expect(parseArgs(['--help', '--format=yaml']).help).toBe(true);
  });

  it('does not treat normal invocations as help or version', () => {
    const parsed = parseArgs(['old.json', 'new.json']);
    expect(parsed.help).toBe(false);
    expect(parsed.version).toBe(false);
  });
});
