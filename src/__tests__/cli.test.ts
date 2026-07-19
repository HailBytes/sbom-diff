import { describe, it, expect } from 'vitest';
import { parseArgs, gateFailures } from '../cli.js';
import type { ChangeReport, CVEEntry } from '../types.js';

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
  const cve = (id: string, severity?: CVEEntry['severity']): CVEEntry => ({
    id,
    affects: 'pkg:npm/example',
    severity,
  });

  const reportWith = (newCVEs: CVEEntry[]): ChangeReport => ({
    added: [],
    removed: [],
    upgraded: [],
    newCVEs,
    fixedCVEs: [],
    summary: {
      totalAdded: 0,
      totalRemoved: 0,
      totalUpgraded: 0,
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
});
