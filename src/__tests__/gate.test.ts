import { describe, it, expect } from 'vitest';
import { evaluateGate, parseGateConditions, ALL_GATE_CONDITIONS } from '../gate.js';
import type { ChangeReport, CVEEntry } from '../types.js';

const emptyReport = (): ChangeReport => ({
  added: [],
  removed: [],
  upgraded: [],
  newCVEs: [],
  fixedCVEs: [],
  summary: {
    totalAdded: 0,
    totalRemoved: 0,
    totalUpgraded: 0,
    totalNewCVEs: 0,
    totalFixedCVEs: 0,
  },
});

const cve = (id: string, severity: CVEEntry['severity']): CVEEntry => ({
  id,
  affects: 'pkg:npm/example@1.0.0',
  severity,
});

describe('parseGateConditions', () => {
  it('parses a comma-separated list', () => {
    expect(parseGateConditions('critical,major')).toEqual(['critical', 'major']);
  });

  it('is case-insensitive and trims whitespace', () => {
    expect(parseGateConditions(' New-CVEs , HIGH ')).toEqual(['new-cves', 'high']);
  });

  it('ignores empty tokens', () => {
    expect(parseGateConditions('any,,')).toEqual(['any']);
  });

  it('throws on unknown conditions', () => {
    expect(() => parseGateConditions('bogus')).toThrow(/Unknown --fail-on condition/);
  });

  it('accepts every documented condition', () => {
    expect(parseGateConditions(ALL_GATE_CONDITIONS.join(','))).toEqual(ALL_GATE_CONDITIONS);
  });
});

describe('evaluateGate', () => {
  it('does not fail an empty report', () => {
    const result = evaluateGate(emptyReport(), ['any', 'critical', 'major', 'new-cves']);
    expect(result.shouldFail).toBe(false);
    expect(result.reasons).toEqual([]);
  });

  it('fails on "any" when there are changes', () => {
    const r = emptyReport();
    r.summary.totalAdded = 2;
    const result = evaluateGate(r, ['any']);
    expect(result.shouldFail).toBe(true);
    expect(result.reasons[0]).toMatch(/2 change/);
  });

  it('fails on added/removed/upgraded counts', () => {
    const r = emptyReport();
    r.summary.totalRemoved = 1;
    expect(evaluateGate(r, ['added']).shouldFail).toBe(false);
    expect(evaluateGate(r, ['removed']).shouldFail).toBe(true);
  });

  it('fails on major bumps only when a major bump exists', () => {
    const r = emptyReport();
    r.upgraded = [
      { component: { name: 'a' }, from: '1.0.0', to: '1.2.0', isMajorBump: false },
    ];
    r.summary.totalUpgraded = 1;
    expect(evaluateGate(r, ['major']).shouldFail).toBe(false);
    expect(evaluateGate(r, ['upgraded']).shouldFail).toBe(true);

    r.upgraded.push({ component: { name: 'b' }, from: '1.0.0', to: '2.0.0', isMajorBump: true });
    r.summary.totalUpgraded = 2;
    expect(evaluateGate(r, ['major']).shouldFail).toBe(true);
  });

  it('fails on new CVEs', () => {
    const r = emptyReport();
    r.newCVEs = [cve('CVE-1', 'low')];
    r.summary.totalNewCVEs = 1;
    expect(evaluateGate(r, ['new-cves']).shouldFail).toBe(true);
  });

  it('applies severity thresholds (at or above)', () => {
    const r = emptyReport();
    r.newCVEs = [cve('CVE-low', 'low'), cve('CVE-high', 'high')];
    r.summary.totalNewCVEs = 2;

    expect(evaluateGate(r, ['critical']).shouldFail).toBe(false);
    expect(evaluateGate(r, ['high']).shouldFail).toBe(true);
    expect(evaluateGate(r, ['medium']).shouldFail).toBe(true);
    expect(evaluateGate(r, ['low']).shouldFail).toBe(true);
  });

  it('ignores CVEs with unknown severity for severity thresholds', () => {
    const r = emptyReport();
    r.newCVEs = [cve('CVE-x', undefined)];
    r.summary.totalNewCVEs = 1;
    expect(evaluateGate(r, ['low']).shouldFail).toBe(false);
    // ...but still counts under the generic new-cves condition
    expect(evaluateGate(r, ['new-cves']).shouldFail).toBe(true);
  });

  it('reports a reason for each triggered condition', () => {
    const r = emptyReport();
    r.summary.totalAdded = 1;
    r.newCVEs = [cve('CVE-1', 'critical')];
    r.summary.totalNewCVEs = 1;
    const result = evaluateGate(r, ['added', 'critical']);
    expect(result.shouldFail).toBe(true);
    expect(result.reasons).toHaveLength(2);
  });
});
