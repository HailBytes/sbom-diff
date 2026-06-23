import { describe, it, expect } from 'vitest';
import { renderReport } from '../reporter.js';
import type { ChangeReport } from '../types.js';

const sampleReport: ChangeReport = {
  added: [{ name: 'express', version: '4.18.2', ecosystem: 'npm' }],
  removed: [{ name: 'moment', version: '2.29.4' }],
  upgraded: [{ component: { name: 'lodash', version: '4.17.21' }, from: '4.17.20', to: '4.17.21', isMajorBump: false }],
  licenseChanges: [{ component: { name: 'chalk', version: '5.3.0' }, from: 'MIT', to: 'GPL-3.0' }],
  newCVEs: [{ id: 'CVE-2023-1234', affects: 'pkg:npm/foo@1.0.0', severity: 'high' }],
  fixedCVEs: [{ id: 'CVE-2022-9999', affects: 'pkg:npm/bar@0.9.0' }],
  summary: { totalAdded: 1, totalRemoved: 1, totalUpgraded: 1, totalLicenseChanges: 1, totalNewCVEs: 1, totalFixedCVEs: 1 },
};

describe('renderReport', () => {
  it('renders text format', () => {
    const out = renderReport(sampleReport, 'text');
    expect(out).toContain('SBOM Diff Report');
    expect(out).toContain('express');
    expect(out).toContain('moment');
    expect(out).toContain('CVE-2023-1234');
    expect(out).toContain('CVE-2022-9999');
    expect(out).toContain('License Changes');
    expect(out).toContain('chalk: MIT');
  });

  it('renders JSON format', () => {
    const out = renderReport(sampleReport, 'json');
    const parsed = JSON.parse(out);
    expect(parsed.summary.totalAdded).toBe(1);
  });

  it('renders markdown format', () => {
    const out = renderReport(sampleReport, 'markdown');
    expect(out).toContain('# SBOM Diff Report');
    expect(out).toContain('| express |');
    expect(out).toContain('CVE-2023-1234');
    expect(out).toContain('## ⚖️ License Changes');
    expect(out).toContain('| chalk | MIT | GPL-3.0 |');
  });

  it('throws on unsupported format', () => {
    expect(() => renderReport(sampleReport, 'xml' as never)).toThrow();
  });

  it('escapes pipes and newlines in markdown cells so the table stays well-formed', () => {
    const report: ChangeReport = {
      added: [{ name: 'evil | pkg', version: '1.0', ecosystem: 'npm' }],
      removed: [],
      upgraded: [],
      licenseChanges: [],
      newCVEs: [{ id: 'CVE-2024-0001', affects: 'pkg:npm/a | b', severity: 'high', description: 'line1\nline2' }],
      fixedCVEs: [],
      summary: { totalAdded: 1, totalRemoved: 0, totalUpgraded: 0, totalLicenseChanges: 0, totalNewCVEs: 1, totalFixedCVEs: 0 },
    };
    const out = renderReport(report, 'markdown');

    // The pipe in the package name must be escaped, not interpreted as a column break.
    expect(out).toContain('| evil \\| pkg | 1.0 | npm |');
    expect(out).toContain('| CVE-2024-0001 | high | \u2014 | pkg:npm/a \\| b |');

    // Every body row under the Added table must keep its column count (4 leading bars: 3 cells).
    const addedRow = out.split('\n').find(l => l.includes('evil'))!;
    expect((addedRow.match(/(?<!\\)\|/g) ?? []).length).toBe(4);
  });
});
