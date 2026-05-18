import { describe, it, expect } from 'vitest';
import { renderReport } from '../reporter.js';
import type { ChangeReport } from '../types.js';

const sampleReport: ChangeReport = {
  added: [{ name: 'express', version: '4.18.2', ecosystem: 'npm' }],
  removed: [{ name: 'moment', version: '2.29.4' }],
  upgraded: [{ component: { name: 'lodash', version: '4.17.21' }, from: '4.17.20', to: '4.17.21', isMajorBump: false }],
  newCVEs: [{ id: 'CVE-2023-1234', affects: 'pkg:npm/foo@1.0.0', severity: 'high' }],
  fixedCVEs: [{ id: 'CVE-2022-9999', affects: 'pkg:npm/bar@0.9.0' }],
  summary: { totalAdded: 1, totalRemoved: 1, totalUpgraded: 1, totalNewCVEs: 1, totalFixedCVEs: 1 },
};

describe('renderReport', () => {
  it('renders text format', () => {
    const out = renderReport(sampleReport, 'text');
    expect(out).toContain('SBOM Diff Report');
    expect(out).toContain('express');
    expect(out).toContain('moment');
    expect(out).toContain('CVE-2023-1234');
    expect(out).toContain('CVE-2022-9999');
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
  });

  it('throws on unsupported format', () => {
    expect(() => renderReport(sampleReport, 'xml' as never)).toThrow();
  });
});
