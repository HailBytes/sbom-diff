import { describe, it, expect } from 'vitest';
import { renderReport } from '../reporter.js';
import type { ChangeReport } from '../types.js';

const sampleReport: ChangeReport = {
  from: { format: 'cyclonedx', specVersion: '1.4', name: 'my-app', version: '1.2.0', generatedAt: '2026-07-01T00:00:00Z' },
  to: { format: 'cyclonedx', specVersion: '1.4', name: 'my-app', version: '1.3.0', generatedAt: '2026-08-01T00:00:00Z' },
  added: [{ name: 'express', version: '4.18.2', ecosystem: 'npm' }],
  removed: [{ name: 'moment', version: '2.29.4' }],
  upgraded: [{ component: { name: 'lodash', version: '4.17.21' }, from: '4.17.20', to: '4.17.21', isMajorBump: false, isDowngrade: false }],
  licenseChanges: [{ component: { name: 'chalk', version: '5.3.0' }, from: 'MIT', to: 'GPL-3.0' }],
  newCVEs: [{ id: 'CVE-2023-1234', affects: ['pkg:npm/foo@1.0.0'], severity: 'high' }],
  fixedCVEs: [{ id: 'CVE-2022-9999', affects: ['pkg:npm/bar@0.9.0'] }],
  severityEscalations: [],
  hashChanges: [],
  summary: { totalAdded: 1, totalRemoved: 1, totalUpgraded: 1, totalLicenseChanges: 1, totalDowngraded: 0, totalNewCVEs: 1, totalFixedCVEs: 1, totalSeverityEscalations: 0, totalHashChanges: 0 },
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

  it('states which two artifacts were compared (issue #52)', () => {
    const text = renderReport(sampleReport, 'text');
    expect(text).toContain('my-app v1.2.0');
    expect(text).toContain('my-app v1.3.0');
    expect(text).toContain('cyclonedx 1.4');
    expect(text).toContain('generated 2026-07-01');
    const md = renderReport(sampleReport, 'markdown');
    expect(md).toContain('## Compared');
    expect(md).toContain('| From | my-app v1.2.0');
    expect(md).toContain('| To | my-app v1.3.0');
  });

  it('throws on unsupported format', () => {
    expect(() => renderReport(sampleReport, 'xml' as never)).toThrow();
  });

it('escapes pipes and newlines in markdown cells so the table stays well-formed', () => {
    const report: ChangeReport = {
      from: { format: 'cyclonedx', specVersion: '1.4' },
      to: { format: 'cyclonedx', specVersion: '1.4' },
      added: [{ name: 'evil | pkg', version: '1.0', ecosystem: 'npm' }],
      removed: [],
      upgraded: [],
      licenseChanges: [],
      newCVEs: [{ id: 'CVE-2024-0001', affects: ['pkg:npm/a | b'], severity: 'high', description: 'line1\nline2' }],
      fixedCVEs: [],
      severityEscalations: [],
      hashChanges: [],
      summary: { totalAdded: 1, totalRemoved: 0, totalUpgraded: 0, totalLicenseChanges: 0, totalDowngraded: 0, totalNewCVEs: 1, totalFixedCVEs: 0, totalSeverityEscalations: 0, totalHashChanges: 0 },
    };
    const out = renderReport(report, 'markdown');

    // The pipe in the package name must be escaped, not interpreted as a column break.
    expect(out).toContain('| evil \\| pkg | 1.0 | npm |');
    expect(out).toContain('| CVE-2024-0001 | high | — | pkg:npm/a \\| b |');

    // Every body row under the Added table must keep its column count (4 leading bars: 3 cells).
    const addedRow = out.split('\n').find(l => l.includes('evil'))!;
    expect((addedRow.match(/(?<!\\)\|/g) ?? []).length).toBe(4);
  });

  it('separates downgrades from upgrades in text output', () => {
    const report: ChangeReport = {
      from: { format: 'cyclonedx', specVersion: '1.4' },
      to: { format: 'cyclonedx', specVersion: '1.4' },
      added: [],
      removed: [],
      upgraded: [
        { component: { name: 'lodash', version: '4.17.21' }, from: '4.17.20', to: '4.17.21', isMajorBump: false, isDowngrade: false },
        { component: { name: 'left-pad', version: '1.1.0' }, from: '1.3.0', to: '1.1.0', isMajorBump: false, isDowngrade: true },
      ],
      licenseChanges: [],
      newCVEs: [],
      fixedCVEs: [],
      severityEscalations: [],
      hashChanges: [],
      summary: { totalAdded: 0, totalRemoved: 0, totalUpgraded: 1, totalLicenseChanges: 0, totalDowngraded: 1, totalNewCVEs: 0, totalFixedCVEs: 0, totalSeverityEscalations: 0, totalHashChanges: 0 },
    };
    const out = renderReport(report, 'text');
    expect(out).toContain('Downgraded:  1');
    expect(out).toContain('Downgraded Components:');
    expect(out).toContain('left-pad: 1.3.0 → 1.1.0 [DOWNGRADE]');
    // The downgraded component must not appear in the Upgraded section.
    const upgradedSection = out.slice(out.indexOf('Upgraded Components:'), out.indexOf('Downgraded Components:'));
    expect(upgradedSection).not.toContain('left-pad');
  });

  it('renders a downgrades table in markdown output', () => {
    const report: ChangeReport = {
      from: { format: 'cyclonedx', specVersion: '1.4' },
      to: { format: 'cyclonedx', specVersion: '1.4' },
      added: [],
      removed: [],
      upgraded: [
        { component: { name: 'left-pad', version: '1.1.0' }, from: '1.3.0', to: '1.1.0', isMajorBump: false, isDowngrade: true },
      ],
      licenseChanges: [],
      newCVEs: [],
      fixedCVEs: [],
      severityEscalations: [],
      hashChanges: [],
      summary: { totalAdded: 0, totalRemoved: 0, totalUpgraded: 1, totalLicenseChanges: 0, totalDowngraded: 1, totalNewCVEs: 0, totalFixedCVEs: 0, totalSeverityEscalations: 0, totalHashChanges: 0 },
    };
    const out = renderReport(report, 'markdown');
    expect(out).toContain('Downgraded Components');
    expect(out).toContain('| left-pad | 1.3.0 | 1.1.0 |');
    expect(out).toContain('| Downgraded components | 1 |');
    expect(out).not.toContain('## ⬆️ Upgraded Components');
  });

it('annotates the VEX analysis state on new CVEs in text and markdown', () => {
    const report: ChangeReport = {
      ...sampleReport,
      newCVEs: [
        { id: 'CVE-2024-2000', affects: ['pkg:npm/foo@1.0.0'], severity: 'critical', analysisState: 'not_affected' },
      ],
    };
    expect(renderReport(report, 'text')).toContain('(VEX: not_affected)');
    expect(renderReport(report, 'markdown')).toContain('(VEX: not_affected)');
  });
});
