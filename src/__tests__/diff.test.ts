import { describe, it, expect } from 'vitest';
import { diff } from '../diff.js';
import type { SBOM } from '../types.js';

const makesbom = (components: SBOM['components'], vulnerabilities: SBOM['vulnerabilities'] = []): SBOM => ({
  format: 'cyclonedx',
  name: 'test-app',
  components,
  vulnerabilities,
});

describe('diff', () => {
  it('returns empty report for identical SBOMs', () => {
    const sbom = makesbom([{ name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' }]);
    const report = diff(sbom, sbom);
    expect(report.added).toHaveLength(0);
    expect(report.removed).toHaveLength(0);
    expect(report.upgraded).toHaveLength(0);
    expect(report.newCVEs).toHaveLength(0);
  });

  it('detects added components', () => {
    const a = makesbom([{ name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' }]);
    const b = makesbom([
      { name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' },
      { name: 'express', version: '4.18.2', purl: 'pkg:npm/express@4.18.2' },
    ]);
    const report = diff(a, b);
    expect(report.added).toHaveLength(1);
    expect(report.added[0].name).toBe('express');
    expect(report.summary.totalAdded).toBe(1);
  });

  it('detects removed components', () => {
    const a = makesbom([
      { name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' },
      { name: 'moment', version: '2.29.4', purl: 'pkg:npm/moment@2.29.4' },
    ]);
    const b = makesbom([{ name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' }]);
    const report = diff(a, b);
    expect(report.removed).toHaveLength(1);
    expect(report.removed[0].name).toBe('moment');
  });

  it('detects version upgrades even when purls are present', () => {
    // purls embed the version, so a version bump changes the purl. The diff must
    // still match on the version-independent purl coordinate and report an upgrade
    // rather than a spurious add + remove — this is the tool's headline feature.
    const a = makesbom([{ name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20' }]);
    const b = makesbom([{ name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' }]);
    const report = diff(a, b);
    expect(report.upgraded).toHaveLength(1);
    expect(report.added).toHaveLength(0);
    expect(report.removed).toHaveLength(0);
    expect(report.upgraded[0].from).toBe('4.17.20');
    expect(report.upgraded[0].to).toBe('4.17.21');
  });

  it('matches scoped purls on their coordinate, not the scope "@"', () => {
    // The scope's "@" (@babel) must not be mistaken for the version delimiter.
    const a = makesbom([{ name: '@babel/core', version: '7.20.0', purl: 'pkg:npm/@babel/core@7.20.0' }]);
    const b = makesbom([{ name: '@babel/core', version: '8.0.0', purl: 'pkg:npm/@babel/core@8.0.0' }]);
    const report = diff(a, b);
    expect(report.upgraded).toHaveLength(1);
    expect(report.upgraded[0].isMajorBump).toBe(true);
  });

  it('matches components whose purls carry qualifiers or a subpath', () => {
    const a = makesbom([{ name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20?arch=x64#lib' }]);
    const b = makesbom([{ name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21?arch=x64#lib' }]);
    const report = diff(a, b);
    expect(report.upgraded).toHaveLength(1);
  });

  it('detects version upgrades when matched by name (no purl)', () => {
    const a = makesbom([{ name: 'lodash', version: '4.17.20' }]);
    const b = makesbom([{ name: 'lodash', version: '4.17.21' }]);
    const report = diff(a, b);
    expect(report.upgraded).toHaveLength(1);
    expect(report.upgraded[0].from).toBe('4.17.20');
    expect(report.upgraded[0].to).toBe('4.17.21');
    expect(report.upgraded[0].isMajorBump).toBe(false);
  });

  it('detects major version bump', () => {
    const a = makesbom([{ name: 'react', version: '17.0.2' }]);
    const b = makesbom([{ name: 'react', version: '18.2.0' }]);
    const report = diff(a, b);
    expect(report.upgraded[0].isMajorBump).toBe(true);
  });

  it('flags a version rollback as a downgrade, not an upgrade', () => {
    const a = makesbom([{ name: 'left-pad', version: '1.3.0' }]);
    const b = makesbom([{ name: 'left-pad', version: '1.1.0' }]);
    const report = diff(a, b);
    expect(report.upgraded).toHaveLength(1);
    expect(report.upgraded[0].isDowngrade).toBe(true);
    expect(report.upgraded[0].isMajorBump).toBe(false);
    expect(report.summary.totalDowngraded).toBe(1);
  });

  it('does not flag a forward upgrade as a downgrade', () => {
    const a = makesbom([{ name: 'lodash', version: '4.17.20' }]);
    const b = makesbom([{ name: 'lodash', version: '4.17.21' }]);
    const report = diff(a, b);
    expect(report.upgraded[0].isDowngrade).toBe(false);
    expect(report.summary.totalDowngraded).toBe(0);
  });

  it('never reports a downgrade as a major bump, even across major versions', () => {
    const a = makesbom([{ name: 'react', version: '18.2.0' }]);
    const b = makesbom([{ name: 'react', version: '17.0.2' }]);
    const report = diff(a, b);
    expect(report.upgraded[0].isDowngrade).toBe(true);
    expect(report.upgraded[0].isMajorBump).toBe(false);
  });

  it('flags a 0.x minor bump as breaking (semver initial-development rule)', () => {
    // Under semver's 0.x clause — honoured by npm's caret, Cargo, Composer —
    // a minor bump while major is 0 is a breaking change.
    const a = makesbom([{ name: 'ky', version: '0.1.0' }]);
    const b = makesbom([{ name: 'ky', version: '0.2.0' }]);
    const report = diff(a, b);
    expect(report.upgraded[0].isMajorBump).toBe(true);
  });

  it('does not flag a 0.x patch bump as breaking', () => {
    const a = makesbom([{ name: 'ky', version: '0.2.0' }]);
    const b = makesbom([{ name: 'ky', version: '0.2.1' }]);
    const report = diff(a, b);
    expect(report.upgraded[0].isMajorBump).toBe(false);
  });

  it('flags a 0.x -> 1.x graduation as breaking', () => {
    const a = makesbom([{ name: 'ky', version: '0.9.0' }]);
    const b = makesbom([{ name: 'ky', version: '1.0.0' }]);
    const report = diff(a, b);
    expect(report.upgraded[0].isMajorBump).toBe(true);
  });

  it('detects new CVEs', () => {
    const cve = { id: 'CVE-2021-44228', affects: 'pkg:npm/log4j@2.14.1', severity: 'critical' as const };
    const a = makesbom([]);
    const b = makesbom([], [cve]);
    const report = diff(a, b);
    expect(report.newCVEs).toHaveLength(1);
    expect(report.newCVEs[0].id).toBe('CVE-2021-44228');
  });

  it('detects fixed CVEs', () => {
    const cve = { id: 'CVE-2021-44228', affects: 'pkg:npm/log4j@2.14.1', severity: 'critical' as const };
    const a = makesbom([], [cve]);
    const b = makesbom([]);
    const report = diff(a, b);
    expect(report.fixedCVEs).toHaveLength(1);
  });

  it('detects a license change on a component present in both SBOMs', () => {
    const a = makesbom([{ name: 'chalk', version: '5.3.0', license: 'MIT' }]);
    const b = makesbom([{ name: 'chalk', version: '5.3.0', license: 'GPL-3.0' }]);
    const report = diff(a, b);
    expect(report.licenseChanges).toHaveLength(1);
    expect(report.licenseChanges[0].component.name).toBe('chalk');
    expect(report.licenseChanges[0].from).toBe('MIT');
    expect(report.licenseChanges[0].to).toBe('GPL-3.0');
    expect(report.summary.totalLicenseChanges).toBe(1);
  });

  it('reports a license change even when the version is unchanged', () => {
    const a = makesbom([{ name: 'left-pad', version: '1.3.0', purl: 'pkg:npm/left-pad@1.3.0', license: 'WTFPL' }]);
    const b = makesbom([{ name: 'left-pad', version: '1.3.0', purl: 'pkg:npm/left-pad@1.3.0', license: 'MIT' }]);
    const report = diff(a, b);
    expect(report.upgraded).toHaveLength(0);
    expect(report.licenseChanges).toHaveLength(1);
    expect(report.licenseChanges[0].to).toBe('MIT');
  });

  it('does not report a change when license metadata is only added or dropped', () => {
    const a = makesbom([{ name: 'lodash', version: '4.17.21' }]);
    const b = makesbom([{ name: 'lodash', version: '4.17.21', license: 'MIT' }]);
    expect(diff(a, b).licenseChanges).toHaveLength(0);
    expect(diff(b, a).licenseChanges).toHaveLength(0);
  });

  it('reports no license change for identical licenses', () => {
    const a = makesbom([{ name: 'react', version: '18.2.0', license: 'MIT' }]);
    const b = makesbom([{ name: 'react', version: '18.2.0', license: 'MIT' }]);
    expect(diff(a, b).licenseChanges).toHaveLength(0);
  });
});

describe('diff ordering', () => {
  it('sorts added/removed components by name regardless of input order', () => {
    const a = makesbom([]);
    const b = makesbom([
      { name: 'zod', version: '3.0.0' },
      { name: 'axios', version: '1.0.0' },
      { name: 'lodash', version: '4.0.0' },
    ]);
    const report = diff(a, b);
    expect(report.added.map(c => c.name)).toEqual(['axios', 'lodash', 'zod']);
  });

  it('orders new CVEs by severity (most severe first), then by id', () => {
    const a = makesbom([]);
    const b = makesbom([], [
      { id: 'CVE-2023-0002', affects: 'x', severity: 'low' },
      { id: 'CVE-2023-0003', affects: 'y', severity: 'critical' },
      { id: 'CVE-2023-0001', affects: 'z', severity: 'critical' },
      { id: 'CVE-2023-0004', affects: 'w', severity: 'medium' },
    ]);
    const report = diff(a, b);
    expect(report.newCVEs.map(v => v.id)).toEqual([
      'CVE-2023-0001', // critical (id breaks the tie)
      'CVE-2023-0003', // critical
      'CVE-2023-0004', // medium
      'CVE-2023-0002', // low
    ]);
  });

  it('sorts upgrades with major bumps first', () => {
    const a = makesbom([
      { name: 'patch-pkg', version: '1.0.0' },
      { name: 'major-pkg', version: '1.0.0' },
    ]);
    const b = makesbom([
      { name: 'patch-pkg', version: '1.0.1' },
      { name: 'major-pkg', version: '2.0.0' },
    ]);
    const report = diff(a, b);
    expect(report.upgraded.map(u => u.component.name)).toEqual(['major-pkg', 'patch-pkg']);
    expect(report.upgraded[0].isMajorBump).toBe(true);
  });

  it('produces identical output for the same components in different input order', () => {
    const order1 = makesbom([{ name: 'b', version: '1' }, { name: 'a', version: '1' }]);
    const order2 = makesbom([{ name: 'a', version: '1' }, { name: 'b', version: '1' }]);
    const empty = makesbom([]);
    expect(diff(empty, order1)).toEqual(diff(empty, order2));
  });

  it('detects a CVE whose severity was re-scored between scans (issue #46)', () => {
    const a = makesbom([], [
      { id: 'CVE-2021-44228', affects: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1', severity: 'medium', cvssScore: 6.0 },
      { id: 'CVE-2023-0001', affects: 'pkg:npm/foo@1.0.0', severity: 'high', cvssScore: 8.0 },
    ]);
    const b = makesbom([], [
      { id: 'CVE-2021-44228', affects: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1', severity: 'critical', cvssScore: 10.0 },
      { id: 'CVE-2023-0001', affects: 'pkg:npm/foo@1.0.0', severity: 'low', cvssScore: 3.0 },
    ]);
    const report = diff(a, b);
    // The escalated CVE is in neither newCVEs nor fixedCVEs.
    expect(report.newCVEs).toHaveLength(0);
    expect(report.fixedCVEs).toHaveLength(0);
    // Only the escalation (medium → critical) is flagged; the de-escalation
    // (high → low) is not.
    expect(report.severityEscalations).toHaveLength(1);
    expect(report.severityEscalations[0].cve.id).toBe('CVE-2021-44228');
    expect(report.severityEscalations[0].fromSeverity).toBe('medium');
    expect(report.severityEscalations[0].toSeverity).toBe('critical');
    expect(report.severityEscalations[0].fromScore).toBe(6.0);
    expect(report.severityEscalations[0].toScore).toBe(10.0);
    expect(report.summary.totalSeverityEscalations).toBe(1);
  });

  it('flags a CVSS score rise even when the severity label is unchanged', () => {
    const a = makesbom([], [
      { id: 'CVE-2024-0001', affects: 'pkg:npm/a@1.0.0', severity: 'high', cvssScore: 7.0 },
    ]);
    const b = makesbom([], [
      { id: 'CVE-2024-0001', affects: 'pkg:npm/a@1.0.0', severity: 'high', cvssScore: 9.0 },
    ]);
    const report = diff(a, b);
    expect(report.severityEscalations).toHaveLength(1);
    expect(report.severityEscalations[0].toScore).toBe(9.0);
  });

  it('detects a hash change on an unchanged version (issue #22)', () => {
    const a = makesbom([
      { name: 'event-stream', version: '4.0.1', purl: 'pkg:npm/event-stream@4.0.1', hashes: { sha256: 'aaaa' } },
      { name: 'clean-pkg', version: '1.0.0', purl: 'pkg:npm/clean-pkg@1.0.0', hashes: { sha256: 'bbbb' } },
    ]);
    const b = makesbom([
      // Same version, different digest — the tampering signal.
      { name: 'event-stream', version: '4.0.1', purl: 'pkg:npm/event-stream@4.0.1', hashes: { sha256: 'cccc' } },
      { name: 'clean-pkg', version: '1.0.0', purl: 'pkg:npm/clean-pkg@1.0.0', hashes: { sha256: 'bbbb' } },
    ]);
    const report = diff(a, b);
    expect(report.hashChanges).toHaveLength(1);
    expect(report.hashChanges[0].component.name).toBe('event-stream');
    expect(report.hashChanges[0].algorithm).toBe('sha256');
    expect(report.hashChanges[0].from).toBe('aaaa');
    expect(report.hashChanges[0].to).toBe('cccc');
    expect(report.summary.totalHashChanges).toBe(1);
    // The unchanged component must not appear.
    expect(report.upgraded).toHaveLength(0);
  });

  it('does not report a hash change when the version also changed (already an upgrade)', () => {
    const a = makesbom([
      { name: 'pkg', version: '1.0.0', purl: 'pkg:npm/pkg@1.0.0', hashes: { sha256: 'aaaa' } },
    ]);
    const b = makesbom([
      { name: 'pkg', version: '1.0.1', purl: 'pkg:npm/pkg@1.0.1', hashes: { sha256: 'cccc' } },
    ]);
    const report = diff(a, b);
    expect(report.upgraded).toHaveLength(1);
    expect(report.hashChanges).toHaveLength(0);
  });
});
