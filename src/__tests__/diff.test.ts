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

  it('detects version upgrades when purls embed the version', () => {
    // Real CycloneDX/SPDX SBOMs put the version in the purl, so the identity
    // key must ignore it — otherwise a bump reads as add + remove, not upgrade.
    const a = makesbom([{ name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20' }]);
    const b = makesbom([{ name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' }]);
    const report = diff(a, b);
    expect(report.added).toHaveLength(0);
    expect(report.removed).toHaveLength(0);
    expect(report.upgraded).toHaveLength(1);
    expect(report.upgraded[0].from).toBe('4.17.20');
    expect(report.upgraded[0].to).toBe('4.17.21');
  });

  it('matches scoped-package purls across an upgrade', () => {
    // npm scopes encode "@" as "%40"; only the literal "@" delimits the version.
    const a = makesbom([{ name: '@angular/core', version: '15.0.0', purl: 'pkg:npm/%40angular/core@15.0.0' }]);
    const b = makesbom([{ name: '@angular/core', version: '16.1.0', purl: 'pkg:npm/%40angular/core@16.1.0' }]);
    const report = diff(a, b);
    expect(report.upgraded).toHaveLength(1);
    expect(report.upgraded[0].isMajorBump).toBe(true);
  });

  it('does not confuse different packages that share a version bump', () => {
    const a = makesbom([{ name: 'left-pad', version: '1.0.0', purl: 'pkg:npm/left-pad@1.0.0' }]);
    const b = makesbom([{ name: 'right-pad', version: '1.0.0', purl: 'pkg:npm/right-pad@1.0.0' }]);
    const report = diff(a, b);
    expect(report.added).toHaveLength(1);
    expect(report.removed).toHaveLength(1);
    expect(report.upgraded).toHaveLength(0);
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
});
