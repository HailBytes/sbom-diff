import { describe, it, expect } from 'vitest';
import { parse, detectFormat } from '../parser.js';

const cyclonedxFixture = {
  bomFormat: 'CycloneDX',
  specVersion: '1.4',
  metadata: {
    timestamp: '2026-01-01T00:00:00Z',
    component: { name: 'my-app', version: '1.0.0' },
  },
  components: [
    { name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' },
    { name: 'express', version: '4.18.2', purl: 'pkg:npm/express@4.18.2' },
  ],
  vulnerabilities: [
    {
      id: 'CVE-2021-44228',
      affects: [{ ref: 'pkg:npm/log4j@2.14.1' }],
      ratings: [{ severity: 'critical' }],
    },
  ],
};

const spdxFixture = {
  spdxVersion: 'SPDX-2.3',
  name: 'my-service',
  creationInfo: { created: '2026-01-01T00:00:00Z' },
  packages: [
    {
      name: 'requests',
      versionInfo: '2.28.0',
      licenseConcluded: 'Apache-2.0',
      externalRefs: [{ referenceType: 'purl', referenceLocator: 'pkg:pypi/requests@2.28.0' }],
    },
  ],
};

describe('detectFormat', () => {
  it('detects CycloneDX', () => {
    expect(detectFormat(cyclonedxFixture)).toBe('cyclonedx');
  });

  it('detects SPDX', () => {
    expect(detectFormat(spdxFixture)).toBe('spdx');
  });

  it('returns unknown for unrecognized format', () => {
    expect(detectFormat({ random: 'data' })).toBe('unknown');
  });
});

describe('parse (CycloneDX)', () => {
  it('parses components', () => {
    const sbom = parse(cyclonedxFixture);
    expect(sbom.format).toBe('cyclonedx');
    expect(sbom.components).toHaveLength(2);
    expect(sbom.components[0].name).toBe('lodash');
    expect(sbom.components[0].version).toBe('4.17.21');
    expect(sbom.components[0].purl).toBe('pkg:npm/lodash@4.17.21');
    expect(sbom.components[0].ecosystem).toBe('npm');
  });

  it('parses vulnerabilities', () => {
    const sbom = parse(cyclonedxFixture);
    expect(sbom.vulnerabilities).toHaveLength(1);
    expect(sbom.vulnerabilities![0].id).toBe('CVE-2021-44228');
    expect(sbom.vulnerabilities![0].severity).toBe('critical');
  });

  it('parses metadata name and version', () => {
    const sbom = parse(cyclonedxFixture);
    expect(sbom.name).toBe('my-app');
    expect(sbom.version).toBe('1.0.0');
  });
});

describe('parse (SPDX)', () => {
  it('parses packages as components', () => {
    const sbom = parse(spdxFixture);
    expect(sbom.format).toBe('spdx');
    expect(sbom.components).toHaveLength(1);
    expect(sbom.components[0].name).toBe('requests');
    expect(sbom.components[0].version).toBe('2.28.0');
    expect(sbom.components[0].license).toBe('Apache-2.0');
  });
});

describe('parse (JSON string input)', () => {
  it('accepts a JSON string', () => {
    const sbom = parse(JSON.stringify(cyclonedxFixture));
    expect(sbom.components).toHaveLength(2);
  });
});
