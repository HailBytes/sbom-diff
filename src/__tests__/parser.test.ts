import { describe, it, expect } from 'vitest';
import { parse, detectFormat } from '../parser.js';
import { diff } from '../diff.js';

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

  it('reports the highest severity when a CVE has multiple ratings', () => {
    const sbom = parse({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [],
      vulnerabilities: [
        {
          id: 'CVE-2024-0001',
          affects: [{ ref: 'pkg:npm/foo@1.0.0' }],
          // Lower-severity rating listed first, NVD critical second.
          ratings: [
            { source: { name: 'vendor' }, severity: 'low' },
            { source: { name: 'nvd' }, severity: 'critical' },
          ],
        },
      ],
    });
    expect(sbom.vulnerabilities![0].severity).toBe('critical');
  });

  it('ignores unknown severity strings when selecting the highest', () => {
    const sbom = parse({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [],
      vulnerabilities: [
        {
          id: 'CVE-2024-0002',
          affects: [{ ref: 'pkg:npm/bar@1.0.0' }],
          ratings: [{ severity: 'unknown' }, { severity: 'medium' }],
        },
      ],
    });
    expect(sbom.vulnerabilities![0].severity).toBe('medium');
  });

  it('captures the numeric CVSS score (highest across ratings)', () => {
    const sbom = parse({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [],
      vulnerabilities: [
        {
          id: 'CVE-2024-0003',
          affects: [{ ref: 'pkg:npm/foo@1.0.0' }],
          ratings: [
            { source: { name: 'vendor' }, severity: 'high', score: 7.5 },
            { source: { name: 'nvd' }, severity: 'critical', score: 9.8 },
          ],
        },
      ],
    });
    expect(sbom.vulnerabilities![0].cvssScore).toBe(9.8);
    expect(sbom.vulnerabilities![0].severity).toBe('critical');
  });

  it('derives severity from the CVSS score when no severity string is present', () => {
    const sbom = parse({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [],
      vulnerabilities: [
        {
          id: 'CVE-2024-0004',
          affects: [{ ref: 'pkg:npm/bar@1.0.0' }],
          // A score-only rating, as emitted by some scanners.
          ratings: [{ source: { name: 'nvd' }, score: 9.8 }],
        },
      ],
    });
    expect(sbom.vulnerabilities![0].cvssScore).toBe(9.8);
    expect(sbom.vulnerabilities![0].severity).toBe('critical');
  });

  it('leaves severity and cvssScore undefined when ratings carry neither', () => {
    const sbom = parse({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [],
      vulnerabilities: [
        {
          id: 'CVE-2024-0005',
          affects: [{ ref: 'pkg:npm/baz@1.0.0' }],
          ratings: [{ source: { name: 'nvd' } }],
        },
      ],
    });
    expect(sbom.vulnerabilities![0].cvssScore).toBeUndefined();
    expect(sbom.vulnerabilities![0].severity).toBeUndefined();
  });

  it('parses the VEX analysis state and lowercases it', () => {
    const sbom = parse({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [],
      vulnerabilities: [
        {
          id: 'CVE-2024-1000',
          affects: [{ ref: 'pkg:npm/foo@1.0.0' }],
          ratings: [{ severity: 'critical' }],
          analysis: { state: 'Not_Affected' },
        },
      ],
    });
    expect(sbom.vulnerabilities![0].analysisState).toBe('not_affected');
  });

  it('leaves analysisState undefined when no analysis block is present', () => {
    const sbom = parse(cyclonedxFixture);
    expect(sbom.vulnerabilities![0].analysisState).toBeUndefined();
  });

  it('parses metadata name and version', () => {
    const sbom = parse(cyclonedxFixture);
    expect(sbom.name).toBe('my-app');
    expect(sbom.version).toBe('1.0.0');
  });

  it('flattens nested sub-components (assembly hierarchy)', () => {
    const sbom = parse({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [
        {
          name: 'app',
          version: '1.0.0',
          purl: 'pkg:npm/app@1.0.0',
          components: [
            { name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' },
            {
              name: 'express',
              version: '4.18.2',
              purl: 'pkg:npm/express@4.18.2',
              // A second level of nesting must be picked up as well.
              components: [{ name: 'qs', version: '6.11.0', purl: 'pkg:npm/qs@6.11.0' }],
            },
          ],
        },
      ],
    });
    // Depth-first, parent before children, document order preserved.
    expect(sbom.components.map((c) => c.name)).toEqual(['app', 'lodash', 'express', 'qs']);
    expect(sbom.components.find((c) => c.name === 'qs')?.version).toBe('6.11.0');
  });

  it('extracts a license from a license id or name object', () => {
    const sbom = parse({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [
        { name: 'a', version: '1.0.0', licenses: [{ license: { id: 'MIT' } }] },
        { name: 'b', version: '1.0.0', licenses: [{ license: { name: 'Custom EULA' } }] },
      ],
    });
    expect(sbom.components[0].license).toBe('MIT');
    expect(sbom.components[1].license).toBe('Custom EULA');
  });

  it('extracts a license from an SPDX license expression', () => {
    const sbom = parse({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [
        { name: 'dual', version: '1.0.0', licenses: [{ expression: 'MIT OR Apache-2.0' }] },
      ],
    });
    expect(sbom.components[0].license).toBe('MIT OR Apache-2.0');
  });

  it('derives the version from the purl when the version field is absent', () => {
    const sbom = parse({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [
        // Valid CycloneDX: `version` is optional; the purl carries it.
        { name: 'lodash', purl: 'pkg:npm/lodash@4.17.21' },
        // Scoped npm package: the `%40` is encoded, so the version `@` is the last one.
        { name: 'core', purl: 'pkg:npm/%40angular/core@17.0.0' },
        // Version with qualifiers/subpath must be stripped.
        { name: 'pg', purl: 'pkg:npm/pg@8.11.3?foo=bar#sub' },
      ],
    });
    expect(sbom.components[0].version).toBe('4.17.21');
    expect(sbom.components[1].version).toBe('17.0.0');
    expect(sbom.components[2].version).toBe('8.11.3');
  });

  it('prefers the explicit version field over the purl version', () => {
    const sbom = parse({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [{ name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.20' }],
    });
    expect(sbom.components[0].version).toBe('4.17.21');
  });

  it('leaves version undefined when neither the field nor the purl carries one', () => {
    const sbom = parse({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [{ name: 'foo', purl: 'pkg:npm/foo' }, { name: 'bare' }],
    });
    expect(sbom.components[0].version).toBeUndefined();
    expect(sbom.components[1].version).toBeUndefined();
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

  it('treats NOASSERTION/NONE version and supplier sentinels as undefined', () => {
    const sbom = parse({
      spdxVersion: 'SPDX-2.3',
      name: 'my-service',
      packages: [
        { name: 'internal-lib', versionInfo: 'NOASSERTION', supplier: 'NOASSERTION' },
        { name: 'other-lib', versionInfo: 'NONE', supplier: 'Organization: Acme' },
      ],
    });
    expect(sbom.components[0].version).toBeUndefined();
    expect(sbom.components[0].supplier).toBeUndefined();
    expect(sbom.components[1].version).toBeUndefined();
    expect(sbom.components[1].supplier).toBe('Organization: Acme');
  });

  it('derives the version from the purl externalRef when versionInfo is absent', () => {
    const sbom = parse({
      spdxVersion: 'SPDX-2.3',
      name: 'my-service',
      packages: [
        {
          name: 'requests',
          externalRefs: [{ referenceType: 'purl', referenceLocator: 'pkg:pypi/requests@2.28.0' }],
        },
      ],
    });
    expect(sbom.components[0].version).toBe('2.28.0');
  });

  it('does not report a spurious upgrade when the old version is NOASSERTION', () => {
    const old = parse({
      spdxVersion: 'SPDX-2.3',
      packages: [{ name: 'internal-lib', versionInfo: 'NOASSERTION' }],
    });
    const next = parse({
      spdxVersion: 'SPDX-2.3',
      packages: [{ name: 'internal-lib', versionInfo: '2.0.0' }],
    });
    const report = diff(old, next);
    expect(report.upgraded).toHaveLength(0);
  });

  it('falls back to licenseDeclared when licenseConcluded is NOASSERTION', () => {
    const sbom = parse({
      spdxVersion: 'SPDX-2.3',
      name: 'app',
      packages: [
        { name: 'foo', versionInfo: '1.0.0', licenseConcluded: 'NOASSERTION', licenseDeclared: 'BSD-3-Clause' },
      ],
    });
    expect(sbom.components[0].license).toBe('BSD-3-Clause');
  });

  it('leaves license undefined when both concluded and declared are NOASSERTION', () => {
    const sbom = parse({
      spdxVersion: 'SPDX-2.3',
      name: 'app',
      packages: [
        { name: 'foo', versionInfo: '1.0.0', licenseConcluded: 'NOASSERTION', licenseDeclared: 'NOASSERTION' },
      ],
    });
    expect(sbom.components[0].license).toBeUndefined();
  });

  it('excludes the document subject named via documentDescribes', () => {
    const sbom = parse({
      spdxVersion: 'SPDX-2.3',
      name: 'my-app',
      documentDescribes: ['SPDXRef-Package-my-app'],
      packages: [
        { SPDXID: 'SPDXRef-Package-my-app', name: 'my-app', versionInfo: '1.0.0' },
        { SPDXID: 'SPDXRef-Package-lodash', name: 'lodash', versionInfo: '4.17.21' },
      ],
    });
    expect(sbom.components).toHaveLength(1);
    expect(sbom.components[0].name).toBe('lodash');
  });

  it('excludes the subject named via a DESCRIBES relationship', () => {
    const sbom = parse({
      spdxVersion: 'SPDX-2.3',
      name: 'my-app',
      relationships: [
        {
          spdxElementId: 'SPDXRef-DOCUMENT',
          relationshipType: 'DESCRIBES',
          relatedSpdxElement: 'SPDXRef-Package-my-app',
        },
      ],
      packages: [
        { SPDXID: 'SPDXRef-Package-my-app', name: 'my-app', versionInfo: '1.0.0' },
        { SPDXID: 'SPDXRef-Package-lodash', name: 'lodash', versionInfo: '4.17.21' },
      ],
    });
    expect(sbom.components.map(c => c.name)).toEqual(['lodash']);
  });

  it('keeps every package when the document declares no subject', () => {
    const sbom = parse({
      spdxVersion: 'SPDX-2.3',
      name: 'my-app',
      packages: [
        { SPDXID: 'SPDXRef-Package-my-app', name: 'my-app', versionInfo: '1.0.0' },
        { SPDXID: 'SPDXRef-Package-lodash', name: 'lodash', versionInfo: '4.17.21' },
      ],
    });
    expect(sbom.components).toHaveLength(2);
  });

  it('derives the version from the purl when versionInfo is absent', () => {
    const sbom = parse({
      spdxVersion: 'SPDX-2.3',
      name: 'my-app',
      packages: [
        {
          name: 'requests',
          externalRefs: [{ referenceType: 'purl', referenceLocator: 'pkg:pypi/requests@2.28.0' }],
        },
      ],
    });
    expect(sbom.components[0].version).toBe('2.28.0');
  });
});

describe('parse (JSON string input)', () => {
  it('accepts a JSON string', () => {
    const sbom = parse(JSON.stringify(cyclonedxFixture));
    expect(sbom.components).toHaveLength(2);
  });

  it('strips a leading UTF-8 BOM before parsing', () => {
    // Some SBOM generators / Windows tooling emit BOM-prefixed JSON, which is
    // valid on disk but makes a naive JSON.parse throw "Unexpected token".
    const withBom = '﻿' + JSON.stringify(cyclonedxFixture);
    const sbom = parse(withBom);
    expect(sbom.format).toBe('cyclonedx');
    expect(sbom.components).toHaveLength(2);
  });

  it('only strips a BOM at the very start, not elsewhere', () => {
    // A BOM appearing inside a string value must be preserved verbatim.
    const sbom = parse(
      JSON.stringify({ bomFormat: 'CycloneDX', components: [{ name: 'a﻿b' }] }),
    );
    expect(sbom.components[0].name).toBe('a﻿b');
  });
});

describe('parse (input validation, issue #21)', () => {
  it('throws ParseError on a non-SBOM object (e.g. a package.json)', () => {
    const notAnSbom = JSON.stringify({ name: 'my-app', dependencies: { lodash: '^4.17.21' } });
    expect(() => parse(notAnSbom)).toThrow(/not a recognized SBOM/);
  });

  it('throws ParseError on invalid JSON', () => {
    expect(() => parse('{not json')).toThrow(/not valid JSON/);
  });

  it('throws ParseError on a JSON array', () => {
    expect(() => parse('[1, 2, 3]')).toThrow(/not an SBOM document/);
  });

  it('throws ParseError on null input', () => {
    expect(() => parse('null')).toThrow(/not an SBOM document/);
  });

  it('throws ParseError on an object passed directly (not a string)', () => {
    expect(() => parse({ name: 'my-app', dependencies: {} })).toThrow(/not a recognized SBOM/);
  });

  it('still accepts valid CycloneDX and SPDX documents', () => {
    expect(parse(JSON.stringify(cyclonedxFixture)).format).toBe('cyclonedx');
    expect(parse({ spdxVersion: 'SPDX-2.3', packages: [] }).format).toBe('spdx');
  });
});
