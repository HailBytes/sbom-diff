import type { SBOM, Component, CVEEntry, SBOMFormat } from './types.js';

/**
 * Detect the SBOM format from a parsed JSON object.
 */
export function detectFormat(obj: Record<string, unknown>): SBOMFormat {
  // CycloneDX has a "bomFormat" field
  if (typeof obj.bomFormat === 'string' && obj.bomFormat.toLowerCase() === 'cyclonedx') {
    return 'cyclonedx';
  }
  // SPDX has an "spdxVersion" field
  if (typeof obj.spdxVersion === 'string') {
    return 'spdx';
  }
  return 'unknown';
}

/**
 * Parse a CycloneDX JSON SBOM object into our canonical SBOM type.
 */
export function parseCycloneDX(obj: Record<string, unknown>): SBOM {
  // CycloneDX components form a tree: a component may carry its own nested
  // `components` array (sub-assemblies / bundled dependencies). Flatten the
  // whole tree so nested components are diffed too — otherwise an upgraded or
  // newly tampered nested dependency would be silently invisible.
  const rawComponents = flattenCycloneDXComponents(obj.components);
  const rawVulns = Array.isArray(obj.vulnerabilities) ? obj.vulnerabilities : [];
  const metadata = obj.metadata && typeof obj.metadata === 'object' ? obj.metadata as Record<string, unknown> : {};
  const component = metadata.component && typeof metadata.component === 'object'
    ? metadata.component as Record<string, unknown>
    : {};

  const components: Component[] = rawComponents.map((c: Record<string, unknown>) => ({
    purl: typeof c.purl === 'string' ? c.purl : undefined,
    name: typeof c.name === 'string' ? c.name : 'unknown',
    version: typeof c.version === 'string' ? c.version : undefined,
    license: extractCycloneDXLicense(c),
    ecosystem: extractEcosystemFromPurl(typeof c.purl === 'string' ? c.purl : ''),
    supplier: extractCycloneDXSupplier(c),
  }));

  const vulnerabilities: CVEEntry[] = rawVulns.map((v: Record<string, unknown>) => {
    const { severity, cvssScore } = extractCycloneDXRating(v);
    return {
      id: typeof v.id === 'string' ? v.id : 'UNKNOWN',
      affects: extractCycloneDXAffects(v),
      severity,
      cvssScore,
      description: typeof v.description === 'string' ? v.description : undefined,
    };
  });

  return {
    format: 'cyclonedx',
    specVersion: typeof obj.specVersion === 'string' ? obj.specVersion : undefined,
    name: typeof component.name === 'string' ? component.name : typeof obj.serialNumber === 'string' ? obj.serialNumber : undefined,
    version: typeof component.version === 'string' ? component.version : undefined,
    generatedAt: extractCycloneDXTimestamp(metadata),
    components,
    vulnerabilities,
  };
}

/**
 * Parse an SPDX JSON SBOM object into our canonical SBOM type.
 */
export function parseSPDX(obj: Record<string, unknown>): SBOM {
  const packages = Array.isArray(obj.packages) ? obj.packages : [];

  const components: Component[] = packages.map((pkg: Record<string, unknown>) => ({
    purl: extractSPDXPurl(pkg),
    name: typeof pkg.name === 'string' ? pkg.name : 'unknown',
    version: normalizeSPDXValue(pkg.versionInfo),
    license: typeof pkg.licenseConcluded === 'string' ? pkg.licenseConcluded : undefined,
    ecosystem: extractEcosystemFromPurl(extractSPDXPurl(pkg) ?? ''),
    supplier: normalizeSPDXValue(pkg.supplier),
  }));

  return {
    format: 'spdx',
    specVersion: typeof obj.spdxVersion === 'string' ? obj.spdxVersion : undefined,
    name: typeof obj.name === 'string' ? obj.name : undefined,
    generatedAt: typeof obj.creationInfo === 'object' && obj.creationInfo !== null
      ? (obj.creationInfo as Record<string, unknown>).created as string | undefined
      : undefined,
    components,
    vulnerabilities: [],
  };
}

/**
 * Parse a JSON string or object into an SBOM, auto-detecting format.
 */
export function parse(input: string | Record<string, unknown>): SBOM {
  // Strip a leading UTF-8 byte order mark (U+FEFF) before parsing. Several SBOM
  // generators and Windows text tooling emit BOM-prefixed JSON, which is valid
  // on disk but makes JSON.parse throw a cryptic "Unexpected token" error.
  const obj: Record<string, unknown> =
    typeof input === 'string' ? JSON.parse(input.replace(/^\uFEFF/, '')) : input;
  const format = detectFormat(obj);

  switch (format) {
    case 'cyclonedx': return parseCycloneDX(obj);
    case 'spdx': return parseSPDX(obj);
    default:
      // Best-effort: treat as CycloneDX-like
      return parseCycloneDX(obj);
  }
}

// --- Helpers ---

/**
 * Recursively flatten a CycloneDX `components` array, including any components
 * nested under a parent component's own `components` array. Components are
 * emitted depth-first (parent before its children), preserving document order.
 *
 * JSON input cannot contain reference cycles, so plain recursion terminates.
 */
function flattenCycloneDXComponents(input: unknown): Record<string, unknown>[] {
  if (!Array.isArray(input)) return [];
  const flat: Record<string, unknown>[] = [];
  for (const raw of input) {
    if (!raw || typeof raw !== 'object') continue;
    const comp = raw as Record<string, unknown>;
    flat.push(comp);
    if (Array.isArray(comp.components)) {
      flat.push(...flattenCycloneDXComponents(comp.components));
    }
  }
  return flat;
}

function extractEcosystemFromPurl(purl: string): string | undefined {
  const match = purl.match(/^pkg:([^/]+)\//);
  return match ? match[1] : undefined;
}

function extractCycloneDXLicense(c: Record<string, unknown>): string | undefined {
  const licenses = c.licenses;
  if (!Array.isArray(licenses) || licenses.length === 0) return undefined;
  const first = licenses[0] as Record<string, unknown>;
  const license = first.license as Record<string, unknown> | undefined;
  if (license && typeof license.id === 'string') return license.id;
  if (license && typeof license.name === 'string') return license.name;
  return undefined;
}

function extractCycloneDXSupplier(c: Record<string, unknown>): string | undefined {
  const supplier = c.supplier as Record<string, unknown> | undefined;
  if (!supplier) return undefined;
  return typeof supplier.name === 'string' ? supplier.name : undefined;
}

function extractCycloneDXAffects(v: Record<string, unknown>): string {
  const affects = v.affects;
  if (!Array.isArray(affects) || affects.length === 0) return 'unknown';
  const ref = affects[0] as Record<string, unknown>;
  return typeof ref.ref === 'string' ? ref.ref : 'unknown';
}

/** Severity ordering, lowest to highest, for selecting the most severe rating. */
const SEVERITY_RANK: Record<NonNullable<CVEEntry['severity']>, number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/**
 * Map a numeric CVSS base score to its qualitative severity, per the CVSS v3
 * specification's qualitative rating scale. Used when a rating carries a `score`
 * but no (or an unrecognized) `severity` string — common in output from
 * scanners such as Grype and Trivy.
 */
function cvssScoreToSeverity(score: number): NonNullable<CVEEntry['severity']> {
  if (score <= 0) return 'none';
  if (score < 4) return 'low';
  if (score < 7) return 'medium';
  if (score < 9) return 'high';
  return 'critical';
}

/**
 * Extract the most severe rating from a CycloneDX vulnerability.
 *
 * A CycloneDX vulnerability may carry multiple ratings from different sources
 * (e.g. a vendor advisory and NVD), and their order is not defined by severity,
 * so we surface the highest severity rather than whichever happens to be listed
 * first — under-reporting a critical CVE as low would defeat the tool's purpose.
 *
 * The numeric CVSS `score` is captured (highest across ratings) and, when a
 * rating omits a usable `severity` string, its severity is derived from the
 * score so a score-only rating still contributes to the threshold.
 */
function extractCycloneDXRating(v: Record<string, unknown>): {
  severity: CVEEntry['severity'];
  cvssScore: number | undefined;
} {
  const ratings = v.ratings;
  if (!Array.isArray(ratings) || ratings.length === 0) {
    return { severity: undefined, cvssScore: undefined };
  }
  let severity: CVEEntry['severity'];
  let highestRank = -1;
  let cvssScore: number | undefined;
  for (const raw of ratings) {
    const rating = raw as Record<string, unknown>;

    const score = typeof rating.score === 'number' ? rating.score : undefined;
    if (score !== undefined && (cvssScore === undefined || score > cvssScore)) {
      cvssScore = score;
    }

    const sev = typeof rating.severity === 'string' ? rating.severity.toLowerCase() : undefined;
    let normalized: NonNullable<CVEEntry['severity']> | undefined;
    if (sev === 'critical' || sev === 'high' || sev === 'medium' || sev === 'low' || sev === 'none') {
      normalized = sev;
    } else if (score !== undefined) {
      normalized = cvssScoreToSeverity(score);
    }

    if (normalized && SEVERITY_RANK[normalized] > highestRank) {
      highestRank = SEVERITY_RANK[normalized];
      severity = normalized;
    }
  }
  return { severity, cvssScore };
}

function extractCycloneDXTimestamp(metadata: Record<string, unknown>): string | undefined {
  return typeof metadata.timestamp === 'string' ? metadata.timestamp : undefined;
}

/**
 * Normalize an SPDX string field, treating the spec's `NOASSERTION` and `NONE`
 * sentinels as "no value" (undefined) rather than real data.
 *
 * These sentinels are extremely common in generator output (e.g. `versionInfo:
 * "NOASSERTION"` when a version can't be determined). Storing them verbatim
 * corrupts the diff: a package whose version is "NOASSERTION" in the old SBOM
 * and "2.0.0" in the new one is reported as an upgrade `NOASSERTION → 2.0.0`,
 * which is meaningless. Collapsing the sentinel to undefined lets the diff's
 * "both versions known" guard correctly skip it.
 *
 * (License normalization is handled separately — see PR #32.)
 */
function normalizeSPDXValue(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (trimmed === '' || trimmed === 'NOASSERTION' || trimmed === 'NONE') return undefined;
  return trimmed;
}

function extractSPDXPurl(pkg: Record<string, unknown>): string | undefined {
  const refs = pkg.externalRefs;
  if (!Array.isArray(refs)) return undefined;
  const purlRef = refs.find(
    (r: Record<string, unknown>) => r.referenceType === 'purl'
  ) as Record<string, unknown> | undefined;
  return purlRef ? (typeof purlRef.referenceLocator === 'string' ? purlRef.referenceLocator : undefined) : undefined;
}
