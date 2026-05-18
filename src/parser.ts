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
  const rawComponents = Array.isArray(obj.components) ? obj.components : [];
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

  const vulnerabilities: CVEEntry[] = rawVulns.map((v: Record<string, unknown>) => ({
    id: typeof v.id === 'string' ? v.id : 'UNKNOWN',
    affects: extractCycloneDXAffects(v),
    severity: extractCycloneDXSeverity(v),
    description: typeof v.description === 'string' ? v.description : undefined,
  }));

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
    version: typeof pkg.versionInfo === 'string' ? pkg.versionInfo : undefined,
    license: typeof pkg.licenseConcluded === 'string' ? pkg.licenseConcluded : undefined,
    ecosystem: extractEcosystemFromPurl(extractSPDXPurl(pkg) ?? ''),
    supplier: typeof pkg.supplier === 'string' ? pkg.supplier : undefined,
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
  const obj: Record<string, unknown> = typeof input === 'string' ? JSON.parse(input) : input;
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

function extractCycloneDXSeverity(v: Record<string, unknown>): CVEEntry['severity'] {
  const ratings = v.ratings;
  if (!Array.isArray(ratings) || ratings.length === 0) return undefined;
  const rating = ratings[0] as Record<string, unknown>;
  const sev = typeof rating.severity === 'string' ? rating.severity.toLowerCase() : undefined;
  if (sev === 'critical' || sev === 'high' || sev === 'medium' || sev === 'low' || sev === 'none') return sev;
  return undefined;
}

function extractCycloneDXTimestamp(metadata: Record<string, unknown>): string | undefined {
  return typeof metadata.timestamp === 'string' ? metadata.timestamp : undefined;
}

function extractSPDXPurl(pkg: Record<string, unknown>): string | undefined {
  const refs = pkg.externalRefs;
  if (!Array.isArray(refs)) return undefined;
  const purlRef = refs.find(
    (r: Record<string, unknown>) => r.referenceType === 'purl'
  ) as Record<string, unknown> | undefined;
  return purlRef ? (typeof purlRef.referenceLocator === 'string' ? purlRef.referenceLocator : undefined) : undefined;
}
