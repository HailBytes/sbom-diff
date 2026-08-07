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
    version: typeof c.version === 'string'
      ? c.version
      : extractVersionFromPurl(typeof c.purl === 'string' ? c.purl : ''),
    license: extractCycloneDXLicense(c),
    ecosystem: extractEcosystemFromPurl(typeof c.purl === 'string' ? c.purl : ''),
    supplier: extractCycloneDXSupplier(c),
    scope: extractCycloneDXScope(c),
    hashes: extractCycloneDXHashes(c),
  }));

  const vulnerabilities: CVEEntry[] = rawVulns.map((v: Record<string, unknown>) => {
    const { severity, cvssScore } = extractCycloneDXRating(v);
    return {
      id: typeof v.id === 'string' ? v.id : 'UNKNOWN',
      affects: extractCycloneDXAffects(v),
      severity,
      cvssScore,
      description: typeof v.description === 'string' ? v.description : undefined,
      analysisState: extractCycloneDXAnalysisState(v),
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
  const rootIds = extractSPDXRootIds(obj);

  const components: Component[] = packages
    // Exclude the document's own subject package(s) — the application being
    // described — so a release-to-release diff doesn't report the app itself
    // as a spurious dependency change. This mirrors CycloneDX, where the
    // subject (metadata.component) is already kept out of `components`.
    .filter((pkg: Record<string, unknown>) => {
      const id = typeof pkg.SPDXID === 'string' ? pkg.SPDXID : undefined;
      return !(id !== undefined && rootIds.has(id));
    })
    .map((pkg: Record<string, unknown>) => {
      const purl = extractSPDXPurl(pkg);
      return {
        purl,
        name: typeof pkg.name === 'string' ? pkg.name : 'unknown',
        version: normalizeSPDXValue(pkg.versionInfo) || extractVersionFromPurl(purl ?? ''),
        license: extractSPDXLicense(pkg),
        ecosystem: extractEcosystemFromPurl(purl ?? ''),
        supplier: normalizeSPDXValue(pkg.supplier),
        hashes: extractSPDXChecksums(pkg),
      };
    });

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
 * Thrown when parse() is given input that is not a recognized SBOM document.
 * The message explains what was expected so a wrong-format file (package.json,
 * a truncated export, garbage JSON) fails loudly instead of silently passing
 * a CI gate with "nothing changed".
 */
export class ParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ParseError';
  }
}

/**
 * Parse a JSON string or object into an SBOM, auto-detecting format.
 *
 * Throws ParseError when the input is not a recognized CycloneDX or SPDX
 * document. Silently accepting wrong-format input as an empty SBOM is a
 * false-negative: a corrupt export or a package.json passed by mistake would
 * sail through a CI gate as if nothing changed (issue #21).
 */
export function parse(input: string | Record<string, unknown>): SBOM {
  let obj: unknown;
  if (typeof input === 'string') {
    try {
      // Strip a leading UTF-8 byte order mark (U+FEFF) before parsing. Several
      // SBOM generators and Windows text tooling emit BOM-prefixed JSON, which
      // is valid on disk but makes JSON.parse throw a cryptic "Unexpected
      // token" error.
      obj = JSON.parse(input.replace(/^\uFEFF/, ''));
    } catch (e) {
      throw new ParseError(`input is not valid JSON: ${(e as Error).message}`);
    }
  } else {
    obj = input;
  }

  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new ParseError('input is not an SBOM document: expected a JSON object with bomFormat or spdxVersion');
  }

  const record = obj as Record<string, unknown>;
  const format = detectFormat(record);

  switch (format) {
    case 'cyclonedx': return parseCycloneDX(record);
    case 'spdx': return parseSPDX(record);
    default:
      throw new ParseError(
        'input is not a recognized SBOM: missing CycloneDX "bomFormat" field and SPDX "spdxVersion" field'
      );
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

/**
 * Extract the version from a Package URL (purl).
 *
 * A purl encodes the version after an unescaped `@`, before any `?qualifiers`
 * or `#subpath` (e.g. `pkg:npm/lodash@4.17.21`, `pkg:npm/%40angular/core@17.0.0`).
 * Per the CycloneDX/SPDX specs a component's dedicated version field is optional,
 * so when it is absent the purl is the authoritative source — otherwise reports
 * render `name@unknown` and JSON consumers get `version: undefined` for a package
 * whose version is right there in the purl.
 *
 * Namespace/name segments must percent-encode any literal `@`, so the last `@`
 * is the version separator. Returns undefined when the purl carries no version.
 */
function extractVersionFromPurl(purl: string): string | undefined {
  if (!purl.startsWith('pkg:')) return undefined;
  const at = purl.lastIndexOf('@');
  if (at === -1) return undefined;
  const raw = purl.slice(at + 1).split(/[?#]/)[0];
  if (!raw) return undefined;
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

function extractCycloneDXLicense(c: Record<string, unknown>): string | undefined {
  const licenses = c.licenses;
  if (!Array.isArray(licenses) || licenses.length === 0) return undefined;
  const first = licenses[0] as Record<string, unknown>;
  const license = first.license as Record<string, unknown> | undefined;
  if (license && typeof license.id === 'string') return license.id;
  if (license && typeof license.name === 'string') return license.name;
  // CycloneDX also allows an SPDX license *expression* in place of a license
  // object, e.g. { "expression": "MIT OR Apache-2.0" }. Dual/expression-licensed
  // components are common, so without this branch their license is silently lost.
  if (typeof first.expression === 'string') return first.expression;
  return undefined;
}

function extractSPDXLicense(pkg: Record<string, unknown>): string | undefined {
  // Prefer a concrete concluded license, but many generators leave it as the SPDX
  // sentinel "NOASSERTION" while the real license sits in licenseDeclared. Fall
  // back to the declared license and drop the sentinel so a package with a known
  // license isn't reported as having the meaningless value "NOASSERTION".
  const meaningful = (v: unknown): string | undefined =>
    typeof v === 'string' && v !== 'NOASSERTION' ? v : undefined;
  return meaningful(pkg.licenseConcluded) ?? meaningful(pkg.licenseDeclared);
}

function extractCycloneDXSupplier(c: Record<string, unknown>): string | undefined {
  const supplier = c.supplier;
  if (typeof supplier !== 'object' || supplier === null) return undefined;
  return typeof (supplier as Record<string, unknown>).name === 'string' ? (supplier as Record<string, unknown>).name as string : undefined;
}

/**
 * Extract the CycloneDX component scope ("required" / "optional" / "excluded").
 * Returns undefined when absent, which is the meaning of "no scope" in CDX:
 * scope defaults to "required" when omitted, but we keep it undefined so the
 * reporter can show "default" rather than a misleading explicit value.
 */
function extractCycloneDXScope(c: Record<string, unknown>): 'required' | 'optional' | 'excluded' | undefined {
  const scope = c.scope;
  if (scope === 'required' || scope === 'optional' || scope === 'excluded') return scope;
  return undefined;
}

function extractCycloneDXAffects(v: Record<string, unknown>): string[] {
  const affects = v.affects;
  if (!Array.isArray(affects) || affects.length === 0) return ['unknown'];
  const refs: string[] = [];
  for (const entry of affects) {
    if (typeof entry === 'object' && entry !== null) {
      const ref = (entry as Record<string, unknown>).ref;
      if (typeof ref === 'string') refs.push(ref);
    }
  }
  return refs.length > 0 ? refs : ['unknown'];
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

/**
 * Extract the VEX analysis state from a CycloneDX vulnerability's `analysis.state`.
 * Returned lowercased so downstream comparisons are case-insensitive; undefined
 * when no analysis block is present.
 */
function extractCycloneDXAnalysisState(v: Record<string, unknown>): string | undefined {
  const analysis = v.analysis;
  if (!analysis || typeof analysis !== 'object') return undefined;
  const state = (analysis as Record<string, unknown>).state;
  return typeof state === 'string' ? state.toLowerCase() : undefined;
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

/**
 * Extract CycloneDX component hashes (the `hashes` array of {alg, content}
 * objects) into a `{ algorithm: value }` map. SHA-256 keys are lowercased to
 * the standard form so digests from different generators compare equal.
 */
function extractCycloneDXHashes(c: Record<string, unknown>): Record<string, string> | undefined {
  if (!Array.isArray(c.hashes) || c.hashes.length === 0) return undefined;
  const hashes: Record<string, string> = {};
  for (const h of c.hashes) {
    if (typeof h !== 'object' || h === null) continue;
    const entry = h as Record<string, unknown>;
    if (typeof entry.alg === 'string' && typeof entry.content === 'string') {
      hashes[entry.alg.toLowerCase()] = entry.content.toLowerCase();
    }
  }
  return Object.keys(hashes).length > 0 ? hashes : undefined;
}

/**
 * Extract SPDX package checksums (the `checksums` array of {algorithm,
 * checksumValue} objects) into a `{ algorithm: value }` map, same shape as the
 * CycloneDX extraction so diff() can compare them uniformly.
 */
function extractSPDXChecksums(pkg: Record<string, unknown>): Record<string, string> | undefined {
  if (!Array.isArray(pkg.checksums) || pkg.checksums.length === 0) return undefined;
  const hashes: Record<string, string> = {};
  for (const cs of pkg.checksums) {
    if (typeof cs !== 'object' || cs === null) continue;
    const entry = cs as Record<string, unknown>;
    if (typeof entry.algorithm === 'string' && typeof entry.checksumValue === 'string') {
      hashes[entry.algorithm.toLowerCase()] = entry.checksumValue.toLowerCase();
    }
  }
  return Object.keys(hashes).length > 0 ? hashes : undefined;
}

/**
 * Collect the SPDXIDs of the package(s) the document describes (its subject).
 *
 * SPDX marks the primary/root element two ways, and generators use either:
 *  - the `documentDescribes` shortcut array of SPDXIDs (SPDX 2.2+), and/or
 *  - a `DESCRIBES` relationship from `SPDXRef-DOCUMENT` (or its inverse,
 *    `DESCRIBED_BY` pointing back at the document).
 *
 * Returns an empty set when the document declares no subject, so packages are
 * only ever excluded when the SBOM explicitly identifies them as the root.
 */
function extractSPDXRootIds(obj: Record<string, unknown>): Set<string> {
  const ids = new Set<string>();

  if (Array.isArray(obj.documentDescribes)) {
    for (const id of obj.documentDescribes) {
      if (typeof id === 'string') ids.add(id);
    }
  }

  if (Array.isArray(obj.relationships)) {
    for (const raw of obj.relationships) {
      const rel = raw as Record<string, unknown>;
      if (
        rel.relationshipType === 'DESCRIBES' &&
        rel.spdxElementId === 'SPDXRef-DOCUMENT' &&
        typeof rel.relatedSpdxElement === 'string'
      ) {
        ids.add(rel.relatedSpdxElement);
      } else if (
        rel.relationshipType === 'DESCRIBED_BY' &&
        rel.relatedSpdxElement === 'SPDXRef-DOCUMENT' &&
        typeof rel.spdxElementId === 'string'
      ) {
        ids.add(rel.spdxElementId);
      }
    }
  }

  return ids;
}

function extractSPDXPurl(pkg: Record<string, unknown>): string | undefined {
  const refs = pkg.externalRefs;
  if (!Array.isArray(refs)) return undefined;
  const purlRef = refs.find(
    (r: Record<string, unknown>) => r.referenceType === 'purl'
  ) as Record<string, unknown> | undefined;
  return purlRef ? (typeof purlRef.referenceLocator === 'string' ? purlRef.referenceLocator : undefined) : undefined;
}
