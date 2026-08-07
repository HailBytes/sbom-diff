import type { SBOM, Component, CVEEntry, ChangeReport, VersionChange, LicenseChange, SBOMIdentity, SeverityEscalation, HashChange } from './types.js';

/**
 * Compare two parsed SBOMs and produce a ChangeReport.
 *
 * Matching strategy:
 * 1. By purl (most precise)
 * 2. By name (fallback)
 */
export function diff(a: SBOM, b: SBOM): ChangeReport {
  const aMap = buildComponentMap(a.components);
  const bMap = buildComponentMap(b.components);

  const added: Component[] = [];
  const removed: Component[] = [];
  const upgraded: VersionChange[] = [];
  const licenseChanges: LicenseChange[] = [];

  // Find added, upgraded, and relicensed
  const hashChanges: HashChange[] = [];
  for (const [key, bComp] of bMap) {
    const aComp = aMap.get(key);
    if (!aComp) {
      added.push(bComp);
      continue;
    }
    if (aComp.version !== bComp.version && aComp.version && bComp.version) {
      const isDowngrade = compareVersions(bComp.version, aComp.version) < 0;
      upgraded.push({
        component: bComp,
        from: aComp.version,
        to: bComp.version,
        // A major bump only makes sense for forward moves; a rollback is never one.
        isMajorBump: !isDowngrade && isMajorVersionBump(aComp.version, bComp.version),
        isDowngrade,
      });
    }
    // A relicensing (e.g. MIT -> GPL-3.0) is a compliance-relevant event even when
    // the version is unchanged. Only surface it when both SBOMs declare a license
    // and they differ — treating newly-added or dropped license metadata as a
    // "change" would produce noise rather than a real relicense signal.
    if (aComp.license && bComp.license && aComp.license !== bComp.license) {
      licenseChanges.push({ component: bComp, from: aComp.license, to: bComp.license });
    }

    // Hash/integrity check: a component whose version is unchanged but whose
    // digest changed is the supply-chain tampering signal (re-published /
    // back-doored artifact under the same name@version). Only compare digests
    // when the version did NOT change — a version bump legitimately changes
    // hashes, and that's already reported as an upgrade.
    if (aComp.version === bComp.version) {
      const aHashes = aComp.hashes ?? {};
      const bHashes = bComp.hashes ?? {};
      for (const [alg, bHash] of Object.entries(bHashes)) {
        const aHash = aHashes[alg];
        if (aHash !== undefined && aHash !== bHash) {
          hashChanges.push({ component: bComp, algorithm: alg, from: aHash, to: bHash });
        }
      }
    }
  }

  // Find removed
  for (const [key, aComp] of aMap) {
    if (!bMap.has(key)) {
      removed.push(aComp);
    }
  }

  // CVE diff
  const aVulns = new Map<string, CVEEntry>((a.vulnerabilities ?? []).map(v => [v.id, v]));
  const bVulns = new Map<string, CVEEntry>((b.vulnerabilities ?? []).map(v => [v.id, v]));

  const newCVEs = [...bVulns.values()].filter(v => !aVulns.has(v.id));
  const fixedCVEs = [...aVulns.values()].filter(v => !bVulns.has(v.id));

  // Severity escalation detection: a CVE present in both SBOMs whose severity
  // or CVSS score was re-scored (e.g. medium → critical). Without this bucket
  // such CVEs fall into neither newCVEs nor fixedCVEs and are invisible.
  const severityEscalations: SeverityEscalation[] = [];
  for (const [id, bVuln] of bVulns) {
    const aVuln = aVulns.get(id);
    if (!aVuln) continue; // already in newCVEs
    const fromSev = aVuln.severity;
    const toSev = bVuln.severity;
    const fromScore = aVuln.cvssScore;
    const toScore = bVuln.cvssScore;
    // Report the escalation when severity rank increased or CVSS score rose.
    // A drop (e.g. critical → high) is a de-escalation and is not flagged.
    if (severityRank(fromSev) < severityRank(toSev) || (fromScore !== undefined && toScore !== undefined && toScore > fromScore)) {
      severityEscalations.push({ cve: bVuln, fromSeverity: fromSev, toSeverity: toSev, fromScore, toScore });
    }
  }

  // Order the report deterministically so it is reproducible regardless of the
  // (arbitrary) order in which the source SBOM listed its components/vulns.
  // Stable output matters for the headline use cases: committed audit trails and
  // PR-comment diffs stay quiet unless something *actually* changed, and the
  // highest-risk findings (critical CVEs, major bumps) surface at the top.
  added.sort(compareComponents);
  removed.sort(compareComponents);
  upgraded.sort(compareVersionChanges);
  newCVEs.sort(compareCVEs);
  fixedCVEs.sort(compareCVEs);

  return {
    from: toIdentity(a),
    to: toIdentity(b),
    added,
    removed,
    upgraded,
    licenseChanges,
    newCVEs,
    fixedCVEs,
    severityEscalations,
    hashChanges,
    summary: {
      totalAdded: added.length,
      totalRemoved: removed.length,
      totalUpgraded: upgraded.length,
      totalLicenseChanges: licenseChanges.length,
      totalDowngraded: upgraded.filter(u => u.isDowngrade).length,
      totalNewCVEs: newCVEs.length,
      totalFixedCVEs: fixedCVEs.length,
      totalSeverityEscalations: severityEscalations.length,
      totalHashChanges: hashChanges.length,
    },
  };
}

/**
 * Map a severity label to an ordinal rank so we can compare them.
 * undefined/none = 0, low = 1, medium = 2, high = 3, critical = 4.
 */
function severityRank(sev: string | undefined): number {
  switch (sev) {
    case 'critical': return 4;
    case 'high': return 3;
    case 'medium': return 2;
    case 'low': return 1;
    default: return 0;
  }
}

/** Carry the parsed SBOM's identity fields forward into a diff report. */
function toIdentity(sbom: SBOM): SBOMIdentity {
  return {
    format: sbom.format,
    specVersion: sbom.specVersion,
    name: sbom.name,
    version: sbom.version,
    generatedAt: sbom.generatedAt,
  };
}

function buildComponentMap(components: Component[]): Map<string, Component> {
  const map = new Map<string, Component>();
  for (const comp of components) {
    map.set(componentKey(comp), comp);
  }
  return map;
}

/**
 * Build a version-independent identity key for a component so the same package
 * at two different versions matches across SBOMs (and is reported as an upgrade
 * rather than an add + remove).
 *
 * A purl embeds the version (`pkg:npm/lodash@4.17.21`), so keying on the raw
 * purl would make every upgrade look like a removal plus an addition — silently
 * breaking the tool's headline "upgraded dependencies" feature for any real SBOM,
 * since real SBOMs almost always carry purls. We therefore key on the purl
 * *coordinate* (the purl with its version stripped), falling back to the name.
 */
function componentKey(comp: Component): string {
  if (comp.purl) {
    const coord = purlCoordinate(comp.purl);
    if (coord) return coord;
  }
  return `name:${comp.name.toLowerCase()}`;
}

/**
 * Strip the version (and any qualifiers/subpath) from a purl, yielding a stable
 * coordinate such as `pkg:npm/lodash` or `pkg:npm/@babel/core`.
 *
 * purl grammar: `pkg:type/namespace.../name@version?qualifiers#subpath`. The
 * version is delimited by the `@` that follows the final path segment, so we
 * drop the subpath and qualifiers first, then cut at the `@` after the last `/`.
 * This leaves scoped names intact (the scope's `@` precedes a `/`).
 */
function purlCoordinate(purl: string): string {
  const base = purl.split('#')[0].split('?')[0];
  const lastSlash = base.lastIndexOf('/');
  const versionAt = base.indexOf('@', lastSlash + 1);
  const coordinate = versionAt === -1 ? base : base.slice(0, versionAt);
  return coordinate.toLowerCase();
}

/**
 * Returns true if an upgrade crosses a breaking-change boundary under semver.
 *
 * For 1.0.0 and above that means the major component increased
 * (e.g. 1.4.0 -> 2.0.0). For 0.x releases semver's "initial development"
 * clause says anything MAY change at any time, and the wider ecosystem
 * (npm's `^0.2.0` caret, Cargo, Composer, ...) treats a *minor* bump as
 * breaking. So while the major is 0, a change in the minor component
 * (e.g. 0.1.0 -> 0.2.0) is also flagged as major/breaking. Without this,
 * breaking upgrades of the many pre-1.0 packages in a typical dependency
 * tree were silently reported as safe.
 *
 * Handles versions like "1.2.3", "2.0.0-beta", "v1.0.0", etc. Downgrades
 * are not treated as bumps here.
 */
function isMajorVersionBump(from: string, to: string): boolean {
  const f = parseVersion(from);
  const t = parseVersion(to);
  if (!f || !t) return false;
  if (t.major !== f.major) return t.major > f.major;
  if (f.major === 0 && t.minor !== f.minor) return t.minor > f.minor;
  return false;
}

/** Parse the leading major.minor out of a version string, tolerating a "v" prefix and pre-release/build suffixes. */
function parseVersion(v: string): { major: number; minor: number } | null {
  const match = v.replace(/^[^0-9]*/, '').match(/^(\d+)(?:\.(\d+))?/);
  if (!match) return null;
  return { major: parseInt(match[1], 10), minor: match[2] ? parseInt(match[2], 10) : 0 };
}

// --- Deterministic ordering ---

/** Severity ordering, highest to lowest, for sorting CVEs by risk. */
const CVE_SEVERITY_ORDER: Record<NonNullable<CVEEntry['severity']>, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  none: 4,
};

/** Sort components by name, then version, for stable add/remove listings. */
function compareComponents(a: Component, b: Component): number {
  return a.name.localeCompare(b.name) || (a.version ?? '').localeCompare(b.version ?? '');
}

/** Sort upgrades with major bumps first (highest risk), then by name. */
function compareVersionChanges(a: VersionChange, b: VersionChange): number {
  if (a.isMajorBump !== b.isMajorBump) return a.isMajorBump ? -1 : 1;
  return compareComponents(a.component, b.component);
}

/** Sort CVEs by severity (most severe first), then by ID for stability. */
function compareCVEs(a: CVEEntry, b: CVEEntry): number {
  const rankA = a.severity ? CVE_SEVERITY_ORDER[a.severity] : 5;
  const rankB = b.severity ? CVE_SEVERITY_ORDER[b.severity] : 5;
  return rankA - rankB || a.id.localeCompare(b.id);
}

/**
 * Compare two version strings segment-by-segment.
 *
 * Returns a negative number if `a < b`, a positive number if `a > b`, and 0 if
 * they compare equal. Any leading non-numeric prefix (e.g. a `v`) is stripped,
 * then the version is split on `.`, `-`, and `+` and compared segment-by-segment:
 * numeric segments numerically, anything else lexicographically. A missing
 * segment counts as `0`, so `1.2` sorts below `1.2.1`.
 *
 * This is intentionally a lightweight comparator (no semver dependency) — enough
 * to tell whether a dependency moved forward or backward, which is all the diff
 * needs to flag a rollback.
 */
function compareVersions(a: string, b: string): number {
  const segments = (v: string): string[] => v.replace(/^[^0-9]*/, '').split(/[.+-]/);
  const as = segments(a);
  const bs = segments(b);
  const len = Math.max(as.length, bs.length);

  for (let i = 0; i < len; i++) {
    const aSeg = as[i] ?? '0';
    const bSeg = bs[i] ?? '0';
    const aNum = Number(aSeg);
    const bNum = Number(bSeg);
    const bothNumeric = aSeg !== '' && bSeg !== '' && !isNaN(aNum) && !isNaN(bNum);

    if (bothNumeric) {
      if (aNum !== bNum) return aNum - bNum;
    } else if (aSeg !== bSeg) {
      return aSeg < bSeg ? -1 : 1;
    }
  }
  return 0;
}
