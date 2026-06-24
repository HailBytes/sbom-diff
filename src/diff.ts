import type { SBOM, Component, CVEEntry, ChangeReport, VersionChange, LicenseChange } from './types.js';

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
    added,
    removed,
    upgraded,
    licenseChanges,
    newCVEs,
    fixedCVEs,
    summary: {
      totalAdded: added.length,
      totalRemoved: removed.length,
      totalUpgraded: upgraded.length,
      totalLicenseChanges: licenseChanges.length,
      totalDowngraded: upgraded.filter(u => u.isDowngrade).length,
      totalNewCVEs: newCVEs.length,
      totalFixedCVEs: fixedCVEs.length,
    },
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
 * Returns true if the major version changed (semver-style).
 * Handles versions like "1.2.3", "2.0.0-beta", etc.
 */
function isMajorVersionBump(from: string, to: string): boolean {
  const fromMajor = parseInt(from.replace(/^[^0-9]*/, ''), 10);
  const toMajor = parseInt(to.replace(/^[^0-9]*/, ''), 10);
  if (isNaN(fromMajor) || isNaN(toMajor)) return false;
  return toMajor > fromMajor;
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
