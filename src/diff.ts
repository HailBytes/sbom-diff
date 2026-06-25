import type { SBOM, Component, CVEEntry, ChangeReport, VersionChange } from './types.js';

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

  // Find added and upgraded
  for (const [key, bComp] of bMap) {
    const aComp = aMap.get(key);
    if (!aComp) {
      added.push(bComp);
    } else if (aComp.version !== bComp.version && aComp.version && bComp.version) {
      upgraded.push({
        component: bComp,
        from: aComp.version,
        to: bComp.version,
        isMajorBump: isMajorVersionBump(aComp.version, bComp.version),
      });
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
    newCVEs,
    fixedCVEs,
    summary: {
      totalAdded: added.length,
      totalRemoved: removed.length,
      totalUpgraded: upgraded.length,
      totalNewCVEs: newCVEs.length,
      totalFixedCVEs: fixedCVEs.length,
    },
  };
}

function buildComponentMap(components: Component[]): Map<string, Component> {
  const map = new Map<string, Component>();
  for (const comp of components) {
    // Prefer purl as key, fall back to name
    const key = comp.purl ?? comp.name;
    map.set(key, comp);
  }
  return map;
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
