import type { SBOM, Component, CVEEntry, ChangeReport, VersionChange } from './types.js';

/**
 * Compare two parsed SBOMs and produce a ChangeReport.
 *
 * Matching strategy:
 * 1. By version-agnostic purl (most precise)
 * 2. By name (fallback)
 *
 * The purl is stripped of its version so the same package matches across
 * SBOMs even when its version changes — this is what enables upgrade
 * detection (see {@link componentKey}).
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
    map.set(componentKey(comp), comp);
  }
  return map;
}

/**
 * Build a version-agnostic identity key for a component so the same package
 * matches across SBOMs even when its version changes (enabling upgrade
 * detection). purls embed the version after "@"
 * (e.g. "pkg:npm/lodash@4.17.21"), so we strip everything from the first
 * literal "@" onward. Scoped npm namespaces encode their "@" as "%40", so the
 * first literal "@" is always the version delimiter. Falls back to name when
 * no purl is present.
 */
function componentKey(comp: Component): string {
  if (comp.purl) {
    const at = comp.purl.indexOf('@');
    return at === -1 ? comp.purl : comp.purl.slice(0, at);
  }
  return comp.name;
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
