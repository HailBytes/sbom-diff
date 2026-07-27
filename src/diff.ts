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
 * Derive a version-independent identity key for a component.
 *
 * A purl normally embeds the component's version (e.g. "pkg:npm/lodash@4.17.21"),
 * so keying on the raw purl makes an upgraded dependency look like a removal plus
 * an addition instead of an upgrade — defeating upgrade detection for essentially
 * every real-world SBOM, since generators (syft, cdxgen, Trivy, …) emit versioned
 * purls. Strip the version so the same package across two SBOMs shares a key and
 * version changes surface as upgrades. Falls back to the name when no purl exists.
 */
function componentKey(comp: Component): string {
  return comp.purl ? purlWithoutVersion(comp.purl) : comp.name;
}

/**
 * Strip the `@version` suffix (plus any `?qualifiers` / `#subpath`) from a purl,
 * leaving the version-independent coordinates. Per the purl spec any literal `@`
 * within the name must be percent-encoded, so the last `@` unambiguously marks
 * the version separator.
 */
function purlWithoutVersion(purl: string): string {
  const base = purl.split('#')[0].split('?')[0];
  const at = base.lastIndexOf('@');
  return at > 0 ? base.slice(0, at) : base;
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
