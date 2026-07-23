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
 * Derive a version-independent identity key for a component so the same package
 * at two different versions maps to the same key (which is what makes upgrade
 * detection work).
 *
 * Real-world purls embed the version — e.g. "pkg:npm/lodash@4.17.21" — so keying
 * on the raw purl would give the old and new versions different keys, making
 * every upgrade look like a removal plus an addition. We strip the version
 * segment while preserving type, namespace, name, qualifiers, and subpath.
 * Components without a purl fall back to matching by name.
 */
export function componentKey(comp: Component): string {
  if (!comp.purl) return `name:${comp.name}`;
  return stripPurlVersion(comp.purl);
}

/**
 * Remove the version from a Package URL, keeping everything else intact.
 *
 * purl layout: scheme:type/namespace/name@version?qualifiers#subpath
 * The version is introduced by the last '@' before any '?' or '#'. Using the
 * last '@' keeps unencoded scoped-npm purls like "pkg:npm/@angular/core@12.0.0"
 * correct — only "@12.0.0" is stripped, not the "@angular" scope.
 */
function stripPurlVersion(purl: string): string {
  const subpathIdx = purl.indexOf('#');
  const subpath = subpathIdx >= 0 ? purl.slice(subpathIdx) : '';
  const withoutSubpath = subpathIdx >= 0 ? purl.slice(0, subpathIdx) : purl;

  const qualIdx = withoutSubpath.indexOf('?');
  const qualifiers = qualIdx >= 0 ? withoutSubpath.slice(qualIdx) : '';
  const coord = qualIdx >= 0 ? withoutSubpath.slice(0, qualIdx) : withoutSubpath;

  const versionless = coord.replace(/@[^@]*$/, '');
  return versionless + qualifiers + subpath;
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
