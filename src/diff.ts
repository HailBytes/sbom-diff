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
 * Compute a version-independent identity key for a component.
 *
 * A component's identity must be stable across version changes so that an
 * upgrade (lodash 4.17.20 -> 4.17.21) matches the same key in both SBOMs
 * and is reported as an upgrade rather than a remove + add. Because purls
 * embed the version (e.g. "pkg:npm/lodash@4.17.21"), keying on the raw purl
 * would give every version a distinct key and break upgrade detection —
 * the tool's headline feature. So we strip the "@version" segment while
 * preserving any qualifiers/subpath that follow it.
 */
function componentKey(comp: Component): string {
  if (comp.purl) return purlIdentity(comp.purl);
  // No purl: fall back to ecosystem-qualified name (or bare name).
  return comp.ecosystem ? `${comp.ecosystem}:${comp.name}` : comp.name;
}

/**
 * Strip the version from a purl, keeping the type/namespace/name and any
 * trailing ?qualifiers or #subpath. purl format:
 *   pkg:type/namespace/name@version?qualifiers#subpath
 * The version separator is the first unescaped "@" (scoped npm names encode
 * their leading "@" as "%40", so indexOf finds the version's "@").
 */
function purlIdentity(purl: string): string {
  const atIdx = purl.indexOf('@');
  if (atIdx === -1) return purl;
  const tail = purl.slice(atIdx).match(/[?#].*$/);
  return purl.slice(0, atIdx) + (tail ? tail[0] : '');
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
