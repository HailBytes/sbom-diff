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
