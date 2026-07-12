import type { SBOM, Component, CVEEntry, ChangeReport, VersionChange } from './types.js';

/**
 * Compare two parsed SBOMs and produce a ChangeReport.
 *
 * Matching strategy — a component's *identity* is version-independent so that a
 * version bump reads as an upgrade rather than an add + remove:
 * 1. By purl with the version stripped (e.g. "pkg:npm/lodash"), most precise
 * 2. By name (fallback when no purl is present)
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
 * Version-independent identity for a component.
 *
 * A purl normally embeds the version (e.g. "pkg:npm/lodash@4.17.21"), so keying
 * on the raw purl would make every version change look like a separate package
 * being added and removed — the "upgraded" bucket would stay empty for any real
 * SBOM. Strip the version so the same package across two SBOMs shares one key.
 */
function componentKey(comp: Component): string {
  if (comp.purl) return stripPurlVersion(comp.purl);
  return `name:${comp.name}`;
}

/**
 * Remove the "@version" segment from a purl, preserving the type/namespace/name.
 *
 * purl syntax: "pkg:type/namespace/name@version?qualifiers#subpath". The version
 * is delimited by a literal "@"; an "@" inside a name (e.g. an npm scope) is
 * percent-encoded as "%40", so a literal "@" unambiguously begins the version.
 * Qualifiers ("?") and subpath ("#") are dropped first so an "@" there can't be
 * mistaken for the version delimiter.
 */
function stripPurlVersion(purl: string): string {
  const base = purl.split('#')[0].split('?')[0];
  const at = base.indexOf('@', base.indexOf('/'));
  return at === -1 ? base : base.slice(0, at);
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
