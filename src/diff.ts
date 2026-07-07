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
 * Build a version-independent identity key for a component so the same
 * package can be matched across two SBOMs even when its version changed.
 *
 * Real-world CycloneDX/SPDX generators almost always embed the version in the
 * purl (e.g. "pkg:npm/lodash@4.17.21"), so keying on the raw purl would make an
 * upgrade look like a removal plus an addition and hide it from the "upgraded"
 * report entirely. We therefore strip the version — and any qualifiers/subpath,
 * which can also vary between builds — leaving the stable "pkg:type/namespace/name"
 * identity. Components without a purl fall back to their name.
 */
function componentKey(comp: Component): string {
  return comp.purl ? purlIdentity(comp.purl) : comp.name;
}

/**
 * Strip the version (`@...`), qualifiers (`?...`), and subpath (`#...`) from a
 * purl, returning the `pkg:type/namespace/name` portion. In a purl any literal
 * `@` in the name or namespace is percent-encoded (e.g. the npm scope `@angular`
 * becomes `%40angular`), so the first unescaped `@` reliably marks the version.
 */
function purlIdentity(purl: string): string {
  const withoutSubpath = purl.split('#', 1)[0];
  const withoutQualifiers = withoutSubpath.split('?', 1)[0];
  const atIndex = withoutQualifiers.indexOf('@');
  return atIndex === -1 ? withoutQualifiers : withoutQualifiers.slice(0, atIndex);
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
