/**
 * Core domain types for @hailbytes/sbom-diff
 *
 * Supports CycloneDX (JSON/XML) and SPDX (JSON) SBOM formats.
 */

/** Supported SBOM formats */
export type SBOMFormat = 'cyclonedx' | 'spdx' | 'unknown';

/** A single software component in an SBOM */
export interface Component {
  /** Package URL (purl), e.g. "pkg:npm/lodash@4.17.21" */
  purl?: string;
  /** Component name */
  name: string;
  /** Component version */
  version?: string;
  /** SPDX license expression or CycloneDX license */
  license?: string;
  /** Source package ecosystem (npm, pypi, maven, etc.) */
  ecosystem?: string;
  /** Supplier / organization */
  supplier?: string;
  /** Hash values keyed by algorithm (sha256, sha1, md5) */
  hashes?: Record<string, string>;
}

/** A CVE or vulnerability entry associated with a component */
export interface CVEEntry {
  /** CVE ID, e.g. "CVE-2021-44228" */
  id: string;
  /** Affected component purl or name */
  affects: string;
  /** Severity: none, low, medium, high, critical */
  severity?: 'none' | 'low' | 'medium' | 'high' | 'critical';
  /** CVSS score 0.0–10.0 */
  cvssScore?: number;
  /** Short description */
  description?: string;
}

/** A parsed SBOM document */
export interface SBOM {
  /** Detected format */
  format: SBOMFormat;
  /** SBOM spec version (e.g. "1.4" for CycloneDX, "SPDX-2.3" for SPDX) */
  specVersion?: string;
  /** Name of the software described by this SBOM */
  name?: string;
  /** Version of the software described by this SBOM */
  version?: string;
  /** When the SBOM was generated */
  generatedAt?: string;
  /** All components / packages */
  components: Component[];
  /** Known vulnerabilities listed in the SBOM */
  vulnerabilities?: CVEEntry[];
}

/** Version change details for an upgraded component */
export interface VersionChange {
  component: Component;
  from: string;
  to: string;
  /** true if semver major bumped */
  isMajorBump: boolean;
}

/** The full result of diffing two SBOMs */
export interface ChangeReport {
  /** Components in B but not in A */
  added: Component[];
  /** Components in A but not in B */
  removed: Component[];
  /** Components where the version changed */
  upgraded: VersionChange[];
  /** Vulnerabilities in B but not in A */
  newCVEs: CVEEntry[];
  /** Vulnerabilities in A but not in B (fixed) */
  fixedCVEs: CVEEntry[];
  summary: {
    totalAdded: number;
    totalRemoved: number;
    totalUpgraded: number;
    totalNewCVEs: number;
    totalFixedCVEs: number;
  };
}

/** Output format for the report */
export type ReportFormat = 'text' | 'json' | 'markdown';
