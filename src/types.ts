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
  /** Component version (falls back to the version encoded in the purl when absent) */
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
  /**
   * VEX analysis state, lowercased, from CycloneDX `vulnerabilities[].analysis.state`
   * (e.g. "not_affected", "false_positive", "exploitable", "in_triage",
   * "resolved"). Absent when the SBOM carries no VEX analysis for the entry.
   * States that declare the product is not impacted are treated as gate
   * suppressions — see `isSuppressed` in cli.ts.
   */
  analysisState?: string;
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

/** Version change details for a component whose version changed */
export interface VersionChange {
  component: Component;
  from: string;
  to: string;
  /** true if the semver major version bumped (only meaningful for upgrades) */
  isMajorBump: boolean;
  /** true if the new version is lower than the old one (a rollback / downgrade) */
  isDowngrade: boolean;
}

/** A license change for a component present in both SBOMs (e.g. MIT -> GPL-3.0) */
export interface LicenseChange {
  component: Component;
  /** License declared in the old SBOM */
  from: string;
  /** License declared in the new SBOM */
  to: string;
}

/** A CVE present in both SBOMs whose severity or CVSS score was re-scored */
export interface SeverityEscalation {
  /** The CVE entry as it now appears in the new SBOM */
  cve: CVEEntry;
  /** Severity in the old SBOM (undefined if it had none) */
  fromSeverity?: 'none' | 'low' | 'medium' | 'high' | 'critical';
  /** Severity in the new SBOM (undefined if it had none) */
  toSeverity?: 'none' | 'low' | 'medium' | 'high' | 'critical';
  /** CVSS score in the old SBOM (undefined if it had none) */
  fromScore?: number;
  /** CVSS score in the new SBOM (undefined if it had none) */
  toScore?: number;
}

/**
 * Minimal carried-forward identity of one of the two SBOMs in a diff. Lets the
 * report state which artifacts it was produced from (issue #52).
 */
export interface SBOMIdentity {
  /** Detected format (cyclonedx / spdx / unknown) */
  format: SBOMFormat;
  /** SBOM spec version (e.g. "1.4" for CycloneDX, "SPDX-2.3" for SPDX) */
  specVersion?: string;
  /** Name of the software described by the SBOM */
  name?: string;
  /** Version of the software described by the SBOM */
  version?: string;
  /** When the SBOM was generated */
  generatedAt?: string;
}

/** The full result of diffing two SBOMs */
export interface ChangeReport {
  /**
   * Identity of the "old" (baseline) SBOM that was diffed. Carried through so
   * audit output can state exactly which two artifacts were compared.
   */
  from: SBOMIdentity;
  /** Identity of the "new" (current) SBOM that was diffed. */
  to: SBOMIdentity;
  /** Components in B but not in A */
  added: Component[];
  /** Components in A but not in B */
  removed: Component[];
  /** Components where the version changed */
  upgraded: VersionChange[];
  /** Components present in both SBOMs whose declared license changed */
  licenseChanges: LicenseChange[];
  /** Vulnerabilities in B but not in A */
  newCVEs: CVEEntry[];
  /** Vulnerabilities in A but not in B (fixed) */
  fixedCVEs: CVEEntry[];
  /**
   * CVEs present in both SBOMs whose severity / CVSS score was re-scored
   * between the scans (e.g. medium → critical). Absent from both the
   * newCVEs and fixedCVEs buckets, so without this they'd be invisible.
   */
  severityEscalations: SeverityEscalation[];
  summary: {
    totalAdded: number;
    totalRemoved: number;
    totalUpgraded: number;
    totalLicenseChanges: number;
    /** Subset of `upgraded` whose version moved backwards */
    totalDowngraded: number;
    totalNewCVEs: number;
    totalFixedCVEs: number;
    /** Number of re-scored CVEs (issue #46) */
    totalSeverityEscalations: number;
  };
}

/** Output format for the report */
export type ReportFormat = 'text' | 'json' | 'markdown';
