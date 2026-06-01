/**
 * @hailbytes/sbom-diff
 *
 * Diff two CycloneDX or SPDX SBOMs and produce human-readable change reports.
 * Highlights added, removed, upgraded dependencies and new CVEs.
 *
 * @example
 * ```ts
 * import { parse, diff, renderReport } from '@hailbytes/sbom-diff';
 *
 * const oldSBOM = parse(oldJSON);
 * const newSBOM = parse(newJSON);
 * const report = diff(oldSBOM, newSBOM);
 * console.log(renderReport(report, 'markdown'));
 * ```
 */

export { parse, parseCycloneDX, parseSPDX, detectFormat } from './parser.js';
export { diff } from './diff.js';
export { renderReport } from './reporter.js';
export {
  evaluateGate,
  parseGateConditions,
  ALL_GATE_CONDITIONS,
} from './gate.js';
export type { GateCondition, GateResult } from './gate.js';
export type {
  SBOM,
  Component,
  CVEEntry,
  ChangeReport,
  VersionChange,
  SBOMFormat,
  ReportFormat,
} from './types.js';
