import type { ChangeReport, CVEEntry } from './types.js';

/**
 * A condition that, when met by a {@link ChangeReport}, should cause the CLI
 * to exit with a non-zero status — enabling use as a CI/CD gate.
 *
 * - `any`        — any added, removed, upgraded component or new CVE
 * - `added`      — any added component
 * - `removed`    — any removed component
 * - `upgraded`   — any version upgrade
 * - `major`      — any major version bump
 * - `new-cves`   — any newly introduced CVE
 * - `low` | `medium` | `high` | `critical`
 *                — any new CVE at or above the given severity
 */
export type GateCondition =
  | 'any'
  | 'added'
  | 'removed'
  | 'upgraded'
  | 'major'
  | 'new-cves'
  | 'low'
  | 'medium'
  | 'high'
  | 'critical';

const SEVERITY_CONDITIONS: GateCondition[] = ['low', 'medium', 'high', 'critical'];

const SEVERITY_RANK: Record<NonNullable<CVEEntry['severity']>, number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export const ALL_GATE_CONDITIONS: GateCondition[] = [
  'any',
  'added',
  'removed',
  'upgraded',
  'major',
  'new-cves',
  ...SEVERITY_CONDITIONS,
];

/** The result of evaluating a set of gate conditions against a report. */
export interface GateResult {
  /** Whether the CLI should exit with a non-zero status. */
  shouldFail: boolean;
  /** Human-readable reasons each triggered condition fired. */
  reasons: string[];
}

/**
 * Parse a comma-separated `--fail-on` value into validated conditions.
 *
 * @throws if any token is not a recognized {@link GateCondition}.
 */
export function parseGateConditions(value: string): GateCondition[] {
  const tokens = value
    .split(',')
    .map(t => t.trim().toLowerCase())
    .filter(t => t.length > 0);

  const valid = new Set<string>(ALL_GATE_CONDITIONS);
  const conditions: GateCondition[] = [];
  for (const token of tokens) {
    if (!valid.has(token)) {
      throw new Error(
        `Unknown --fail-on condition: "${token}". ` +
          `Valid values: ${ALL_GATE_CONDITIONS.join(', ')}.`,
      );
    }
    conditions.push(token as GateCondition);
  }
  return conditions;
}

/**
 * Evaluate gate conditions against a {@link ChangeReport}.
 *
 * Pure function: returns whether the run should fail and why, without any
 * side effects. The CLI maps `shouldFail` to a process exit code.
 */
export function evaluateGate(report: ChangeReport, conditions: GateCondition[]): GateResult {
  const reasons: string[] = [];

  for (const condition of conditions) {
    switch (condition) {
      case 'any': {
        const total =
          report.summary.totalAdded +
          report.summary.totalRemoved +
          report.summary.totalUpgraded +
          report.summary.totalNewCVEs;
        if (total > 0) reasons.push(`${total} change(s) detected`);
        break;
      }
      case 'added':
        if (report.summary.totalAdded > 0) {
          reasons.push(`${report.summary.totalAdded} added component(s)`);
        }
        break;
      case 'removed':
        if (report.summary.totalRemoved > 0) {
          reasons.push(`${report.summary.totalRemoved} removed component(s)`);
        }
        break;
      case 'upgraded':
        if (report.summary.totalUpgraded > 0) {
          reasons.push(`${report.summary.totalUpgraded} upgraded component(s)`);
        }
        break;
      case 'major': {
        const majors = report.upgraded.filter(u => u.isMajorBump).length;
        if (majors > 0) reasons.push(`${majors} major version bump(s)`);
        break;
      }
      case 'new-cves':
        if (report.summary.totalNewCVEs > 0) {
          reasons.push(`${report.summary.totalNewCVEs} new CVE(s)`);
        }
        break;
      default: {
        // Severity threshold: fail on any new CVE at or above this level.
        const threshold = SEVERITY_RANK[condition];
        const matches = report.newCVEs.filter(
          v => v.severity != null && SEVERITY_RANK[v.severity] >= threshold,
        );
        if (matches.length > 0) {
          reasons.push(`${matches.length} new CVE(s) at or above ${condition} severity`);
        }
        break;
      }
    }
  }

  return { shouldFail: reasons.length > 0, reasons };
}
