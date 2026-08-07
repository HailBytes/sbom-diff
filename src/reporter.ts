import type { ChangeReport, CVEEntry, ReportFormat, SBOMIdentity } from './types.js';

/**
 * Render one SBOM's identity as a compact single-line description, e.g.
 * "my-app v1.4.2 (cyclonedx 1.4, generated 2026-08-01T00:00:00Z)". Falls back
 * to the format alone when the SBOM carries no identity fields.
 */
function describeIdentity(id: SBOMIdentity): string {
  const parts: string[] = [];
  const name = id.name ? `${id.name}${id.version ? ` v${id.version}` : ''}` : '';
  if (name) parts.push(name);
  if (id.specVersion) parts.push(`${id.format} ${id.specVersion}`);
  else if (id.format !== 'unknown') parts.push(id.format);
  if (id.generatedAt) parts.push(`generated ${id.generatedAt}`);
  return parts.length > 0 ? parts.join(' · ') : 'unknown artifact';
}

/**
 * A short parenthetical noting a vulnerability's VEX analysis state, so a
 * suppressed CVE that still appears in the report explains why a CI gate did
 * not fail on it. Empty when the entry carries no analysis state.
 */
function vexNote(v: CVEEntry): string {
  return v.analysisState ? ` (VEX: ${v.analysisState})` : '';
}

/** Join a CVE's affected components into a display string (blast radius). */
function joinAffects(v: CVEEntry): string {
  return (v.affects ?? ['unknown']).join(', ');
}

/**
 * Render a ChangeReport to a human-readable string.
 *
 * Supported formats: 'text' | 'json' | 'markdown'
 */
export function renderReport(report: ChangeReport, format: ReportFormat = 'text'): string {
  switch (format) {
    case 'json': return JSON.stringify(report, null, 2);
    case 'markdown': return renderMarkdown(report);
    case 'text': return renderText(report);
    default: throw new Error(`Unsupported format: ${String(format)}`);
  }
}

function renderText(r: ChangeReport): string {
  const lines: string[] = ['SBOM Diff Report', '=================', ''];

  lines.push(`Compared:`);
  lines.push(`  From: ${describeIdentity(r.from)}`);
  lines.push(`  To:   ${describeIdentity(r.to)}`);
  lines.push('');

  lines.push(`Summary:`);
  lines.push(`  Added:       ${r.summary.totalAdded}`);
  lines.push(`  Removed:     ${r.summary.totalRemoved}`);
  lines.push(`  Upgraded:    ${r.summary.totalUpgraded - r.summary.totalDowngraded}`);
  lines.push(`  Downgraded:  ${r.summary.totalDowngraded}`);
  lines.push(`  Licenses:    ${r.summary.totalLicenseChanges}`);
  lines.push(`  New CVEs:    ${r.summary.totalNewCVEs}`);
  lines.push(`  Fixed CVEs:  ${r.summary.totalFixedCVEs}`);
  lines.push(`  Hash changes: ${r.summary.totalHashChanges}`);
  lines.push('');

  if (r.added.length > 0) {
    lines.push('+ Added Components:');
    for (const c of r.added) lines.push(`  + ${c.name}@${c.version ?? 'unknown'}`);
    lines.push('');
  }
  if (r.removed.length > 0) {
    lines.push('- Removed Components:');
    for (const c of r.removed) lines.push(`  - ${c.name}@${c.version ?? 'unknown'}`);
    lines.push('');
  }
  const upgrades = r.upgraded.filter(u => !u.isDowngrade);
  const downgrades = r.upgraded.filter(u => u.isDowngrade);
  if (upgrades.length > 0) {
    lines.push('\u2191 Upgraded Components:');
    for (const u of upgrades) {
      const major = u.isMajorBump ? ' [MAJOR]' : '';
      lines.push(`  ~ ${u.component.name}: ${u.from} \u2192 ${u.to}${major}`);
    }
    lines.push('');
  }
  if (r.licenseChanges.length > 0) {
    lines.push('\u2696 License Changes:');
    for (const l of r.licenseChanges) {
      lines.push(`  ~ ${l.component.name}: ${l.from} \u2192 ${l.to}`);
    }
    lines.push('');
  }
  if (downgrades.length > 0) {
    lines.push('\u2193 Downgraded Components:');
    for (const u of downgrades) {
      lines.push(`  ~ ${u.component.name}: ${u.from} \u2192 ${u.to} [DOWNGRADE]`);
    }
    lines.push('');
  }
  if (r.newCVEs.length > 0) {
    lines.push('\u26a0 New CVEs:');
    for (const v of r.newCVEs) {
      const score = v.cvssScore !== undefined ? `, CVSS ${v.cvssScore}` : '';
      lines.push(`  ! ${v.id} [${v.severity ?? 'unknown'}${score}]${vexNote(v)} — ${joinAffects(v)}`);
    }
    lines.push('');
  }
  if (r.fixedCVEs.length > 0) {
    lines.push('\u2713 Fixed CVEs:');
    for (const v of r.fixedCVEs) {
      lines.push(`  \u2713 ${v.id} \u2014 ${joinAffects(v)}`);
    }
  }
  if (r.severityEscalations.length > 0) {
    lines.push('\u26a0 Severity Escalations:');
    for (const e of r.severityEscalations) {
      const from = e.fromSeverity ?? 'none';
      const to = e.toSeverity ?? 'none';
      const score = e.toScore !== undefined && e.fromScore !== undefined
        ? ` (CVSS ${e.fromScore} \u2192 ${e.toScore})`
        : '';
      lines.push(`  \u26a0 ${e.cve.id} [${from} \u2192 ${to}${score}] \u2014 ${joinAffects(e.cve)}`);
    }
    lines.push('');
  }
  if (r.hashChanges.length > 0) {
    lines.push('\u26a0 Hash Changes (potential supply-chain tampering):');
    for (const hc of r.hashChanges) {
      lines.push(`  \u26a0 ${hc.component.name}@${hc.component.version} [${hc.algorithm}: ${hc.from} \u2192 ${hc.to}]`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Escape a value for safe interpolation into a Markdown table cell.
 *
 * Component and CVE strings originate from the SBOM under inspection, whose
 * package names, versions, and CVE descriptions are attacker-influenced. A raw
 * `|` adds a phantom column (corrupting the table), and a newline starts a new
 * row (letting crafted input forge or hide entries) — both matter because the
 * README pitches this Markdown output for posting into PR comments. Escape `|`
 * and flatten line breaks so a value always renders as exactly one cell.
 */
function escapeCell(value: string | undefined, fallback = '—'): string {
  if (value === undefined || value === '') return fallback;
  return value.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function renderMarkdown(r: ChangeReport): string {
  const lines: string[] = [
    '# SBOM Diff Report',
    '',
    '## Compared',
    '',
    `| | Artifact |`,
    `|--------|----------|`,
    `| From | ${escapeCell(describeIdentity(r.from))} |`,
    `| To | ${escapeCell(describeIdentity(r.to))} |`,
    '',
    '## Summary',
    '',
    '| Metric | Count |',
    '|--------|-------|',
    `| Added components | ${r.summary.totalAdded} |`,
    `| Removed components | ${r.summary.totalRemoved} |`,
    `| Upgraded components | ${r.summary.totalUpgraded - r.summary.totalDowngraded} |`,
    `| Downgraded components | ${r.summary.totalDowngraded} |`,
    `| License changes | ${r.summary.totalLicenseChanges} |`,
    `| New CVEs | ${r.summary.totalNewCVEs} |`,
    `| Fixed CVEs | ${r.summary.totalFixedCVEs} |`,
    `| Severity escalations | ${r.summary.totalSeverityEscalations} |`,
    `| Hash changes | ${r.summary.totalHashChanges} |`,
    '',
  ];

  if (r.added.length > 0) {
    lines.push('## \u2795 Added Components', '');
    lines.push('| Name | Version | Ecosystem |');
    lines.push('|------|---------|-----------|');
    for (const c of r.added) lines.push(`| ${escapeCell(c.name)} | ${escapeCell(c.version)} | ${escapeCell(c.ecosystem)} |`);
    lines.push('');
  }
  if (r.removed.length > 0) {
    lines.push('## \u2796 Removed Components', '');
    lines.push('| Name | Version |');
    lines.push('|------|---------|');
    for (const c of r.removed) lines.push(`| ${escapeCell(c.name)} | ${escapeCell(c.version)} |`);
    lines.push('');
  }
  const mdUpgrades = r.upgraded.filter(u => !u.isDowngrade);
  const mdDowngrades = r.upgraded.filter(u => u.isDowngrade);
  if (mdUpgrades.length > 0) {
    lines.push('## \u2b06\ufe0f Upgraded Components', '');
    lines.push('| Name | From | To | Major? |');
    lines.push('|------|------|----|--------|');
    for (const u of mdUpgrades) {
      lines.push(`| ${escapeCell(u.component.name)} | ${escapeCell(u.from)} | ${escapeCell(u.to)} | ${u.isMajorBump ? '\u26a0\ufe0f Yes' : 'No'} |`);
    }
    lines.push('');
  }
  if (r.licenseChanges.length > 0) {
    lines.push('## \u2696\ufe0f License Changes', '');
    lines.push('| Component | From | To |');
    lines.push('|-----------|------|----|');
    for (const l of r.licenseChanges) lines.push(`| ${escapeCell(l.component.name)} | ${escapeCell(l.from)} | ${escapeCell(l.to)} |`);
    lines.push('');
  }
  if (mdDowngrades.length > 0) {
    lines.push('## \u2b07\ufe0f Downgraded Components', '');
    lines.push('| Name | From | To |');
    lines.push('|------|------|----|');
    for (const u of mdDowngrades) {
      lines.push(`| ${escapeCell(u.component.name)} | ${escapeCell(u.from)} | ${escapeCell(u.to)} |`);
    }
    lines.push('');
  }
  if (r.newCVEs.length > 0) {
    lines.push('## \ud83d\udea8 New CVEs', '');
lines.push('| CVE ID | Severity | CVSS | Affects |');
    lines.push('|--------|----------|------|---------|');
    for (const v of r.newCVEs) {
      const score = v.cvssScore !== undefined ? String(v.cvssScore) : '—';
      lines.push(`| ${escapeCell(v.id)} | ${escapeCell(v.severity)}${vexNote(v)} | ${escapeCell(score)} | ${escapeCell(joinAffects(v))} |`);
    }
    lines.push('');
  }
  if (r.fixedCVEs.length > 0) {
    lines.push('## \u2705 Fixed CVEs', '');
    lines.push('| CVE ID | Affects |');
    lines.push('|--------|---------|');
    for (const v of r.fixedCVEs) lines.push(`| ${escapeCell(v.id)} | ${escapeCell(joinAffects(v))} |`);
  }
  if (r.severityEscalations.length > 0) {
    lines.push('## \u26a0\ufe0f Severity Escalations', '');
    lines.push('| CVE ID | From | To | CVSS | Affects |');
    lines.push('|--------|------|----|------|---------|');
    for (const e of r.severityEscalations) {
      lines.push(`| ${escapeCell(e.cve.id)} | ${escapeCell(e.fromSeverity ?? 'none')} | ${escapeCell(e.toSeverity ?? 'none')} | ${escapeCell(e.fromScore !== undefined && e.toScore !== undefined ? `${e.fromScore} \u2192 ${e.toScore}` : undefined)} | ${escapeCell(joinAffects(e.cve))} |`);
    }
  }
  if (r.hashChanges.length > 0) {
    lines.push('## \u26a0\ufe0f Hash Changes (supply-chain tampering)', '');
    lines.push('| Component | Version | Algorithm | From | To |');
    lines.push('|-----------|---------|-----------|------|----|');
    for (const hc of r.hashChanges) {
      lines.push(`| ${escapeCell(hc.component.name)} | ${escapeCell(hc.component.version)} | ${escapeCell(hc.algorithm)} | \`${escapeCell(hc.from)}\` | \`${escapeCell(hc.to)}\` |`);
    }
  }

  return lines.join('\n');
}
