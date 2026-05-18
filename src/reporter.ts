import type { ChangeReport, ReportFormat } from './types.js';

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

  lines.push(`Summary:`);
  lines.push(`  Added:       ${r.summary.totalAdded}`);
  lines.push(`  Removed:     ${r.summary.totalRemoved}`);
  lines.push(`  Upgraded:    ${r.summary.totalUpgraded}`);
  lines.push(`  New CVEs:    ${r.summary.totalNewCVEs}`);
  lines.push(`  Fixed CVEs:  ${r.summary.totalFixedCVEs}`);
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
  if (r.upgraded.length > 0) {
    lines.push('\u2191 Upgraded Components:');
    for (const u of r.upgraded) {
      const major = u.isMajorBump ? ' [MAJOR]' : '';
      lines.push(`  ~ ${u.component.name}: ${u.from} \u2192 ${u.to}${major}`);
    }
    lines.push('');
  }
  if (r.newCVEs.length > 0) {
    lines.push('\u26a0 New CVEs:');
    for (const v of r.newCVEs) {
      lines.push(`  ! ${v.id} [${v.severity ?? 'unknown'}] \u2014 ${v.affects}`);
    }
    lines.push('');
  }
  if (r.fixedCVEs.length > 0) {
    lines.push('\u2713 Fixed CVEs:');
    for (const v of r.fixedCVEs) {
      lines.push(`  \u2713 ${v.id} \u2014 ${v.affects}`);
    }
  }

  return lines.join('\n');
}

function renderMarkdown(r: ChangeReport): string {
  const lines: string[] = [
    '# SBOM Diff Report',
    '',
    '## Summary',
    '',
    '| Metric | Count |',
    '|--------|-------|',
    `| Added components | ${r.summary.totalAdded} |`,
    `| Removed components | ${r.summary.totalRemoved} |`,
    `| Upgraded components | ${r.summary.totalUpgraded} |`,
    `| New CVEs | ${r.summary.totalNewCVEs} |`,
    `| Fixed CVEs | ${r.summary.totalFixedCVEs} |`,
    '',
  ];

  if (r.added.length > 0) {
    lines.push('## \u2795 Added Components', '');
    lines.push('| Name | Version | Ecosystem |');
    lines.push('|------|---------|-----------|');
    for (const c of r.added) lines.push(`| ${c.name} | ${c.version ?? '\u2014'} | ${c.ecosystem ?? '\u2014'} |`);
    lines.push('');
  }
  if (r.removed.length > 0) {
    lines.push('## \u2796 Removed Components', '');
    lines.push('| Name | Version |');
    lines.push('|------|---------|');
    for (const c of r.removed) lines.push(`| ${c.name} | ${c.version ?? '\u2014'} |`);
    lines.push('');
  }
  if (r.upgraded.length > 0) {
    lines.push('## \u2b06\ufe0f Upgraded Components', '');
    lines.push('| Name | From | To | Major? |');
    lines.push('|------|------|----|--------|');
    for (const u of r.upgraded) {
      lines.push(`| ${u.component.name} | ${u.from} | ${u.to} | ${u.isMajorBump ? '\u26a0\ufe0f Yes' : 'No'} |`);
    }
    lines.push('');
  }
  if (r.newCVEs.length > 0) {
    lines.push('## \ud83d\udea8 New CVEs', '');
    lines.push('| CVE ID | Severity | Affects |');
    lines.push('|--------|----------|---------|');
    for (const v of r.newCVEs) lines.push(`| ${v.id} | ${v.severity ?? '\u2014'} | ${v.affects} |`);
    lines.push('');
  }
  if (r.fixedCVEs.length > 0) {
    lines.push('## \u2705 Fixed CVEs', '');
    lines.push('| CVE ID | Affects |');
    lines.push('|--------|---------|');
    for (const v of r.fixedCVEs) lines.push(`| ${v.id} | ${v.affects} |`);
  }

  return lines.join('\n');
}
