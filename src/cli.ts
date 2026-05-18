#!/usr/bin/env node
/**
 * @hailbytes/sbom-diff CLI
 *
 * Usage:
 *   npx @hailbytes/sbom-diff <old.json> <new.json> [--format text|json|markdown]
 */

import { readFile } from 'node:fs/promises';
import { parse } from './parser.js';
import { diff } from './diff.js';
import { renderReport } from './reporter.js';
import type { ReportFormat } from './types.js';

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  const positional = args.filter(a => !a.startsWith('--'));
  if (positional.length < 2) {
    console.error('Usage: sbom-diff <old.json> <new.json> [--format text|json|markdown]');
    process.exit(1);
  }

  const [oldPath, newPath] = positional;
  const formatArg = args.find(a => a.startsWith('--format='))?.split('=')[1]
    ?? args[args.indexOf('--format') + 1];
  const format: ReportFormat = (formatArg as ReportFormat) ?? 'text';

  const [oldRaw, newRaw] = await Promise.all([
    readFile(oldPath, 'utf-8'),
    readFile(newPath, 'utf-8'),
  ]);

  const oldSBOM = parse(oldRaw);
  const newSBOM = parse(newRaw);
  const report = diff(oldSBOM, newSBOM);

  console.log(renderReport(report, format));
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
