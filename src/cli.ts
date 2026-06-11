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
import { parseArgs } from './args.js';
import type { ReportFormat } from './types.js';

async function main(): Promise<void> {
  let oldPath: string;
  let newPath: string;
  let format: ReportFormat;
  try {
    ({ oldPath, newPath, format } = parseArgs(process.argv.slice(2)));
  } catch (err) {
    console.error((err as Error).message);
    process.exit(1);
  }

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
