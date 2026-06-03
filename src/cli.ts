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
import { parseArgs, ArgError } from './args.js';

async function main(): Promise<void> {
  const { oldPath, newPath, format } = parseArgs(process.argv.slice(2));

  const [oldRaw, newRaw] = await Promise.all([
    readFile(oldPath, 'utf-8'),
    readFile(newPath, 'utf-8'),
  ]);

  const oldSBOM = parse(oldRaw);
  const newSBOM = parse(newRaw);
  const report = diff(oldSBOM, newSBOM);

  console.log(renderReport(report, format));
}

main().catch((err) => {
  // Argument errors are user-facing: show a clean message, not a stack trace.
  if (err instanceof ArgError) {
    console.error(err.message);
  } else {
    console.error(err);
  }
  process.exit(1);
});
