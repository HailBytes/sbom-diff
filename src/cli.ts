#!/usr/bin/env node
/**
 * @hailbytes/sbom-diff CLI
 *
 * Usage:
 *   npx @hailbytes/sbom-diff <old.json> <new.json> [--format text|json|markdown]
 */

import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { parse } from './parser.js';
import { diff } from './diff.js';
import { renderReport } from './reporter.js';
import type { ReportFormat } from './types.js';

const VALID_FORMATS: readonly ReportFormat[] = ['text', 'json', 'markdown'];

/**
 * Resolve the requested report format from CLI args.
 *
 * Supports both `--format=json` and `--format json` syntax. Defaults to
 * 'text' when the flag is absent or has no value.
 *
 * @throws if a `--format` value is supplied that is not a supported format.
 */
export function resolveFormat(args: string[]): ReportFormat {
  // `--format=value`
  const inline = args.find(a => a.startsWith('--format='));
  let value: string | undefined;
  if (inline) {
    value = inline.slice('--format='.length);
  } else {
    // `--format value`
    const idx = args.indexOf('--format');
    if (idx !== -1) {
      const next = args[idx + 1];
      if (next !== undefined && !next.startsWith('--')) value = next;
    }
  }

  if (value === undefined || value === '') return 'text';
  if (!VALID_FORMATS.includes(value as ReportFormat)) {
    throw new Error(
      `Unsupported format: ${value}. Valid formats: ${VALID_FORMATS.join(', ')}.`,
    );
  }
  return value as ReportFormat;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  const positional = args.filter(a => !a.startsWith('--'));
  if (positional.length < 2) {
    console.error('Usage: sbom-diff <old.json> <new.json> [--format text|json|markdown]');
    process.exit(1);
  }

  const [oldPath, newPath] = positional;
  const format = resolveFormat(args);

  const [oldRaw, newRaw] = await Promise.all([
    readFile(oldPath, 'utf-8'),
    readFile(newPath, 'utf-8'),
  ]);

  const oldSBOM = parse(oldRaw);
  const newSBOM = parse(newRaw);
  const report = diff(oldSBOM, newSBOM);

  console.log(renderReport(report, format));
}

// Only run when invoked directly (not when imported by tests).
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(err => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  });
}
