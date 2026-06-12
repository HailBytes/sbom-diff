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

const USAGE = 'Usage: sbom-diff <old.json> <new.json> [--format text|json|markdown]';
const VALID_FORMATS: ReportFormat[] = ['text', 'json', 'markdown'];

export interface ParsedArgs {
  positional: string[];
  format: ReportFormat;
}

/**
 * Parse CLI arguments into positional paths and the requested output format.
 *
 * Supports `--format text`, `--format=text`, and flags appearing in any
 * position relative to the positional file paths. Defaults to `text`.
 *
 * @throws if an unknown flag or unsupported format value is supplied.
 */
export function parseArgs(argv: string[]): ParsedArgs {
  const positional: string[] = [];
  let format: ReportFormat = 'text';

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--format') {
      format = assertFormat(argv[++i]);
    } else if (arg.startsWith('--format=')) {
      format = assertFormat(arg.slice('--format='.length));
    } else if (arg.startsWith('-')) {
      throw new Error(`Unknown option: ${arg}\n${USAGE}`);
    } else {
      positional.push(arg);
    }
  }

  return { positional, format };
}

function assertFormat(value: string | undefined): ReportFormat {
  if (value !== undefined && (VALID_FORMATS as string[]).includes(value)) {
    return value as ReportFormat;
  }
  throw new Error(
    `Invalid --format value: ${value ?? '(none)'}. Expected one of: ${VALID_FORMATS.join(', ')}`,
  );
}

async function main(): Promise<void> {
  const { positional, format } = parseArgs(process.argv.slice(2));

  if (positional.length < 2) {
    console.error(USAGE);
    process.exit(1);
  }

  const [oldPath, newPath] = positional;

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
const invokedPath = process.argv[1];
if (invokedPath && import.meta.url === pathToFileURL(invokedPath).href) {
  main().catch(err => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  });
}
