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

const VALID_FORMATS: readonly ReportFormat[] = ['text', 'json', 'markdown'];

export const USAGE =
  'Usage: sbom-diff <old.json> <new.json> [--format text|json|markdown]';

/** Parsed CLI arguments. */
export interface CliArgs {
  oldPath: string;
  newPath: string;
  format: ReportFormat;
}

/** Thrown when arguments are invalid; carries a user-facing message. */
export class CliUsageError extends Error {}

/**
 * Parse argv (without the leading `node` and script entries) into structured
 * CLI arguments. Throws {@link CliUsageError} on invalid input.
 */
export function parseArgs(argv: string[]): CliArgs {
  const positional: string[] = [];
  let format: ReportFormat | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--format') {
      // Consume the next token as the value so it is not treated as positional.
      format = argv[++i] as ReportFormat | undefined;
    } else if (arg.startsWith('--format=')) {
      format = arg.slice('--format='.length) as ReportFormat;
    } else if (!arg.startsWith('--')) {
      positional.push(arg);
    }
    // Unknown flags are ignored.
  }

  if (positional.length < 2) {
    throw new CliUsageError(USAGE);
  }
  if (format !== undefined && !VALID_FORMATS.includes(format)) {
    throw new CliUsageError(
      `Invalid format: ${String(format)}. Valid formats: ${VALID_FORMATS.join(', ')}`,
    );
  }

  return { oldPath: positional[0], newPath: positional[1], format: format ?? 'text' };
}

async function main(): Promise<void> {
  let parsed: CliArgs;
  try {
    parsed = parseArgs(process.argv.slice(2));
  } catch (err) {
    if (err instanceof CliUsageError) {
      console.error(err.message);
      process.exit(1);
    }
    throw err;
  }

  const { oldPath, newPath, format } = parsed;

  const [oldRaw, newRaw] = await Promise.all([
    readFile(oldPath, 'utf-8'),
    readFile(newPath, 'utf-8'),
  ]);

  const oldSBOM = parse(oldRaw);
  const newSBOM = parse(newRaw);
  const report = diff(oldSBOM, newSBOM);

  console.log(renderReport(report, format));
}

// Only run when invoked directly, not when imported (e.g. by tests).
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(err => {
    console.error(err);
    process.exit(1);
  });
}
