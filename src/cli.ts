#!/usr/bin/env node
/**
 * @hailbytes/sbom-diff CLI
 *
 * Usage:
 *   npx @hailbytes/sbom-diff <old.json> <new.json> [options]
 */

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parse } from './parser.js';
import { diff } from './diff.js';
import { renderReport } from './reporter.js';
import { parseGateConditions, evaluateGate, ALL_GATE_CONDITIONS } from './gate.js';
import type { ReportFormat } from './types.js';

const VALID_FORMATS: ReportFormat[] = ['text', 'json', 'markdown'];

const HELP = `sbom-diff — diff two CycloneDX or SPDX SBOMs

Usage:
  sbom-diff <old.json> <new.json> [options]

Options:
  --format <fmt>      Output format: text | json | markdown   (default: text)
  --fail-on <conds>   Exit non-zero when the diff matches the given,
                      comma-separated condition(s). Use as a CI/CD gate.
                      Conditions: ${ALL_GATE_CONDITIONS.join(', ')}
  -h, --help          Show this help and exit
  -v, --version       Show version and exit

Examples:
  sbom-diff old.json new.json
  sbom-diff old.json new.json --format markdown
  sbom-diff old.json new.json --fail-on critical,major
`;

/** Flags that consume the following token as their value (space-separated form). */
const VALUE_FLAGS = new Set(['--format', '--fail-on']);

function getFlag(args: string[], name: string): string | undefined {
  const eq = args.find(a => a.startsWith(`${name}=`));
  if (eq) return eq.slice(name.length + 1);
  const idx = args.indexOf(name);
  if (idx !== -1 && idx + 1 < args.length) return args[idx + 1];
  return undefined;
}

/** Collect positional arguments, skipping flags and their consumed values. */
function getPositionals(args: string[]): string[] {
  const positionals: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('-')) {
      // Space-separated value flag (e.g. "--format markdown") consumes next token.
      if (VALUE_FLAGS.has(arg) && i + 1 < args.length) i++;
      continue;
    }
    positionals.push(arg);
  }
  return positionals;
}

async function readVersion(): Promise<string> {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(await readFile(join(here, '..', 'package.json'), 'utf-8'));
    return typeof pkg.version === 'string' ? pkg.version : 'unknown';
  } catch {
    return 'unknown';
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes('-h') || args.includes('--help')) {
    console.log(HELP);
    return;
  }
  if (args.includes('-v') || args.includes('--version')) {
    console.log(await readVersion());
    return;
  }

  const positional = getPositionals(args);
  if (positional.length < 2) {
    console.error('Usage: sbom-diff <old.json> <new.json> [--format text|json|markdown] [--fail-on <conditions>]');
    console.error('Run "sbom-diff --help" for details.');
    process.exit(1);
  }

  const [oldPath, newPath] = positional;

  const format = (getFlag(args, '--format') ?? 'text') as ReportFormat;
  if (!VALID_FORMATS.includes(format)) {
    console.error(`Error: unknown --format "${format}". Valid values: ${VALID_FORMATS.join(', ')}.`);
    process.exit(1);
  }

  const failOnRaw = getFlag(args, '--fail-on');
  let gateConditions;
  try {
    gateConditions = failOnRaw != null ? parseGateConditions(failOnRaw) : [];
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
    return;
  }

  const [oldRaw, newRaw] = await Promise.all([
    readFile(oldPath, 'utf-8'),
    readFile(newPath, 'utf-8'),
  ]);

  const oldSBOM = parse(oldRaw);
  const newSBOM = parse(newRaw);
  const report = diff(oldSBOM, newSBOM);

  console.log(renderReport(report, format));

  if (gateConditions.length > 0) {
    const gate = evaluateGate(report, gateConditions);
    if (gate.shouldFail) {
      console.error(`\nGate failed (--fail-on ${failOnRaw}): ${gate.reasons.join('; ')}.`);
      process.exit(1);
    }
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
