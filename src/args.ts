import type { ReportFormat } from './types.js';

/** Report formats the CLI accepts. */
export const VALID_FORMATS: readonly ReportFormat[] = ['text', 'json', 'markdown'];

/** Parsed CLI arguments. */
export interface CliArgs {
  oldPath: string;
  newPath: string;
  format: ReportFormat;
}

const USAGE = 'Usage: sbom-diff <old.json> <new.json> [--format text|json|markdown]';

/**
 * Parse CLI arguments (the slice after `node cli.js`).
 *
 * Supports both `--format=json` and `--format json`. When `--format` is
 * omitted, the format defaults to `text`.
 *
 * Throws an Error with a user-facing message on invalid input.
 */
export function parseArgs(argv: string[]): CliArgs {
  const positional = argv.filter((a) => !a.startsWith('--'));
  if (positional.length < 2) {
    throw new Error(USAGE);
  }
  const [oldPath, newPath] = positional;

  // Support `--format=json` (inline) and `--format json` (spaced).
  const inlineFormat = argv.find((a) => a.startsWith('--format='))?.split('=')[1];
  const flagIndex = argv.indexOf('--format');
  const spacedFormat = flagIndex !== -1 ? argv[flagIndex + 1] : undefined;
  const format = inlineFormat ?? spacedFormat ?? 'text';

  if (!VALID_FORMATS.includes(format as ReportFormat)) {
    throw new Error(
      `Invalid format: "${format}". Valid formats: ${VALID_FORMATS.join(', ')}.`,
    );
  }

  return { oldPath, newPath, format: format as ReportFormat };
}
