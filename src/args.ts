import type { ReportFormat } from './types.js';

/** Result of parsing the CLI arguments. */
export interface ParsedArgs {
  oldPath: string;
  newPath: string;
  format: ReportFormat;
}

const SUPPORTED_FORMATS: ReportFormat[] = ['text', 'json', 'markdown'];

/** A user-facing argument error. The CLI turns this into a clean message + non-zero exit. */
export class ArgError extends Error {}

/**
 * Parse the CLI argument vector (everything after `node cli.js`).
 *
 * Supports both `--format json` and `--format=json`, in any position. When
 * `--format` is omitted the report defaults to `text`.
 *
 * @throws {ArgError} when positional args are missing or the format is invalid.
 */
export function parseArgs(argv: string[]): ParsedArgs {
  const positional: string[] = [];
  let format: ReportFormat | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];

    if (arg.startsWith('--format=')) {
      format = validateFormat(arg.slice('--format='.length));
    } else if (arg === '--format') {
      // Consume the next token as the value so it is not mistaken for a file.
      format = validateFormat(argv[++i]);
    } else if (arg.startsWith('--')) {
      throw new ArgError(`Unknown option: ${arg}`);
    } else {
      positional.push(arg);
    }
  }

  if (positional.length < 2) {
    throw new ArgError(
      'Usage: sbom-diff <old.json> <new.json> [--format text|json|markdown]',
    );
  }

  const [oldPath, newPath] = positional;
  return { oldPath, newPath, format: format ?? 'text' };
}

/** Validate a `--format` value, throwing a friendly error for anything unsupported. */
function validateFormat(value: string | undefined): ReportFormat {
  if (value === undefined || value === '') {
    throw new ArgError(
      `Missing value for --format. Supported formats: ${SUPPORTED_FORMATS.join(', ')}.`,
    );
  }
  if (!SUPPORTED_FORMATS.includes(value as ReportFormat)) {
    throw new ArgError(
      `Invalid format: "${value}". Supported formats: ${SUPPORTED_FORMATS.join(', ')}.`,
    );
  }
  return value as ReportFormat;
}
