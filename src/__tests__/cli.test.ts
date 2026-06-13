import { describe, it, expect } from 'vitest';
import { parseArgs, CliUsageError } from '../cli.js';

describe('parseArgs', () => {
  it('defaults to text format when --format is omitted', () => {
    // Regression: previously this resolved the format to the old-file path,
    // crashing the tool's primary documented invocation.
    const args = parseArgs(['old.json', 'new.json']);
    expect(args).toEqual({ oldPath: 'old.json', newPath: 'new.json', format: 'text' });
  });

  it('parses --format with a separate value token', () => {
    const args = parseArgs(['old.json', 'new.json', '--format', 'json']);
    expect(args.format).toBe('json');
    expect(args.oldPath).toBe('old.json');
    expect(args.newPath).toBe('new.json');
  });

  it('parses --format=value form', () => {
    const args = parseArgs(['old.json', 'new.json', '--format=markdown']);
    expect(args.format).toBe('markdown');
  });

  it('does not treat the --format value as a positional file path', () => {
    const args = parseArgs(['--format', 'markdown', 'old.json', 'new.json']);
    expect(args.oldPath).toBe('old.json');
    expect(args.newPath).toBe('new.json');
    expect(args.format).toBe('markdown');
  });

  it('throws CliUsageError when fewer than two files are given', () => {
    expect(() => parseArgs(['old.json'])).toThrow(CliUsageError);
  });

  it('throws CliUsageError on an unsupported format', () => {
    expect(() => parseArgs(['old.json', 'new.json', '--format', 'xml'])).toThrow(
      /Invalid format: xml/,
    );
  });
});
