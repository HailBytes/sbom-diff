import { describe, it, expect } from 'vitest';
import { parseArgs, ArgError } from '../args.js';

describe('parseArgs', () => {
  it('defaults to text format when --format is omitted', () => {
    // Regression: previously `args.indexOf('--format')` returned -1 and the
    // first positional arg was mis-read as the format, crashing the headline
    // `sbom-diff old.json new.json` command.
    const parsed = parseArgs(['old.json', 'new.json']);
    expect(parsed.oldPath).toBe('old.json');
    expect(parsed.newPath).toBe('new.json');
    expect(parsed.format).toBe('text');
  });

  it('parses --format=value (inline form)', () => {
    expect(parseArgs(['old.json', 'new.json', '--format=json']).format).toBe('json');
  });

  it('parses --format value (space-separated form)', () => {
    expect(parseArgs(['old.json', 'new.json', '--format', 'markdown']).format).toBe('markdown');
  });

  it('accepts the flag before positional arguments', () => {
    const parsed = parseArgs(['--format', 'json', 'old.json', 'new.json']);
    expect(parsed.format).toBe('json');
    expect(parsed.oldPath).toBe('old.json');
    expect(parsed.newPath).toBe('new.json');
  });

  it('throws ArgError when fewer than two files are given', () => {
    expect(() => parseArgs(['old.json'])).toThrow(ArgError);
    expect(() => parseArgs([])).toThrow(ArgError);
  });

  it('throws ArgError on an unsupported format', () => {
    expect(() => parseArgs(['old.json', 'new.json', '--format', 'xml'])).toThrow(ArgError);
    expect(() => parseArgs(['old.json', 'new.json', '--format=xml'])).toThrow(/Invalid format/);
  });
});
