import { describe, it, expect } from 'vitest';
import { parseArgs } from '../args.js';

describe('parseArgs', () => {
  it('defaults to text format when --format is omitted', () => {
    const args = parseArgs(['old.json', 'new.json']);
    expect(args).toEqual({ oldPath: 'old.json', newPath: 'new.json', format: 'text' });
  });

  it('parses the spaced form: --format json', () => {
    const args = parseArgs(['old.json', 'new.json', '--format', 'json']);
    expect(args.format).toBe('json');
  });

  it('parses the inline form: --format=markdown', () => {
    const args = parseArgs(['old.json', 'new.json', '--format=markdown']);
    expect(args.format).toBe('markdown');
  });

  it('throws when fewer than two positional args are given', () => {
    expect(() => parseArgs(['only-one.json'])).toThrow(/Usage:/);
  });

  it('throws on an unknown format', () => {
    expect(() => parseArgs(['old.json', 'new.json', '--format', 'xml'])).toThrow(/Invalid format/);
  });
});
