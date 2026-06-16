import { describe, it, expect } from 'vitest';
import { parseArgs } from '../cli.js';

describe('parseArgs', () => {
  it('defaults to text format when no flag is given', () => {
    const { positional, format } = parseArgs(['old.json', 'new.json']);
    expect(positional).toEqual(['old.json', 'new.json']);
    expect(format).toBe('text');
  });

  it('parses --format=json', () => {
    const { positional, format } = parseArgs(['old.json', 'new.json', '--format=json']);
    expect(positional).toEqual(['old.json', 'new.json']);
    expect(format).toBe('json');
  });

  it('parses space-separated --format markdown', () => {
    const { positional, format } = parseArgs(['old.json', 'new.json', '--format', 'markdown']);
    expect(positional).toEqual(['old.json', 'new.json']);
    expect(format).toBe('markdown');
  });

  it('handles the flag appearing before positional paths', () => {
    const { positional, format } = parseArgs(['--format', 'json', 'old.json', 'new.json']);
    expect(positional).toEqual(['old.json', 'new.json']);
    expect(format).toBe('json');
  });

  it('throws on an unsupported format value', () => {
    expect(() => parseArgs(['old.json', 'new.json', '--format=yaml'])).toThrow(/Invalid --format/);
  });

  it('throws when --format is given without a value', () => {
    expect(() => parseArgs(['old.json', 'new.json', '--format'])).toThrow(/Invalid --format/);
  });

  it('throws on an unknown option', () => {
    expect(() => parseArgs(['old.json', 'new.json', '--bogus'])).toThrow(/Unknown option/);
  });
});
