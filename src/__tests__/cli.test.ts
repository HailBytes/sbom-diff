import { describe, it, expect } from 'vitest';
import { resolveFormat } from '../cli.js';

describe('resolveFormat', () => {
  it('defaults to text when --format is absent (regression for #5)', () => {
    // Previously `args.indexOf('--format')` returned -1, so args[0] (the old
    // file path) was used as the format and renderReport threw.
    expect(resolveFormat(['old.json', 'new.json'])).toBe('text');
  });

  it('parses `--format json`', () => {
    expect(resolveFormat(['old.json', 'new.json', '--format', 'json'])).toBe('json');
  });

  it('parses `--format=markdown`', () => {
    expect(resolveFormat(['old.json', 'new.json', '--format=markdown'])).toBe('markdown');
  });

  it('defaults to text when --format has no value', () => {
    expect(resolveFormat(['old.json', 'new.json', '--format'])).toBe('text');
  });

  it('throws a helpful error on an unsupported format', () => {
    expect(() => resolveFormat(['old.json', 'new.json', '--format', 'xml'])).toThrow(
      /Unsupported format: xml/,
    );
  });
});
