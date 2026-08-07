# Contributing

Thanks for your interest in contributing to `@hailbytes/sbom-diff`! 🎉

This package is **published on npm** and under active development. Bug
reports, feature requests, and pull requests are all welcome.

## Ways to contribute

- **Report a bug** — open an [issue](https://github.com/HailBytes/sbom-diff/issues)
  with a minimal SBOM snippet (or the smallest reproduction you can share) and
  the command you ran.
- **Propose a feature** — open an issue describing the use case before sending a
  large PR, so we can agree on the direction.
- **Send a fix** — small, self-contained fixes can go straight to a pull request.

## Development setup

Requires Node.js `>=18` (see the `engines` field in `package.json`).

```bash
git clone https://github.com/HailBytes/sbom-diff.git
cd sbom-diff
npm install
```

## Useful scripts

| Script | What it does |
|--------|--------------|
| `npm test` | Run the Vitest suite once |
| `npm run test:watch` | Run tests in watch mode while developing |
| `npm run test:coverage` | Run tests with a coverage report |
| `npm run lint` | Lint `src` with ESLint |
| `npm run typecheck` | Type-check without emitting (`tsc --noEmit`) |
| `npm run build` | Compile to `dist/` |
| `npm run cli -- old.json new.json` | Run the built CLI locally |

Before opening a PR, please make sure the same checks CI runs all pass locally:

```bash
npm run lint
npm test
npm run build
```

(CI runs lint + test + build on every pull request targeting `main`.)

## Pull request guidelines

1. Fork the repo and create a topic branch off `main`.
2. Keep each PR focused on a single change, and add or update tests for any
   behavior change.
3. Follow the existing [Conventional Commits](https://www.conventionalcommits.org/)
   style used throughout the history, e.g.:
   - `fix(cli): default to text format when --format is omitted`
   - `feat(diff): detect license changes`
   - `docs: clarify programmatic usage example`
4. Make sure `lint`, `test`, and `build` are green before requesting review.

## License

By contributing, you agree that your contributions will be licensed under the
project's [MIT License](LICENSE).
