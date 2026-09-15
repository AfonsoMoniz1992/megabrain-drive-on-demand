# Development

## Requirements

- Node.js 20+ and npm.
- An Obsidian desktop vault for manual plugin loading.
- No Google credential is needed for unit/build tests.

## Commands

```bash
npm install
npm run check
npm test
npm run build
npm run verify
```

`npm run verify` is the release gate: TypeScript check, Vitest and a minified production build. The resulting `main.js` is intentionally committed/released alongside `manifest.json` and `styles.css`. CI enforces the same triplet/artifact version check.

## Controlled upstream process

The project is a documented derivative of an audited upstream snapshot. Do not auto-merge upstream changes. Review each candidate change in a separate branch, update `UPSTREAM_AUDIT.md`, run the full verification suite, and manually port only the changes that are accepted.

## Local desktop test install

Copy the artifact triplet to:

```text
<vault>/.obsidian/plugins/obsidian-gdrive-streaming/
```

Enable Community Plugins and this plugin. Use only a dedicated harmless Drive test root during development; never point tests at a production knowledge tree.

## Test fixture

Create a dedicated Google Drive folder:

```text
example-test-root/
  notes/a.md
  notes/b.md
  assets/image.jpg
  assets/document.pdf
  nested/level1/level2/c.md
```

Use a dedicated test account/project if possible. The fixture is read/list-only until write/conflict test gates are implemented.
