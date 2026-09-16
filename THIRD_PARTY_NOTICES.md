# Third-party notices

## obsidian-drive-on-demand upstream snapshot

This project was initiated after auditing `solutions-real-it-org/obsidian-drive-on-demand` at commit `25f7149789d53672af4b04722d7fedc435cc47ce`.

Upstream licence: MIT License

Copyright (c) 2026 Real-IT (Loïc Bertrand)

The full MIT licence text is retained in [LICENSE](LICENSE). This project is independently maintained and has no operational relationship with Real-IT, its Google OAuth client, callback domains, services, accounts, subscriptions or infrastructure.

## Bundled dependencies in the plugin artefact

The published `main.js` bundles the following libraries so the plugin can run on
mobile without a build step in the vault. Each is MIT licensed, and each
licence notice is reproduced below this table.

| Package | Version in this repository | Licence |
|---|---|---|
| `@noble/ciphers` | 2.4.0 | MIT |
| `@noble/curves` | 2.4.0 | MIT |
| `@noble/hashes` | 2.4.0 | MIT |

```text
The MIT License (MIT)

Copyright (c) 2022 Paul Miller (https://paulmillr.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

These libraries are independent projects and are not affiliated with this one.
To rebuild `main.js` without them, change the crypto dependencies in
`package.json` and re-run `npm run verify`.

