# gitaalekhyapaul-vuln-app

- Repository: <https://github.com/gitaalekhyapaul/vuln-app>
- Commit: `0ddf9bdc9672cc53ebd66cb829382bd702a98876`
- Ecosystem / language: npm / TypeScript (compiled to `build/` by `tsc`)
- Why this repository: the README documents CVE-2017-5941 in node-serialize, and
  `api/app.ts` calls `unserialize` on the request body. It adds what case 1 lacks:
  a lockfile (yarn.lock v1), vulnerable transitive packages (qs, path-to-regexp,
  minimatch), TypeScript source, and a dependency (ejs) that is used without being
  imported.

## How each input was produced

| File | Produced by | Command / branch / commit of SBOMber used |
|---|---|---|
| canonical-scan.json | Component 1 | pending: no command on main writes it yet |
| usage-graph.json | Component 2 | pending: `sbomber usage` (feature/s5-10-usage-cli, not merged) |
| localisation.json | Component 3 (`sbomber localise`) | pending |

The three files are committed exactly as produced. Do not edit them by hand;
if one is wrong, regenerate it and record the new command here.

## Labelling notes

Labels were written from the application source and dependency package source
before any SBOMber command was run on this repository. They are keyed below by
package and advisory; `findingId`s are mapped once canonical-scan.json exists.
Any finding in the scan that is not listed here is labelled by the same method
and listed under "Added after the scan listing".

What ships: `tsconfig.json` has `rootDir ./api`, `include ["api"]`,
`exclude ["exploit-poc"]`; `package.json` has `main ./build/app.js`. Application
code is therefore `api/app.ts` (with `api/views/index.ejs`). `exploit-poc/` is
attacker tooling that does not ship (rule 5). Line numbers below are in
`api/app.ts`, the source of `build/app.js`.

Locked versions (yarn.lock): node-serialize 0.0.4, ejs 3.1.6, express 4.17.1,
body-parser 1.19.0, qs 6.7.0, path-to-regexp 0.1.7, cookie 0.4.0, send 0.17.1,
serve-static 1.14.1, jake 10.8.2, minimatch 3.0.4, brace-expansion 1.1.11,
tsc-watch 4.4.0, cross-spawn 7.0.3, strip-ansi 6.0.0, ansi-regex 5.0.0.

### Searches (run from the repository root at the pinned commit)

| # | Command | Result |
|---|---|---|
| S1 | `grep -rnE "^import\|require\(" api exploit-poc` | api/app.ts:1 express, :2 dotenv, :3 path, :4 `{ unserialize } from "node-serialize"`; exploit-poc requires node-serialize (`serialize` only), net, child_process |
| S2 | `grep -rnE "unserialize\|serialize" api exploit-poc` | api/app.ts:22 `unserialize(payload)`; exploit-poc calls only `serialize` |
| S3 | `grep -rnE "app\.(set\|use\|get\|post\|put\|delete\|all)\(\|express\.[a-z]+\(" api` | :9 `app.set("view engine", "ejs")`, :10 views, :11 `app.use(express.json())`, routes `"/"` :13, `"/api/v1/uppercase"` :17, `"*"` :29, error handler :35 |
| S4 | `grep -rnE "\.(render\|redirect\|location\|cookie\|clearCookie\|sendFile\|download)\(\|express\.static\|urlencoded\|limit\|query parser\|comma" api` | only :14 `res.render("index", { result: null })` |
| S5 | `grep -rn "stringify" api` | only client-side `JSON.stringify` in api/views/index.ejs:52, :58 |

### Dependency-side checks (tarballs from registry.npmjs.org)

| # | Command | Result |
|---|---|---|
| D1 | `grep -n "require(" ejs@3.1.6/lib/ejs.js; grep -rln jake ejs@3.1.6/bin ejs@3.1.6/lib` | ejs runtime requires only fs, path, ./utils (47-49); jake is used only by bin/cli.js |
| D2 | `grep -n "view options\|shallowCopyFromList(opts, data\|exports.__express" ejs@3.1.6/lib/ejs.js` | `__express` is `renderFile` (914); `renderFile` copies `data.settings['view options']` and data into options (473-481) |
| D3 | `grep -n "'query parser', 'extended'\|query(this.get('query parser fn'))" express@4.17.1/lib/application.js` | default query parser is `extended` (77); query middleware mounted on the router (144) |
| D4 | `sed -n 291,295p express@4.17.1/lib/utils.js` | `parseExtendedQueryString` calls `qs.parse(str, { allowPrototypes: true })` |
| D5 | `grep -rn "stringify" express@4.17.1/lib \| grep -v "JSON\|function stringify\|= stringify("` | no matches: express does not call `qs.stringify` |
| D6 | `grep -n "cookie.serialize\|send(req" express@4.17.1/lib/response.js` | `send` only in sendFile/download paths (430, 499); `cookie.serialize` only in `res.cookie` (857) |
| D7 | yarn.lock parents of minimatch, brace-expansion, cross-spawn, strip-ansi, jake, filelist | jake <- ejs; filelist <- jake; minimatch <- jake, filelist; brace-expansion <- minimatch; cross-spawn, strip-ansi <- tsc-watch (devDependency); ansi-regex <- strip-ansi |

### Worksheet

| Package | Advisory | Symbols / trigger the advisory names | Label | Evidence / reasoning |
|---|---|---|---|---|
| node-serialize 0.0.4 | GHSA-q4v7-4rhw-9hqm / CVE-2017-5941 | unserialize | genuine_usage | api/app.ts:22 `unserialize(payload)`, payload decoded from `req.body.payload` at :20 in the POST /api/v1/uppercase handler; the repository README names this CVE |
| ejs 3.1.6 | GHSA-phwq-j96m-2c2q / CVE-2022-29078 | renderFile options taken from data (`settings['view options']`, `outputFunctionName`) | genuine_usage (rule 8) | ejs is not imported; api/app.ts:9 sets it as the view engine and :14 calls `res.render`, which runs `ejs.renderFile` (D2: 914) and its option copy from data (473-481). The data passed is constant (`{ result: null }`); rule 8 labels by the executed path, not input control |
| ejs 3.1.6 | GHSA-ghr5-ch3p-vcr6 / CVE-2024-33883 | missing pollution protection in render options | genuine_usage (rule 8) | same path as above: :9, :14 -> `renderFile` |
| qs 6.7.0 (via express) | GHSA-hrpp-h998-j3pp / CVE-2022-24999 | qs.parse (`__proto__` key) | genuine_usage (rule 8) | the app never sets `query parser` (S4), so express's default `extended` parser (D3: 77, 144) runs `qs.parse(str, { allowPrototypes: true })` (D4) on the query string of every request to the app (routes :13, :17, :29) |
| qs 6.7.0 (via express) | GHSA-6rw7-vpxm-498p / CVE-2025-15284 | qs.parse bracket notation bypasses `arrayLimit` | genuine_usage (rule 8) | same `qs.parse` call (D3, D4) with the default `arrayLimit`; the advisory notes the default `parameterLimit` (1000) bounds the practical effect. Recorded; the label is about the executed path |
| qs 6.7.0 (via express) | GHSA-w7fw-mjwx-w883 / CVE-2026-2391 | qs.parse with `comma: true` | no_genuine_usage (rule 8) | express passes only `allowPrototypes: true` (D4); `comma` is not set by express or the app (S4) |
| qs 6.7.0 (via express) | GHSA-4mjr-xmp4-gh2g / CVE-2026-82417 | qs.parse with `allowPrototypes`/`plainObjects`, then qs.stringify on the result | no_genuine_usage (rule 8) | the parse half is present (D4), but neither the app (S5) nor express (D5) calls `qs.stringify`, which the trigger requires |
| path-to-regexp 0.1.7 (via express) | GHSA-9wv6-86v2-598j / CVE-2024-45296 | two or more parameters in one path segment | no_genuine_usage (rule 8) | routes are `"/"`, `"/api/v1/uppercase"`, `"*"` (S3): express compiles them, but none has a parameter |
| path-to-regexp 0.1.7 (via express) | GHSA-rhx6-c78j-4q9w / CVE-2024-52798 | two parameters in one segment (e.g. `/:a-:b`) | no_genuine_usage (rule 8) | as above |
| path-to-regexp 0.1.7 (via express) | GHSA-37ch-88jc-xwx2 / CVE-2026-4867 | three or more parameters in one segment | no_genuine_usage (rule 8) | as above |
| express 4.17.1 | GHSA-qw6h-vgh9-j6wx / CVE-2024-43796 | res.redirect | no_genuine_usage | S4: not called |
| express 4.17.1 | GHSA-rv95-896h-c2vc / CVE-2024-29041 | res.location, res.redirect | no_genuine_usage | S4: not called |
| body-parser 1.19.0 | GHSA-qwcr-r2fm-qrc7 / CVE-2024-45590 | urlencoded (extended) | no_genuine_usage | only `express.json()` (= body-parser json) at :11 (S3, S4) |
| body-parser 1.19.0 | GHSA-v422-hmwv-36x6 / CVE-2026-12590 | `limit` option with an invalid value | no_genuine_usage (rule 8) | `express.json()` at :11 is called with no options; no `limit` (S4) |
| cookie 0.4.0 (via express) | GHSA-pxg6-pf52-xh8x / CVE-2024-47764 | cookie.serialize with untrusted name/path/domain | no_genuine_usage | reached only through `res.cookie` (D6: 857); the app sets no cookies (S4) |
| send 0.17.1 (via express) | GHSA-m6fv-jmcg-4jfg / CVE-2024-43799 | SendStream redirect | no_genuine_usage | reached through `res.sendFile`/`res.download` (D6: 430, 499) or serve-static; none used (S4) |
| serve-static 1.14.1 (via express) | GHSA-cm22-4g7w-348p / CVE-2024-43800 | serve-static redirect | no_genuine_usage | `express.static` not used (S4) |
| minimatch 3.0.4 (via ejs -> jake/filelist) | GHSA-f8q6-p94x-37v3, GHSA-3ppc-4f35-3m26, GHSA-7r86-cg39-jmmj, GHSA-23c5-xmqv-rm74 | minimatch pattern matching | no_genuine_usage | only reachable through jake, which ejs uses only in bin/cli.js (D1, D7); the ejs runtime the app loads does not require it |
| brace-expansion 1.1.11 (via minimatch) | GHSA-3jxr-9vmj-r5cp, GHSA-6j4f-fj2g-mc7p, GHSA-f886-m6hf-6m8v, GHSA-mh99-v99m-4gvg, GHSA-q2hr-2g5m-vwhr, GHSA-qhr7-859c-m2p7, GHSA-rgw5-rvv9-x895, GHSA-v6h2-p8h4-qcjw | brace expansion | no_genuine_usage | only reachable through minimatch, as above (D1, D7) |
| cross-spawn 7.0.3 (via tsc-watch) | GHSA-3xgq-45jj-v275 / CVE-2024-21538 | cross-spawn argument escaping | no_genuine_usage (rule 5) | pulled in only by tsc-watch, a devDependency used by the `dev` script (D7); not part of `build/` |
| ansi-regex 5.0.0 (via tsc-watch -> strip-ansi) | GHSA-93q8-gq69-wqmw / CVE-2021-3807 | ansi-regex pattern | no_genuine_usage (rule 5) | pulled in only by tsc-watch (devDependency) through strip-ansi (D7); not part of `build/` |

### Added after the scan listing

(none yet)

## Known limitations of this case

- Single application source file; the shipped artefact is compiled output, so labels cite the TypeScript source lines.
- Whether Component 1 includes devDependency packages from yarn.lock depends on its producer; dev-only rows above are labelled in case it does.
- Advisory list above comes from the GitHub Advisory Database; the findings in
  canonical-scan.json are what the labels are finally keyed to.
