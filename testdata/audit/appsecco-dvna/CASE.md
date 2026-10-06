# appsecco-dvna

- Repository: <https://github.com/appsecco/dvna>
- Commit: `9ba473add536f66ac9007966acb2a775dd31277a`
- Ecosystem / language: npm / JavaScript
- Why this repository: a deliberately vulnerable Node.js application whose own
  solution docs (docs/solution/a9-using-components-with-known-vulnerability.md)
  describe the mathjs remote code execution reached through `mathjs.eval`. It adds
  several genuine_usage labels on direct dependencies (mathjs, node-serialize,
  ejs, express, bcrypt, passport, morgan), which is where a missed_usage would show.

## How each input was produced

| File | Produced by | Command / branch / commit of SBOMber used |
|---|---|---|
| canonical-scan.json | Component 1 | pending: no command on main writes it yet |
| usage-graph.json | Component 2 | pending: `sbomber usage` (feature/s5-10-usage-cli, not merged) |
| localisation.json | Component 3 (`sbomber localise`) | pending |

The three files are committed exactly as produced. Do not edit them by hand;
if one is wrong, regenerate it and record the new command here.

## Labelling notes

Labels below were written from the application source (and, where noted,
dependency package source) before any SBOMber command was run on this
repository. They are keyed by package and advisory; `findingId`s are mapped once
canonical-scan.json exists.

What ships: `package.json` has `main server.js`, `start node server.js`. Application
code is `server.js`, `config/`, `core/`, `models/`, `routes/` (and `views/`).

No lockfile. Exact pins: mathjs 3.10.1, node-serialize 0.0.4, express-flash 0.0.2.
Everything else is a caret range (e.g. `sequelize ^4.13.10`, `libxmljs ^0.19.1`).
`ParsePackageJSON` on main (internal/npm/parse.go) records the raw constraint, so
the version each finding refers to is only known once canonical-scan.json exists.
Advisories whose label depends on dependency internals at a specific version are
listed under "Pending: version" and are labelled after the scan listing, before
usage-graph.json, localisation.json or the audit are produced.

### Searches (run from the repository root at the pinned commit)

| # | Command | Result |
|---|---|---|
| S1 | `grep -rnE "require\(" server.js core models routes config` | server.js:1-7 express, body-parser, passport, express-session, ejs, morgan, express-fileupload; core/appHandler.js:2-6 bcrypt, child_process, mathjs, libxmljs, node-serialize; core/authHandler.js:2-3 bcrypt, md5; core/passport.js:2-3 passport-local, bcrypt; models/index.js:5 sequelize. mysql2 is not required by the application (sequelize loads it for dialect `mysql`) |
| S2 | `grep -rnE "unserialize\|mathjs\.\|libxmljs\.\|\.attrs\(\|\.namespaces\(\|\.config\(\|\.import\(" server.js core routes` | core/appHandler.js:197 `mathjs.eval(req.body.eqn)`, :218 `serialize.unserialize(req.files.products.data...)`, :235 `libxmljs.parseXmlString(..., {noent:true,noblanks:true})`; no `attrs`, `namespaces`, `config`, `import` |
| S3 | `grep -rnE "res\.redirect\(" core routes` | core/appHandler.js:188 `res.redirect(req.query.url)`; all other calls use constant paths |
| S4 | `grep -rnE "morgan\(\|fileUpload\(\|parseNested\|\.mv\(\|bodyParser\.[a-z]+\(" server.js core routes` | server.js:15 `morgan('tiny')`, :16 `bodyParser.urlencoded({ extended: false })`, :17 `fileUpload()` (no options); no `parseNested`, no `.mv(` |
| S5 | `grep -rnE "sequelize\.query\(\|replacements\|attributes\|dialect\|DATABASE_URL" core models config` | core/appHandler.js:11 `db.sequelize.query(query, { model: db.User })` (no replacements); models/index.js:9-10 `new Sequelize(process.env.DATABASE_URL)` when set, else :14 `dialect: config.dialect`; config/db.js:7 `dialect: 'mysql'`; no `attributes` option |
| S6 | `grep -rnE "bCrypt\.[A-Za-z]+\(\|passport\.authenticate\|req\.logout\|req\.login" core routes` | `bCrypt.hashSync` core/appHandler.js:153, core/authHandler.js:79, core/passport.js:86; `bCrypt.compareSync` core/passport.js:47; routes/main.js:41 `req.logout()`, :51 and :57 `passport.authenticate(...)` |

### Dependency-side checks (tarballs from registry.npmjs.org)

| # | Command | Result |
|---|---|---|
| D1 | `diff -r bcrypt@4.0.1/src bcrypt@5.0.0/src` | the CVE-2020-7689 fix passes the real key length into `bcrypt()` instead of a `strlen` capped to `u_int8_t`; the changed call sites are in `EncryptSync`, `CompareSync` and their async workers (bcrypt_node.cc 151, 188, 209, 246), exported as `encrypt_sync`/`compare_sync`, which `hashSync`/`compareSync` call |
| D2 | `diff morgan@1.9.0/index.js morgan@1.9.1/index.js` | the CVE-2019-5413 fix is in `compile()` (index.js 378-388); `morgan('tiny')` reaches it through `getFormatFunction` (453) |
| D3 | `grep -n "morgan.format('tiny'" morgan@1.9.0/index.js` | `tiny` is `:method :url :status :res[content-length] - :response-time ms` (177): no `:remote-user`, no quoted fields |

### Worksheet

| Package | Advisory | Symbols / trigger the advisory names | Label | Evidence / reasoning |
|---|---|---|---|---|
| node-serialize 0.0.4 | GHSA-q4v7-4rhw-9hqm / CVE-2017-5941 | unserialize | genuine_usage | core/appHandler.js:218 `serialize.unserialize(...)` on an uploaded file, route POST /app/bulkproductslegacy (routes/app.js:64) |
| mathjs 3.10.1 | GHSA-vx5c-87qx-cv6c / CVE-2017-1001002 | typed function creation with code in the name (no function named) | genuine_usage | core/appHandler.js:197 `mathjs.eval(req.body.eqn)`, route POST /app/calc (routes/app.js:60); the repository's docs/solution/a9 describes the mathjs code execution reached through this call |
| mathjs 3.10.1 | GHSA-pv8x-p9hq-j328 / CVE-2017-1001003 | private properties (e.g. constructor) replaced via unicode in expressions | genuine_usage | core/appHandler.js:197, as above; expressions from the request are evaluated |
| mathjs 3.10.1 | GHSA-x2fc-mxcx-w4mf / CVE-2020-7743 | deepExtend during configuration updates | no_genuine_usage | S2: no `math.config` or `import` call; the application only calls `eval` |
| ejs (^2.5.7) | GHSA-phwq-j96m-2c2q / CVE-2022-29078 | renderFile options taken from data | genuine_usage (rule 8) | server.js:14 `app.set('view engine','ejs')` and `res.render` throughout (e.g. routes/app.js:23 passes `req.query.legacy` as data); express runs `ejs.renderFile` |
| ejs (^2.5.7) | GHSA-ghr5-ch3p-vcr6 / CVE-2024-33883 | missing pollution protection in render options | genuine_usage (rule 8) | same render path: server.js:14, `res.render` throughout |
| express (^4.16.2) | GHSA-qw6h-vgh9-j6wx / CVE-2024-43796 | res.redirect | genuine_usage | core/appHandler.js:188 `res.redirect(req.query.url)`, route GET /app/redirect (routes/app.js:48) |
| express (^4.16.2) | GHSA-rv95-896h-c2vc / CVE-2024-29041 | res.location, res.redirect with malformed URLs | genuine_usage | core/appHandler.js:188, as above: the URL comes from the query string |
| bcrypt (^1.0.3) | GHSA-5wg4-74h6-q47v / CVE-2020-7689 | input over 255 bytes truncated wrongly (no function named) | genuine_usage | `hashSync` core/appHandler.js:153, core/authHandler.js:79, core/passport.js:86 and `compareSync` core/passport.js:47 hash request passwords; the fix changes exactly these hashing paths (D1) |
| passport (^0.4.0) | GHSA-v923-w3x8-wh69 / CVE-2022-25896 | session handling on login and logout | genuine_usage | routes/main.js:51, :57 `passport.authenticate('login'/'signup', ...)` and :41 `req.logout()` |
| morgan (^1.9.0) | GHSA-gwg9-rgvj-4h5j / CVE-2019-5413 | format compilation (user input into the format/filter) | genuine_usage (rule 8) | server.js:15 `morgan('tiny')` runs `compile()`, the code the fix changed (D2); the format is constant, recorded |
| morgan (^1.9.0) | GHSA-4vj7-5mj6-jm8m / CVE-2026-5078 | `:remote-user` token | no_genuine_usage (rule 8) | server.js:15 uses `tiny`, which has no `:remote-user` (D3) |
| morgan (^1.9.0) | GHSA-9f6g-j8ch-79g4 / CVE-2026-87859 | quoted fields (combined, common, default, custom quoted tokens) | no_genuine_usage (rule 8) | `tiny` has no quoted fields (D3) |
| express-fileupload (^0.4.0) | GHSA-9wcg-jrwf-8gg7 / CVE-2020-7699 | `parseNested` option | no_genuine_usage (rule 8) | server.js:17 `fileUpload()` with no options; no `parseNested` anywhere (S4) |
| libxmljs (^0.19.1) | GHSA-6433-x5p4-8jc7 / CVE-2024-34391 | functions on the result of `attrs()` | no_genuine_usage | S2: `attrs()` not called; core/appHandler.js:236-241 uses only `root()`, `childNodes()`, `text()` |
| libxmljs (^0.19.1) | GHSA-mg49-jqgw-gcj6 / CVE-2024-34392 | `namespaces()` | no_genuine_usage | S2: `namespaces()` not called |
| sequelize (^4.13.10) | GHSA-wrh9-cjv3-2hpw / CVE-2023-25813 | `replacements` together with `where` | no_genuine_usage (rule 8) | S5: the only `sequelize.query` (core/appHandler.js:11) passes no `replacements`; no `replacements` anywhere |
| sequelize (^4.13.10) | GHSA-f598-mfpv-gmfx / CVE-2023-22578 | `attributes` with parentheses | no_genuine_usage (rule 8) | S5: no `attributes` option anywhere |
| sequelize (^4.13.10) | GHSA-v8fg-2rw7-q452 / CVE-2026-69240 | Oracle dialect only | no_genuine_usage (rule 8) | config/db.js:7 `dialect: 'mysql'`; models/index.js:10 takes the dialect from `DATABASE_URL` when set, which the repository does not set to Oracle |

### Pending: version (labelled after the scan listing)

These depend on dependency internals at the version canonical-scan.json records,
or the advisory names no function the application source can be checked against.

| Package | Advisory | Why it cannot be labelled from application source alone |
|---|---|---|
| express-fileupload | GHSA-q3w9-g74q-vp5f (no CVE) | large filename of `.` characters; whether `fileUpload()` (server.js:17) runs the affected filename handling depends on the version's code |
| express-fileupload | GHSA-w4m6-x6c2-j5c9 / CVE-2022-27261 | same-name uploads overwriting files; the advisory names no function, and the application keeps uploads in memory (`req.files.products.data`) and never calls `.mv()` (S4); needs the version's code |
| libxmljs | GHSA-jv72-59wq-8rxm / CVE-2025-25341 | `_ref` access on entity_ref/entity_decl nodes; whether parsing with `noent:true` and walking `childNodes()` (core/appHandler.js:235-241) reaches it needs the version's code |
| libxmljs | GHSA-773h-w45w-f2f9 / CVE-2022-21144 | names `parseXml` with a non-buffer argument; the application calls `parseXmlString` with a string, and whether that shares the affected path needs the version's code |
| morgan | GHSA-jxfw-x594-9x9m | unescaped Unicode line separators; which tokens are affected (`tiny` includes `:url`) needs the advisory detail and the version's code |
| mysql2 (via sequelize) | GHSA-rgwj-5xj2-c3m3, GHSA-fpw7-j2hg-69v5, GHSA-4rch-2fh8-94vw, GHSA-pmh2-wpjm-fj45, GHSA-mqr2-w7wj-jjgr, GHSA-49j4-86m8-q2jw, GHSA-3f6p-5ww8-9rcr | the application never calls mysql2; whether sequelize 4.x's mysql dialect passes the triggering options (compression, timezone, nestTables, typeCast) or runs the affected parser code needs both packages' code at the scanned versions |
| sequelize | GHSA-vqfx-gj96-3w95, GHSA-8c25-f3mj-v6h8, GHSA-m9jw-237r-gvfv, GHSA-fw4p-36j9-rrj3, GHSA-j9xp-92vc-559j | `where` handling internals (`getWhereConditions`, JSON paths, mysql escaping); the application builds `where` from request values (e.g. core/appHandler.js:85-88, :107-110, :145-148, core/authHandler.js:21-25), so these need the version's code |

### Added after the scan listing

(none yet)

## Known limitations of this case

- No lockfile: versions are caret ranges, so which advisories appear depends on how Component 1 resolves them.
- 17 advisories are labelled after the scan listing (see "Pending: version").
- `views/` (EJS templates) and `public/` were not searched for server-side calls beyond what `res.render` implies.
- Advisory list above comes from the GitHub Advisory Database at the range floors; the findings in
  canonical-scan.json are what the labels are finally keyed to.
