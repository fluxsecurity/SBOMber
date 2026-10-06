# <case-id>

- Repository: <https://github.com/owner/repo>
- Commit: `<full SHA>`
- Ecosystem / language: <npm / JavaScript>
- Why this repository: <one or two sentences: which real CVE, why it is a useful case>

## How each input was produced

| File | Produced by | Command / branch / commit of SBOMber used |
|---|---|---|
| canonical-scan.json | Component 1 | |
| usage-graph.json | Component 2 | |
| localisation.json | Component 3 (`sbomber localise`) | |

The three files are committed exactly as produced. Do not edit them by hand;
if one is wrong, regenerate it and record the new command here.

## Labelling notes

<Anything a reviewer needs to check the labels: files read, searches run,
code that does not ship, anything you were unsure about.>

## Known limitations of this case

<e.g. no lockfile; single file; no transitive case.>
