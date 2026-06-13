# Adopt on a legacy codebase

Legacy codebases contain existing EXPOSED or UNKNOWN endpoints. Use a baseline file to ignore existing findings and only fail CI on new violations.

## 1. Generate baseline

`ash
authmap --project . --write-baseline .authmap-baseline.json
`
Exit code is 0. All current endpoints are saved to .authmap-baseline.json.

## 2. Track in version control

`ash
git add .authmap-baseline.json
git commit -m "chore: add authmap baseline"
`

## 3. Enforce in CI

Add --baseline flag to the CI scan command. 

`ash
authmap --project . --fail-on EXPOSED --baseline .authmap-baseline.json --quiet
`
* Exact matches found in .authmap-baseline.json are ignored.
* Non-zero exit code triggers only if a *new* finding violates the --fail-on threshold.
