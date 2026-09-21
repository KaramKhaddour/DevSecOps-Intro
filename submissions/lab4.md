# Lab 4 — Submission

SBOM generation and software composition analysis on `bkimminich/juice-shop:v20.0.0`.

## Setup

```console
$ syft version
Application:   syft
Version:       1.52.0

$ grype version
Application:         grype
Version:             0.119.0

$ trivy --version
Version: 0.74.0

$ jq --version
jq-1.7.1
```

Grype's vulnerability database for this run: schema `v6.1.9`, built `2026-09-20T06:27:54Z`. Recording it matters
because the same SBOM scanned next week gives different numbers, and only the DB version explains why.

## Task 1

### 4.1 Two SBOMs from one image

```console
$ syft bkimminich/juice-shop:v20.0.0 -o cyclonedx-json=labs/lab4/juice-shop.cdx.json
$ syft bkimminich/juice-shop:v20.0.0 -o spdx-json=labs/lab4/juice-shop.spdx.json

$ jq '.components | length' labs/lab4/juice-shop.cdx.json
3069
$ jq '.packages   | length' labs/lab4/juice-shop.spdx.json
909
$ jq -r '.specVersion' labs/lab4/juice-shop.cdx.json
1.7
```

| | CycloneDX | SPDX |
|---|---:|---:|
| top-level count queried | `.components` → **3069** | `.packages` → **909** |
| spec version | **1.7** | SPDX-2.3 |
| file size | 1.8 MB | 3.0 MB |

### Why the two formats disagree

They do not actually disagree about the image — the two numbers are counting different things, and the
arithmetic shows it exactly. Breaking the CycloneDX array down by component type:

```console
$ jq -r '[.components[].type] | group_by(.) | map("\(.[0]): \(length)") | .[]' labs/lab4/juice-shop.cdx.json
application: 1
file: 2160
library: 907
operating-system: 1
```

**907 library + 1 operating-system + 1 application = 909 — precisely the SPDX package count.** CycloneDX
flattens packages *and* individual files into one `components` array, while SPDX keeps them in two separate
arrays: `packages` (909) and `files` (2167). So `.components | length` compares a mixed list against only half
of the other format's inventory. Both formats describe the same ~909 packages; the 3069-versus-909 gap is a
question I asked wrong, not a difference in what syft catalogued.

The remaining detail is the file arrays: 2160 in CycloneDX against 2167 in SPDX. The seven extras are all
SPDX-only, with nothing CycloneDX-only:

```
juice-shop/node_modules/iltorb/build/Release/iltorb.node
juice-shop/node_modules/iltorb/build/Release/obj.target/iltorb.node
juice-shop/node_modules/iltorb/build/bindings/iltorb.node
juice-shop/node_modules/libxmljs2/build/Release/xmljs.node
juice-shop/node_modules/portscanner/package.json
juice-shop/node_modules/sqlite3/build/Release/node_sqlite3.node
juice-shop/node_modules/toposort-class/package.json
```

Each of those seven carries a single `SHA1` checksum and no `fileTypes`, where files present in both formats
carry `SHA1` *and* `SHA256`. SPDX requires a SHA1 on every file it references, so it lists them regardless;
syft's CycloneDX serializer emits nothing for them. Five of the seven are compiled `.node` native addons —
exactly the kind of artifact a licence or provenance audit would care about most, and the kind most easily lost
by picking a format and trusting the count.

### 4.2 Scanning the SBOM rather than the image

```console
$ grype sbom:labs/lab4/juice-shop.cdx.json -o json --file labs/lab4/grype-from-sbom.json
$ grype sbom:labs/lab4/juice-shop.cdx.json -o table | tee labs/lab4/grype-from-sbom.txt
NAME          INSTALLED  FIXED IN   TYPE  VULNERABILITY        SEVERITY  EPSS          RISK
lodash        2.4.2      4.17.21    npm   GHSA-35jh-r3h4-6jhm  High      21.3% (97th)  15.7
moment        2.0.0      2.29.2     npm   GHSA-8hfj-j24r-96c4  High      13.9% (96th)  10.4
jsonwebtoken  0.1.0      4.2.2      npm   GHSA-c7hr-j4mj-j2w6  Critical  8.7% (94th)   7.8
...
```

```console
$ jq '[.matches[].vulnerability.severity] | group_by(.) | map({severity: .[0], count: length})' \
    labs/lab4/grype-from-sbom.json
```

| Severity | Count |
|---|---:|
| Critical | 14 |
| High | 85 |
| Medium | 65 |
| Low | 12 |
| Negligible | 7 |
| **Total matches** | **183** |
| *distinct advisory ids* | *157* |

183 matches but only 157 distinct identifiers, because the same advisory hits several packages at once — the
`tar` rows below are one advisory counted three times.

### 4.3 Top ten, ranked properly

Sorting the severity string alphabetically would put `Low` above `Medium`, so the rank comes from an explicit
order array:

```
Critical	GHSA-c7hr-j4mj-j2w6	jsonwebtoken@0.1.0	fix: 4.2.2
Critical	GHSA-c7hr-j4mj-j2w6	jsonwebtoken@0.4.0	fix: 4.2.2
Critical	GHSA-jf85-cpcp-j695	lodash@2.4.2	fix: 4.17.12
Critical	CVE-2026-63073	libssl3t64@3.5.5-1~deb13u2	fix: 3.5.7-1~deb13u2
Critical	GHSA-mp2f-45pm-3cg9	decompress@4.2.1	fix:
Critical	GHSA-xwcq-pm8m-c4vf	crypto-js@3.3.0	fix: 4.2.0
Critical	CVE-2026-34182	libssl3t64@3.5.5-1~deb13u2	fix: 3.5.6-1~deb13u2
Critical	GHSA-23hp-3jrh-7fpw	tar@4.4.19	fix: 7.5.19
Critical	GHSA-23hp-3jrh-7fpw	tar@6.2.1	fix: 7.5.19
Critical	GHSA-23hp-3jrh-7fpw	tar@7.5.15	fix: 7.5.19
```

All ten are Critical, and **nine of the ten have a fix version**. The single exception is
`GHSA-mp2f-45pm-3cg9` on `decompress@4.2.1`, where the fix column is empty.

### What I would do first, using only severity and fix availability

Those two columns sort the work into "a version bump closes this" and "a version bump cannot". I would start
with the nine fixable Criticals, because the fix column has already told me the remediation and the cost is a
dependency bump rather than an investigation — and I would sequence them by how many findings one bump retires.
`tar` is the clearest win: three of the ten rows are one advisory against three copies of `tar` (4.4.19, 6.2.1
and 7.5.15, all pulled in transitively), and `7.5.19` closes all three. `jsonwebtoken` is two rows for one bump
to 4.2.2, and the two `libssl3t64` CVEs are one base-image update, since `3.5.7-1~deb13u2` satisfies both.
That is six of the ten findings cleared by three changes.

`decompress@4.2.1` I would deliberately leave until last despite being Critical, because no amount of urgency
produces a patch that does not exist. Its absent fix column changes the question from "when do we upgrade" to
"can we drop this dependency, or do we need a compensating control" — a design decision that should not hold up
nine bumps that are ready to merge today. Severity says what matters; the fix column says what is actionable,
and triaging on severity alone would have put the one unfixable finding at the front of the queue.

## Task 2

### 4.4 Trivy against the image

```console
$ trivy image bkimminich/juice-shop:v20.0.0 \
    --severity LOW,MEDIUM,HIGH,CRITICAL \
    --format json --output labs/lab4/trivy.json
INFO  Detected OS  family="debian" version="13.4"
INFO  [debian] Detecting vulnerabilities...  os_version="13" pkg_num=13
INFO  Number of language-specific files  num=1
INFO  [node-pkg] Detecting vulnerabilities...
```

### Side by side

Trivy prints severities upper case and Grype in title case, so the two tables are normalised before comparing —
joining them raw silently yields zeros.

| Severity | Grype | Trivy | Delta |
|---|---:|---:|---:|
| Critical | 14 | 10 | **+4** |
| High | 85 | 64 | **+21** |
| Medium | 65 | 68 | **-3** |
| Low | 12 | 31 | **-19** |
| Negligible | 7 | — | **+7** |
| **Total findings** | **183** | **173** | **+10** |
| *distinct ids* | *157* | *146* | *+11* |

Trivy has no `Negligible` bucket, and this scan passed `--severity LOW,MEDIUM,HIGH,CRITICAL`, so anything Trivy
rated `UNKNOWN` was filtered out before it reached the file — part of that column is a flag I chose, not a
disagreement. The severity deltas are also partly a rating difference rather than a detection one: both tools
inherit CVSS from whichever advisory feed they trust, so the same CVE can land in different rows.

Where the totals come from is more interesting than the totals:

| Source | Grype | Trivy |
|---|---:|---:|
| Debian OS packages | 50 | 50 |
| npm packages | 118 | 123 |
| binary (Node.js runtime) | 15 | 0 |

The Debian side agrees exactly, 50 against 50. The whole net gap is `+15` from a component Trivy never
catalogued, less `5` npm findings Trivy has and Grype does not.

### 4.5 Where they disagree

The raw identifier diff badly overstates the divergence:

```console
$ comm -23 /tmp/grype-ids.txt /tmp/trivy-ids.txt | wc -l   # grype only
104
$ comm -13 /tmp/grype-ids.txt /tmp/trivy-ids.txt | wc -l   # trivy only
93
```

Grype reports 92 `GHSA-` and 65 `CVE-` identifiers; Trivy reports 3 `GHSA-` and 140 `CVE-`. They are largely
naming the same advisories from different namespaces. Expanding each Grype match with its
`relatedVulnerabilities` aliases and re-comparing:

```
grype distinct ids                    : 157
grype ids + aliases                   : 246
trivy-only, raw                       : 93
trivy-only, after alias expansion     : 4
-> 89 of Trivy's 93 "unique" findings are CVE names for GHSAs Grype already reported
```

**One Grype found and Trivy missed: `CVE-2026-48617`, package `node@24.15.0`** — the Node.js runtime itself, not
an npm package. This is the ecosystem-parsing case. Syft's `binary-classifier-cataloger` identified the
executable at `/nodejs/bin/node` and catalogued it as `pkg:generic/node@24.15.0`, so Grype had something to
match against and produced 15 findings for it via its stock matcher. Trivy's scan of the same image reported
exactly two vulnerability targets — `debian` OS packages and `node-pkg` language packages — and zero findings
with `PkgName` `node`. It read the `node_modules` tree and the Debian package database, but never treated the
interpreter binary shipped in the image as an inventory item. Fourteen sibling CVEs against the same runtime
(`CVE-2026-48931`, `-48932`, `-48937`, the `CVE-2026-568xx` group and others) are invisible to Trivy here for
the same reason.

**One Trivy found and Grype missed: `NSWG-ECO-17`, package `jsonwebtoken@0.1.0` and `@0.4.0`** — the advisory
source case. `NSWG-ECO-*` identifiers come from the Node Security Working Group ecosystem advisory set, a feed
Trivy carries and Grype's database does not, so the finding has no identifier Grype could ever emit. The other
three genuine Trivy-only findings fit the same shape: `NSWG-ECO-154` on `sanitize-html@1.4.2`, `NSWG-ECO-428`
on `base64url@0.0.6`, and `CVE-2025-57349` on `messageformat@2.3.0`. Three of the four are one feed Grype does
not subscribe to — a far smaller and far more explainable divergence than the raw 93 suggested.

### Decoupled inventory versus the single binary

The decoupled split earns its extra moving part whenever the inventory has to outlive the scan. Once
`juice-shop.cdx.json` exists it is a durable artifact that other things consume: re-running Grype against the
file answers "are we affected" in about a second with no registry pull, which is what you want at 2am when an
advisory drops for a package you might ship, and the same file answers licence and provenance questions a
vulnerability scanner never touches. **Lab 8 takes this exact file and attaches it to the image as a signed
Cosign attestation** — the bonus below builds the in-toto envelope by hand — and that is only possible because
the inventory is a separate, addressable thing rather than console output. An SBOM you can sign is an SBOM
someone downstream can verify against the digest they actually pulled.

The single binary is the better answer when the output is a pass/fail gate and nobody will ever read the
inventory again: a PR check that blocks on new Criticals wants one tool, one DB and one exit code, not a
pipeline stage that produces a file for a second stage to consume. Trivy is also the one that already knows
about the Debian layer, the `node_modules` tree and secrets in one pass, so for "is this image fit to merge"
it is less to install, less to break and less to explain. The honest reading of the numbers above is that this
is not either/or — 50 identical Debian findings, `node` runtime CVEs only Grype saw, `NSWG-ECO` advisories only
Trivy saw. Two tools over one image each found things the other could not, so a gate that runs only one is
accepting a known blind spot, and the useful question is which blind spot you can live with.

## Bonus

### The command

```console
$ DIGEST=$(docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}' \
           | cut -d@ -f2 | sed 's/^sha256://')

$ jq -n --arg name "bkimminich/juice-shop:v20.0.0" \
        --arg digest "$DIGEST" \
        --slurpfile bom labs/lab4/juice-shop.cdx.json \
   '{_type: "https://in-toto.io/Statement/v0.1",
     subject: [{name: $name, digest: {sha256: $digest}}],
     predicateType: "https://cyclonedx.org/bom",
     predicate: $bom[0]}' > labs/lab4/juice-shop-attestation.json
```

`--slurpfile` reads the whole SBOM into `$bom` as a one-element array, so `$bom[0]` embeds the document
unchanged as the predicate; `--arg` keeps the digest a string rather than letting jq interpret it.

### First 20 lines

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "bkimminich/juice-shop:v20.0.0",
      "digest": {
        "sha256": "fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.7",
    "serialNumber": "urn:uuid:77142b11-7931-42d5-8571-f2c3e19fe854",
    "version": 1,
    "metadata": {
      "timestamp": "2026-09-21T09:38:49+03:00",
      "tools": {
```

The two type strings are not guesses. Cosign's `generateCycloneDXStatement` sets `in_toto.StatementInTotoV01`
and `in_toto.PredicateCycloneDX`, and its own test fixtures pin the literal values:

```json
{"_type":"https://in-toto.io/Statement/v0.1", ... ,"predicateType":"https://cyclonedx.org/bom", ...}
```

So the statement type is `v0.1`, not the in-toto spec's current `v1`, and the CycloneDX predicate type carries
no version at all — which means the predicate's own `specVersion: 1.7` is the only record of which CycloneDX
schema was used.

### The digest, and why not the tag

```console
$ docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}'
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

A tag is a mutable pointer: `v20.0.0` can be repushed to different bytes tomorrow, which would leave this
attestation making a true-looking claim about an image that no longer exists. The digest *is* the content, so
binding the statement to `sha256:fd58bdc…` means the claim either matches the bytes a verifier pulled or
visibly does not.

### What this file claims, who checks it, and what it does not prove

It claims that the CycloneDX inventory in `predicate` is the inventory of the image whose manifest digests to
`sha256:fd58bdc…` — a claim about *those* bytes, which stays checkable after the tag moves. The checker is
whoever is about to run the image and did not build it: a deploy-time admission controller, a downstream team,
an auditor asking what is inside what you shipped; in Lab 8 that is `cosign verify-attestation` against the
signing key.

What it does not prove is almost everything else. As written it is an unsigned JSON file that anybody can
author or edit, so on its own it carries no evidence of who produced it — the signature Lab 8 adds is what
turns "this document says so" into "a key you trust says so". Even signed, it would not prove the inventory is
*correct*: it inherits whatever syft missed, and this lab already found seven files and a Node runtime that one
tool or another failed to catalogue. And it says nothing about whether the components listed are vulnerable,
licensed acceptably or built from the source they claim — it is an inventory bound to a digest, not a safety
verdict.
