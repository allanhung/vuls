# Design: Alibaba Cloud Linux 3 & 4 support

Date: 2026-08-28
Status: Draft for review
Author: Allan Hung (with Claude)

## 1. Goal

Add first-class vulnerability-detection support for **Alibaba Cloud Linux 3**
and **Alibaba Cloud Linux 4** (`ID=alinux` in `/etc/os-release`) to the Vuls
stack, end to end:

- vuls scanner recognises the OS and produces a scan result with
  `Family = "alinux"`.
- The vuls2 detection DB carries Alibaba Cloud Linux OVAL data keyed by
  ecosystem `alinux:3` / `alinux:4`.
- `vuls scan` / `vuls detect` reports fixed/unfixed CVEs for installed RPMs
  the same way it already does for Oracle Linux / AlmaLinux / Rocky Linux.

Alibaba Cloud Linux **2** is explicitly **out of scope** for detection. The
fetcher will still download the `alinux-2` OVAL file (the mirror serves all
three together) but the extractor and ecosystem mapping only emit majors 3
and 4.

## 2. Context: how detection is wired today

This branch of `future-architect/vuls` no longer uses
`goval-dictionary` / `gost`. All OS-package CVE detection goes through the
`vuls2` library:

```
vuls (scanner)                         -> detects OS, builds models.ScanResult{Family,Release,Packages}
  detector/detector.go:239             -> family gate; calls vuls2.DetectPkgs for known families
  detector/vuls2/vuls2.go              -> converts to vuls2 scanTypes.ScanResult
  detector/vuls2/vendor.go             -> toVuls2Family / toVuls2Release / advisoryReference
vuls2/pkg/detect/ospkg/ospkg.go        -> ecosystemTypes.GetEcosystem(family, release); dispatch
vuls2/pkg/detect/ospkg/base/base.go    -> generic RPM range matching (Oracle/Alma/Rocky ride this)
vuls2 DB (ghcr.io/vulsio/vuls-nightly-db) built from:
vuls-data-update/pkg/fetch/<src>       -> download upstream advisory data -> JSON
vuls-data-update/pkg/extract/<src>     -> normalise -> dataTypes.Data with detection segments
```

The shared contract between the three repos is the **ecosystem string**
produced by
`vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem/ecosystem.go`
(`GetEcosystem`). Its `default` branch returns an error, so a new OS family
cannot work until a case is added there.

Local checkouts for this work:

| Repo | Path |
|---|---|
| vuls (fork) | `/Users/allan/Downloads/git/allanhung/vuls` |
| vuls2 (fork) | `/Users/allan/Downloads/git/allanhung/vuls2` |
| vuls-data-update (fork) | `/Users/allan/Downloads/git/allanhung/vuls-data-update` |

## 3. The data source

`https://mirrors.aliyun.com/alinux/cve/data/OVAL/` — nginx-style HTML
autoindex (there is **no JSON API**; the `?format=json` query returns the
Aliyun portal SPA). Relative links in the page body:

```
<a href="alinux-2.1903.oval.xml">alinux-2.1903.oval.xml</a>
<a href="alinux-3.2104.oval.xml">alinux-3.2104.oval.xml</a>
<a href="alinux-4.oval.xml">alinux-4.oval.xml</a>
```

| File | major | dist tag | `<definition>` count | regenerated |
|---|---|---|---|---|
| `alinux-2.1903.oval.xml` | 2 | `.al7` | 571 | daily |
| `alinux-3.2104.oval.xml` | 3 | `.al8` | 1197 | daily |
| `alinux-4.oval.xml` | 4 | `.alnx4` | 622 | daily |

### 3.1 Schema

OVAL 5.11.2, generator `Alibaba Cloud Linux OVAL Generator 0.1`, namespace
prefix `oval:com.aliyun:`. It is the same patch-OVAL dialect already parsed
by `pkg/fetch/anolis/oval` (`oval:cn.openanolis:`) and
`pkg/extract/oracle/linux` (`oval:com.oracle.elsa:`):

```xml
<definition class="patch" id="oval:com.aliyun:def:20260003">
  <metadata>
    <title>ALINUX2-SA-2026:0003: cloud-kernel bugfix, enhancement and security update (Important)</title>
    <affected family="unix"><platform>Alibaba Cloud Linux 2</platform></affected>
    <reference ref_id="ALINUX2-SA-2026:0003"
               ref_url="https://alas.aliyun-inc.com/errata/detail/ALINUX2-SA-2026:0003"
               source="ALINUX2-SA"/>
    <description>...</description>
    <advisory from="alas.aliyun-inc.com">
      <severity>Important</severity>
      <issued date="2026-05-29"/>
      <updated date="2026-05-29"/>
      <cve cvss3="7.8/CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
           impact="Important" cwe="CWE-269"
           href="https://alas.aliyun-inc.com/cves/detail/CVE-2026-46333"
           public="20260528">CVE-2026-46333</cve>
      <affected_cpe_list>
        <cpe>cpe:2.3:o:alibabacloud:alibaba_cloud_linux_2:-:*:*:*:*:*:*:*</cpe>
      </affected_cpe_list>
    </advisory>
  </metadata>
  <criteria operator="AND">
    <criterion comment="Alibaba Cloud Linux 2.1903 is installed" test_ref="oval:com.aliyun:tst:1"/>
    <criteria operator="OR">
      <criterion comment="kernel is earlier than 0:4.19.91-28.7.al7" test_ref="oval:com.aliyun:tst:20260003003"/>
      ...
    </criteria>
  </criteria>
</definition>
```

Facts confirmed against the live files:

- **CVSS**: `cvss3` attribute only, always `CVSS:3.1`. No `cvss2` anywhere.
  (Oracle's extractor handles both; the Alinux extractor only needs the 3.1
  branch, plus a 3.0 guard for safety.)
- **CVE references**: exactly one `<reference>` per definition (the advisory
  itself). CVE identifiers and their metadata come from
  `<advisory><cve>` — same as Oracle.
- **Advisory ID**: use `reference[source="ALINUXn-SA"].ref_id`
  (`ALINUX2-SA-2026:0003`). Do **not** `strings.Cut(title, ":")` like the
  Oracle extractor — the Alinux ID itself contains a colon.
- **OS-installed test**: a single `textfilecontent54_test`
  (`oval:com.aliyun:tst:1`) against `/etc/alinux-release`:
  - v2 pattern `(Alibaba Cloud Linux \(Aliyun Linux\) release) \d*`, state `2`
  - v3 pattern `(Alibaba Cloud Linux release) \d.*`, state `3`
  - v4 pattern `(Alibaba Cloud Linux release) \d.*`, state `4`
  The major version is redundant with the filename, so the extractor takes
  the major from the fetch version directory (like `pkg/fetch/anolis/oval`),
  not from this test.
- **No module streams**: unlike Oracle EL8, there is no
  `/etc/dnf/modules.d/` `textfilecontent54` logic. The only object names
  containing `:` are Alibaba's kernel-line naming `kernel:5.10` (al8) and
  `kernel:6.6` (alnx4); a plain `kernel` criterion with the same fixed
  version always co-exists in the same OR group. The extractor normalises
  `kernel:X.Y` -> `kernel` and de-duplicates.
- Package criteria: `rpminfo_test` -> `rpminfo_object` (`<name>`) ->
  `rpminfo_state` (`<evr datatype="evr_string" operation="less than">`).
  Operation is always `less than` (fixed-version semantics).

### 3.2 Upstream data-quality bug: corrupted EVR strings

**75–83 % of `<rpminfo_state>` EVR values in all three Alinux OVAL files are
malformed.** A fragment of the sub-package name is spliced in front of the
version:

```
criterion: "kernel-headers is earlier than 0:debug-devel-4.19.91-28.7.al7"
rpminfo_state evr:                          0:debug-devel-4.19.91-28.7.al7   (should be 0:4.19.91-28.7.al7)

criterion: "resource-agents is earlier than 0:agents-4.9.0-54.al8.36"
rpminfo_state evr:                          0:agents-4.9.0-54.al8.36         (should be 0:4.9.0-54.al8.36)
```

Corruption rate measured on 2026-08-28 data:

| File | rpminfo_state total | EVR not matching `^\d+:\d` |
|---|---|---|
| alinux-2 | 5 680 | 4 271 (75 %) |
| alinux-3 | 12 600 | 10 012 (79 %) |
| alinux-4 | 4 696 | 3 905 (83 %) |

The same corruption is present in the criterion `comment`, so the comment is
**not** a usable fallback. The real `version-release` is intact — it is only
*prefixed* with one or more spliced `token-` runs (the fragment comes from a
sub-package name, sometimes the package's own, often mis-shifted from a
sibling; fragments can be mixed-case and can contain dots and digits).

> **Revised during implementation (Task 3).** The first mitigation below —
> blind lowercase-token strip + a hard "repaired value must equal a clean
> anchor in the same OR group" gate — was found unshippable against the full
> dataset: ~1,110 repairs in majors 3/4 legitimately contradict every clean
> anchor (multi-source advisories carry two different correct versions in one
> OR group; some corrupted packages have no clean sibling). It was replaced
> with the **RPM dash-count invariant** (see below), which is simpler and
> rests on an RPM rule rather than a shape heuristic.

**Mitigation — normalise in `pkg/extract/alinux/oval` only** (never in shared
code). RPM forbids `-` in **both** the version and the release, so a
well-formed EVR body (`epoch:body`) contains **exactly one** `-`. A
prefix-splice always *adds* `token-` runs, so a corrupted body has **two or
more** dashes, and the true body is always the **last two `-`-separated
tokens** (`version-release`):

1. Split `epoch:body` on the first `:` (error if absent).
2. `n := strings.Count(body, "-")`. `n == 1` → already clean, keep as-is.
   `n == 0` → fail the definition (no version–release separator).
   `n >= 2` → `epoch + ":" + strings.Join(split(body,"-")[-2:], "-")`.
3. Retain `sanitizeEVR` (the blind-strip + clean-anchor gate) and its unit
   test as an unreachable last-resort fallback before the error path.
4. Any repair failure → wrap with the definition id and **return** the error
   (the whole definition is dropped; no partial data — "better to drop one
   advisory than emit a wrong version", since a wrong `lessThan` is a silent
   false negative in the scanner).
5. `slog.Warn` a repaired-count once per version directory.
6. A committed test asserts every emitted `lessThan` / `fixed` matches
   `^\d+:[^-]+-[^-]+$` — the predicate that catches a regression to
   emitting corrupted versions.

Validated over all 17,296 `rpminfo_state` entries in majors 3/4: the
dash-count rule yields a well-formed `epoch:version-release` for 100 % of
them. The corruption rate itself is unchanged from the table above.

**Also:** file a bug with Alibaba Cloud Linux / OpenAnolis
(`ali-yum@alibaba-inc.com`, or the alinux mirror issue tracker) — this
defect affects every OVAL consumer. Link the report from a code comment.

Decision for review: **ship 3 and 4 now with the extractor-side
normalisation + upstream bug report**, rather than blocking on an upstream
fix. Rationale: the version data is fully recoverable, the fix is contained,
and the alternative is indefinitely no coverage.

## 4. Repo-by-repo changes

### 4.1 vuls-data-update (bulk of the work)

| Path | New / changed | Template | Notes |
|---|---|---|---|
| `pkg/fetch/alinux/oval/oval.go` | new | `pkg/fetch/anolis/oval/oval.go` | Base URL `https://mirrors.aliyun.com/alinux/cve/data/OVAL/`. Replace the JSON list call with an HTML scrape: GET the index, regexp `href="(alinux-[0-9.]+\.oval\.xml)"`, unique. For each file: `ver := strings.TrimPrefix(strings.TrimSuffix(name, ".oval.xml"), "alinux-")` (`2.1903`, `3.2104`, `4`); write per-def/test/object/state JSON under `<cache>/fetch/alinux/oval/<ver>/…`. |
| `pkg/fetch/alinux/oval/types.go` | new | `pkg/fetch/anolis/oval/types.go` | Same struct shape (schema is identical). Drop the `list` struct; the HTML scrape needs no JSON types. |
| `pkg/fetch/alinux/oval/oval_test.go` + `testdata/` | new | anolis `oval_test.go` | Fixtures = trimmed real files (a handful of definitions incl. one corrupted-EVR advisory and the `kernel:X.Y` case). |
| `pkg/extract/alinux/oval/oval.go` | new | `pkg/extract/oracle/linux/linux.go` | See 4.1.1. |
| `pkg/extract/alinux/oval/oval_test.go` + `testdata/` | new | oracle `linux_test.go` | Golden output; explicit cases for EVR normalisation and `kernel:X.Y` folding. |
| `pkg/extract/types/source/source.go` | +1 const | — | `AlinuxOVAL SourceID = "alinux-oval"` (next to `AnolisOVAL`). |
| `pkg/extract/types/data/detection/segment/ecosystem/ecosystem.go` | +const, +case | Oracle case | `EcosystemTypeAlinux = "alinux"`; in `GetEcosystem` add `case EcosystemTypeAlinux: return Ecosystem(fmt.Sprintf("%s:%s", family, strings.Split(release, ".")[0])), nil`; add `EcosystemTypeAlinux` to the `unexpected family` error list. |
| `pkg/cmd/fetch/fetch.go` | +import, +`newCmdAlinuxOVAL()`, +registration | `newCmdAnolisOVAL` | `Use: "alinux-oval"`. |
| `pkg/cmd/extract/extract.go` | +import, +`newCmdAlinuxOVAL()`, +registration | `newCmdOracleLinux` | `Use: "alinux-oval"`, takes the fetch dir as `args[0]`. |
| `README.md` / datasource docs | doc | — | Add Alibaba Cloud Linux row. |

#### 4.1.1 `pkg/extract/alinux/oval/oval.go`

Start from `pkg/extract/oracle/linux/linux.go` and change:

- **Walk** `<inputDir>/<ver>/definitions/*.json` for `ver` in `{3.2104, 4}`
  only (skip `2.1903` with a log line). Reuse the Oracle `evalCriteria` /
  `evalCriterions` recursion (same criteria shape).
- **rpminfo_state -> fixed version**: apply the §3.2 normaliser before using
  `state.Evr.Text`. Keep the `operation == "less than"` assertion.
- **Object name**: `strings.SplitN(name, ":", 2)[0]` so `kernel:6.6` -> `kernel`.
  De-dup `ovalPackage` keys (Oracle's code already maps into a `map`, so
  identical `{major,name,fixedVersion,modularityLabel}` collapse for free).
- **modularityLabel**: always `""` for Alinux. Drop Oracle's
  `textfilecontent54` / `modules.d` branch entirely.
- **major**: from `strings.Split(ver, ".")[0]`, not from an
  `oraclelinux-release` object.
- **Ecosystem**: `ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeAlinux, major))`.
- **Advisory ID / RootID**: from `reference[source ~ "^ALINUX\d-SA$"].ref_id`
  (`ALINUX3-SA-2026:0255`). Parse `^ALINUX(\d)-SA-(\d{4}):(\d+)$`; write
  under `data/<year>/<ID>.json` (`:` is filesystem-safe on the platforms
  vuls-data-update targets; if not, replace with `-` as the Oracle code does
  for ELSA).
- **Severity**: `severityTypes.SeverityTypeVendor` from
  `advisory.Severity`; plus per-CVE `severityTypes.SeverityTypeCVSSv31`
  parsed from `cve.Cvss3` (`<score>/CVSS:3.1/<vector>` — cut on first `/`).
  Guard a `CVSS:3.0` prefix just in case; error on anything else.
- **References**: advisory `ref_url`; also synthesise the public errata URL
  `https://alas.aliyun.com/errata/detail/<ID>` (the OVAL ships the internal
  `alas.aliyun-inc.com` host — see §4.3).
- **Published**: `advisory.Issued.Date` (`2006-01-02`); per-CVE
  `cve.Public` (`20060102`).
- **datasource.json**: `sourceTypes.AlinuxOVAL`, name
  `"Alibaba Cloud Linux OVAL"`.

### 4.2 vuls2 (minimal)

`pkg/detect/ospkg/ospkg.go` already dispatches everything non-Microsoft to
`base.Detect`, and `base.go`'s package/version logic has a `default:` branch
that serves Oracle/Alma/Rocky today. `alinux:3` / `alinux:4` ride the same
generic `RangeTypeRPM` path.

- **Expected change: `go.mod` / `go.sum` only** — bump
  `github.com/MaineK00n/vuls-data-update` to the revision that defines
  `EcosystemTypeAlinux`.
- **Verification tasks** (in the plan, not assumed):
  - `grep isKernelPackage / rename` in `pkg/detect/ospkg/base/base.go` — if
    kernel-source handling is family-gated and lacks a generic fallback that
    works for Alinux, add `ecosystemTypes.EcosystemTypeAlinux` alongside
    `EcosystemTypeRedHat`. Alinux ships `kernel` exactly like RHEL, so the
    default branch is expected to be correct.
  - Confirm `GetEcosystem("alinux", "4")` -> `alinux:4` resolves and
    `base.Detect` accepts an unknown-to-its-switch ecosystem (it should:
    the switch only special-cases, it does not allowlist).
- **Tests**: add an `alinux:3` / `alinux:4` case to whatever table drives
  `pkg/detect/ospkg` if one exists; otherwise rely on the vuls end-to-end
  test in §5.

### 4.3 vuls (this fork)

| Path | Change |
|---|---|
| `constant/constant.go` | `// Alinux is` / `Alinux = "alinux"`. |
| `scanner/alinux.go` | New file, structural copy of `scanner/rocky.go`: `type alinux struct{ redhatBase }`, `newAlinux(c)`, `checkScanMode` / `checkDeps` / `depsFast[Root]` / `depsDeep` / `checkIfSudoNoPasswd` / `sudoNoPasswdCmds*`, `type rootPrivAlinux struct{}` with `repoquery` / `yumMakeCache` / `yumPS`. Alinux 3/4 are dnf-based like Rocky/Alma 8/9. |
| `scanner/redhatbase.go` | New detection block, placed **after** the Oracle block and **before** the AlmaLinux / Rocky / CentOS blocks: `if r := exec(c, "ls /etc/alinux-release", noSudo); r.isSuccess()` -> `cat /etc/alinux-release` -> regexp `Alibaba Cloud Linux(?: \(Aliyun Linux\))? release (\d+)`. Guard `major` in `{3,4}` (2 -> `setErrs` "not supported", <3 message). `newAlinux(c)`, `setDistro(constant.Alinux, release)` where `release` is the bare major (`"3"` / `"4"`). Also accept the `os-release` path: some minimal images may lack `/etc/alinux-release`; add a fallback that parses `/etc/os-release` `ID=alinux` + `VERSION_ID`. |
| `scanner/scanner.go` | `ParseInstalledPkgs` switch (~line 279): `case constant.Alinux: osType = &alinux{redhatBase: redhatBase{base: base}}`. Any other family switch that enumerates RedHat-likes (grep `constant.Oracle` across `scanner/`, `models/`, `config/`). |
| `detector/detector.go` | Add `constant.Alinux` to the family list at ~line 239 (the `vuls2.DetectPkgs` gate). |
| `detector/vuls2/vendor.go` | `toVuls2Family`: default already returns `"alinux"` unchanged — OK, no edit needed but add a comment. `advisoryReference`: add `case ecosystemTypes.EcosystemTypeAlinux:` -> `models.Reference{Source: "alas.aliyun.com", Link: fmt.Sprintf("https://alas.aliyun.com/errata/detail/%s", da.AdvisoryID)}` (mirror of the Alma/Rocky/Oracle cases). |
| `detector/vuls2/vendor.go` `toVuls2Release` | default returns release unchanged; `"3"` / `"4"` pass straight through. No edit. |
| `go.mod` | Dev: `replace github.com/MaineK00n/vuls2 => ../vuls2` and `replace github.com/MaineK00n/vuls-data-update => ../vuls-data-update`. Before PR: drop the `replace`s and bump to real pseudo-versions from the merged commits. |
| `scanner/redhatbase_test.go` | Add Alinux 3 and 4 cases: OS detection from `/etc/alinux-release` + `/etc/os-release`, and `parseInstalledPackages` from the captured `rpm -qa` fixtures. |
| `README.md`, `setup/*`, docs site | Add Alibaba Cloud Linux 3 / 4 to the supported-OS matrix. |

## 5. Testing

### 5.1 Unit / golden

- `vuls-data-update`: `go test ./pkg/fetch/alinux/... ./pkg/extract/alinux/... ./pkg/extract/types/...`
  - fetch: HTML-index scrape picks exactly the three files; XML decodes.
  - extract golden: a corrupted-EVR advisory normalises to the clean
    version; a no-clean-anchor group errors; `kernel:X.Y` folds to `kernel`;
    `alinux-2` input produces no output.
- `vuls2`: `go test ./pkg/detect/...` after the `go.mod` bump.
- `vuls`: `go test ./scanner/... ./detector/...`.

### 5.2 End-to-end (real data)

Fixtures captured 2026-08-28:

| Env | Source | Local copy |
|---|---|---|
| Alinux 4 | `ssh 10.21.34.9` (live) | `/tmp/alinux4/data.txt` — 559 pkgs as `NAME|EPOCHNUM|VERSION|RELEASE|ARCH`, `/etc/alinux-release` = `Alibaba Cloud Linux release 4 (OpenAnolis Edition)`, no `/etc/dnf/modules.d/`, kernel `6.6.102-5.3.3.alnx4` |
| Alinux 3 | provided | `/tmp/alinux3/os-release.txt`, `/tmp/alinux3/rpm-qa.txt` — 1338 pkgs, `VERSION_ID="3"`, `PLATFORM_ID="platform:al8"` |

(SSH note: `known_hosts:488` has a stale key for `10.21.34.9`; refresh it
before a clean connection. Data above was captured over an existing
ControlMaster socket.)

Pipeline:

```
cd vuls-data-update
go run ./cmd/vuls-data-update fetch   alinux-oval
go run ./cmd/vuls-data-update extract alinux-oval "$(...)/fetch/alinux/oval"
# build a vuls2 DB pointing at $(...)/extract/alinux/oval  (+ minimal deps)
cd ../vuls
go run . scan   -config=... alinux3-fixture alinux4-fixture   # pseudo servers from the rpm -qa fixtures
go run . detect -config=...
```

Pass criteria:

- OS detected as `alinux` major `3` / `4`.
- `alinux-release` / base packages produce no false positive (installed
  version >= fixed).
- At least one known-vulnerable package in each fixture is reported with the
  correct `ALINUXn-SA` advisory ID, CVE list, CVSS 3.1 score, and errata
  link `https://alas.aliyun.com/errata/detail/...`.
- Oracle / Alma / Rocky detection unchanged (run their existing e2e/tests).

## 6. Rollout

1. Branch + PR per repo against the `allanhung` forks, in order:
   `vuls-data-update` -> `vuls2` -> `vuls`.
2. Keep `go.mod replace` directives for local cross-repo dev; swap to real
   pseudo-versions once the upstream-of-us repo's PR is merged.
3. File the Alibaba OVAL EVR-corruption bug; link it from
   `pkg/extract/alinux/oval/oval.go`.
4. (Optional follow-up, not in this spec) wire Alibaba Cloud Linux 2, and/or
   finish the half-built `anolis` extractor using the same template.

## 7. Out of scope

- Alibaba Cloud Linux 2 detection.
- Anolis OS detection (shares the format; separate advisories `ANSA`).
- CSAF / SBOM ingestion from the same mirror.
- Upstreaming to `future-architect/vuls` / `MaineK00n/*` (forks only for now).
- Fixing the EVR corruption anywhere other than the Alinux extractor.
