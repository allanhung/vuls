# Alibaba Cloud Linux 3 & 4 Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add end-to-end vulnerability-detection support for Alibaba Cloud Linux 3 and 4 to the Vuls stack (`vuls-data-update` → `vuls2` → `vuls`).

**Architecture:** `vuls-data-update` gains an `alinux/oval` fetcher (HTML-index scrape of `mirrors.aliyun.com`, same patch-OVAL schema as `anolis`/`oracle`) and an `alinux/oval` extractor (copy of `oracle/linux` minus module logic, plus an EVR-corruption normaliser), a new `EcosystemTypeAlinux` + `GetEcosystem` case, and an `AlinuxOVAL` source id. `vuls2` needs only a dependency bump — `alinux:3` / `alinux:4` ride the generic RPM detection path. The `vuls` fork gains `constant.Alinux`, a `scanner/alinux.go` OS handler, `/etc/alinux-release` detection in `redhatbase.go`, entries in ~10 family switches, and an errata-link case.

**Tech Stack:** Go 1.26, cobra CLI, `github.com/PuerkitoBio/goquery` (HTML parse), `github.com/pkg/errors`, `encoding/xml`, `encoding/json/v2`, `github.com/google/go-cmp` (golden tests).

**Spec:** `docs/superpowers/specs/2026-08-28-alinux-support-design.md` (in the `vuls` fork, branch `feat/alinux-support`). Read it alongside this plan.

## Global Constraints

- **Identifier** (verbatim, everywhere): family/ecosystem string = `alinux`; ecosystem values `alinux:3`, `alinux:4`; `sourceTypes.SourceID` = `alinux-oval`; `models.CveContentType` = `alinux` (dynamic, via `models.NewCveContentType`); advisory-reference `Source` = `ALINUX`.
- **Scope:** detection for **major 3 and 4 only**. The fetcher downloads all files the mirror lists (including `alinux-2`); the extractor skips any major that is not `3` or `4` with a `slog.Info` line.
- **OVAL source URL:** `https://mirrors.aliyun.com/alinux/cve/data/OVAL/` — HTML autoindex, plain uncompressed `.oval.xml` (no bzip2), regenerated daily, no auth.
- **EVR corruption:** 75–83 % of `<rpminfo_state>/<evr>` values carry a spliced lowercase-token prefix before the real version (`0:debug-devel-4.19.91-28.7.al7` → `0:4.19.91-28.7.al7`). Repair in `pkg/extract/alinux/oval` **only**; never in shared code. Validate every repair against the clean EVRs in the same definition's OR-group; fail the definition if no clean anchor exists.
- **Errata host:** rewrite the OVAL's internal `alas.aliyun-inc.com` to public `alas.aliyun.com` in advisory reference links.
- **Cross-repo dev:** while implementing, `vuls/go.mod` and `vuls2/go.mod` use `replace` directives pointing at the sibling local checkouts:
  - `/Users/allan/Downloads/git/allanhung/vuls`
  - `/Users/allan/Downloads/git/allanhung/vuls2`
  - `/Users/allan/Downloads/git/allanhung/vuls-data-update`
  Replace directives are removed and pseudo-versions bumped only in the final task of each downstream repo.
- **Reference OVAL data** for fixtures (downloaded 2026-08-28, in this session's scratchpad; re-downloadable from the URL above):
  - `alinux-2.1903.oval.xml` (7.0 MB, major 2, `.al7`)
  - `alinux-3.2104.oval.xml` (16 MB, major 3, `.al8`)
  - `alinux-4.oval.xml` (6.9 MB, major 4, `.alnx4`)
- **Real-host fixtures** for the end-to-end test:
  - Alinux 3: `/tmp/alinux3/os-release.txt`, `/tmp/alinux3/rpm-qa.txt` (1338 pkgs)
  - Alinux 4: `/tmp/alinux4/data.txt` (559 pkgs as `NAME|EPOCHNUM|VERSION|RELEASE|ARCH`, plus `/etc/alinux-release` dump); live host `ssh 10.21.34.9` (refresh `known_hosts:488` first)
- Every task ends with `go build ./...` + `go test ./<touched dirs>/...` green and a commit. Conventional-commit messages; end bodies with `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>`.

---

## Phase A — vuls-data-update

Repo: `/Users/allan/Downloads/git/allanhung/vuls-data-update`. Create branch `feat/alinux-oval` off `main` before Task A1.

### Task A1: Shared contract — ecosystem type + source id

**Files:**
- Modify: `pkg/extract/types/data/detection/segment/ecosystem/ecosystem.go` (const block ~line 11-34; `GetEcosystem` `case EcosystemTypeOracle` ~line 88; error list ~line 149)
- Modify: `pkg/extract/types/source/source.go` (const block; next to `AnolisOVAL` ~line 24)
- Test: `pkg/extract/types/data/detection/segment/ecosystem/ecosystem_test.go` (create if absent)

**Interfaces:**
- Produces: `ecosystemTypes.EcosystemTypeAlinux = "alinux"`; `ecosystemTypes.GetEcosystem("alinux", "3")` → `Ecosystem("alinux:3")`, `("alinux", "4")` → `Ecosystem("alinux:4")`, `("alinux", "3.2104")` → `Ecosystem("alinux:3")`. `sourceTypes.AlinuxOVAL SourceID = "alinux-oval"`.

- [ ] **Step 1: Write the failing test**

Create `pkg/extract/types/data/detection/segment/ecosystem/ecosystem_test.go` (or add the case if the file exists):

```go
package ecosystem

import "testing"

func TestGetEcosystem_Alinux(t *testing.T) {
	for _, tt := range []struct {
		family, release, want string
	}{
		{"alinux", "3", "alinux:3"},
		{"alinux", "4", "alinux:4"},
		{"alinux", "3.2104", "alinux:3"},
	} {
		got, err := GetEcosystem(tt.family, tt.release)
		if err != nil {
			t.Fatalf("GetEcosystem(%q,%q) error: %v", tt.family, tt.release, err)
		}
		if string(got) != tt.want {
			t.Fatalf("GetEcosystem(%q,%q) = %q, want %q", tt.family, tt.release, got, tt.want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/extract/types/data/detection/segment/ecosystem/ -run TestGetEcosystem_Alinux -v`
Expected: FAIL — `GetEcosystem("alinux","3")` returns error `unexpected family`.

- [ ] **Step 3: Add the constant**

In `ecosystem.go`, in the const block, after `EcosystemTypeAlma = "alma"` (keep alphabetical grouping with the other RHEL-likes — put it right after `EcosystemTypeAlma`):

```go
	EcosystemTypeAlinux              = "alinux"
```

- [ ] **Step 4: Add the GetEcosystem case**

In `GetEcosystem`, immediately after the `case EcosystemTypeAlma:` block:

```go
	case EcosystemTypeAlinux:
		return Ecosystem(fmt.Sprintf("%s:%s", family, strings.Split(release, ".")[0])), nil
```

- [ ] **Step 5: Add to the error message family list**

In the `default:` branch's `errors.Errorf("unexpected family. expected: %q, actual: %q", []Ecosystem{...}, family)` slice, add `EcosystemTypeAlinux` next to `EcosystemTypeAlma`.

- [ ] **Step 6: Add the source id**

In `pkg/extract/types/source/source.go`, in the `const (...)` `SourceID` block, directly after `AnolisOVAL SourceID = "anolis-oval"`:

```go
	AlinuxOVAL                 SourceID = "alinux-oval"
```

(Match the existing gofmt column alignment of that block.)

- [ ] **Step 7: Run tests**

Run: `go test ./pkg/extract/types/... -v`
Expected: PASS. Also `go build ./...`.

- [ ] **Step 8: Commit**

```bash
git add pkg/extract/types/
git commit -m "feat(extract/types): add alinux ecosystem type and alinux-oval source id

Shared contract consumed by the alinux OVAL fetcher/extractor and by
vuls2's ecosystem dispatch. GetEcosystem(\"alinux\", <release>) -> alinux:<major>.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task A2: Fetcher — `pkg/fetch/alinux/oval`

**Files:**
- Create: `pkg/fetch/alinux/oval/types.go`
- Create: `pkg/fetch/alinux/oval/oval.go`
- Create: `pkg/fetch/alinux/oval/oval_test.go`
- Create: `pkg/fetch/alinux/oval/testdata/fixtures/happy/index.html`
- Create: `pkg/fetch/alinux/oval/testdata/fixtures/happy/alinux-4.oval.xml` (trimmed)
- Modify: `pkg/cmd/fetch/fetch.go` (import block ~line 22; `cmd.AddCommand(...)` list ~line 225; add `newCmdAlinuxOVAL` func near `newCmdAnolisOVAL` ~line 584)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `oval.Fetch(oval.WithBaseURL(string), oval.WithDir(string), oval.WithRetry(int)) error`. Writes `<dir>/<ver>/definitions/<id>.json`, `<dir>/<ver>/tests/rpminfo_test/<id>.json`, `.../tests/textfilecontent54_test/<id>.json`, `.../objects/rpminfo_object/<id>.json`, `.../objects/textfilecontent54_object/<id>.json`, `.../states/rpminfo_state/<id>.json`, `.../states/textfilecontent54_state/<id>.json`, where `<ver>` is the raw suffix from the filename (`2.1903`, `3.2104`, `4`). Exported named types: `oval.Definition`, `oval.Criteria`, `oval.Criterion`, `oval.RpminfoTest`, `oval.RpminfoObject`, `oval.RpminfoState`, `oval.Textfilecontent54Test`, `oval.Textfilecontent54Object`, `oval.Textfilecontent54State` (consumed by Task A3).

- [ ] **Step 1: Write `types.go`**

Model on `pkg/fetch/oracle/linux/types.go` but with the Alinux schema (confirmed against the live files). Use **named** element types (not anonymous inline structs) so the extractor can reference them:

```go
package oval

type root struct {
	Generator struct {
		ProductName    string `xml:"product_name"`
		ProductVersion string `xml:"product_version"`
		SchemaVersion  string `xml:"schema_version"`
		Timestamp      string `xml:"timestamp"`
	} `xml:"generator"`
	Definitions struct {
		Definition []Definition `xml:"definition"`
	} `xml:"definitions"`
	Tests   Tests   `xml:"tests"`
	Objects Objects `xml:"objects"`
	States  States  `xml:"states"`
}

type Definition struct {
	ID       string `xml:"id,attr" json:"id,omitempty"`
	Version  string `xml:"version,attr" json:"version,omitempty"`
	Class    string `xml:"class,attr" json:"class,omitempty"`
	Metadata struct {
		Title    string `xml:"title" json:"title,omitempty"`
		Affected struct {
			Family   string `xml:"family,attr" json:"family,omitempty"`
			Platform string `xml:"platform" json:"platform,omitempty"`
		} `xml:"affected" json:"affected,omitzero"`
		Reference []struct {
			RefID  string `xml:"ref_id,attr" json:"ref_id,omitempty"`
			RefURL string `xml:"ref_url,attr" json:"ref_url,omitempty"`
			Source string `xml:"source,attr" json:"source,omitempty"`
		} `xml:"reference" json:"reference,omitempty"`
		Description string `xml:"description" json:"description,omitempty"`
		Advisory    struct {
			From     string `xml:"from,attr" json:"from,omitempty"`
			Severity string `xml:"severity" json:"severity,omitempty"`
			Rights   string `xml:"rights" json:"rights,omitempty"`
			Issued   struct {
				Date string `xml:"date,attr" json:"date,omitempty"`
			} `xml:"issued" json:"issued,omitzero"`
			Updated struct {
				Date string `xml:"date,attr" json:"date,omitempty"`
			} `xml:"updated" json:"updated,omitzero"`
			Cve []struct {
				Text   string `xml:",chardata" json:"text,omitempty"`
				Cvss3  string `xml:"cvss3,attr" json:"cvss3,omitempty"`
				Impact string `xml:"impact,attr" json:"impact,omitempty"`
				Cwe    string `xml:"cwe,attr" json:"cwe,omitempty"`
				Href   string `xml:"href,attr" json:"href,omitempty"`
				Public string `xml:"public,attr" json:"public,omitempty"`
			} `xml:"cve" json:"cve,omitempty"`
			AffectedCpeList struct {
				Cpe []string `xml:"cpe" json:"cpe,omitempty"`
			} `xml:"affected_cpe_list" json:"affected_cpe_list,omitzero"`
		} `xml:"advisory" json:"advisory,omitzero"`
	} `xml:"metadata" json:"metadata,omitzero"`
	Criteria Criteria `xml:"criteria" json:"criteria,omitzero"`
}

type Criteria struct {
	Operator   string      `xml:"operator,attr" json:"operator,omitempty"`
	Criterias  []Criteria  `xml:"criteria" json:"criterias,omitempty"`
	Criterions []Criterion `xml:"criterion" json:"criterions,omitempty"`
}

type Criterion struct {
	TestRef string `xml:"test_ref,attr" json:"test_ref,omitempty"`
	Comment string `xml:"comment,attr" json:"comment,omitempty"`
}

type RpminfoTest struct {
	Xmlns   string `xml:"xmlns,attr" json:"xmlns,omitempty"`
	Check   string `xml:"check,attr" json:"check,omitempty"`
	Comment string `xml:"comment,attr" json:"comment,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	ID      string `xml:"id,attr" json:"id,omitempty"`
	Object  struct {
		ObjectRef string `xml:"object_ref,attr" json:"object_ref,omitempty"`
	} `xml:"object" json:"object,omitzero"`
	State struct {
		StateRef string `xml:"state_ref,attr" json:"state_ref,omitempty"`
	} `xml:"state" json:"state,omitzero"`
}

type Textfilecontent54Test struct {
	Xmlns   string `xml:"xmlns,attr" json:"xmlns,omitempty"`
	Check   string `xml:"check,attr" json:"check,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	Comment string `xml:"comment,attr" json:"comment,omitempty"`
	ID      string `xml:"id,attr" json:"id,omitempty"`
	Object  struct {
		ObjectRef string `xml:"object_ref,attr" json:"object_ref,omitempty"`
	} `xml:"object" json:"object,omitzero"`
	State struct {
		StateRef string `xml:"state_ref,attr" json:"state_ref,omitempty"`
	} `xml:"state" json:"state,omitzero"`
}

type Tests struct {
	RpminfoTest           []RpminfoTest           `xml:"rpminfo_test" json:"rpminfo_test,omitempty"`
	Textfilecontent54Test []Textfilecontent54Test `xml:"textfilecontent54_test" json:"textfilecontent54_test,omitempty"`
}

type RpminfoObject struct {
	Xmlns   string `xml:"xmlns,attr" json:"xmlns,omitempty"`
	ID      string `xml:"id,attr" json:"id,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	Name    string `xml:"name" json:"name,omitempty"`
}

type Textfilecontent54Object struct {
	Xmlns    string `xml:"xmlns,attr" json:"xmlns,omitempty"`
	ID       string `xml:"id,attr" json:"id,omitempty"`
	Version  string `xml:"version,attr" json:"version,omitempty"`
	Path     string `xml:"path" json:"path,omitempty"`
	Filename string `xml:"filename" json:"filename,omitempty"`
	Pattern  struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"pattern" json:"pattern,omitzero"`
	Instance struct {
		Text     string `xml:",chardata" json:"text,omitempty"`
		Datatype string `xml:"datatype,attr" json:"datatype,omitempty"`
	} `xml:"instance" json:"instance,omitzero"`
}

type Objects struct {
	RpminfoObject           []RpminfoObject           `xml:"rpminfo_object" json:"rpminfo_object,omitempty"`
	Textfilecontent54Object []Textfilecontent54Object `xml:"textfilecontent54_object" json:"textfilecontent54_object,omitempty"`
}

type RpminfoState struct {
	Xmlns   string `xml:"xmlns,attr" json:"xmlns,omitempty"`
	ID      string `xml:"id,attr" json:"id,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	Evr     *struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Datatype  string `xml:"datatype,attr" json:"datatype,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"evr" json:"evr,omitempty"`
}

type Textfilecontent54State struct {
	Xmlns   string `xml:"xmlns,attr" json:"xmlns,omitempty"`
	ID      string `xml:"id,attr" json:"id,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	Text    struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"text" json:"text,omitzero"`
}

type States struct {
	RpminfoState           []RpminfoState           `xml:"rpminfo_state" json:"rpminfo_state,omitempty"`
	Textfilecontent54State []Textfilecontent54State `xml:"textfilecontent54_state" json:"textfilecontent54_state,omitempty"`
}
```

- [ ] **Step 2: Write `oval.go`**

Model on `pkg/fetch/alma/oval/oval.go` (HTML-index variant). Key differences: base URL, plain XML (no bzip2), file prefix `alinux-` / suffix `.oval.xml`, scrape `<a href>` for `alinux-*.oval.xml`.

```go
package oval

import (
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://mirrors.aliyun.com/alinux/cve/data/OVAL/"

var ovalFilePattern = regexp.MustCompile(`^alinux-[0-9.]+\.oval\.xml$`)

type options struct {
	baseURL string
	dir     string
	retry   int
}

type Option interface{ apply(*options) }

type baseURLOption string

func (u baseURLOption) apply(o *options) { o.baseURL = string(u) }
func WithBaseURL(u string) Option        { return baseURLOption(u) }

type dirOption string

func (d dirOption) apply(o *options) { o.dir = string(d) }
func WithDir(d string) Option        { return dirOption(d) }

type retryOption int

func (r retryOption) apply(o *options) { o.retry = int(r) }
func WithRetry(r int) Option           { return retryOption(r) }

func Fetch(opts ...Option) error {
	options := &options{
		baseURL: baseURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "alinux", "oval"),
		retry:   3,
	}
	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch Alibaba Cloud Linux OVAL")
	ovals, err := options.walkIndexOf()
	if err != nil {
		return errors.Wrap(err, "walk index of")
	}

	for _, ovalname := range ovals {
		ver := strings.TrimPrefix(strings.TrimSuffix(ovalname, ".oval.xml"), "alinux-")

		slog.Info("Fetch Alibaba Cloud Linux OVAL", slog.String("version", ver))
		root, err := options.fetch(ovalname)
		if err != nil {
			return errors.Wrapf(err, "fetch alinux %s oval", ver)
		}

		slog.Info("Fetch Alibaba Cloud Linux Definitions", slog.String("version", ver))
		bar := progressbar.Default(int64(len(root.Definitions.Definition)))
		for _, def := range root.Definitions.Definition {
			p := filepath.Join(options.dir, ver, "definitions", fmt.Sprintf("%s.json", def.ID))
			if err := util.Write(p, def); err != nil {
				return errors.Wrapf(err, "write %s", p)
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		slog.Info("Fetch Alibaba Cloud Linux Tests", slog.String("version", ver))
		bar = progressbar.Default(int64(len(root.Tests.RpminfoTest) + len(root.Tests.Textfilecontent54Test)))
		for _, test := range root.Tests.RpminfoTest {
			p := filepath.Join(options.dir, ver, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID))
			if err := util.Write(p, test); err != nil {
				return errors.Wrapf(err, "write %s", p)
			}
			_ = bar.Add(1)
		}
		for _, test := range root.Tests.Textfilecontent54Test {
			p := filepath.Join(options.dir, ver, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID))
			if err := util.Write(p, test); err != nil {
				return errors.Wrapf(err, "write %s", p)
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		slog.Info("Fetch Alibaba Cloud Linux Objects", slog.String("version", ver))
		bar = progressbar.Default(int64(len(root.Objects.RpminfoObject) + len(root.Objects.Textfilecontent54Object)))
		for _, object := range root.Objects.RpminfoObject {
			p := filepath.Join(options.dir, ver, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID))
			if err := util.Write(p, object); err != nil {
				return errors.Wrapf(err, "write %s", p)
			}
			_ = bar.Add(1)
		}
		for _, object := range root.Objects.Textfilecontent54Object {
			p := filepath.Join(options.dir, ver, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID))
			if err := util.Write(p, object); err != nil {
				return errors.Wrapf(err, "write %s", p)
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		slog.Info("Fetch Alibaba Cloud Linux States", slog.String("version", ver))
		bar = progressbar.Default(int64(len(root.States.RpminfoState) + len(root.States.Textfilecontent54State)))
		for _, state := range root.States.RpminfoState {
			p := filepath.Join(options.dir, ver, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID))
			if err := util.Write(p, state); err != nil {
				return errors.Wrapf(err, "write %s", p)
			}
			_ = bar.Add(1)
		}
		for _, state := range root.States.Textfilecontent54State {
			p := filepath.Join(options.dir, ver, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID))
			if err := util.Write(p, state); err != nil {
				return errors.Wrapf(err, "write %s", p)
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()
	}

	return nil
}

func (opts options) walkIndexOf() ([]string, error) {
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(opts.baseURL)
	if err != nil {
		return nil, errors.Wrap(err, "fetch index of")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "parse as html")
	}

	seen := map[string]struct{}{}
	var ovals []string
	d.Find("a").Each(func(_ int, s *goquery.Selection) {
		href, ok := s.Attr("href")
		if !ok {
			return
		}
		name := strings.TrimSuffix(path.Base(href), "/")
		if !ovalFilePattern.MatchString(name) {
			return
		}
		if _, dup := seen[name]; dup {
			return
		}
		seen[name] = struct{}{}
		ovals = append(ovals, name)
	})
	if len(ovals) == 0 {
		return nil, errors.Errorf("no alinux-*.oval.xml links found at %s", opts.baseURL)
	}
	return ovals, nil
}

func (opts options) fetch(ovalname string) (*root, error) {
	u, err := url.JoinPath(opts.baseURL, ovalname)
	if err != nil {
		return nil, errors.Wrap(err, "join url path")
	}

	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(u)
	if err != nil {
		return nil, errors.Wrapf(err, "fetch %s", u)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var r root
	if err := xml.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, errors.Wrap(err, "decode xml")
	}
	return &r, nil
}
```

Add `"path"` to the import list (used in `walkIndexOf`). Run `goimports`.

- [ ] **Step 3: Build the trimmed fixtures**

From the real `alinux-4.oval.xml` (scratchpad), create `testdata/fixtures/happy/alinux-4.oval.xml` containing the `<oval_definitions>` root + generator + **exactly 2 `<definition>` blocks** and their referenced tests/objects/states:
  - one "clean" advisory (e.g. a small non-kernel one, all EVRs already `^\d+:\d`);
  - one "corrupted" advisory (a `kernel` one — includes `kernel:6.6` object name and several `0:debug-...` / `0:devel-...` corrupted EVRs, plus the clean `kernel` / `bpftool` anchors).
Keep the single `<textfilecontent54_test id="oval:com.aliyun:tst:1">` + its object/state.

Create `testdata/fixtures/happy/index.html`:

```html
<!DOCTYPE html><html><body>
<a href="../">../</a>
<a href="alinux-2.1903.oval.xml">alinux-2.1903.oval.xml</a>
<a href="alinux-3.2104.oval.xml">alinux-3.2104.oval.xml</a>
<a href="alinux-4.oval.xml">alinux-4.oval.xml</a>
</body></html>
```

- [ ] **Step 4: Write `oval_test.go`**

Model on `pkg/fetch/anolis/oval/oval_test.go` but the test HTTP server serves `index.html` for the directory path and the trimmed `alinux-4.oval.xml` for the file path; only `alinux-4.oval.xml` returns 200 (the 2 and 3 URLs return 404 so the test stays small). Assert the fetch writes the expected JSON tree under `<tmp>/4/...` and that a known definition/test/object/state file exists with expected content (use `cmp.Diff` against golden files under `testdata/golden/4/...`, generated with an `-update` flag as anolis does).

```go
package oval_test

import (
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/alinux/oval"
)

func TestFetch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/OVAL/") || strings.HasSuffix(r.URL.Path, "/OVAL"):
			http.ServeFile(w, r, filepath.Join("testdata", "fixtures", "happy", "index.html"))
		case path.Base(r.URL.Path) == "alinux-4.oval.xml":
			http.ServeFile(w, r, filepath.Join("testdata", "fixtures", "happy", "alinux-4.oval.xml"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	dir := t.TempDir()
	if err := oval.Fetch(oval.WithBaseURL(ts.URL+"/alinux/cve/data/OVAL/"), oval.WithDir(dir), oval.WithRetry(0)); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	for _, rel := range []string{
		"4/definitions", "4/tests/rpminfo_test", "4/objects/rpminfo_object", "4/states/rpminfo_state",
	} {
		entries, err := filepath.Glob(filepath.Join(dir, rel, "*.json"))
		if err != nil || len(entries) == 0 {
			t.Fatalf("expected json files under %s, got %v (err %v)", rel, entries, err)
		}
	}
}
```

(Expand with golden-file `cmp.Diff` assertions matching the anolis test's structure.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./pkg/fetch/alinux/... -v`
Expected: PASS.

- [ ] **Step 6: Register the fetch subcommand**

In `pkg/cmd/fetch/fetch.go`:
- import block (after `anolisOVAL "..."` line): `alinuxOVAL "github.com/MaineK00n/vuls-data-update/pkg/fetch/alinux/oval"` — placed to keep import order (`alinux` sorts before `alpine`/`alt`/`amazon`; put it before `altOVAL`).
- `cmd.AddCommand(...)` list: add `newCmdAlinuxOVAL(),` on the line with `newCmdAnolisOVAL()` grouping — put it right after `newCmdAlpineSecDB(), newCmdAlpineOSV(),` block or near `newCmdAnolisOVAL()`; grouping is cosmetic.
- add the constructor next to `newCmdAnolisOVAL`:

```go
func newCmdAlinuxOVAL() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "alinux", "oval"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "alinux-oval",
		Short: "Fetch Alibaba Cloud Linux OVAL data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch alinux-oval
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := alinuxOVAL.Fetch(alinuxOVAL.WithDir(options.dir), alinuxOVAL.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch alinux oval")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", options.retry, "number of retry http request")

	return cmd
}
```

- [ ] **Step 7: Verify the command wires up**

Run: `go run ./cmd/vuls-data-update fetch alinux-oval --help`
Expected: help text prints, no panic. `go build ./...` green.

- [ ] **Step 8: Live smoke (optional but recommended)**

Run: `go run ./cmd/vuls-data-update fetch alinux-oval -d /tmp/alinux-fetch`
Expected: writes `/tmp/alinux-fetch/{2.1903,3.2104,4}/definitions/*.json` etc. Spot-check one JSON file.

- [ ] **Step 9: Commit**

```bash
git add pkg/fetch/alinux/ pkg/cmd/fetch/fetch.go
git commit -m "feat(fetch): add Alibaba Cloud Linux OVAL fetcher

Scrapes the mirrors.aliyun.com HTML autoindex for alinux-*.oval.xml,
decodes the com.aliyun patch-OVAL (same schema as anolis/oracle) and
writes per-object JSON under fetch/alinux/oval/<version>/.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task A3: Extractor — `pkg/extract/alinux/oval`

**Files:**
- Create: `pkg/extract/alinux/oval/oval.go`
- Create: `pkg/extract/alinux/oval/evr.go` (the normaliser — kept separate so it is trivially unit-testable)
- Create: `pkg/extract/alinux/oval/evr_test.go`
- Create: `pkg/extract/alinux/oval/oval_test.go`
- Create: `pkg/extract/alinux/oval/testdata/fixtures/...` (fetch-shaped JSON tree; derive from Task A2's trimmed fixture by running the fetcher on it, or hand-write a minimal tree)
- Create: `pkg/extract/alinux/oval/testdata/golden/...`
- Modify: `pkg/cmd/extract/extract.go` (import ~line 97; `cmd.AddCommand` list ~line 195; new `newCmdAlinuxOVAL` near `newCmdOracleLinux` ~line 2387)

**Interfaces:**
- Consumes: `oval.*` types from Task A2; `ecosystemTypes.EcosystemTypeAlinux`, `sourceTypes.AlinuxOVAL` from Task A1.
- Produces: `oval.Extract(inputDir string, opts ...oval.Option) error` (option `oval.WithDir(string)`). Writes `<dir>/data/<year>/<ADVISORY_ID>.json` (`:` in the id replaced with `-` for the filename) as `dataTypes.Data`, and `<dir>/datasource.json`. Emits detections with `Ecosystem` = `alinux:3` / `alinux:4`; skips majors other than 3/4.

- [ ] **Step 1: Write the failing EVR normaliser test**

`pkg/extract/alinux/oval/evr_test.go`:

```go
package oval

import "testing"

func TestSanitizeEVR(t *testing.T) {
	clean := map[string]struct{}{"0:4.19.91-28.7.al7": {}, "0:7.1-3.alnx4": {}}
	for _, tt := range []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"0:4.19.91-28.7.al7", "0:4.19.91-28.7.al7", false},         // already clean
		{"0:debug-devel-4.19.91-28.7.al7", "0:4.19.91-28.7.al7", false},
		{"0:devel-4.19.91-28.7.al7", "0:4.19.91-28.7.al7", false},
		{"0:utils-devel-7.1-3.alnx4", "0:7.1-3.alnx4", false},
		{"0:agents-4.9.0-54.al8.36", "", true},                      // repaired value not among clean anchors
		{"0:", "", true},                                            // empty version
		{"4.19.91-28.7.al7", "", true},                              // missing epoch
	} {
		got, err := sanitizeEVR(tt.in, clean)
		if (err != nil) != tt.wantErr {
			t.Fatalf("sanitizeEVR(%q) err=%v wantErr=%v", tt.in, err, tt.wantErr)
		}
		if !tt.wantErr && got != tt.want {
			t.Fatalf("sanitizeEVR(%q) = %q want %q", tt.in, got, tt.want)
		}
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./pkg/extract/alinux/oval/ -run TestSanitizeEVR -v`
Expected: FAIL — `sanitizeEVR` undefined.

- [ ] **Step 3: Implement `evr.go`**

```go
package oval

import (
	"regexp"

	"github.com/pkg/errors"
)

// evrNoiseToken matches one leading lowercase-letter-led "<token>-" run. The
// real RPM version always starts with a digit and never contains a bare
// lowercase token before its first digit, so stripping these runs recovers
// the version from the Alibaba Cloud Linux OVAL EVR-corruption bug, e.g.
// "debug-devel-4.19.91-28.7.al7" -> "4.19.91-28.7.al7".
var evrNoiseToken = regexp.MustCompile(`^[a-z][a-z0-9_+]*-`)

// sanitizeEVR repairs a possibly-corrupted "epoch:version-release" string.
// clean is the set of already-clean EVRs (version starts with a digit) seen
// elsewhere in the same advisory's OR-group. A repaired value MUST appear in
// clean when clean is non-empty; otherwise the repair is rejected so bad data
// can never reach the detection DB.
func sanitizeEVR(evr string, clean map[string]struct{}) (string, error) {
	i := indexByte(evr, ':')
	if i < 0 {
		return "", errors.Errorf("evr has no epoch separator: %q", evr)
	}
	epoch, rest := evr[:i], evr[i+1:]
	if rest == "" {
		return "", errors.Errorf("evr has empty version: %q", evr)
	}
	if isDigit(rest[0]) {
		return evr, nil
	}
	for len(rest) > 0 && !isDigit(rest[0]) {
		loc := evrNoiseToken.FindStringIndex(rest)
		if loc == nil {
			break
		}
		rest = rest[loc[1]:]
	}
	if rest == "" || !isDigit(rest[0]) {
		return "", errors.Errorf("cannot repair corrupted evr: %q", evr)
	}
	repaired := epoch + ":" + rest
	if len(clean) > 0 {
		if _, ok := clean[repaired]; !ok {
			return "", errors.Errorf("repaired evr %q (from %q) is not among the advisory's clean anchors", repaired, evr)
		}
	}
	return repaired, nil
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
```

- [ ] **Step 4: Run the EVR test to verify it passes**

Run: `go test ./pkg/extract/alinux/oval/ -run TestSanitizeEVR -v`
Expected: PASS. (If the `0:agents-...` case does not error, the `clean` set check is wrong — fix before moving on.)

- [ ] **Step 5: Implement `oval.go`**

Start from `pkg/extract/oracle/linux/linux.go`. Changes:

1. **Package + imports:** package `oval`; import `oval` types via
   `"github.com/MaineK00n/vuls-data-update/pkg/fetch/alinux/oval"` — but this
   package *is* `oval`, so instead **import the fetch package with an alias**:
   `alinux "github.com/MaineK00n/vuls-data-update/pkg/fetch/alinux/oval"` and
   reference `alinux.Definition` etc. (The extractor package is
   `pkg/extract/alinux/oval`, import path distinct from the fetch one.)
2. **`Extract(inputDir, opts...)`** default dir
   `filepath.Join(util.CacheDir(), "extract", "alinux", "oval")`.
3. **Walk** `filepath.Join(inputDir, v, "definitions")` for `v` in the set of
   immediate sub-directories of `inputDir` (`os.ReadDir`), and for each parse
   `major := strings.Split(v, ".")[0]`. If `major` is not `"3"` or `"4"`,
   `slog.Info("skip unsupported Alibaba Cloud Linux major", ...)` and `continue`.
4. **Advisory id:** from `def.Metadata.Reference` — the entry whose `Source`
   matches `^ALINUX\d-SA$`; use its `RefID` (`ALINUX3-SA-2026:0255`). Error if
   absent. `rootID := dataTypes.RootID(refID)`.
5. **Year / output path:** `m := regexp.MustCompile(`^ALINUX\d-SA-(\d{4}):(\d+)$`).FindStringSubmatch(refID)`; year `m[1]`. Write to
   `filepath.Join(options.dir, "data", year, fmt.Sprintf("%s.json", strings.ReplaceAll(refID, ":", "-")))`.
6. **collectPackages / evalCriteria / evalCriterions:** keep Oracle's recursion
   structure. In `evalCriterions`:
   - read `alinux.RpminfoTest` → `alinux.RpminfoObject` (name) + `alinux.RpminfoState` (evr).
   - `name := strings.SplitN(obj.Name, ":", 2)[0]` (folds `kernel:6.6` → `kernel`).
   - if `state.Evr == nil` → skip criterion (the OS-installed `textfilecontent54` test path: on `os.ErrNotExist` for the rpminfo file, fall through to reading `alinux.Textfilecontent54Test`; that test only identifies the platform and carries no package, so treat it as the "base ANY" and continue — **no** `modules.d` handling).
   - assert `state.Evr.Operation == "less than"`.
   - **defer EVR sanitisation to a second pass** (see 7).
   - `modularityLabel` is always `""`.
7. **Two-pass EVR repair per definition:** first pass collects every raw
   `state.Evr.Text` for the definition into `rawEVRs`, and the subset that is
   already clean (`regexp.MustCompile(`^\d+:\d`).MatchString`) into
   `clean := map[string]struct{}{}`. Second pass calls
   `sanitizeEVR(raw, clean)` for each package's fixed version. If any call
   errors, wrap with the definition id and **return the error** (fail the
   definition — do not emit partial data). Maintain a package-level counter
   and `slog.Warn("repaired corrupted Alibaba Cloud Linux OVAL EVRs", slog.Int("count", n), slog.String("version", v))` once per version dir.
8. **Detection ecosystem:** `ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeAlinux, major))`. Reuse Oracle's
   `map[string][]criterionTypes.Criterion` → `[]detectionTypes.Detection` shape
   (binary package, `RangeTypeRPM`, `LessThan: fixedVersion`, `Fixed: [...]`).
9. **Severity:**
   - advisory-level: `severityTypes.Severity{Type: severityTypes.SeverityTypeVendor, Source: "alas.aliyun.com", Vendor: &def.Metadata.Advisory.Severity}`.
   - per-CVE from `cve.Cvss3` — only CVSS 3.x. Cut on the first `/`; if the
     remainder has prefix `CVSS:3.0` parse with `cvssV30Types.Parse`, if
     `CVSS:3.1` parse with `cvssV31Types.Parse`, else error. Mirror Oracle's
     `slog.Warn` + `errors.Is(err, gocvss3x.Err...)` tolerance. No CVSS 2 branch.
10. **Vulnerabilities:** one `vulnerabilityTypes.Vulnerability` per
    `def.Metadata.Advisory.Cve`, `ID = cve.Text`, `References` = `[{Source: "alas.aliyun.com", URL: rewriteHost(cve.Href)}]`, `Published = utiltime.Parse([]string{"20060102"}, cve.Public)`, `Segments = segs`.
11. **Advisory:** `advisoryContentTypes.Content{ ID, Title: strings.TrimSpace(def.Metadata.Title), Description: strings.TrimSpace(def.Metadata.Description), Severity: [...vendor...], References: rewriteHost(each reference.RefURL) with Source "alas.aliyun.com", Published: utiltime.Parse([]string{"2006-01-02"}, def.Metadata.Advisory.Issued.Date) }`.
12. **`rewriteHost`:** helper — `strings.Replace(u, "alas.aliyun-inc.com", "alas.aliyun.com", 1)`.
13. **datasource.json:** `datasourceTypes.DataSource{ ID: sourceTypes.AlinuxOVAL, Name: new("Alibaba Cloud Linux OVAL"), Raw / Extracted: utilgit helpers as Oracle does }`. `DataSource` field on each `dataTypes.Data` → `sourceTypes.Source{ ID: sourceTypes.AlinuxOVAL, Raws: e.r.Paths() }`.

- [ ] **Step 6: Write `oval_test.go` (golden)**

Model on `pkg/extract/oracle/linux/linux_test.go`. Build the input tree under
`testdata/fixtures/` by running the Task A2 fetcher against its trimmed
`alinux-4.oval.xml` fixture (script it in the test's `TestMain` or check the
tree in). Assert:
  - the corrupted-kernel advisory produces detections whose `LessThan` is the
    repaired `0:6.6.102-7.alnx4` for every kernel sub-package;
  - `kernel:6.6` and `kernel` collapse to a single `kernel` criterion;
  - ecosystem is `alinux:4`;
  - advisory id / year / filename (`ALINUX4-SA-2026-0392.json`) are correct;
  - a fixture definition with a deliberately unrepairable EVR (no clean
    anchor) makes `Extract` return an error.
Use the `-update` golden pattern from the Oracle test.

- [ ] **Step 7: Run tests**

Run: `go test ./pkg/extract/alinux/... -v`
Expected: PASS.

- [ ] **Step 8: Register the extract subcommand**

In `pkg/cmd/extract/extract.go`:
- import (keep sorted; `alinux` sorts early — near the top of the alias list):
  `alinuxOVAL "github.com/MaineK00n/vuls-data-update/pkg/extract/alinux/oval"`
- `cmd.AddCommand(...)`: add `newCmdAlinuxOVAL(),` (place near the Alma group).
- constructor near `newCmdOracleLinux`:

```go
func newCmdAlinuxOVAL() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "alinux", "oval"),
	}

	cmd := &cobra.Command{
		Use:   "alinux-oval <Raw Alibaba Cloud Linux OVAL Repository PATH>",
		Short: "Extract Alibaba Cloud Linux OVAL data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract alinux-oval vuls-data-raw-alinux-oval
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := alinuxOVAL.Extract(args[0], alinuxOVAL.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract alinux oval")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output extract results to specified directory")

	return cmd
}
```

- [ ] **Step 9: Full-data smoke**

```bash
go run ./cmd/vuls-data-update fetch   alinux-oval -d /tmp/alinux-fetch
go run ./cmd/vuls-data-update extract alinux-oval /tmp/alinux-fetch -d /tmp/alinux-extract
```
Expected: `/tmp/alinux-extract/data/<year>/ALINUX{3,4}-SA-*.json` written; **no** `ALINUX2-*`; `slog.Warn` reports a large repaired-EVR count; no error. Spot-check that a kernel advisory JSON has clean `lessThan` versions.

- [ ] **Step 10: Commit**

```bash
git add pkg/extract/alinux/ pkg/cmd/extract/extract.go
git commit -m "feat(extract): add Alibaba Cloud Linux OVAL extractor

Converts com.aliyun patch-OVAL into detection data keyed by ecosystem
alinux:3 / alinux:4 (majors 2 skipped). Includes an EVR normaliser that
repairs the upstream corruption where a sub-package name fragment is
spliced before the version (~75-83% of rpminfo_state entries), validated
against the clean EVR anchors in each advisory's OR-group.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task A4: File the upstream bug + open the PR

- [ ] **Step 1:** Add a code comment at the top of `pkg/extract/alinux/oval/evr.go` linking the upstream bug report once filed.
- [ ] **Step 2:** File an issue with Alibaba Cloud Linux / OpenAnolis (mirror contact `ali-yum@alibaba-inc.com`, or the alinux repo tracker) describing the `<rpminfo_state>/<evr>` corruption, with the measured rates and 2–3 concrete `advisory-id / package / observed / expected` rows from §3.2 of the spec.
- [ ] **Step 3:** Push `feat/alinux-oval`, open a PR against `allanhung/vuls-data-update:main`. Body references the spec and lists the 3 commits.
- [ ] **Step 4 (after self/CI review):** merge; note the merge commit SHA — Phase B/C bump to it.

---

## Phase B — vuls2

Repo: `/Users/allan/Downloads/git/allanhung/vuls2`. Branch `feat/alinux` off `main`.

### Task B1: Dependency bump + detection-path verification

**Files:**
- Modify: `go.mod`, `go.sum`
- Test: `pkg/detect/ospkg/ospkg_test.go` (or the nearest existing detect table test)

**Interfaces:**
- Consumes: `ecosystemTypes.EcosystemTypeAlinux` / `GetEcosystem` from Phase A.
- Produces: a `vuls2` module version in which `ospkg.Detect` resolves `alinux:3` / `alinux:4` and routes them through `base.Detect`.

- [ ] **Step 1: Point at local vuls-data-update**

Add to `go.mod`:

```
replace github.com/MaineK00n/vuls-data-update => ../vuls-data-update
```

Run `go mod tidy`.

- [ ] **Step 2: Write the failing test**

In `pkg/detect/ospkg/ospkg_test.go` (create if absent):

```go
package ospkg

import (
	"testing"

	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
)

func TestDetect_AlinuxEcosystemResolves(t *testing.T) {
	for _, rel := range []string{"3", "4"} {
		eco, err := ecosystemTypes.GetEcosystem("alinux", rel)
		if err != nil {
			t.Fatalf("GetEcosystem(alinux,%s): %v", rel, err)
		}
		if string(eco) != "alinux:"+rel {
			t.Fatalf("ecosystem = %q, want alinux:%s", eco, rel)
		}
	}
	// Detect must not panic / must not hit the Microsoft branch for alinux.
	_ = scanTypes.ScanResult{Family: "alinux", Release: "4"}
}
```

- [ ] **Step 3: Run it**

Run: `go test ./pkg/detect/ospkg/ -run TestDetect_AlinuxEcosystemResolves -v`
Expected: PASS once Step 1's replace is in (the constant now exists). If it FAILs with `unexpected family`, Phase A Task A1 is not actually on the local path — fix the replace / `go mod tidy`.

- [ ] **Step 4: Audit `base.go` for family gaps**

Run: `grep -n "EcosystemType" pkg/detect/ospkg/base/base.go`
Confirm every `switch family` in `convertVCQueryPackage`, `rename`, `isKernelPackage` has a `default` that is correct for a generic RPM distro (it does today — only Debian/Ubuntu/RedHat/CentOS are special-cased, and Alinux wants the generic path). **Only if** a switch lacks a safe default, add `case ecosystemTypes.EcosystemTypeAlinux:` alongside `ecosystemTypes.EcosystemTypeRedHat`. Document the finding in the commit message either way.

- [ ] **Step 5: Bump to the merged commit**

Once Phase A's PR is merged, replace the `replace` with a real bump:

```bash
go get github.com/MaineK00n/vuls-data-update@<merge-sha>
# remove the replace line
go mod tidy
```

- [ ] **Step 6: Run the detect suite**

Run: `go test ./pkg/detect/...`
Expected: PASS.

- [ ] **Step 7: Commit + PR**

```bash
git add go.mod go.sum pkg/detect/ospkg/ospkg_test.go
git commit -m "feat: recognise alinux:3 / alinux:4 ecosystems

Bumps vuls-data-update for EcosystemTypeAlinux. Alibaba Cloud Linux
rides the generic RPM path in base.Detect; no family-specific handling
required (verified: rename/isKernelPackage/convertVCQueryPackage all
have correct RPM defaults).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

Open PR against `allanhung/vuls2:main`; note the merge SHA for Phase C.

---

## Phase C — vuls (fork)

Repo: `/Users/allan/Downloads/git/allanhung/vuls`. Continue on branch `feat/alinux-support` (already has the spec commit).

### Task C1: `constant.Alinux` + `scanner/alinux.go` + OS detection

**Files:**
- Modify: `constant/constant.go` (add after the `Oracle` block ~line 33)
- Create: `scanner/alinux.go`
- Modify: `scanner/redhatbase.go` (new detection block after the Oracle block ~line 70, before the AlmaLinux block ~line 72; `parseInstalledPackagesLineFromRepoquery` family list ~line 871 is Task C2)
- Modify: `scanner/scanner.go` (`ParseInstalledPkgs` switch ~line 279)
- Test: `scanner/redhatbase_test.go`

**Interfaces:**
- Produces: `constant.Alinux = "alinux"`; `newAlinux(config.ServerInfo) *alinux` with `redhatBase` embedded; `detectRedhat` returns `(true, *alinux)` for an Alinux 3/4 host with `Distro{Family: constant.Alinux, Release: "<major>"}`.

- [ ] **Step 1: Write the failing detection test**

In `scanner/redhatbase_test.go`, add:

```go
func TestDetectAlinux(t *testing.T) {
	// cat /etc/alinux-release output -> expected (family, release)
	tests := []struct {
		release      string
		wantFamily   string
		wantRelease  string
		wantErr      bool
	}{
		{"Alibaba Cloud Linux release 4 (OpenAnolis Edition) ", constant.Alinux, "4", false},
		{"Alibaba Cloud Linux release 3.2104 (Soaring Falcon) ", constant.Alinux, "3.2104", false},
		{"Alibaba Cloud Linux (Aliyun Linux) release 2.1903 (Hunting Beagle) ", "", "", true}, // major 2 unsupported
	}
	for _, tt := range tests {
		got := releasePattern.FindStringSubmatch(strings.TrimSpace(tt.release))
		if len(got) != 3 {
			if !tt.wantErr {
				t.Fatalf("releasePattern did not match %q", tt.release)
			}
			continue
		}
		// name is got[1], version got[2]
		if strings.ToLower(strings.TrimSpace(strings.TrimSuffix(got[1], "(Aliyun Linux)"))) == "" {
			t.Fatalf("unexpected name parse for %q", tt.release)
		}
	}
}
```

(This is a lightweight regex-level guard. The full behavioural test — feeding a fake `exec` — follows the existing `TestScanUpdatablePackages` / `redhatBase` test harness in this file; model the new case on how `TestX` fakes `/etc/rocky-release`.)

- [ ] **Step 2: Run it**

Run: `go test ./scanner/ -run TestDetectAlinux -v`
Expected: FAIL (compile error: `constant.Alinux` undefined).

- [ ] **Step 3: Add the constant**

`constant/constant.go`, after the `Oracle` block:

```go
	// Alinux is
	Alinux = "alinux"
```

- [ ] **Step 4: Create `scanner/alinux.go`**

Structural copy of `scanner/rocky.go` with `rocky`→`alinux`, `Rocky`→`Alinux`:

```go
package scanner

import (
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
)

// inherit OsTypeInterface
type alinux struct {
	redhatBase
}

// newAlinux is constructor
func newAlinux(c config.ServerInfo) *alinux {
	r := &alinux{
		redhatBase{
			base: base{
				osPackages: osPackages{
					Packages:  models.Packages{},
					VulnInfos: models.VulnInfos{},
				},
			},
			sudo: rootPrivAlinux{},
		},
	}
	r.log = logging.NewNormalLogger()
	r.setServerInfo(c)
	return r
}

func (o *alinux) checkScanMode() error { return nil }

func (o *alinux) checkDeps() error {
	if o.getServerInfo().Mode.IsFast() {
		return o.execCheckDeps(o.depsFast())
	}
	if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckDeps(o.depsFastRoot())
	}
	return o.execCheckDeps(o.depsDeep())
}

func (o *alinux) depsFast() []string {
	if o.getServerInfo().Mode.IsOffline() {
		return []string{}
	}
	return []string{"yum-utils"}
}

func (o *alinux) depsFastRoot() []string {
	if o.getServerInfo().Mode.IsOffline() {
		return []string{}
	}
	return []string{"yum-utils"}
}

func (o *alinux) depsDeep() []string { return o.depsFastRoot() }

func (o *alinux) checkIfSudoNoPasswd() error {
	if o.getServerInfo().Mode.IsFast() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFast())
	}
	if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFastRoot())
	}
	return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsDeep())
}

func (o *alinux) sudoNoPasswdCmdsFast() []cmd { return []cmd{} }

func (o *alinux) sudoNoPasswdCmdsFastRoot() []cmd {
	if !o.ServerInfo.IsContainer() {
		return []cmd{
			{"repoquery -h", exitStatusZero},
			{"needs-restarting", exitStatusZero},
			{"which which", exitStatusZero},
			{"stat /proc/1/exe", exitStatusZero},
			{"ls -l /proc/1/exe", exitStatusZero},
			{"cat /proc/1/maps", exitStatusZero},
			{"lsof -i -P -n", exitStatusZero},
		}
	}
	return []cmd{
		{"repoquery -h", exitStatusZero},
		{"needs-restarting", exitStatusZero},
	}
}

func (o *alinux) sudoNoPasswdCmdsDeep() []cmd { return o.sudoNoPasswdCmdsFastRoot() }

type rootPrivAlinux struct{}

func (o rootPrivAlinux) repoquery() bool     { return false }
func (o rootPrivAlinux) yumMakeCache() bool  { return false }
func (o rootPrivAlinux) yumPS() bool         { return false }
```

- [ ] **Step 5: Add the detection block in `redhatbase.go`**

Immediately after the Oracle block's closing `}` (the block that starts `if r := exec(c, "ls /etc/oracle-release", noSudo); r.isSuccess() {`), and **before** `if r := exec(c, "ls /etc/almalinux-release", noSudo); ...`:

```go
	if r := exec(c, "ls /etc/alinux-release", noSudo); r.isSuccess() {
		// Alibaba Cloud Linux ships an RHEL-compatible /etc/redhat-release and
		// (on 3) /etc/centos-release, so it must be discovered before the
		// AlmaLinux / Rocky / CentOS blocks.
		if r := exec(c, "cat /etc/alinux-release", noSudo); r.isSuccess() {
			ali := newAlinux(c)
			result := releasePattern.FindStringSubmatch(strings.TrimSpace(r.Stdout))
			if len(result) != 3 {
				ali.setErrs([]error{xerrors.Errorf("Failed to parse /etc/alinux-release. r.Stdout: %s", r.Stdout)})
				return true, ali
			}

			release := result[2]
			major, err := strconv.Atoi(util.Major(release))
			if err != nil {
				ali.setErrs([]error{xerrors.Errorf("Failed to parse major version from release: %s", release)})
				return true, ali
			}
			if major < 3 {
				ali.setErrs([]error{xerrors.Errorf("Failed to init Alibaba Cloud Linux. err: not supported major version. versions prior to Alibaba Cloud Linux 3 are not supported, detected version is %s", release)})
				return true, ali
			}

			name := strings.ToLower(strings.TrimSpace(strings.Replace(result[1], "(Aliyun Linux)", "", 1)))
			switch name {
			case "alibaba cloud linux":
				ali.setDistro(constant.Alinux, release)
				return true, ali
			default:
				ali.setErrs([]error{xerrors.Errorf("Failed to parse Alibaba Cloud Linux Name. release: %s", result[1])})
				return true, ali
			}
		}
	}
```

- [ ] **Step 6: Wire the package-parse dispatch**

`scanner/scanner.go` `ParseInstalledPkgs` switch — after `case constant.Rocky:`:

```go
	case constant.Alinux:
		osType = &alinux{redhatBase: redhatBase{base: base}}
```

- [ ] **Step 7: Add the `parseInstalledPackages` test with the real fixture**

In `scanner/redhatbase_test.go`, add a case to the existing `parseInstalledPackages` table (mirror the `constant.Alma` case at ~line 32): feed ~10 lines pulled from `/tmp/alinux4/data.txt` converted to the scanner's expected `rpm -qa` format, assert `Distro{Family: constant.Alinux, Release: "4"}` yields the expected `models.Package{Name,Version,Release,Arch}` entries (including `alinux-release` and a `kernel` entry `6.6.102-5.3.3.alnx4`).

- [ ] **Step 8: Run tests**

Run: `go test ./scanner/ -run 'Alinux|ParseInstalled|Detect' -v`
Expected: PASS. `go build ./...` green (there will still be `default`-case gaps elsewhere — those are Task C2; build must still pass since new family just isn't listed).

- [ ] **Step 9: Commit**

```bash
git add constant/constant.go scanner/alinux.go scanner/redhatbase.go scanner/scanner.go scanner/redhatbase_test.go
git commit -m "feat(scanner): detect Alibaba Cloud Linux 3 and 4

Adds constant.Alinux, scanner/alinux.go (dnf-based redhatBase handler),
and /etc/alinux-release detection ahead of the AlmaLinux/Rocky/CentOS
blocks. Major < 3 is rejected.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task C2: Wire `constant.Alinux` into the remaining family switches

**Files (all Modify):**
- `config/os.go` (`GetEOL` — add case after `constant.Rocky` ~line 96)
- `scanner/utils.go` (`isRunningKernel` outer family list ~line 22)
- `scanner/redhatbase.go` (`isExecNeedsRestarting` list ~line 871; `parseInstalledPackagesLineFromRepoquery` switch ~line 871 area — the `case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky, constant.Oracle:` at line 871)
- `models/cvecontents.go` (`GetCveContentTypes` — after `constant.Rocky` ~line 446)
- `reporter/sbom/purl.go` (`osPkgToPURL` RPM list ~line 17)
- `detector/detector.go` (vuls2 family gate ~line 239)
- Test: `config/os_test.go`, `scanner/utils_test.go` (extend existing tables)

**Interfaces:**
- Consumes: `constant.Alinux` (Task C1).
- Produces: `config.GetEOL("alinux", "4")` returns a populated `EOL` with `found == true`; `detector.DetectPkgCves` routes `alinux` through `vuls2.DetectPkgs`.

- [ ] **Step 1: Write failing EOL test**

`config/os_test.go` — add to the table:

```go
{
	name:   "Alibaba Cloud Linux 4",
	fields: fields{family: constant.Alinux, release: "4"},
	now:    time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	found:  true,
	stdEOL: time.Date(2033, 3, 31, 23, 59, 59, 0, time.UTC),
},
```

(Adjust `name`/assertion field names to match the existing `TestEOL` table in that file.)

- [ ] **Step 2: Run it**

Run: `go test ./config/ -run EOL -v`
Expected: FAIL — `found == false` for `alinux`.

- [ ] **Step 3: Add the EOL case**

`config/os.go`, after the `case constant.Rocky:` block in `GetEOL`:

```go
	case constant.Alinux:
		// https://www.alibabacloud.com/help/en/alinux/product-overview/lifecycle-of-alibaba-cloud-linux
		// Dates below are the published EOL for the 3.2104 LTS line and the
		// projected 4.x window; refine when Alibaba publishes firm 4.x dates.
		eol, found = map[string]EOL{
			"3": {StandardSupportUntil: time.Date(2030, 3, 31, 23, 59, 59, 0, time.UTC)},
			"4": {StandardSupportUntil: time.Date(2033, 3, 31, 23, 59, 59, 0, time.UTC)},
		}[major(release)]
```

- [ ] **Step 4: Add to `isRunningKernel`**

`scanner/utils.go` line ~22 — add `constant.Alinux` to:

```go
	case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky, constant.Fedora, constant.Oracle, constant.Amazon, constant.Alinux:
```

The inner `switch family { case constant.RedHat, constant.CentOS, constant.Oracle: ... case constant.Fedora: ... default: ... }` already has a `default` that formats `%s-%s.%s` (matches Alinux's `6.6.102-5.3.3.alnx4.x86_64` uname) — **no inner change**.

- [ ] **Step 5: Add to `isExecNeedsRestarting`**

`scanner/redhatbase.go` ~line 871:

```go
	case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky, constant.Oracle, constant.Alinux:
```

- [ ] **Step 6: Add to `parseInstalledPackagesLineFromRepoquery`**

`scanner/redhatbase.go` — the `case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky, constant.Oracle:` around line 871 (the repoquery line parser). Add `constant.Alinux`.

- [ ] **Step 7: Add to `GetCveContentTypes`**

`models/cvecontents.go` after `case constant.Rocky:`:

```go
	case constant.Alinux:
		return []CveContentType{NewCveContentType(constant.Alinux)}
```

- [ ] **Step 8: Add to `osPkgToPURL`**

`reporter/sbom/purl.go` line ~17 — add `constant.Alinux` to the `packageurl.TypeRPM` case list (keep alphabetical: after `constant.Alma`).

- [ ] **Step 9: Add to the vuls2 family gate**

`detector/detector.go` line ~239 — change:

```go
	case constant.RedHat, constant.CentOS, constant.Fedora, constant.Alma, constant.Rocky, constant.Oracle, constant.Amazon, constant.Alinux,
```

- [ ] **Step 10: Sweep for anything missed**

Run:
```bash
grep -rn "constant.Rocky\b" --include="*.go" . | grep -v _test | grep -v /vendor/
```
For every hit not already handled above, add `constant.Alinux` in the same position (they are all RHEL-clone family lists). Expected remaining hits after Steps 3-9: none. If `models/scanresults.go:298` (`constant.Oracle` in a fast-mode reboot list) shows up — leave it: Alinux should behave like Alma/Rocky (not in that list → `default: return true`), which is correct.

- [ ] **Step 11: Run the broad test set**

Run: `go test ./config/... ./scanner/... ./models/... ./reporter/... ./detector/...`
Expected: PASS. `go build ./...` green.

- [ ] **Step 12: Commit**

```bash
git add config/os.go scanner/utils.go scanner/redhatbase.go models/cvecontents.go reporter/sbom/purl.go detector/detector.go config/os_test.go scanner/utils_test.go
git commit -m "feat: wire alinux into OS family switches

EOL dates, running-kernel detection, needs-restarting, repoquery line
parsing, CVE-content type, SBOM PURL type (rpm), and the vuls2 detection
family gate.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task C3: Errata reference link (`detector/vuls2/vendor.go`)

**Files:**
- Modify: `detector/vuls2/vendor.go` (`advisoryReference` — add case after `EcosystemTypeOracle` ~line 640; `toVuls2Family` — add clarifying comment only)
- Test: `detector/vuls2/vendor_test.go` (extend if a table for `advisoryReference` exists; else add one)

**Interfaces:**
- Consumes: `ecosystemTypes.EcosystemTypeAlinux` (Phase A, on the local module path via Task C4's replace).
- Produces: `advisoryReference("alinux:4", sourceTypes.AlinuxOVAL, models.DistroAdvisory{AdvisoryID: "ALINUX4-SA-2026:0392"})` → `models.Reference{Link: "https://alas.aliyun.com/errata/detail/ALINUX4-SA-2026:0392", Source: "ALINUX", RefID: "ALINUX4-SA-2026:0392"}`.

- [ ] **Step 1: Write the failing test**

`detector/vuls2/vendor_test.go`:

```go
func TestAdvisoryReference_Alinux(t *testing.T) {
	got, err := advisoryReference(
		ecosystemTypes.Ecosystem("alinux:4"),
		sourceTypes.AlinuxOVAL,
		models.DistroAdvisory{AdvisoryID: "ALINUX4-SA-2026:0392"},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := models.Reference{
		Link:   "https://alas.aliyun.com/errata/detail/ALINUX4-SA-2026:0392",
		Source: "ALINUX",
		RefID:  "ALINUX4-SA-2026:0392",
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
```

- [ ] **Step 2: Run it**

Run: `go test ./detector/vuls2/ -run TestAdvisoryReference_Alinux -v`
Expected: FAIL — `advisoryReference` returns `unsupported family: alinux`.

- [ ] **Step 3: Add the case**

In `advisoryReference`, after the `case ecosystemTypes.EcosystemTypeOracle:` block:

```go
	case ecosystemTypes.EcosystemTypeAlinux:
		return models.Reference{
			Link:   fmt.Sprintf("https://alas.aliyun.com/errata/detail/%s", da.AdvisoryID),
			Source: "ALINUX",
			RefID:  da.AdvisoryID,
		}, nil
```

- [ ] **Step 4: Comment `toVuls2Family`**

In `toVuls2Family`, in the `default:` return, add a line comment:

```go
	default:
		// alinux, oracle, alma, rocky, centos, ... map 1:1 to their ecosystem type.
		return vuls0Family
```

- [ ] **Step 5: Run it**

Run: `go test ./detector/vuls2/ -run TestAdvisoryReference_Alinux -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add detector/vuls2/vendor.go detector/vuls2/vendor_test.go
git commit -m "feat(detector/vuls2): alinux errata reference links

ALINUXn-SA-YYYY:NNNN -> https://alas.aliyun.com/errata/detail/<id>.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task C4: Cross-repo wiring + end-to-end test

**Files:**
- Modify: `go.mod`, `go.sum`
- Create: `scanner/testdata/alinux3_rpm_qa.txt`, `scanner/testdata/alinux4_rpm_qa.txt` (checked-in trimmed copies of the real fixtures — ~40 pkgs each, enough to hit a known advisory)
- Create: `detector/alinux_e2e_test.go` (a `//go:build e2e`-tagged test, or a `TestAlinux*` that is `t.Skip`-ped without a local DB)

**Interfaces:**
- Consumes: everything from Phases A–C.
- Produces: a green `vuls detect` run for an Alinux 3 and an Alinux 4 pseudo-server.

- [ ] **Step 1: Local replace directives**

Add to `vuls/go.mod`:

```
replace (
	github.com/MaineK00n/vuls2 => ../vuls2
	github.com/MaineK00n/vuls-data-update => ../vuls-data-update
)
```

Run `go mod tidy`, `go build ./...`.

- [ ] **Step 2: Build a local vuls2 DB from the alinux extract**

```bash
cd ../vuls-data-update
go run ./cmd/vuls-data-update fetch   alinux-oval -d /tmp/alinux-fetch
go run ./cmd/vuls-data-update extract alinux-oval /tmp/alinux-fetch -d /tmp/alinux-extract
cd ../vuls2
# use vuls2's db build entrypoint to assemble a sqlite/boltdb from /tmp/alinux-extract
# (see vuls2/pkg/db + cmd; command name discovered during Phase B)
go run ./cmd/... db add --root /tmp/alinux-extract --path /tmp/alinux-vuls2.db
```

(The exact vuls2 DB-build invocation is confirmed in Phase B Step 4; record it in this plan's margin when known.)

- [ ] **Step 3: Pseudo-server configs**

Write `/tmp/alinux-e2e/config.toml` with two `[servers.*]` of `type = "pseudo"`, and drop the scanned-result JSONs built from the fixtures (family `alinux`, release `3` / `4`, packages parsed from `scanner/testdata/alinux{3,4}_rpm_qa.txt`). Point `[vuls2].path` at `/tmp/alinux-vuls2.db` and `[vuls2].skipUpdate = true`.

- [ ] **Step 4: Run detect**

```bash
cd ../vuls
go run . detect -config=/tmp/alinux-e2e/config.toml -results-dir=/tmp/alinux-e2e/results
```

Pass criteria:
  - both servers report `family: alinux`, `release: 3` / `4`;
  - `alinux-release` and other base packages: no false positive;
  - at least one deliberately down-rev package per server is reported with the
    right `ALINUXn-SA` id, CVE list, CVSS 3.1 score, and errata link
    `https://alas.aliyun.com/errata/detail/...`;
  - JSON + one-line-summary reporters render without error.

- [ ] **Step 5: Regression check**

Run: `go test ./...` in `vuls`. Then a quick manual Oracle/Alma pseudo-scan (reuse any existing fixture) to confirm unchanged behaviour.

- [ ] **Step 6: Bump to merged commits**

After Phase A & B PRs merge:

```bash
go get github.com/MaineK00n/vuls-data-update@<A-merge-sha>
go get github.com/MaineK00n/vuls2@<B-merge-sha>
# delete the replace block
go mod tidy
go build ./... && go test ./...
```

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum scanner/testdata/alinux3_rpm_qa.txt scanner/testdata/alinux4_rpm_qa.txt detector/alinux_e2e_test.go
git commit -m "test(alinux): end-to-end detection against real Alinux 3/4 package sets

Bumps vuls2 + vuls-data-update to the merged alinux commits and adds
trimmed rpm -qa fixtures captured from a live Alinux 4 host and a
provided Alinux 3 dump.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task C5: Documentation

**Files:**
- Modify: `README.md` (supported-OS table / list)
- Modify: any `setup/` or `docs/` supported-platforms reference that enumerates Rocky/Alma (grep `AlmaLinux` in `README.md` and `*.md`)

- [ ] **Step 1:** `grep -rn "AlmaLinux\|Rocky Linux" README.md` — for each supported-OS enumeration, add `Alibaba Cloud Linux 3, 4`.
- [ ] **Step 2:** If there is a per-distro "how it detects / which data source" table, add a row: Alibaba Cloud Linux → `alinux-oval` (mirrors.aliyun.com) via vuls2.
- [ ] **Step 3:** `go build ./...` (sanity), commit:

```bash
git add README.md
git commit -m "docs: list Alibaba Cloud Linux 3 and 4 as supported

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

- [ ] **Step 4:** Push `feat/alinux-support`, open PR against `allanhung/vuls:main`. Body links the spec + the vuls-data-update / vuls2 PRs, and calls out the EVR-normalisation workaround + upstream bug link.

---

## Self-Review

**Spec coverage:**
- §3 data source / HTML scrape → Task A2 ✓
- §3.1 schema (advisory id from ref_id, CVSS 3.1 only, no modules, textfilecontent54 OS test) → Task A2 types, Task A3 steps 4-5,9 ✓
- §3.2 EVR corruption + normalisation + clean-anchor validation + upstream report → Task A3 (evr.go, two-pass), Task A4 ✓
- §4.1 vuls-data-update (fetch, extract, source id, ecosystem, cmds, README) → Tasks A1-A4, A2 step 6, A3 step 8 ✓
- §4.2 vuls2 (go.mod only, verify kernel/rename defaults) → Task B1 ✓
- §4.3 vuls fork (constant, scanner/alinux.go, redhatbase detection, scanner.go, detector gate, vendor.go reference, go.mod, tests, README) → Tasks C1-C5 ✓
- §5 testing (unit/golden per repo, e2e with real fixtures, regression) → Task A2 step 4, A3 step 6, B1 step 6, C4 ✓
- §6 rollout (PR per repo, replace→pseudo-version, bug filing, order) → A4, B1 steps 5&7, C4 steps 6-7, C5 step 4 ✓
- §7 out of scope (alinux 2, anolis, CSAF, upstreaming) → respected; alinux 2 skipped in Task A3 step 3 ✓

**Placeholder scan:** The only deferred detail is the exact vuls2 DB-build command in Task C4 Step 2, explicitly resolved during Task B1 Step 4 and to be recorded back into the plan — acceptable (it is a discovery step with a named owner, not a hand-wave). EOL dates in Task C2 Step 3 are marked approximate with the source URL and a "refine" note — acceptable. All code steps carry real code.

**Type consistency:** `oval.Fetch` / `oval.Extract` signatures, `oval.WithDir` / `oval.WithBaseURL` / `oval.WithRetry` options, `sanitizeEVR(string, map[string]struct{}) (string, error)`, `newAlinux(config.ServerInfo) *alinux`, `rootPrivAlinux`, `constant.Alinux = "alinux"`, `ecosystemTypes.EcosystemTypeAlinux = "alinux"`, `sourceTypes.AlinuxOVAL = "alinux-oval"`, advisory-reference `Source: "ALINUX"` — all consistent across tasks. The extractor imports the fetch package aliased as `alinux` to avoid the `oval` package-name clash (Task A3 Step 5.1).
