//go:build !scanner

package detector

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/detector/vuls2"
	"github.com/future-architect/vuls/models"
)

// TestAlinuxEndToEnd exercises the full Alibaba Cloud Linux 3/4 stack:
// the trimmed real `rpm -qa` fixtures in scanner/testdata are turned into a
// pseudo scan result and detected against a locally-built vuls2 boltdb that
// was assembled from `vuls-data-update extract alinux-oval`.
//
// It is SKIPPED unless that db is present, so `go test ./...` stays green in
// CI without it. To run it:
//
//	cd ../vuls-data-update
//	GOEXPERIMENT=jsonv2 go run ./cmd/vuls-data-update fetch   alinux-oval -d /tmp/alinux-fetch
//	GOEXPERIMENT=jsonv2 go run ./cmd/vuls-data-update extract alinux-oval /tmp/alinux-fetch -d /tmp/alinux-extract
//	cd ../vuls2
//	GOEXPERIMENT=jsonv2 go run ./cmd/vuls db init --dbtype boltdb --dbpath /tmp/alinux-vuls2.db
//	GOEXPERIMENT=jsonv2 go run ./cmd/vuls db add  --dbtype boltdb --dbpath /tmp/alinux-vuls2.db /tmp/alinux-extract
//	cd ../vuls
//	GOEXPERIMENT=jsonv2 go test ./detector/ -run TestAlinuxEndToEnd -v
//
// The db path defaults to /tmp/alinux-vuls2.db and can be overridden with
// the VULS2_ALINUX_DB environment variable.
func TestAlinuxEndToEnd(t *testing.T) {
	dbPath := os.Getenv("VULS2_ALINUX_DB")
	if dbPath == "" {
		dbPath = "/tmp/alinux-vuls2.db"
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Skipf("vuls2 alinux db not found at %s (set VULS2_ALINUX_DB or build it); skipping e2e", dbPath)
	}

	tests := []struct {
		name    string
		release string
		fixture string
		// wantCVE must be detected, keyed to the package it must land on.
		wantCVE string
		wantPkg string
		// wantAdvisoryPrefix is the ALINUXn-SA prefix the distro advisory id
		// and the errata reference link must carry.
		wantAdvisoryPrefix string
		// downRevPkgs are every package the fixture deliberately ships below a
		// fixed version: detection must touch at least these and nothing else.
		downRevPkgs []string
	}{
		{
			name:               "alinux3",
			release:            "3",
			fixture:            "alinux3_rpm_qa.txt",
			wantCVE:            "CVE-2023-20593",
			wantPkg:            "iwl3945-firmware",
			wantAdvisoryPrefix: "ALINUX3-SA-",
			downRevPkgs:        []string{"iwl3945-firmware", "iwl5150-firmware", "iwl6000-firmware"},
		},
		{
			name:               "alinux4",
			release:            "4",
			fixture:            "alinux4_rpm_qa.txt",
			wantCVE:            "CVE-2026-41992",
			wantPkg:            "gzip",
			wantAdvisoryPrefix: "ALINUX4-SA-",
			downRevPkgs:        []string{"expat", "gzip", "krb5-libs", "libssh"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgs := loadAlinuxFixture(t, filepath.Join("..", "scanner", "testdata", tt.fixture))
			if len(pkgs) < 20 {
				t.Fatalf("fixture %s parsed only %d packages", tt.fixture, len(pkgs))
			}

			r := models.ScanResult{
				ServerName:  tt.name + "-pseudo",
				Family:      constant.Alinux,
				Release:     tt.release,
				Packages:    pkgs,
				ScannedCves: models.VulnInfos{},
			}

			sesh := vuls2.NewSession(config.Vuls2Conf{Path: dbPath, SkipUpdate: true}, true)
			defer sesh.Close()

			if err := DetectPkgCves(&r, sesh); err != nil {
				t.Fatalf("DetectPkgCves: %v", err)
			}

			if r.Family != constant.Alinux {
				t.Errorf("family mutated to %q, want %q", r.Family, constant.Alinux)
			}
			if len(r.ScannedCves) == 0 {
				t.Fatalf("no CVEs detected for %s", tt.name)
			}

			// The specific advisory-linked CVE must be reported on the right
			// package, with an ALINUXn-SA id, a CVSS 3.1 score and the aliyun
			// errata link.
			vi, ok := r.ScannedCves[tt.wantCVE]
			if !ok {
				t.Fatalf("expected %s to be detected, got %v", tt.wantCVE, cveIDs(r.ScannedCves))
			}
			if !hasAffectedPkg(vi, tt.wantPkg) {
				t.Errorf("%s not reported on %s (affected: %v)", tt.wantCVE, tt.wantPkg, affectedNames(vi))
			}
			if got := vi.MaxCvss3Score().Value.Score; got <= 0 {
				t.Errorf("%s has no CVSS3 score", tt.wantCVE)
			}
			if c := vi.Confidences.SortByConfident(); len(c) == 0 || c[0].Score == 0 {
				t.Errorf("%s has zero-score confidence %v (alinux missing from an OS family switch?)", tt.wantCVE, vi.Confidences)
			}
			if !hasAdvisoryPrefix(vi, tt.wantAdvisoryPrefix) {
				t.Errorf("%s carries no %s* distro advisory (advisories: %v)", tt.wantCVE, tt.wantAdvisoryPrefix, advisoryIDs(vi))
			}
			if !hasErrataLink(vi, tt.wantAdvisoryPrefix) {
				t.Errorf("%s carries no https://alas.aliyun.com/errata/detail/%s* reference", tt.wantCVE, tt.wantAdvisoryPrefix)
			}

			// No false positives: every affected package across every detected
			// CVE must be one of the deliberately down-rev packages. In
			// particular alinux-release and the other base packages that are
			// already at or above their fixed version must not appear.
			want := map[string]bool{}
			for _, p := range tt.downRevPkgs {
				want[p] = true
			}
			touched := map[string]bool{}
			for id, v := range r.ScannedCves {
				for _, p := range v.AffectedPackages {
					touched[p.Name] = true
					if !want[p.Name] {
						t.Errorf("false positive: %s reported on %s which is not a down-rev package", id, p.Name)
					}
				}
			}
			for _, p := range tt.downRevPkgs {
				if !touched[p] {
					t.Errorf("expected down-rev package %s to be reported, but it was not", p)
				}
			}
		})
	}
}

// loadAlinuxFixture parses a trimmed rpm -qa dump in the canonical vuls
// queryformat "%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{ARCH} %{SOURCERPM}"
// into models.Packages, embedding a non-zero epoch into Version as
// "epoch:version" exactly as scanner/redhatbase.go does.
func loadAlinuxFixture(t *testing.T, path string) models.Packages {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixture %s: %v", path, err)
	}
	defer f.Close()

	pkgs := models.Packages{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			t.Fatalf("malformed fixture line %q", line)
		}
		name, epoch, version, release, arch := fields[0], fields[1], fields[2], fields[3], fields[4]
		if epoch != "0" && epoch != "(none)" && epoch != "" {
			version = epoch + ":" + version
		}
		pkgs[name] = models.Package{
			Name:    name,
			Version: version,
			Release: release,
			Arch:    arch,
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan fixture %s: %v", path, err)
	}
	return pkgs
}

func cveIDs(vis models.VulnInfos) []string {
	ids := make([]string, 0, len(vis))
	for id := range vis {
		ids = append(ids, id)
	}
	return ids
}

func affectedNames(vi models.VulnInfo) []string {
	names := make([]string, 0, len(vi.AffectedPackages))
	for _, p := range vi.AffectedPackages {
		names = append(names, p.Name)
	}
	return names
}

func hasAffectedPkg(vi models.VulnInfo, name string) bool {
	for _, p := range vi.AffectedPackages {
		if p.Name == name {
			return true
		}
	}
	return false
}

func advisoryIDs(vi models.VulnInfo) []string {
	ids := make([]string, 0, len(vi.DistroAdvisories))
	for _, a := range vi.DistroAdvisories {
		ids = append(ids, a.AdvisoryID)
	}
	return ids
}

func hasAdvisoryPrefix(vi models.VulnInfo, prefix string) bool {
	for _, a := range vi.DistroAdvisories {
		if strings.HasPrefix(a.AdvisoryID, prefix) {
			return true
		}
	}
	return false
}

func hasErrataLink(vi models.VulnInfo, advisoryPrefix string) bool {
	want := "https://alas.aliyun.com/errata/detail/" + advisoryPrefix
	for _, contents := range vi.CveContents {
		for _, cc := range contents {
			for _, ref := range cc.References {
				if strings.HasPrefix(ref.Link, want) {
					return true
				}
			}
		}
	}
	return false
}
