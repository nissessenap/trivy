package local

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

// PoC for https://github.com/aquasecurity/trivy/issues/10021 (option B).

// PURL namespace => OS family, where auditwheel's namespace is not Trivy's family name.
var bundledOSFamilies = map[string]ftypes.OSType{
	"almalinux":  ftypes.Alma,
	"rockylinux": ftypes.Rocky,
}

var elRelease = regexp.MustCompile(`\.el(\d+)`)

// scanBundledOSPkgs detects vulnerabilities in OS packages bundled into language packages,
// against the OS they were built on rather than the OS of the target.
// It returns the applications that it did not handle.
//
// The results keep the class of an application, so that they stay one result per file
// and survive an SBOM round trip without a second OS component.
func (s Service) scanBundledOSPkgs(ctx context.Context, apps []ftypes.Application, options types.ScanOptions) (types.Results, []ftypes.Application) {
	var results types.Results
	var rest []ftypes.Application
	for _, app := range apps {
		if app.Type != ftypes.BundledOSPkgs {
			rest = append(rest, app)
			continue
		}
		buildOS, ok := inferBuildOS(app.Packages)
		if !ok {
			// Report-only (option A): the language scanner lists the packages.
			rest = append(rest, app)
			continue
		}
		// ponytail: reuses the OS scanner as is, so it logs "Detected OS" for the build OS
		// and its EOSL verdict is dropped. Split the detector call out of it for a real version.
		res, _, err := s.osPkgScanner.Scan(ctx, types.ScanTarget{
			Name:     app.FilePath,
			OS:       buildOS,
			Packages: app.Packages,
		}, options)
		if err != nil {
			log.WarnContext(ctx, "Unable to scan bundled OS packages", log.FilePath(app.FilePath), log.Err(err))
			rest = append(rest, app)
			continue
		}
		// ponytail: the build OS is only visible in the target name. An application decoded
		// from a Trivy SBOM already has it there, so do not add it twice.
		res.Target = app.FilePath
		if suffix := fmt.Sprintf(" (%s %s)", buildOS.Family, buildOS.Name); !strings.HasSuffix(app.FilePath, suffix) {
			res.Target += suffix
		}
		res.Class = types.ClassLangPkg
		res.Type = ftypes.BundledOSPkgs
		results = append(results, res)
	}
	return results, rest
}

// inferBuildOS guesses the OS that the packages were built for from their PURLs,
// as auditwheel adds no distro qualifier.
// ponytail: rpm with an elN release tag only (manylinux). deb and apk PURLs carry no OS version.
func inferBuildOS(pkgs ftypes.Packages) (ftypes.OS, bool) {
	for _, pkg := range pkgs {
		p := pkg.Identifier.PURL
		if p == nil {
			continue
		}
		m := elRelease.FindStringSubmatch(pkg.Release)
		if m == nil {
			continue
		}
		family, ok := bundledOSFamilies[p.Namespace]
		if !ok {
			family = ftypes.OSType(p.Namespace)
		}
		return ftypes.OS{Family: family, Name: m[1]}, true
	}
	return ftypes.OS{}, false
}
