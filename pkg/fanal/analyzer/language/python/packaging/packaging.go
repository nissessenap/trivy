package packaging

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/packaging"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypePythonPkg, newPackagingAnalyzer)
}

const version = 4

func newPackagingAnalyzer(opt analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &packagingAnalyzer{
		logger:                           log.WithPrefix("python"),
		pkgParser:                        packaging.NewParser(),
		licenseClassifierConfidenceLevel: opt.LicenseScannerOption.ClassifierConfidenceLevel,
	}, nil
}

var (
	eggFiles = []string{
		// .egg format
		// https://setuptools.readthedocs.io/en/latest/deprecated/python_eggs.html#eggs-and-their-formats
		// ".egg" is zip format. We check it in `eggAnalyzer`.
		"EGG-INFO/PKG-INFO",

		// .egg-info format: .egg-info can be a file or directory
		// https://setuptools.readthedocs.io/en/latest/deprecated/python_eggs.html#eggs-and-their-formats
		".egg-info",
		".egg-info/PKG-INFO",
		// https://github.com/aquasecurity/trivy/issues/9171
		".egg-info/METADATA",
	}
)

type packagingAnalyzer struct {
	logger                           *log.Logger
	pkgParser                        language.Parser
	licenseClassifierConfidenceLevel float64
}

// PostAnalyze analyzes egg and wheel files.
func (a packagingAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {

	var apps []types.Application

	required := func(path string, _ fs.DirEntry) bool {
		return filepath.Base(path) == "METADATA" || isEggFile(path) || input.FilePatterns.Match(path)
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(filePath string, _ fs.DirEntry, r io.Reader) error {
		rsa, ok := r.(xio.ReadSeekerAt)
		if !ok {
			return xerrors.New("invalid reader")
		}

		app, err := a.parse(ctx, filePath, rsa, input.Options.FileChecksum)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		opener := func(licPath string) (io.ReadCloser, error) {
			// Note that fs.FS is always slashed regardless of the platform,
			// and path.Join should be used rather than filepath.Join.
			f, err := input.FS.Open(path.Join(path.Dir(filePath), licPath))
			if errors.Is(err, fs.ErrNotExist) {
				return nil, nil
			} else if err != nil {
				return nil, xerrors.Errorf("file open error: %w", err)
			}
			return f, nil
		}

		if err = fillAdditionalData(opener, app, a.licenseClassifierConfidenceLevel); err != nil {
			a.logger.Warn("Unable to collect additional info", log.Err(err))
		}

		apps = append(apps, *app)

		// PEP 770: SBOMs shipped in `<name>.dist-info/sboms/`
		if strings.HasSuffix(path.Dir(filePath), ".dist-info") {
			apps = append(apps, a.pep770Apps(ctx, input.FS, path.Join(path.Dir(filePath), "sboms"))...)
		}
		return nil
	})

	if err != nil {
		return nil, xerrors.Errorf("python package walk error: %w", err)
	}
	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

// pep770Apps decodes every SBOM in the PEP 770 `sboms/` dir and returns the cargo applications.
// ponytail: cargo only; OS packages (auditwheel rpm) and generic/purl-less components are dropped,
// they need a design for mixing package types. cf. https://github.com/aquasecurity/trivy/issues/10021
func (a packagingAnalyzer) pep770Apps(ctx context.Context, fsys fs.FS, sbomDir string) []types.Application {
	entries, err := fs.ReadDir(fsys, sbomDir)
	if err != nil { // No sboms dir
		return nil
	}

	var apps []types.Application
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		sbomPath := path.Join(sbomDir, entry.Name())
		sbomApps, err := decodeSBOM(ctx, fsys, sbomPath)
		if err != nil {
			a.logger.Warn("Unable to parse PEP 770 SBOM", log.FilePath(sbomPath), log.Err(err))
			continue
		}
		for _, app := range sbomApps {
			if app.Type != types.Cargo {
				continue
			}
			// ponytail: SBOM path as FilePath => one result per SBOM file; revisit if that is too noisy.
			app.FilePath = sbomPath
			// BOM refs from third-party SBOMs collide between wheels (same crate in two SBOMs),
			// which yields duplicate bom-refs in Trivy's CycloneDX output and breaks the round trip.
			for i := range app.Packages {
				app.Packages[i].Identifier.BOMRef = ""
			}
			apps = append(apps, app)
		}
	}
	return apps
}

func decodeSBOM(ctx context.Context, fsys fs.FS, sbomPath string) ([]types.Application, error) {
	f, err := fsys.Open(sbomPath)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()

	rs, ok := f.(io.ReadSeeker)
	if !ok {
		return nil, xerrors.New("invalid reader")
	}

	// Detect by content: PEP 770 doesn't mandate file names (e.g. cargo-cyclonedx writes `*.cyclonedx.json`)
	format, err := sbom.DetectFormat(rs)
	if err != nil {
		return nil, xerrors.Errorf("failed to detect SBOM format: %w", err)
	}
	if _, err = rs.Seek(0, io.SeekStart); err != nil {
		return nil, xerrors.Errorf("seek error: %w", err)
	}
	bom, err := sbom.Decode(ctx, rs, format)
	if err != nil {
		return nil, xerrors.Errorf("SBOM decode error: %w", err)
	}
	return bom.Applications, nil
}

type fileOpener func(filePath string) (io.ReadCloser, error)

func fillAdditionalData(opener fileOpener, app *types.Application, licenseClassifierConfidenceLevel float64) error {
	for i, pkg := range app.Packages {
		var licenses []string
		for _, lic := range pkg.Licenses {
			// Parser adds `file://` prefix to filepath from `License-File` field
			// We need to read this file to find licenses
			// Otherwise, this is the name of the license
			if !strings.HasPrefix(lic, licensing.LicenseFilePrefix) {
				licenses = append(licenses, lic)
				continue
			}
			licensePath := path.Base(strings.TrimPrefix(lic, licensing.LicenseFilePrefix))

			foundLicenses, err := classifyLicenses(opener, licensePath, licenseClassifierConfidenceLevel)
			if err != nil {
				return xerrors.Errorf("unable to classify licenses: %w", err)
			}
			licenses = append(licenses, foundLicenses...)
		}
		app.Packages[i].Licenses = licenses
	}

	return nil
}

func classifyLicenses(opener fileOpener, licPath string, licenseClassifierConfidenceLevel float64) ([]string, error) {
	f, err := opener(licPath)
	if err != nil {
		return nil, xerrors.Errorf("unable to open license file: %w", err)
	} else if f == nil { // File doesn't exist
		return nil, nil
	}
	defer f.Close()

	l, err := licensing.Classify("", f, licenseClassifierConfidenceLevel)
	if err != nil {
		return nil, xerrors.Errorf("license classify error: %w", err)
	} else if l == nil { // No licenses found
		return nil, nil
	}

	// License found
	return xslices.Map(l.Findings, func(finding types.LicenseFinding) string {
		return finding.Name
	}), nil
}

func (a packagingAnalyzer) parse(ctx context.Context, filePath string, r xio.ReadSeekerAt, checksum bool) (*types.Application, error) {
	return language.ParsePackage(ctx, types.PythonPkg, filePath, r, a.pkgParser, checksum)
}

func (a packagingAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return strings.Contains(filePath, ".dist-info") || isEggFile(filePath)
}

func isEggFile(filePath string) bool {
	return lo.SomeBy(eggFiles, func(fileName string) bool {
		return strings.HasSuffix(filePath, fileName)
	})
}

func (a packagingAnalyzer) Type() analyzer.Type {
	return analyzer.TypePythonPkg
}

func (a packagingAnalyzer) Version() int {
	return version
}
