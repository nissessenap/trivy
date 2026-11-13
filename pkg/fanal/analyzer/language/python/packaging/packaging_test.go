package packaging

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_packagingAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name            string
		dir             string
		includeChecksum bool
		want            *analyzer.AnalysisResult
		wantErr         string
	}{
		{
			name:            "egg-info",
			dir:             "testdata/happy-egg",
			includeChecksum: true,
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.PythonPkg,
						FilePath: "distlib-0.3.1.egg-info/PKG-INFO",
						Packages: types.Packages{
							{
								Name:     "distlib",
								Version:  "0.3.1",
								Licenses: []string{"Python license"},
								FilePath: "distlib-0.3.1.egg-info/PKG-INFO",
								Digest:   "sha1:d9d89d8ed3b2b683767c96814c9c5d3e57ef2e1b",
								Digests: []digest.SourcedDigest{
									{
										Digest: "sha1:d9d89d8ed3b2b683767c96814c9c5d3e57ef2e1b",
										Source: digest.SourceFileContent,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "egg-info license classifiers",
			dir:  "testdata/classifier-license-egg",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.PythonPkg,
						FilePath: "setuptools-51.3.3.egg-info/PKG-INFO",
						Packages: types.Packages{
							{
								Name:     "setuptools",
								Version:  "51.3.3",
								Licenses: []string{"MIT License"},
								FilePath: "setuptools-51.3.3.egg-info/PKG-INFO",
							},
						},
					},
				},
			},
		},
		{
			name: "dist-info license classifiers",
			dir:  "testdata/classifier-license-dist",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.PythonPkg,
						FilePath: "setuptools-51.3.3.dist-info/METADATA",
						Packages: types.Packages{
							{
								Name:     "setuptools",
								Version:  "51.3.3",
								Licenses: []string{"MIT License"},
								FilePath: "setuptools-51.3.3.dist-info/METADATA",
							},
						},
					},
				},
			},
		},
		{
			name: "wheel",
			dir:  "testdata/happy-dist",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.PythonPkg,
						FilePath: "distlib-0.3.1.dist-info/METADATA",
						Packages: types.Packages{
							{
								Name:     "distlib",
								Version:  "0.3.1",
								Licenses: []string{"Python license"},
								FilePath: "distlib-0.3.1.dist-info/METADATA",
							},
						},
					},
				},
			},
		},
		{
			name: "license file in dist.info",
			dir:  "testdata/license-file-dist",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.PythonPkg,
						FilePath: "typing_extensions-4.4.0.dist-info/METADATA",
						Packages: []types.Package{
							{
								Name:    "typing_extensions",
								Version: "4.4.0",
								Licenses: []string{
									"BeOpen",
									"CNRI-Python-GPL-Compatible",
									"LicenseRef-MIT-Lucent",
									"Python-2.0",
								},
								FilePath: "typing_extensions-4.4.0.dist-info/METADATA",
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			a, err := newPackagingAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)
			got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
				Options: analyzer.AnalysisOptions{
					FileChecksum: tt.includeChecksum,
				},
			})

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

}

func Test_packagingAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "egg",
			filePath: "python2.7/site-packages/cssutils-1.0-py2.7.egg/EGG-INFO/PKG-INFO",
			want:     true,
		},
		{
			name:     "egg-info/METADATA",
			filePath: "Amazon/AWSCLIV2/cryptography-3.3.2-py3.8.egg-info/METADATA",
			want:     true,
		},
		{
			name:     "egg-info",
			filePath: "python3.8/site-packages/wrapt-1.12.1.egg-info",
			want:     true,
		},
		{
			name:     "egg-info PKG-INFO",
			filePath: "python3.8/site-packages/wrapt-1.12.1.egg-info/PKG-INFO",
			want:     true,
		},
		{
			name:     "wheel",
			filePath: "python3.8/site-packages/wrapt-1.12.1.dist-info/METADATA",
			want:     true,
		},
		{
			name:     "wheel license",
			filePath: "python3.8/site-packages/wrapt-1.12.1.dist-info/LICENSE",
			want:     true,
		},
		{
			name:     "sad",
			filePath: "random/PKG-INFO",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := packagingAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

// PEP 770: cargo crates from `<name>.dist-info/sboms/` are reported as a separate cargo application.
func Test_packagingAnalyzer_PEP770(t *testing.T) {
	a, err := newPackagingAnalyzer(analyzer.AnalyzerOptions{})
	require.NoError(t, err)
	got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{
		FS: os.DirFS("testdata/pep770-sboms"),
	})
	require.NoError(t, err)
	require.Len(t, got.Applications, 2)

	// The Python package is not touched
	py := got.Applications[0]
	assert.Equal(t, types.PythonPkg, py.Type)
	assert.Equal(t, "orjson-3.13.0.dist-info/METADATA", py.FilePath)
	require.Len(t, py.Packages, 1)
	assert.Empty(t, py.Packages[0].DependsOn)

	cargo := got.Applications[1]
	assert.Equal(t, types.Cargo, cargo.Type)
	assert.Equal(t, "orjson-3.13.0.dist-info/sboms/orjson.cyclonedx.json", cargo.FilePath)

	var ids []string
	for _, pkg := range cargo.Packages {
		ids = append(ids, pkg.ID)
		assert.Empty(t, pkg.Identifier.BOMRef)
	}
	// `cc` (build dependency, scope: excluded) and `orjson` (root crate, download_url=file://.) are dropped.
	assert.Equal(t, []string{"libc@0.2.190"}, ids)
}
