package local

import (
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_inferBuildOS(t *testing.T) {
	rpm := func(namespace, release string) ftypes.Package {
		return ftypes.Package{
			Release:    release,
			Identifier: ftypes.PkgIdentifier{PURL: &packageurl.PackageURL{Type: packageurl.TypeRPM, Namespace: namespace}},
		}
	}
	tests := []struct {
		name   string
		pkgs   ftypes.Packages
		want   ftypes.OS
		wantOK bool
	}{
		{
			name:   "manylinux2014 is CentOS 7",
			pkgs:   ftypes.Packages{rpm("centos", "55.el7_9")},
			want:   ftypes.OS{Family: ftypes.CentOS, Name: "7"},
			wantOK: true,
		},
		{
			name:   "auditwheel's almalinux is Trivy's alma",
			pkgs:   ftypes.Packages{rpm("almalinux", "3.el8")},
			want:   ftypes.OS{Family: ftypes.Alma, Name: "8"},
			wantOK: true,
		},
		{
			name: "no release tag, no OS",
			pkgs: ftypes.Packages{rpm("centos", "55")},
		},
		{
			name: "package without PURL",
			pkgs: ftypes.Packages{{Release: "3.el8"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := inferBuildOS(tt.pkgs)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}
