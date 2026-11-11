package scantemplate_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/scantemplate"
)

func TestReadOfficialBundleRejectsCorruptSourceAndLicense(t *testing.T) {
	manifest, templates, err := scantemplate.OfficialBundle()
	if err != nil {
		t.Fatal(err)
	}
	if len(templates) != 11 || manifest.Version != "13f9bc679405927b7f78eb5dfd3e7260ed3d40f3" {
		t.Fatalf("snapshot=%+v", manifest)
	}
	for _, test := range []struct{ file, want string }{{"nginx-version.yaml", "template checksum mismatch"}, {"LICENSE.md", "license checksum mismatch"}} {
		t.Run(test.file, func(t *testing.T) {
			dir := t.TempDir()
			entries, err := os.ReadDir("bundles/official")
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				data, err := os.ReadFile(filepath.Join("bundles/official", entry.Name()))
				if err != nil {
					t.Fatal(err)
				}
				if entry.Name() == test.file {
					data = append(data, []byte("changed")...)
				}
				if err = os.WriteFile(filepath.Join(dir, entry.Name()), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			_, returned, err := scantemplate.ReadBundle(os.DirFS(dir))
			if err == nil || !strings.Contains(err.Error(), test.want) || returned != nil {
				t.Fatalf("corruption accepted templates=%d err=%v", len(returned), err)
			}
		})
	}
}
