package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/iamsuriyan/doorkeep/internal/scoring"
	"github.com/iamsuriyan/doorkeep/internal/store"
	"github.com/iamsuriyan/doorkeep/internal/store/sqlstore"
)

func TestRoundTrip(t *testing.T) {
	ctx := context.Background()
	src := t.TempDir()
	db, err := sqlstore.Open(filepath.Join(src, FileDB))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateSite(ctx, &store.Site{ID: "s1", Name: "Shop", SiteKey: "dk_pk_a", SecretHash: "h", Origins: []string{"https://shop.example"}, Mode: scoring.ModeEnforce}); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(src, FileSecret), []byte("secret\n"), 0o600)
	os.WriteFile(filepath.Join(src, FileTokenKey), []byte("key\n"), 0o600)

	archive := filepath.Join(t.TempDir(), "b.tar.gz")
	// Snapshot while the database is open and in use (WAL mode).
	if err := Create(ctx, db, src, archive, "test"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err := Create(ctx, db, src, archive, "test"); err == nil {
		t.Fatal("overwrote an existing archive")
	}

	dst := t.TempDir()
	m, err := Restore(archive, dst, false)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "test" || len(m.Files) != 3 {
		t.Fatalf("manifest %+v", m)
	}
	for _, f := range []string{FileDB, FileSecret, FileTokenKey} {
		fi, err := os.Stat(filepath.Join(dst, f))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", f, fi, err)
		}
	}
	got, err := sqlstore.Open(filepath.Join(dst, FileDB))
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	if s, err := got.SiteByKey(ctx, "dk_pk_a"); err != nil || s.Name != "Shop" {
		t.Fatalf("restored site: %+v %v", s, err)
	}
	if _, err := Restore(archive, dst, false); !errors.Is(err, ErrNotEmpty) {
		t.Fatalf("restore over an existing database without --force: %v", err)
	}
	if _, err := Restore(archive, dst, true); err != nil {
		t.Fatalf("restore with force: %v", err)
	}
}

func TestRestoreRejectsForeignArchives(t *testing.T) {
	for name, entries := range map[string]map[string]string{
		"path traversal":    {"manifest.json": `{"format":1,"files":["doorkeep.db"]}`, "doorkeep.db": "x", "../evil": "x"},
		"unexpected file":   {"manifest.json": `{"format":1,"files":["doorkeep.db"]}`, "doorkeep.db": "x", "authorized_keys": "x"},
		"no manifest":       {"doorkeep.db": "x"},
		"missing listed db": {"manifest.json": `{"format":1,"files":["doorkeep.db","token.key"]}`, "doorkeep.db": "x"},
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "a.tar.gz")
			f, _ := os.Create(p)
			gz := gzip.NewWriter(f)
			tw := tar.NewWriter(gz)
			for n, body := range entries {
				tw.WriteHeader(&tar.Header{Name: n, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg})
				tw.Write([]byte(body))
			}
			tw.Close()
			gz.Close()
			f.Close()
			dst := t.TempDir()
			if _, err := Restore(p, dst, false); err == nil {
				t.Fatal("accepted")
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(dst), "evil")); err == nil {
				t.Fatal("wrote outside the data directory")
			}
			if _, err := os.Stat(filepath.Join(dst, FileDB)); err == nil {
				t.Fatal("partial restore left a database behind")
			}
		})
	}
}
