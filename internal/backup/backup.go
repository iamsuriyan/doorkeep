// Package backup writes and restores a single-node doorkeep data directory
// as one .tar.gz: a consistent SQLite snapshot plus the generated secrets.
// IP intelligence is not included (it is re-downloaded); Postgres (cluster
// mode) is backed up with pg_dump instead, and its secrets live in the
// environment.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Files restored into the data directory. Nothing else is accepted from an
// archive.
const (
	FileDB       = "doorkeep.db"
	FileSecret   = "instance.secret"
	FileTokenKey = "token.key"
	fileManifest = "manifest.json"
)

// Manifest describes an archive.
type Manifest struct {
	Format  int       `json:"format"`
	Version string    `json:"doorkeep_version"`
	Created time.Time `json:"created"`
	Files   []string  `json:"files"`
}

// Snapshotter writes a consistent database copy to a new file.
type Snapshotter interface {
	Snapshot(ctx context.Context, path string) error
}

// Create writes an archive of dataDir to out.
func Create(ctx context.Context, db Snapshotter, dataDir, out, version string) error {
	tmpDir, err := os.MkdirTemp(filepath.Dir(out), ".doorkeep-backup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	snap := filepath.Join(tmpDir, FileDB)
	if err := db.Snapshot(ctx, snap); err != nil {
		return fmt.Errorf("backup: database snapshot: %w", err)
	}
	files := map[string]string{FileDB: snap}
	for _, name := range []string{FileSecret, FileTokenKey} {
		p := filepath.Join(dataDir, name)
		if _, err := os.Stat(p); err == nil {
			files[name] = p
		}
	}
	m := Manifest{Format: 1, Version: version, Created: time.Now().UTC()}
	for _, n := range []string{FileDB, FileSecret, FileTokenKey} {
		if files[n] != "" {
			m.Files = append(m.Files, n)
		}
	}

	part := out + ".part"
	f, err := os.OpenFile(part, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(part)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	mb, _ := json.MarshalIndent(m, "", "  ")
	if err := writeEntry(tw, fileManifest, mb); err != nil {
		f.Close()
		return err
	}
	for _, name := range m.Files {
		b, err := os.ReadFile(files[name])
		if err != nil {
			f.Close()
			return err
		}
		if err := writeEntry(tw, name, b); err != nil {
			f.Close()
			return err
		}
	}
	if err := tw.Close(); err != nil {
		f.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(part, out)
}

func writeEntry(tw *tar.Writer, name string, b []byte) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), ModTime: time.Now()}); err != nil {
		return err
	}
	_, err := tw.Write(b)
	return err
}

// ErrNotEmpty is returned by Restore when the data directory already holds
// a database and force is false.
var ErrNotEmpty = errors.New("backup: data directory already has a database (stop doorkeep and use --force to replace it)")

// maxEntry bounds one file in an archive.
const maxEntry = 8 << 30

// Restore unpacks an archive into dataDir. Only the known files are
// written, with mode 0600; existing ones are replaced only with force.
func Restore(in, dataDir string, force bool) (*Manifest, error) {
	if _, err := os.Stat(filepath.Join(dataDir, FileDB)); err == nil && !force {
		return nil, ErrNotEmpty
	}
	f, err := os.Open(in)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("backup: not a doorkeep backup: %w", err)
	}
	tr := tar.NewReader(gz)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	stage, err := os.MkdirTemp(dataDir, ".restore-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)
	allowed := map[string]bool{FileDB: true, FileSecret: true, FileTokenKey: true, fileManifest: true}
	var m *Manifest
	got := map[string]bool{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("backup: corrupt archive: %w", err)
		}
		if h.Typeflag != tar.TypeReg || !allowed[h.Name] || got[h.Name] || h.Size > maxEntry {
			return nil, fmt.Errorf("backup: unexpected entry %q in archive", h.Name)
		}
		got[h.Name] = true
		if h.Name == fileManifest {
			m = &Manifest{}
			if err := json.NewDecoder(io.LimitReader(tr, 1<<20)).Decode(m); err != nil {
				return nil, fmt.Errorf("backup: bad manifest: %w", err)
			}
			continue
		}
		w, err := os.OpenFile(filepath.Join(stage, h.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		n, err := io.Copy(w, io.LimitReader(tr, maxEntry))
		if cerr := w.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return nil, err
		}
		if n != h.Size {
			return nil, fmt.Errorf("backup: %s truncated", h.Name)
		}
	}
	if m == nil || m.Format != 1 || !got[FileDB] {
		return nil, errors.New("backup: not a doorkeep backup (missing manifest or database)")
	}
	for _, name := range m.Files {
		if !got[name] {
			return nil, fmt.Errorf("backup: archive is missing %s", name)
		}
	}
	// Remove the old database's WAL files so they are not replayed onto
	// the restored copy, then move the staged files into place.
	if force {
		for _, ext := range []string{"-wal", "-shm"} {
			_ = os.Remove(filepath.Join(dataDir, FileDB+ext))
		}
	}
	for _, name := range m.Files {
		if err := os.Rename(filepath.Join(stage, name), filepath.Join(dataDir, name)); err != nil {
			return nil, err
		}
	}
	return m, nil
}
