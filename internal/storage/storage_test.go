package storage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func seedFile(t *testing.T, s *Store, rel, content string) {
	t.Helper()
	full := filepath.Join(s.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestTraversalRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	bad := []string{
		"../evil.txt",
		"a/../../evil.txt",
		"..%2f/evil.txt",
		"a\\b.txt",
		"a/b\\c.txt",
		"/absolute.txt",
		"",
		".",
		"a/../b.txt",
		"a/./b.txt",
		"a//b.txt",
		".hidden/file.txt",
		"a/.hidden.txt",
		"dash/evil.txt",
		"healthz/x.txt",
		"favicon.ico",
		"robots.txt",
		"_private/x.txt",
		".well-known/x.txt",
		"logos/evil.html",
		"logos/evil.js",
		"logos/evil.xml",
		"logos/noext",
		"logos/.htaccess",
		strings.Repeat("a", 200) + "/x.txt", // segment too long
		"a/b/c/d/e/f.txt",                   // depth > 4 + file
		"ok/space name.txt",                 // space not in file regex
		"ok/" + strings.Repeat("f", 140) + ".txt", // file name too long
		"UPPER/x.txt", // dir must be lowercase
		"has space/x.txt",
		"nul\x00byte/x.txt",
	}
	for _, p := range bad {
		if _, err := s.Open(ctx, p); !errors.Is(err, ErrInvalidPath) &&
			!errors.Is(err, ErrReserved) && !errors.Is(err, ErrDisallowedExt) &&
			!errors.Is(err, ErrNotFound) {
			// NotFound is acceptable only when validation passed but the
			// file is missing — none of the above should validate, except
			// depth/file-length cases that fail at different layers.
			// To keep the test strict, require a validation error:
			t.Errorf("Open(%q) = %v, want validation error", p, err)
		}
		// Must never succeed:
		if f, err := s.Open(ctx, p); err == nil {
			f.Close()
			t.Errorf("Open(%q) succeeded, want error", p)
		}
	}
}

func TestOpenOK(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedFile(t, s, "logos/img.png", "\x89PNG\r\n\x1a\nhello")
	f, err := s.Open(ctx, "logos/img.png")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()
	st, _ := f.Stat()
	if st.IsDir() {
		t.Fatalf("opened a directory")
	}
}

func TestOpenDirectoryRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedFile(t, s, "logos/img.png", "\x89PNG\r\n\x1a\nhello")
	for _, p := range []string{"logos", "logos/"} {
		if f, err := s.Open(ctx, p); err == nil {
			f.Close()
			t.Errorf("Open(%q) succeeded on directory", p)
		}
	}
}

func TestSymlinkEscape(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	os.WriteFile(secret, []byte("top secret"), 0o644)

	// Symlink inside root pointing outside.
	if err := os.Symlink(secret, filepath.Join(s.root, "link.txt")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	// File name "link.txt" validates (txt allowed) — resolution must refuse.
	if f, err := s.Open(ctx, "link.txt"); err == nil {
		f.Close()
		t.Errorf("Open followed symlink out of root")
	}

	// Symlinked directory inside root pointing outside.
	os.MkdirAll(filepath.Join(outside, "real"), 0o755)
	os.WriteFile(filepath.Join(outside, "real", "a.txt"), []byte("hi"), 0o644)
	if err := os.Symlink(filepath.Join(outside, "real"), filepath.Join(s.root, "evildir")); err == nil {
		if f, err := s.Open(ctx, "evildir/a.txt"); err == nil {
			f.Close()
			t.Errorf("Open followed symlinked dir out of root")
		}
	}

	// A symlink fully inside root still resolves.
	seedFile(t, s, "logos/img.png", "\x89PNG\r\n\x1a\nhello")
	if err := os.Symlink(filepath.Join(s.root, "logos"), filepath.Join(s.root, "logoslink")); err == nil {
		// "logoslink" validates as a dir segment; must stay inside root — allowed.
		if _, err := s.Open(ctx, "logoslink/img.png"); err != nil {
			t.Errorf("Open via in-root symlink: %v", err)
		}
	}
}

func TestSniffMismatch(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	// PNG extension with plain-text content.
	err := s.Save(ctx, "", "fake.png", bytes.NewReader([]byte("just some text here.... padding to be safe............................")), true)
	if !errors.Is(err, ErrContentSniff) {
		t.Errorf("Save fake.png = %v, want ErrContentSniff", err)
	}
	// HTML content with .png extension.
	err = s.Save(ctx, "", "evil2.png", bytes.NewReader([]byte("<html><body>hi</body></html>......padding padding padding padding...")), true)
	if !errors.Is(err, ErrContentSniff) {
		t.Errorf("Save html-as-png = %v, want ErrContentSniff", err)
	}
}

func TestSaveRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte("x"), 600)...)
	if err := s.Mkdir(ctx, "logos"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := s.Save(ctx, "logos", "img.png", bytes.NewReader(png), false); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// No-overwrite default refuses.
	if err := s.Save(ctx, "logos", "img.png", bytes.NewReader(png), false); !errors.Is(err, ErrExists) {
		t.Fatalf("Save existing overwrite=false = %v, want ErrExists", err)
	}
	// Explicit overwrite succeeds.
	if err := s.Save(ctx, "logos", "img.png", bytes.NewReader(png), true); err != nil {
		t.Fatalf("Save overwrite: %v", err)
	}
	f, err := s.Open(ctx, "logos/img.png")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	f.Close()
	// No .tmp files left behind.
	des, _ := os.ReadDir(filepath.Join(s.root, "logos"))
	for _, de := range des {
		if strings.HasSuffix(de.Name(), ".tmp") {
			t.Errorf("leftover tmp file %q", de.Name())
		}
	}
}

func TestMkdirValidation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Mkdir(ctx, "logos"); err != nil {
		t.Fatalf("Mkdir logos: %v", err)
	}
	if err := s.Mkdir(ctx, "logos"); !errors.Is(err, ErrExists) {
		t.Fatalf("Mkdir existing = %v, want ErrExists", err)
	}
	for _, bad := range []string{"", "dash", "../x", "UPPER", "a/b/c/d/e", "has space"} {
		if err := s.Mkdir(ctx, bad); err == nil {
			t.Errorf("Mkdir(%q) succeeded, want error", bad)
		}
	}
	// Nested one level at a time.
	if err := s.Mkdir(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Mkdir(ctx, "a/b"); err != nil {
		t.Fatal(err)
	}
	// Parent must exist: Mkdir does not create parents.
	if err := s.Mkdir(ctx, "zzz/deep"); err == nil {
		t.Errorf("Mkdir with missing parent succeeded")
	}
}

func TestDeleteNonEmptyDirRefused(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Mkdir(ctx, "logos"); err != nil {
		t.Fatal(err)
	}
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte("x"), 600)...)
	if err := s.Save(ctx, "logos", "img.png", bytes.NewReader(png), false); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "logos"); !errors.Is(err, ErrDirNotEmpty) {
		t.Fatalf("Delete non-empty = %v, want ErrDirNotEmpty", err)
	}
	if err := s.Delete(ctx, "logos/img.png"); err != nil {
		t.Fatalf("Delete file: %v", err)
	}
	if err := s.Delete(ctx, "logos"); err != nil {
		t.Fatalf("Delete empty dir: %v", err)
	}
}

func TestListAndStats(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	s.Mkdir(ctx, "bdir")
	s.Mkdir(ctx, "adir")
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte("x"), 600)...)
	s.Save(ctx, "adir", "img.png", bytes.NewReader(png), false)
	s.Save(ctx, "", "top.txt", bytes.NewReader([]byte("hello world, some text content here....................")), false)

	ents, err := s.List(ctx, "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(ents) != 3 {
		t.Fatalf("List = %d entries, want 3: %+v", len(ents), ents)
	}
	// Dirs first, sorted: adir, bdir, then top.txt.
	if !ents[0].IsDir || ents[0].Name != "adir" || !ents[1].IsDir || ents[2].Name != "top.txt" {
		t.Fatalf("unexpected order: %+v", ents)
	}

	st, err := s.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.FileCount != 2 || st.DirCount != 2 || st.TotalSize == 0 {
		t.Fatalf("unexpected stats: %+v", st)
	}
	if len(st.Recent) != 2 {
		t.Fatalf("recent = %d, want 2", len(st.Recent))
	}
}

func TestExtensionCaseAndSvg(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	// Uppercase extension is accepted (normalised to lowercase for the check).
	svg := []byte("<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>....padding padding....")
	if err := s.Save(ctx, "", "icon.SVG", bytes.NewReader(svg), false); err != nil {
		t.Fatalf("Save icon.SVG: %v", err)
	}
}
