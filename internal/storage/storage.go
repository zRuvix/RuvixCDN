package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Sentinel errors. Handlers translate Open failures into a bare 404;
// dashboard code (v0.3) can match on these for user-facing messages.
var (
	ErrInvalidPath   = errors.New("invalid path")
	ErrReserved      = errors.New("reserved name")
	ErrDisallowedExt = errors.New("file type not allowed")
	ErrContentSniff  = errors.New("content does not match extension")
	ErrExists        = errors.New("file already exists")
	ErrDirNotEmpty   = errors.New("directory not empty")
	ErrNotFound      = errors.New("not found")
)

var (
	dirSegmentRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	fileNameRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// MaxDirDepth is the maximum nesting depth for directories (§9).
const MaxDirDepth = 4

// AllowedExtensions is the strict default allowlist (§9). js/html/xml are
// deliberately absent — see the same-origin threat note in CLAUDE.md §9.
var AllowedExtensions = map[string]bool{
	"png": true, "jpg": true, "jpeg": true, "gif": true,
	"webp": true, "avif": true, "ico": true, "svg": true,
	"css": true, "woff": true, "woff2": true, "ttf": true,
	"mp4": true, "webm": true, "mp3": true, "pdf": true,
	"json": true, "txt": true,
}

// sniffAllow maps an extension to the content-type prefixes considered
// consistent with it. http.DetectContentType only knows some formats, so
// extensions it cannot sniff accept application/octet-stream as a fallback.
// Comparison ignores any "; charset=..." suffix.
var sniffAllow = map[string][]string{
	"png":   {"image/png"},
	"jpg":   {"image/jpeg"},
	"jpeg":  {"image/jpeg"},
	"gif":   {"image/gif"},
	"webp":  {"image/webp"},
	"avif":  {"image/avif", "application/octet-stream"},
	"ico":   {"image/x-icon", "image/vnd.microsoft.icon", "application/octet-stream"},
	"svg":   {"image/svg+xml", "text/xml", "text/plain"},
	"css":   {"text/css", "text/plain"},
	"woff":  {"font/woff", "application/font-woff", "application/octet-stream"},
	"woff2": {"font/woff2", "application/octet-stream"},
	"ttf":   {"font/ttf", "font/sfnt", "application/octet-stream"},
	"mp4":   {"video/mp4"},
	"webm":  {"video/webm"},
	"mp3":   {"audio/mpeg"},
	"pdf":   {"application/pdf"},
	"json":  {"application/json", "text/plain"},
	"txt":   {"text/plain"},
}

// Store is the sole gateway to user-controlled filesystem paths (§3.3).
// All paths are resolved under root and verified to stay inside it.
type Store struct {
	root string // canonical absolute path, symlinks resolved
}

// New opens root as a Store, creating it if needed.
func New(root string) (*Store, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("storage: resolve root: %w", err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, fmt.Errorf("storage: create root: %w", err)
	}
	canon, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("storage: eval root: %w", err)
	}
	return &Store{root: canon}, nil
}

// Root returns the canonical root path (for tests).
func (s *Store) Root() string { return s.root }

// isReservedTop reports whether a top-level segment is reserved (§2, §9).
func isReservedTop(seg string) bool {
	switch seg {
	case "dash", "healthz", "favicon.ico", "robots.txt":
		return true
	}
	return strings.HasPrefix(seg, "_") || strings.HasPrefix(seg, ".")
}

func extOf(name string) string {
	i := strings.LastIndex(name, ".")
	if i < 0 || i == len(name)-1 {
		return ""
	}
	return strings.ToLower(name[i+1:])
}

// validateDirPath checks a directory path ("" means root).
func validateDirPath(dir string) ([]string, error) {
	if dir == "" {
		return nil, nil
	}
	if strings.Contains(dir, "\\") || strings.ContainsRune(dir, 0) || strings.HasPrefix(dir, "/") {
		return nil, fmt.Errorf("%w: bad directory %q", ErrInvalidPath, dir)
	}
	parts := strings.Split(dir, "/")
	if len(parts) > MaxDirDepth {
		return nil, fmt.Errorf("%w: directory too deep %q", ErrInvalidPath, dir)
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || !dirSegmentRe.MatchString(p) {
			return nil, fmt.Errorf("%w: bad directory segment %q", ErrInvalidPath, p)
		}
	}
	if isReservedTop(parts[0]) {
		return nil, fmt.Errorf("%w: %q", ErrReserved, parts[0])
	}
	return parts, nil
}

// validateFileName checks a bare file name and its extension.
func validateFileName(name string) (string, error) {
	if name == "" || name == "." || name == ".." ||
		strings.Contains(name, "/") || strings.Contains(name, "\\") ||
		strings.ContainsRune(name, 0) || strings.HasPrefix(name, ".") {
		return "", fmt.Errorf("%w: bad file name %q", ErrInvalidPath, name)
	}
	if !fileNameRe.MatchString(name) {
		return "", fmt.Errorf("%w: bad file name %q", ErrInvalidPath, name)
	}
	ext := extOf(name)
	if ext == "" || !AllowedExtensions[ext] {
		return "", fmt.Errorf("%w: .%s", ErrDisallowedExt, ext)
	}
	return ext, nil
}

// validateFilePath splits and validates a full relative file path,
// returning dir parts and the extension.
func validateFilePath(rel string) ([]string, string, error) {
	if rel == "" || strings.HasPrefix(rel, "/") ||
		strings.Contains(rel, "\\") || strings.ContainsRune(rel, 0) {
		return nil, "", fmt.Errorf("%w: %q", ErrInvalidPath, rel)
	}
	parts := strings.Split(rel, "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return nil, "", fmt.Errorf("%w: bad segment %q", ErrInvalidPath, p)
		}
	}
	if isReservedTop(parts[0]) {
		return nil, "", fmt.Errorf("%w: %q", ErrReserved, parts[0])
	}
	file := parts[len(parts)-1]
	ext, err := validateFileName(file)
	if err != nil {
		return nil, "", err
	}
	dirParts := parts[:len(parts)-1]
	if len(dirParts) > MaxDirDepth {
		return nil, "", fmt.Errorf("%w: directory too deep %q", ErrInvalidPath, rel)
	}
	for _, p := range dirParts {
		if !dirSegmentRe.MatchString(p) {
			return nil, "", fmt.Errorf("%w: bad directory segment %q", ErrInvalidPath, p)
		}
	}
	return dirParts, ext, nil
}

// join resolves rel under root and requires the result to stay inside root.
func (s *Store) join(rel string) (string, error) {
	full := filepath.Join(s.root, filepath.FromSlash(rel))
	if full != s.root && !strings.HasPrefix(full, s.root+string(os.PathSeparator)) {
		return "", fmt.Errorf("%w: escape %q", ErrInvalidPath, rel)
	}
	return full, nil
}

// resolveExisting resolves rel and re-verifies after symlink evaluation.
// Never follows symlinks out of root.
func (s *Store) resolveExisting(rel string) (string, error) {
	full, err := s.join(rel)
	if err != nil {
		return "", err
	}
	canon, err := filepath.EvalSymlinks(full)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("%w: %q: %v", ErrNotFound, rel, err)
		}
		return "", fmt.Errorf("%w: %q: %v", ErrNotFound, rel, err)
	}
	if canon != s.root && !strings.HasPrefix(canon, s.root+string(os.PathSeparator)) {
		return "", fmt.Errorf("%w: symlink escape %q", ErrInvalidPath, rel)
	}
	return canon, nil
}

// Open returns a read-only handle for a CDN file path. Any error must be
// rendered as a bare 404 by the caller — never leak why.
func (s *Store) Open(_ context.Context, rel string) (*os.File, error) {
	if _, _, err := validateFilePath(rel); err != nil {
		return nil, err
	}
	full, err := s.resolveExisting(rel)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(full)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %v", ErrNotFound, rel, err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%w: %q: %v", ErrNotFound, rel, err)
	}
	if fi.IsDir() {
		f.Close()
		return nil, fmt.Errorf("%w: is directory %q", ErrInvalidPath, rel)
	}
	return f, nil
}

// sniffOK reports whether the sniffed content type is consistent with ext.
func sniffOK(ext, sniffed string) bool {
	base := strings.SplitN(sniffed, ";", 2)[0]
	base = strings.TrimSpace(strings.ToLower(base))
	for _, want := range sniffAllow[ext] {
		if base == want {
			return true
		}
	}
	return false
}

// Save stores src as dir/filename atomically (tmp + fsync + rename).
// The caller enforces size limits with http.MaxBytesReader. When overwrite
// is false an existing destination is left untouched and ErrExists is
// returned. Filenames are validated as-is; sanitising (spaces → "-",
// unicode stripping, lowercasing the extension) is the dashboard's job.
func (s *Store) Save(ctx context.Context, dir, filename string, src io.Reader, overwrite bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dirParts, err := validateDirPath(dir)
	if err != nil {
		return err
	}
	ext, err := validateFileName(filename)
	if err != nil {
		return err
	}
	_ = dirParts

	dirFull, err := s.resolveExisting(dir)
	if err != nil {
		return err
	}
	fi, err := os.Stat(dirFull)
	if err != nil || !fi.IsDir() {
		return fmt.Errorf("%w: directory %q", ErrInvalidPath, dir)
	}
	dstRel := filename
	if dir != "" {
		dstRel = dir + "/" + filename
	}
	dst, err := s.join(dstRel)
	if err != nil {
		return err
	}
	// If the destination exists, make sure it isn't a symlink escape.
	if _, err := os.Lstat(dst); err == nil {
		if canon, err := filepath.EvalSymlinks(dst); err == nil {
			if canon != s.root && !strings.HasPrefix(canon, s.root+string(os.PathSeparator)) {
				return fmt.Errorf("%w: symlink escape %q", ErrInvalidPath, dstRel)
			}
		}
		if !overwrite {
			return fmt.Errorf("%w: %q", ErrExists, dstRel)
		}
	}

	// Sniff the first 512 bytes, then stream the rest.
	var head [512]byte
	n, err := io.ReadFull(src, head[:])
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return fmt.Errorf("storage: read: %w", err)
	}
	if sniffed := sniffDetect(head[:n]); !sniffOK(ext, sniffed) {
		return fmt.Errorf("%w: .%s smells like %s", ErrContentSniff, ext, sniffed)
	}
	body := io.MultiReader(strings.NewReader(string(head[:n])), src)

	tmp, err := os.CreateTemp(dirFull, ".upload-*.tmp")
	if err != nil {
		return fmt.Errorf("storage: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename
	if _, err := io.Copy(tmp, body); err != nil {
		tmp.Close()
		return fmt.Errorf("storage: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("storage: fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("storage: close: %w", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("storage: chmod: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("storage: rename: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

// Mkdir creates a single directory level; the parent must already exist.
func (s *Store) Mkdir(ctx context.Context, dir string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if dir == "" {
		return fmt.Errorf("%w: empty directory", ErrInvalidPath)
	}
	if _, err := validateDirPath(dir); err != nil {
		return err
	}
	parent := ""
	if i := strings.LastIndex(dir, "/"); i >= 0 {
		parent = dir[:i]
	}
	if _, err := s.resolveExisting(parent); err != nil {
		return fmt.Errorf("%w: parent of %q: %v", ErrInvalidPath, dir, err)
	}
	full, err := s.join(dir)
	if err != nil {
		return err
	}
	if err := os.Mkdir(full, 0o755); err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%w: %q", ErrExists, dir)
		}
		return fmt.Errorf("storage: mkdir: %w", err)
	}
	return nil
}

// Delete removes a file or an empty directory. Non-empty dirs are refused.
func (s *Store) Delete(ctx context.Context, rel string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if rel == "" || strings.HasPrefix(rel, "/") ||
		strings.Contains(rel, "\\") || strings.ContainsRune(rel, 0) {
		return fmt.Errorf("%w: %q", ErrInvalidPath, rel)
	}
	parts := strings.Split(rel, "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return fmt.Errorf("%w: bad segment %q", ErrInvalidPath, p)
		}
	}
	if isReservedTop(parts[0]) {
		return fmt.Errorf("%w: %q", ErrReserved, parts[0])
	}
	full, err := s.resolveExisting(rel)
	if err != nil {
		return err
	}
	fi, err := os.Stat(full)
	if err != nil {
		return fmt.Errorf("%w: %q: %v", ErrNotFound, rel, err)
	}
	if fi.IsDir() {
		if _, err := validateDirPath(rel); err != nil {
			return err
		}
		entries, err := os.ReadDir(full)
		if err != nil {
			return fmt.Errorf("storage: readdir: %w", err)
		}
		if len(entries) > 0 {
			return fmt.Errorf("%w: %q", ErrDirNotEmpty, rel)
		}
		if err := os.Remove(full); err != nil {
			return fmt.Errorf("storage: rmdir: %w", err)
		}
		return nil
	}
	if _, _, err := validateFilePath(rel); err != nil {
		return err
	}
	if err := os.Remove(full); err != nil {
		return fmt.Errorf("storage: remove: %w", err)
	}
	return nil
}

// Entry describes one file or directory.
type Entry struct {
	Path    string // relative to root, slash-separated
	Name    string
	IsDir   bool
	Size    int64
	ModTime int64 // unix seconds, to keep templates simple
}

// List returns the direct children of dir ("" means root).
func (s *Store) List(ctx context.Context, dir string) ([]Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := validateDirPath(dir); err != nil {
		return nil, err
	}
	full, err := s.resolveExisting(dir)
	if err != nil {
		return nil, err
	}
	des, err := os.ReadDir(full)
	if err != nil {
		return nil, fmt.Errorf("storage: readdir: %w", err)
	}
	var out []Entry
	for _, de := range des {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := de.Name()
		// Skip temp files and anything that wouldn't validate.
		if strings.HasSuffix(name, ".tmp") || strings.HasPrefix(name, ".upload-") {
			continue
		}
		rel := name
		if dir != "" {
			rel = dir + "/" + name
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		e := Entry{
			Path:    rel,
			Name:    name,
			IsDir:   de.IsDir(),
			ModTime: info.ModTime().Unix(),
		}
		if !de.IsDir() {
			e.Size = info.Size()
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir // dirs first
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// Stats aggregates file count, directory count, total size and the 10 most
// recently modified files. Symlinks are not followed.
type Stats struct {
	FileCount int
	DirCount  int
	TotalSize int64
	Recent    []Entry // up to 10, newest first
}

// Stats walks the whole tree. Fine for v1 scale; revisit with quotas.
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var st Stats
	var files []Entry
	err := filepath.WalkDir(s.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == s.root {
			return nil
		}
		rel, err := filepath.Rel(s.root, path)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			st.DirCount++
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		st.FileCount++
		st.TotalSize += info.Size()
		files = append(files, Entry{
			Path:    rel,
			Name:    info.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime().Unix(),
		})
		return nil
	})
	if err != nil {
		return Stats{}, fmt.Errorf("storage: stats: %w", err)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].ModTime > files[j].ModTime })
	if len(files) > 10 {
		files = files[:10]
	}
	st.Recent = files
	return st, nil
}
