package web

// Package web embeds dashboard templates and static assets into the binary.
// Real templates land in v0.2/v0.3 (dashboard); v0.1 keeps the placeholder
// so the layout in CLAUDE.md §4 exists from the start.
import "embed"

//go:embed all:templates all:static
var Files embed.FS
