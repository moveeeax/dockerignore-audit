package audit

import (
	"bytes"
	"os"
	"sort"
	"strings"
)

// Usage is a file count and byte total.
type Usage struct {
	Files int   `json:"files"`
	Bytes int64 `json:"bytes"`
}

// DirUsage is the share of the build context under one top-level directory.
type DirUsage struct {
	Path string
	Usage
}

// ContextUsage is what Docker would send for the context at dir under ig,
// with a per-directory breakdown for the top-level directories, largest first.
type ContextUsage struct {
	Usage
	Dirs []DirUsage
}

// MeasureContext sums the files Docker would send from dir under ig. Sizes
// are file sizes as reported by lstat; symlinks count as links, the way
// Docker sends them.
func MeasureContext(dir string, ig *Ignore) (ContextUsage, error) {
	var cu ContextUsage
	byDir := map[string]*Usage{}
	err := walkContext(dir, dir, ig, func(rel string, info os.FileInfo) error {
		if info.IsDir() {
			return nil
		}
		cu.Files++
		cu.Bytes += info.Size()
		if top, _, ok := strings.Cut(rel, "/"); ok {
			u := byDir[top]
			if u == nil {
				u = &Usage{}
				byDir[top] = u
			}
			u.Files++
			u.Bytes += info.Size()
		}
		return nil
	})
	if err != nil {
		return ContextUsage{}, err
	}
	for p, u := range byDir {
		cu.Dirs = append(cu.Dirs, DirUsage{Path: p, Usage: *u})
	}
	sort.Slice(cu.Dirs, func(i, j int) bool {
		a, b := cu.Dirs[i], cu.Dirs[j]
		if a.Bytes != b.Bytes {
			return a.Bytes > b.Bytes
		}
		return a.Path < b.Path
	})
	return cu, nil
}

// TopDirs is how many directories the size report lists.
const TopDirs = 10

// SizeReport compares the build context now with the context after the
// suggested patterns are added.
type SizeReport struct {
	Before ContextUsage
	After  ContextUsage
}

// MeasureSize measures dir under its current .dockerignore (ig) and under the
// content fix would write, so "after" matches what -fix produces.
func MeasureSize(dir string, ig *Ignore, fix *Fix) (*SizeReport, error) {
	before, err := MeasureContext(dir, ig)
	if err != nil {
		return nil, err
	}
	next, err := ParseIgnore(bytes.NewReader(fix.New))
	if err != nil {
		return nil, err
	}
	after, err := MeasureContext(dir, next)
	if err != nil {
		return nil, err
	}
	return &SizeReport{Before: before, After: after}, nil
}

// topDirs returns at most TopDirs entries of the before-breakdown.
func (s *SizeReport) topDirs() []DirUsage {
	if len(s.Before.Dirs) > TopDirs {
		return s.Before.Dirs[:TopDirs]
	}
	return s.Before.Dirs
}
