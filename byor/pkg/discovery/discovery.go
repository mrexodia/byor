package discovery

import (
	"io/fs"
	"math/rand"
	"path/filepath"
	"sort"
	"time"

	"byor/pkg/worker"
)

// Strategy defines the file discovery algorithm.
type Strategy int

const (
	// Default strategy walks the directory and sends files as they are found.
	Default Strategy = iota
	// Intelligent strategy finds all files, then sorts them by size (largest first).
	Intelligent
	// Shuffle strategy finds all files and shuffles them randomly.
	Shuffle
)

// Discoverer is responsible for finding files based on a strategy.
type Discoverer struct {
	Strategy Strategy
	Pool     *worker.Pool
}

// NewDiscoverer creates a new Discoverer.
func NewDiscoverer(strategy Strategy, pool *worker.Pool) *Discoverer {
	return &Discoverer{
		Strategy: strategy,
		Pool:     pool,
	}
}

// DiscoverFiles starts the file discovery process based on the chosen strategy.
func (d *Discoverer) DiscoverFiles(root string) error {
	defer d.Pool.CloseJobs()

	switch d.Strategy {
	case Intelligent:
		return d.discoverIntelligent(root)
	case Shuffle:
		return d.discoverShuffle(root)
	default:
		return d.discoverDefault(root)
	}
}

// discoverDefault walks the directory and sends files to the pool as they are found.
func (d *Discoverer) discoverDefault(root string) error {
	return filepath.WalkDir(root, func(path string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !de.IsDir() {
			d.Pool.AddJob(worker.Job(path))
		}
		return nil
	})
}

// fileInfo helps store path and size for sorting.
type fileInfo struct {
	path string
	size int64
}

// discoverAndProcess walks the entire directory tree to collect all file paths first.
func (d *Discoverer) discoverAndProcess(root string) ([]fileInfo, error) {
	var files []fileInfo
	err := filepath.WalkDir(root, func(path string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !de.IsDir() {
			info, err := de.Info()
			if err != nil {
				// Log or handle error, maybe skip the file
				return nil
			}
			files = append(files, fileInfo{path: path, size: info.Size()})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// discoverIntelligent finds all files, sorts them by size (largest first), and sends to pool.
func (d *Discoverer) discoverIntelligent(root string) error {
	files, err := d.discoverAndProcess(root)
	if err != nil {
		return err
	}

	// Sort files by size, descending
	sort.Slice(files, func(i, j int) bool {
		return files[i].size > files[j].size
	})

	for _, file := range files {
		d.Pool.AddJob(worker.Job(file.path))
	}

	return nil
}

// discoverShuffle finds all files, shuffles them, and sends them to the pool.
func (d *Discoverer) discoverShuffle(root string) error {
	files, err := d.discoverAndProcess(root)
	if err != nil {
		return err
	}

	// Shuffle the files
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	r.Shuffle(len(files), func(i, j int) {
		files[i], files[j] = files[j], files[i]
	})

	for _, file := range files {
		d.Pool.AddJob(worker.Job(file.path))
	}

	return nil
}
