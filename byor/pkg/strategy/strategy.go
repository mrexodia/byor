package strategy

import (
	"path/filepath"
	"strings"
)

const (
	ModeIntelligentStr = "intelligent"
	ModeFullStr        = "full"
	ModeHeaderStr      = "header"
	ModePartialStr     = "partial"
)

type Mode uint8

const (
	ModeIntelligent Mode = iota
	ModeFull
	ModeHeader
	ModePartial
)

type Strategy struct {
	Mode           Mode
	PartialPercent int
	PartialBlocks  int
}

const (
	headerSize    = 1048576
	smallFileSize = 5242880
)

var (
	dbExtensions = map[string]struct{}{
		".db": {}, ".sql": {}, ".sqlite": {}, ".mdf": {}, ".sdf": {}, ".dbf": {},
	}
	vmExtensions = map[string]struct{}{
		".vdi": {}, ".vhd": {}, ".vmdk": {}, ".iso": {}, ".raw": {}, ".qcow2": {},
	}
)

func DetermineMode(filePath string, fileSize int64) Mode {
	ext := strings.ToLower(filepath.Ext(filePath))
	if _, ok := dbExtensions[ext]; ok {
		return ModeFull
	}
	if _, ok := vmExtensions[ext]; ok {
		return ModePartial
	}

	if fileSize <= headerSize {
		return ModeFull
	}
	if fileSize <= smallFileSize {
		return ModeHeader
	}
	return ModePartial
}