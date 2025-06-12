package metadata

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"

	"byor/pkg/strategy"
)

var byteOrder = binary.BigEndian

const (
	MagicNumber uint32 = 0xDEADC0DE
	FooterSize         = 12
	Extension          = ".ransomx"
)

type Metadata struct {
	CipherType   string
	Mode         strategy.Mode
	OriginalSize int64
	KeyMaterial  []byte
	Segments     []strategy.Segment
}

type Footer struct {
	MetadataOffset int64
	Magic          uint32
}

func Write(file *os.File, meta *Metadata) error {
	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("could not stat file for metadata: %w", err)
	}
	metadataOffset := stat.Size()

	jsonData, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("could not marshal metadata: %w", err)
	}

	if _, err := file.WriteAt(jsonData, metadataOffset); err != nil {
		return fmt.Errorf("could not write metadata: %w", err)
	}

	footer := Footer{
		MetadataOffset: metadataOffset,
		Magic:          MagicNumber,
	}

	footerBytes := make([]byte, 12)
	byteOrder.PutUint64(footerBytes[0:8], uint64(footer.MetadataOffset))
	byteOrder.PutUint32(footerBytes[8:12], footer.Magic)

	footerOffset := metadataOffset + int64(len(jsonData))
	if _, err := file.WriteAt(footerBytes, footerOffset); err != nil {
		return fmt.Errorf("could not write footer: %w", err)
	}

	return nil
}

func Read(file *os.File) (*Metadata, error) {
	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("could not stat file for footer: %w", err)
	}
	fileSize := stat.Size()

	if fileSize < FooterSize {
		return nil, fmt.Errorf("file is too small to contain a footer")
	}

	footerBytes := make([]byte, FooterSize)
	if _, err := file.ReadAt(footerBytes, fileSize-FooterSize); err != nil {
		return nil, fmt.Errorf("could not read footer: %w", err)
	}

	magic := byteOrder.Uint32(footerBytes[8:12])
	if magic != MagicNumber {
		return nil, fmt.Errorf("invalid magic number on file")
	}
	metadataOffset := int64(byteOrder.Uint64(footerBytes[0:8]))
	metadataSize := fileSize - FooterSize - metadataOffset

	if metadataSize <= 0 {
		return nil, fmt.Errorf("invalid metadata size calculated: %d", metadataSize)
	}

	jsonData := make([]byte, metadataSize)
	if _, err := file.ReadAt(jsonData, metadataOffset); err != nil {
		return nil, fmt.Errorf("could not read metadata blob: %w", err)
	}

	var meta Metadata
	if err := json.Unmarshal(jsonData, &meta); err != nil {
		return nil, fmt.Errorf("could not unmarshal metadata: %w", err)
	}

	return &meta, nil
}
