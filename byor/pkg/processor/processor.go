package processor

import (
	"fmt"
	"os"
	"strings"

	"byor/pkg/cipher"
	"byor/pkg/metadata"
	"byor/pkg/strategy"
)

func EncryptFile(filePath string, c cipher.Cipher, s *strategy.Strategy) error {
	if strings.HasSuffix(filePath, metadata.Extension) {
		return nil
	}

	file, err := os.OpenFile(filePath, os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	fileSize := stat.Size()

	if s.Mode == strategy.ModeIntelligent {
		s.Mode = strategy.DetermineMode(filePath, fileSize)
	}

	keyMaterial, stream, err := c.NewEncryptionContext()
	if err != nil {
		return fmt.Errorf("failed to create encryption context: %w", err)
	}

	segments := strategy.CalculateSegments(fileSize, s)

	for _, segment := range segments {
		if err := processStream(file, stream, segment.Offset, segment.Size); err != nil {
			return fmt.Errorf("failed to process segment: %w", err)
		}
	}

	meta := &metadata.Metadata{
		CipherType:   c.Name(),
		Mode:         s.Mode,
		OriginalSize: fileSize,
		KeyMaterial:  keyMaterial,
		Segments:     segments,
	}
	if err := metadata.Write(file, meta); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	file.Close()

	newPath := filePath + metadata.Extension
	if err := os.Rename(filePath, newPath); err != nil {
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}

func DecryptFile(filePath string, ciphers map[string]cipher.Cipher) error {
	if !strings.HasSuffix(filePath, metadata.Extension) {
		return nil
	}

	file, err := os.OpenFile(filePath, os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	meta, err := metadata.Read(file)
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	c, ok := ciphers[meta.CipherType]
	if !ok {
		return fmt.Errorf("unknown cipher type found in metadata: %s", meta.CipherType)
	}

	stream, err := c.LoadDecryptionContext(meta.KeyMaterial)
	if err != nil {
		return fmt.Errorf("failed to load decryption context: %w", err)
	}

	for _, segment := range meta.Segments {
		if err := processStream(file, stream, segment.Offset, segment.Size); err != nil {
			return fmt.Errorf("failed to process segment for decryption: %w", err)
		}
	}

	if err := file.Truncate(meta.OriginalSize); err != nil {
		return fmt.Errorf("failed to truncate file: %w", err)
	}

	file.Close()

	newPath := strings.TrimSuffix(filePath, metadata.Extension)
	if err := os.Rename(filePath, newPath); err != nil {
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}
