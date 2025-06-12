package processor

import (
	"crypto/cipher"
	"fmt"
	"io"
	"os"
)

const streamBufferSize = 1024 * 1024

func processStream(file *os.File, stream cipher.Stream, offset int64, size int64) error {
	if size == 0 {
		return nil
	}

	buf := make([]byte, streamBufferSize)
	var currentPosition int64

	if seeker, ok := stream.(io.Seeker); ok {
		if _, err := seeker.Seek(offset, io.SeekStart); err != nil {
			return fmt.Errorf("stream cipher does not support seeking: %w", err)
		}
	} else {
		if offset > 0 {
			dummy := make([]byte, offset)
			stream.XORKeyStream(dummy, dummy)
		}
	}

	for currentPosition < size {
		bytesToProcess := int64(streamBufferSize)
		if size-currentPosition < streamBufferSize {
			bytesToProcess = size - currentPosition
		}

		chunk := buf[:bytesToProcess]
		readOffset := offset + currentPosition

		n, err := file.ReadAt(chunk, readOffset)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read at offset %d: %w", readOffset, err)
		}
		if n == 0 {
			break
		}

		chunk = chunk[:n]
		stream.XORKeyStream(chunk, chunk)

		if _, err := file.WriteAt(chunk, readOffset); err != nil {
			return fmt.Errorf("failed to write at offset %d: %w", readOffset, err)
		}
		currentPosition += int64(n)
	}
	return nil
}