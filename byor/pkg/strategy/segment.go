package strategy

type Segment struct {
	Offset int64
	Size   int64
}

func CalculateSegments(fileSize int64, s *Strategy) []Segment {
	switch s.Mode {
	case ModeFull:
		return []Segment{{Offset: 0, Size: fileSize}}
	case ModeHeader:
		if fileSize < headerSize {
			return []Segment{{Offset: 0, Size: fileSize}}
		}
		return []Segment{{Offset: 0, Size: headerSize}}
	case ModePartial:
		if s.PartialBlocks <= 0 || s.PartialPercent <= 0 {
			return CalculateSegments(fileSize, &Strategy{Mode: ModeHeader})
		}
		if s.PartialPercent > 100 {
			s.PartialPercent = 100
		}
		partSize := (fileSize / 100) * int64(s.PartialPercent)
		if partSize == 0 {
			return []Segment{}
		}

		if int64(s.PartialBlocks)*partSize >= fileSize {
			return []Segment{{Offset: 0, Size: fileSize}}
		}

		segments := make([]Segment, 0, s.PartialBlocks)
		stepSize := (fileSize - (partSize * int64(s.PartialBlocks))) / int64(s.PartialBlocks-1)

		var currentOffset int64
		for i := 0; i < s.PartialBlocks; i++ {
			segments = append(segments, Segment{Offset: currentOffset, Size: partSize})
			currentOffset += partSize + stepSize
		}
		return segments
	}
	return []Segment{}
}