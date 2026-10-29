package ntfs

import (
	"errors"
	"io"
)

type StreamReader struct {
	fs     *NTFSFS
	stream *Stream
}

func (fs *NTFSFS) OpenStream(st *Stream) *StreamReader {
	return &StreamReader{
		fs:     fs,
		stream: st,
	}
}

func (sr *StreamReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}

	if sr.stream.IsResident {
		if off >= int64(len(sr.stream.ResidentData)) {
			return 0, io.EOF
		}
		n := copy(p, sr.stream.ResidentData[off:])
		if n < len(p) {
			return n, io.EOF
		}
		return n, nil
	}

	// Non-resident stream
	if uint64(off) >= sr.stream.RealSize {
		return 0, io.EOF
	}

	clusterSize := int64(sr.fs.Boot.ClusterSizeBytes)
	bytesRead := 0
	targetLen := int64(len(p))
	if int64(off)+targetLen > int64(sr.stream.RealSize) {
		targetLen = int64(sr.stream.RealSize) - int64(off)
	}

	for _, run := range sr.stream.DataRuns {
		runStartByte := int64(run.VCN) * clusterSize
		runLenBytes := int64(run.Length) * clusterSize
		runEndByte := runStartByte + runLenBytes

		curOff := int64(off) + int64(bytesRead)
		if curOff >= runEndByte {
			continue
		}
		if curOff < runStartByte {
			break
		}

		offInRun := curOff - runStartByte
		availInRun := runLenBytes - offInRun
		toRead := targetLen - int64(bytesRead)
		if toRead > availInRun {
			toRead = availInRun
		}

		if run.IsSparse {
			// Sparse run (zeros)
			for i := int64(0); i < toRead; i++ {
				p[int64(bytesRead)+i] = 0
			}
		} else {
			absDiskOff := sr.fs.LCNToOffset(run.LCN) + offInRun
			n, err := sr.fs.dev.ReadAt(p[bytesRead:int64(bytesRead)+toRead], absDiskOff)
			if err != nil && err != io.EOF {
				return bytesRead + n, err
			}
		}

		bytesRead += int(toRead)
		if int64(bytesRead) >= targetLen {
			break
		}
	}

	return bytesRead, nil
}

// ReadSlack reads the slack space bytes of a non-resident stream.
func (sr *StreamReader) ReadSlack() ([]byte, error) {
	if sr.stream.IsResident || sr.stream.SlackBytes == 0 {
		return nil, nil
	}

	clusterSize := int64(sr.fs.Boot.ClusterSizeBytes)
	slackLen := int(sr.stream.SlackBytes)
	slackBuf := make([]byte, slackLen)

	// Slack space starts immediately after RealSize up to AllocatedSize
	slackStartLogical := int64(sr.stream.RealSize)
	bytesRead := 0

	for _, run := range sr.stream.DataRuns {
		runStartByte := int64(run.VCN) * clusterSize
		runLenBytes := int64(run.Length) * clusterSize
		runEndByte := runStartByte + runLenBytes

		curOff := slackStartLogical + int64(bytesRead)
		if curOff >= runEndByte {
			continue
		}
		if curOff < runStartByte {
			break
		}

		offInRun := curOff - runStartByte
		availInRun := runLenBytes - offInRun
		toRead := int64(slackLen - bytesRead)
		if toRead > availInRun {
			toRead = availInRun
		}

		if !run.IsSparse {
			absDiskOff := sr.fs.LCNToOffset(run.LCN) + offInRun
			sr.fs.dev.ReadAt(slackBuf[bytesRead:bytesRead+int(toRead)], absDiskOff)
		}
		bytesRead += int(toRead)
		if bytesRead >= slackLen {
			break
		}
	}

	return slackBuf, nil
}

// EnumerateFiles iterates through the first maxRecords MFT entries.
func (fs *NTFSFS) EnumerateFiles(maxRecords uint32) ([]*FileRecord, error) {
	var records []*FileRecord
	for i := uint32(0); i < maxRecords; i++ {
		rec, err := fs.ReadMFTRecord(i)
		if err != nil {
			continue
		}
		if rec.FileName != "" {
			records = append(records, rec)
		}
	}
	return records, nil
}
