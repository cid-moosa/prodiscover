package ntfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
	"unicode/utf16"
)

var (
	ErrInvalidMFTRecord = errors.New("invalid MFT record header")
)

type DataRun struct {
	VCN        uint64
	LCN        int64
	Length     uint64 // in clusters
	IsSparse   bool
}

type Stream struct {
	Name          string
	IsResident    bool
	ResidentData  []byte
	DataRuns      []DataRun
	AllocatedSize uint64
	RealSize      uint64
	SlackBytes    uint64
}

type FileRecord struct {
	RecordNumber uint32
	SequenceNum  uint16
	IsAllocated  bool
	IsDirectory  bool
	FileName     string
	ParentRecord uint32
	CreatedTime  time.Time
	ModifiedTime time.Time
	MFTModTime   time.Time
	AccessedTime time.Time
	DefaultStream *Stream
	AlternateStreams []*Stream
}

func parseFileTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	// Windows file time is 100-nanosecond intervals since Jan 1, 1601 UTC
	sec := int64(ft/10000000) - 11644473600
	nsec := int64((ft % 10000000) * 100)
	return time.Unix(sec, nsec).UTC()
}

func decodeSignedInt(b []byte) int64 {
	if len(b) == 0 {
		return 0
	}
	var val int64
	for i := len(b) - 1; i >= 0; i-- {
		val = (val << 8) | int64(b[i])
	}
	// Sign extend if top bit is 1
	if b[len(b)-1]&0x80 != 0 {
		shift := (8 - len(b)) * 8
		val = (val << shift) >> shift
	}
	return val
}

func decodeUint(b []byte) uint64 {
	var val uint64
	for i := len(b) - 1; i >= 0; i-- {
		val = (val << 8) | uint64(b[i])
	}
	return val
}

// ReadMFTRecord reads and applies fixups to an MFT record at the given record index.
func (fs *NTFSFS) ReadMFTRecord(recordIndex uint32) (*FileRecord, error) {
	recordSize := fs.Boot.MFTRecordSize
	mftOffset := fs.LCNToOffset(fs.Boot.MFTCluster) + (int64(recordIndex) * int64(recordSize))

	raw := make([]byte, recordSize)
	if _, err := fs.dev.ReadAt(raw, mftOffset); err != nil {
		return nil, fmt.Errorf("reading MFT record %d: %w", recordIndex, err)
	}

	magic := string(raw[:4])
	if magic != "FILE" && magic != "BAAD" {
		return nil, ErrInvalidMFTRecord
	}

	// Apply fixup array
	fixupOff := binary.LittleEndian.Uint16(raw[4:6])
	fixupCount := binary.LittleEndian.Uint16(raw[6:8])
	if int(fixupOff)+int(fixupCount)*2 <= len(raw) && fixupCount > 1 {
		sectorSize := 512
		for i := 0; i < int(fixupCount)-1; i++ {
			secEnd := (i+1)*sectorSize - 2
			origBytes := raw[fixupOff+2+uint16(i*2) : fixupOff+4+uint16(i*2)]
			raw[secEnd] = origBytes[0]
			raw[secEnd+1] = origBytes[1]
		}
	}

	firstAttrOff := binary.LittleEndian.Uint16(raw[20:22])
	flags := binary.LittleEndian.Uint16(raw[22:24])
	seqNum := binary.LittleEndian.Uint16(raw[16:18])

	rec := &FileRecord{
		RecordNumber: recordIndex,
		SequenceNum:  seqNum,
		IsAllocated:  (flags & 0x01) != 0,
		IsDirectory:  (flags & 0x02) != 0,
	}

	pos := int(firstAttrOff)
	for pos+8 < len(raw) {
		attrType := binary.LittleEndian.Uint32(raw[pos : pos+4])
		if attrType == 0xFFFFFFFF || attrType == 0 {
			break
		}
		attrLen := binary.LittleEndian.Uint32(raw[pos+4 : pos+8])
		if attrLen == 0 || pos+int(attrLen) > len(raw) {
			break
		}

		isNonRes := raw[pos+8] == 1
		nameLen := int(raw[pos+9])
		nameOff := int(binary.LittleEndian.Uint16(raw[pos+10 : pos+12]))
		attrName := ""
		if nameLen > 0 && pos+nameOff+nameLen*2 <= len(raw) {
			var chars []uint16
			for i := 0; i < nameLen; i++ {
				chars = append(chars, binary.LittleEndian.Uint16(raw[pos+nameOff+i*2:pos+nameOff+i*2+2]))
			}
			attrName = string(utf16.Decode(chars))
		}

		switch attrType {
		case 0x10: // $STANDARD_INFORMATION
			if !isNonRes && pos+24 <= len(raw) {
				cOff := int(binary.LittleEndian.Uint16(raw[pos+20 : pos+22]))
				if pos+cOff+48 <= len(raw) {
					p := pos + cOff
					rec.CreatedTime = parseFileTime(binary.LittleEndian.Uint64(raw[p : p+8]))
					rec.ModifiedTime = parseFileTime(binary.LittleEndian.Uint64(raw[p+8 : p+16]))
					rec.MFTModTime = parseFileTime(binary.LittleEndian.Uint64(raw[p+16 : p+24]))
					rec.AccessedTime = parseFileTime(binary.LittleEndian.Uint64(raw[p+24 : p+32]))
				}
			}

		case 0x30: // $FILE_NAME
			if !isNonRes && pos+24 <= len(raw) {
				cOff := int(binary.LittleEndian.Uint16(raw[pos+20 : pos+22]))
				fnPos := pos + cOff
				if fnPos+66 <= len(raw) {
					parentRef := binary.LittleEndian.Uint32(raw[fnPos : fnPos+4])
					fnLen := int(raw[fnPos+64])
					if fnPos+66+fnLen*2 <= len(raw) {
						var chars []uint16
						for i := 0; i < fnLen; i++ {
							chars = append(chars, binary.LittleEndian.Uint16(raw[fnPos+66+i*2:fnPos+66+i*2+2]))
						}
						parsedName := string(utf16.Decode(chars))
						// Prefer Win32 / POSIX names over DOS 8.3 names
						if rec.FileName == "" || len(parsedName) > len(rec.FileName) {
							rec.FileName = parsedName
							rec.ParentRecord = parentRef
						}
					}
				}
			}

		case 0x80: // $DATA
			st := &Stream{
				Name:       attrName,
				IsResident: !isNonRes,
			}

			if !isNonRes {
				// Resident data
				cOff := int(binary.LittleEndian.Uint16(raw[pos+20 : pos+22]))
				cLen := binary.LittleEndian.Uint32(raw[pos+16 : pos+20])
				if pos+cOff+int(cLen) <= len(raw) {
					st.ResidentData = make([]byte, cLen)
					copy(st.ResidentData, raw[pos+cOff:pos+cOff+int(cLen)])
					st.RealSize = uint64(cLen)
					st.AllocatedSize = uint64(cLen)
				}
			} else {
				// Non-resident data
				if pos+64 <= len(raw) {
					allocSize := binary.LittleEndian.Uint64(raw[pos+40 : pos+48])
					realSize := binary.LittleEndian.Uint64(raw[pos+48 : pos+56])
					runsOff := int(binary.LittleEndian.Uint16(raw[pos+32 : pos+34]))

					st.AllocatedSize = allocSize
					st.RealSize = realSize
					if allocSize > realSize {
						st.SlackBytes = allocSize - realSize
					}

					// Parse data runs
					rpos := pos + runsOff
					var prevLCN int64
					var currentVCN uint64

					for rpos < pos+int(attrLen) {
						b := raw[rpos]
						if b == 0 {
							break
						}
						rpos++
						lenBytes := int(b & 0x0F)
						offBytes := int((b >> 4) & 0x0F)

						if rpos+lenBytes+offBytes > pos+int(attrLen) {
							break
						}

						runLen := decodeUint(raw[rpos : rpos+lenBytes])
						rpos += lenBytes

						var runLCN int64
						isSparse := (offBytes == 0)
						if !isSparse {
							delta := decodeSignedInt(raw[rpos : rpos+offBytes])
							rpos += offBytes
							runLCN = prevLCN + delta
							prevLCN = runLCN
						}

						st.DataRuns = append(st.DataRuns, DataRun{
							VCN:      currentVCN,
							LCN:      runLCN,
							Length:   runLen,
							IsSparse: isSparse,
						})
						currentVCN += runLen
					}
				}
			}

			if attrName == "" {
				rec.DefaultStream = st
			} else {
				rec.AlternateStreams = append(rec.AlternateStreams, st)
			}
		}

		pos += int(attrLen)
	}

	return rec, nil
}
