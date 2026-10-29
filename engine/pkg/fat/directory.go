package fat

import (
	"encoding/binary"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	AttrReadOnly  = 0x01
	AttrHidden    = 0x02
	AttrSystem    = 0x04
	AttrVolumeID  = 0x08
	AttrDirectory = 0x10
	AttrArchive   = 0x20
	AttrLFN       = 0x0F
)

type FileEntry struct {
	Name            string
	ShortName       string
	Size            uint32
	StartCluster    uint32
	IsDirectory     bool
	IsDeleted       bool
	IsHidden        bool
	Attributes      uint8
	CreatedTime     time.Time
	ModifiedTime    time.Time
	AccessedTime    time.Time
	ClusterChain    []uint32
	SlackSizeBytes  uint32
}

func parseDOSTime(dosDate, dosTime uint16) time.Time {
	if dosDate == 0 {
		return time.Time{}
	}
	year := int((dosDate >> 9) & 0x7F) + 1980
	month := time.Month((dosDate >> 5) & 0x0F)
	day := int(dosDate & 0x1F)

	hour := int((dosTime >> 11) & 0x1F)
	minute := int((dosTime >> 5) & 0x3F)
	second := int((dosTime & 0x1F) * 2)

	return time.Date(year, month, day, hour, minute, second, 0, time.UTC)
}

// ReadRootDirEntries parses all directory entries in the root directory.
func (fs *FATFS) ReadRootDirEntries() ([]FileEntry, error) {
	var entries []FileEntry
	var rawEntries []byte

	if fs.Boot.Type == FAT32 {
		chain := fs.GetClusterChain(fs.Boot.RootDirCluster32)
		rawEntries = make([]byte, len(chain)*int(fs.Boot.ClusterSizeBytes))
		for i, c := range chain {
			start := i * int(fs.Boot.ClusterSizeBytes)
			if err := fs.ReadCluster(c, rawEntries[start:]); err != nil {
				return nil, err
			}
		}
	} else {
		rootDirBytes := int64(fs.Boot.RootDirSectors) * int64(fs.Boot.BytesPerSector)
		rootDirOffset := fs.offset + (int64(fs.Boot.ReservedSectors)+(int64(fs.Boot.NumberOfFATs)*int64(fs.Boot.SectorsPerFAT)))*int64(fs.Boot.BytesPerSector)
		rawEntries = make([]byte, rootDirBytes)
		if _, err := fs.dev.ReadAt(rawEntries, rootDirOffset); err != nil {
			return nil, err
		}
	}

	var lfnParts []string

	for i := 0; i < len(rawEntries); i += 32 {
		entry := rawEntries[i : i+32]
		firstByte := entry[0]

		if firstByte == 0x00 {
			break // End of directory
		}

		attr := entry[11]

		if attr == AttrLFN {
			// Long File Name entry
			var chars []uint16
			for _, off := range []int{1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30} {
				ch := binary.LittleEndian.Uint16(entry[off : off+2])
				if ch == 0x0000 || ch == 0xFFFF {
					break
				}
				chars = append(chars, ch)
			}
			part := string(utf16.Decode(chars))
			lfnParts = append([]string{part}, lfnParts...)
			continue
		}

		isDeleted := (firstByte == 0xE5)
		rawName := entry[0:8]
		rawExt := entry[8:11]

		baseName := strings.TrimRight(string(rawName), " ")
		ext := strings.TrimRight(string(rawExt), " ")
		shortName := baseName
		if ext != "" {
			shortName = baseName + "." + ext
		}

		displayName := shortName
		if len(lfnParts) > 0 {
			displayName = strings.Join(lfnParts, "")
			lfnParts = nil
		}

		clusterHigh := binary.LittleEndian.Uint16(entry[20:22])
		clusterLow := binary.LittleEndian.Uint16(entry[26:28])
		startCluster := (uint32(clusterHigh) << 16) | uint32(clusterLow)
		fileSize := binary.LittleEndian.Uint32(entry[28:32])

		createTime := parseDOSTime(binary.LittleEndian.Uint16(entry[16:18]), binary.LittleEndian.Uint16(entry[14:16]))
		writeTime := parseDOSTime(binary.LittleEndian.Uint16(entry[18:20]), binary.LittleEndian.Uint16(entry[22:24]))
		accessTime := parseDOSTime(binary.LittleEndian.Uint16(entry[18:20]), 0)

		fe := FileEntry{
			Name:         displayName,
			ShortName:    shortName,
			Size:         fileSize,
			StartCluster: startCluster,
			IsDirectory:  (attr & AttrDirectory) != 0,
			IsDeleted:    isDeleted,
			IsHidden:     (attr & AttrHidden) != 0,
			Attributes:   attr,
			CreatedTime:  createTime,
			ModifiedTime: writeTime,
			AccessedTime: accessTime,
		}

		if !fe.IsDirectory && startCluster >= 2 {
			fe.ClusterChain = fs.GetClusterChain(startCluster)
			clusterSize := fs.Boot.ClusterSizeBytes
			if clusterSize > 0 && fileSize > 0 {
				rem := fileSize % clusterSize
				if rem > 0 {
					fe.SlackSizeBytes = clusterSize - rem
				}
			}
		}

		entries = append(entries, fe)
	}

	return entries, nil
}
