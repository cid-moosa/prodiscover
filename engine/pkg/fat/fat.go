package fat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"prodiscover/pkg/block"
)

var (
	ErrNotFAT = errors.New("not a valid FAT filesystem")
)

type FATType int

const (
	FAT12 FATType = 12
	FAT16 FATType = 16
	FAT32 FATType = 32
)

func (t FATType) String() string {
	switch t {
	case FAT12:
		return "FAT12"
	case FAT16:
		return "FAT16"
	case FAT32:
		return "FAT32"
	default:
		return "Unknown FAT"
	}
}

// BootSector contains BIOS Parameter Block (BPB) parameters.
type BootSector struct {
	OEMName            string
	BytesPerSector     uint16
	SectorsPerCluster  uint8
	ReservedSectors    uint16
	NumberOfFATs       uint8
	RootDirEntries     uint16
	TotalSectors16     uint16
	MediaDescriptor    uint8
	SectorsPerFAT16    uint16
	SectorsPerTrack    uint16
	NumberOfHeads      uint16
	HiddenSectors      uint32
	TotalSectors32     uint32
	// FAT32 specific
	SectorsPerFAT32    uint32
	RootDirCluster32   uint32
	// Calculated fields
	TotalSectors       uint32
	SectorsPerFAT      uint32
	RootDirSectors     uint32
	FirstDataSector    uint32
	DataSectors        uint32
	TotalClusters      uint32
	Type               FATType
	ClusterSizeBytes   uint32
}

type FATFS struct {
	dev        block.BlockDevice
	offset     int64
	Boot       BootSector
	fatTable   []byte
}

func OpenFAT(dev block.BlockDevice, partitionOffset int64) (*FATFS, error) {
	sector := make([]byte, 512)
	if _, err := dev.ReadAt(sector, partitionOffset); err != nil {
		return nil, fmt.Errorf("reading boot sector: %w", err)
	}

	// Check boot signature 0x55, 0xAA at end of sector
	if sector[510] != 0x55 || sector[511] != 0xAA {
		return nil, ErrNotFAT
	}

	bs := BootSector{
		OEMName:           strings.TrimSpace(string(sector[3:11])),
		BytesPerSector:    binary.LittleEndian.Uint16(sector[11:13]),
		SectorsPerCluster: sector[13],
		ReservedSectors:   binary.LittleEndian.Uint16(sector[14:16]),
		NumberOfFATs:      sector[16],
		RootDirEntries:    binary.LittleEndian.Uint16(sector[17:19]),
		TotalSectors16:    binary.LittleEndian.Uint16(sector[19:21]),
		MediaDescriptor:   sector[21],
		SectorsPerFAT16:   binary.LittleEndian.Uint16(sector[22:24]),
		SectorsPerTrack:   binary.LittleEndian.Uint16(sector[24:26]),
		NumberOfHeads:     binary.LittleEndian.Uint16(sector[26:28]),
		HiddenSectors:     binary.LittleEndian.Uint32(sector[28:32]),
		TotalSectors32:    binary.LittleEndian.Uint32(sector[32:36]),
	}

	if bs.BytesPerSector == 0 || bs.SectorsPerCluster == 0 {
		return nil, ErrNotFAT
	}

	if bs.TotalSectors16 != 0 {
		bs.TotalSectors = uint32(bs.TotalSectors16)
	} else {
		bs.TotalSectors = bs.TotalSectors32
	}

	if bs.SectorsPerFAT16 != 0 {
		bs.SectorsPerFAT = uint32(bs.SectorsPerFAT16)
	} else {
		bs.SectorsPerFAT32 = binary.LittleEndian.Uint32(sector[36:40])
		bs.SectorsPerFAT = bs.SectorsPerFAT32
		bs.RootDirCluster32 = binary.LittleEndian.Uint32(sector[44:48])
	}

	bs.RootDirSectors = ((uint32(bs.RootDirEntries) * 32) + (uint32(bs.BytesPerSector) - 1)) / uint32(bs.BytesPerSector)
	bs.FirstDataSector = uint32(bs.ReservedSectors) + (uint32(bs.NumberOfFATs) * bs.SectorsPerFAT) + bs.RootDirSectors
	if bs.TotalSectors > bs.FirstDataSector {
		bs.DataSectors = bs.TotalSectors - bs.FirstDataSector
	}
	bs.TotalClusters = bs.DataSectors / uint32(bs.SectorsPerCluster)
	bs.ClusterSizeBytes = uint32(bs.BytesPerSector) * uint32(bs.SectorsPerCluster)

	if bs.TotalClusters < 4085 {
		bs.Type = FAT12
	} else if bs.TotalClusters < 65525 {
		bs.Type = FAT16
	} else {
		bs.Type = FAT32
	}

	// Read FAT table 0 into memory for fast cluster chain traversal
	fatTableBytes := int64(bs.SectorsPerFAT) * int64(bs.BytesPerSector)
	fatOffset := partitionOffset + int64(bs.ReservedSectors)*int64(bs.BytesPerSector)
	fatBuf := make([]byte, fatTableBytes)
	if _, err := dev.ReadAt(fatBuf, fatOffset); err != nil {
		return nil, fmt.Errorf("reading FAT table: %w", err)
	}

	return &FATFS{
		dev:      dev,
		offset:   partitionOffset,
		Boot:     bs,
		fatTable: fatBuf,
	}, nil
}

// ClusterToSector returns the first sector number for a given cluster number.
func (fs *FATFS) ClusterToSector(cluster uint32) uint32 {
	if cluster < 2 {
		return 0
	}
	return ((cluster - 2) * uint32(fs.Boot.SectorsPerCluster)) + fs.Boot.FirstDataSector
}

// ClusterToOffset returns the absolute byte offset in the block device for a cluster.
func (fs *FATFS) ClusterToOffset(cluster uint32) int64 {
	sec := fs.ClusterToSector(cluster)
	return fs.offset + (int64(sec) * int64(fs.Boot.BytesPerSector))
}

// ReadCluster reads the complete content of a given cluster.
func (fs *FATFS) ReadCluster(cluster uint32, dest []byte) error {
	if cluster < 2 || cluster >= fs.Boot.TotalClusters+2 {
		return fmt.Errorf("cluster %d out of valid range", cluster)
	}
	off := fs.ClusterToOffset(cluster)
	clusterSize := int(fs.Boot.ClusterSizeBytes)
	if len(dest) < clusterSize {
		return fmt.Errorf("buffer too small (expected %d bytes)", clusterSize)
	}
	_, err := fs.dev.ReadAt(dest[:clusterSize], off)
	return err
}

// GetNextCluster returns the next cluster in the chain according to the FAT table.
func (fs *FATFS) GetNextCluster(cluster uint32) (uint32, bool) {
	switch fs.Boot.Type {
	case FAT12:
		entryOffset := cluster + (cluster / 2)
		if int(entryOffset)+2 > len(fs.fatTable) {
			return 0, false
		}
		val := binary.LittleEndian.Uint16(fs.fatTable[entryOffset : entryOffset+2])
		if cluster%2 == 1 {
			val >>= 4
		} else {
			val &= 0x0FFF
		}
		if val >= 0x0FF8 {
			return 0, false // EOF
		}
		return uint32(val), true

	case FAT16:
		entryOffset := cluster * 2
		if int(entryOffset)+2 > len(fs.fatTable) {
			return 0, false
		}
		val := binary.LittleEndian.Uint16(fs.fatTable[entryOffset : entryOffset+2])
		if val >= 0xFFF8 {
			return 0, false // EOF
		}
		return uint32(val), true

	case FAT32:
		entryOffset := cluster * 4
		if int(entryOffset)+4 > len(fs.fatTable) {
			return 0, false
		}
		val := binary.LittleEndian.Uint32(fs.fatTable[entryOffset:entryOffset+4]) & 0x0FFFFFFF
		if val >= 0x0FFFFFF8 {
			return 0, false // EOF
		}
		return val, true
	}
	return 0, false
}

// IsClusterAllocated checks if a cluster is allocated (non-zero and not bad).
func (fs *FATFS) IsClusterAllocated(cluster uint32) bool {
	switch fs.Boot.Type {
	case FAT12:
		entryOffset := cluster + (cluster / 2)
		if int(entryOffset)+2 > len(fs.fatTable) {
			return false
		}
		val := binary.LittleEndian.Uint16(fs.fatTable[entryOffset : entryOffset+2])
		if cluster%2 == 1 {
			val >>= 4
		} else {
			val &= 0x0FFF
		}
		return val != 0 && val != 0x0FF7

	case FAT16:
		entryOffset := cluster * 2
		if int(entryOffset)+2 > len(fs.fatTable) {
			return false
		}
		val := binary.LittleEndian.Uint16(fs.fatTable[entryOffset : entryOffset+2])
		return val != 0 && val != 0xFFF7

	case FAT32:
		entryOffset := cluster * 4
		if int(entryOffset)+4 > len(fs.fatTable) {
			return false
		}
		val := binary.LittleEndian.Uint32(fs.fatTable[entryOffset:entryOffset+4]) & 0x0FFFFFFF
		return val != 0 && val != 0x0FFFFFF7
	}
	return false
}

// GetClusterChain collects all cluster numbers for a file starting at startCluster.
func (fs *FATFS) GetClusterChain(startCluster uint32) []uint32 {
	var chain []uint32
	curr := startCluster
	for curr >= 2 && curr < fs.Boot.TotalClusters+2 {
		chain = append(chain, curr)
		next, hasNext := fs.GetNextCluster(curr)
		if !hasNext {
			break
		}
		curr = next
	}
	return chain
}
