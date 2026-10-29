package extfs

import (
	"encoding/binary"
	"errors"
	"prodiscover/pkg/block"
	"strings"
)

const (
	EXT_MAGIC       = 0xEF53
	SUPERBLOCK_OFF  = 1024
	SUPERBLOCK_SIZE = 1024
)

var (
	ErrNotExtFS = errors.New("not a valid ext2/3/4 filesystem")
)

type Superblock struct {
	InodesCount      uint32
	BlocksCount      uint32
	ReservedBlocks   uint32
	FreeBlocksCount  uint32
	FreeInodesCount  uint32
	FirstDataBlock   uint32
	LogBlockSize     uint32
	LogClusterSize   uint32
	BlocksPerGroup   uint32
	ClustersPerGroup uint32
	InodesPerGroup   uint32
	Mtime            uint32
	Wtime            uint32
	MountCount       uint16
	MaxMountCount    int16
	Magic            uint16
	State            uint16
	Errors           uint16
	MinorRevLevel    uint16
	LastCheck        uint32
	CheckInterval    uint32
	CreatorOS        uint32
	RevLevel         uint32
	DefResUID        uint16
	DefResGID        uint16
	// EXT4 fields
	FirstIno         uint32
	InodeSize        uint16
	BlockGroupNr     uint16
	FeatureCompat    uint32
	FeatureIncompat  uint32
	FeatureROCompat  uint32
	UUID             [16]byte
	VolumeName       string
}

type ExtFS struct {
	Dev         block.BlockDevice
	PartOffset  int64
	Super       Superblock
	BlockSize   uint32
	InodeSize   uint32
	GroupsCount uint32
	DescSize    uint32
}

func OpenExtFS(dev block.BlockDevice, partOffset int64) (*ExtFS, error) {
	buf := make([]byte, SUPERBLOCK_SIZE)
	_, err := dev.ReadAt(buf, partOffset+SUPERBLOCK_OFF)
	if err != nil {
		return nil, err
	}

	magic := binary.LittleEndian.Uint16(buf[0x38:0x3A])
	if magic != EXT_MAGIC {
		return nil, ErrNotExtFS
	}

	var sb Superblock
	sb.InodesCount = binary.LittleEndian.Uint32(buf[0x00:0x04])
	sb.BlocksCount = binary.LittleEndian.Uint32(buf[0x04:0x08])
	sb.ReservedBlocks = binary.LittleEndian.Uint32(buf[0x08:0x0C])
	sb.FreeBlocksCount = binary.LittleEndian.Uint32(buf[0x0C:0x10])
	sb.FreeInodesCount = binary.LittleEndian.Uint32(buf[0x10:0x14])
	sb.FirstDataBlock = binary.LittleEndian.Uint32(buf[0x14:0x18])
	sb.LogBlockSize = binary.LittleEndian.Uint32(buf[0x18:0x1C])
	sb.BlocksPerGroup = binary.LittleEndian.Uint32(buf[0x20:0x24])
	sb.InodesPerGroup = binary.LittleEndian.Uint32(buf[0x28:0x2C])
	sb.Magic = magic
	sb.RevLevel = binary.LittleEndian.Uint32(buf[0x4C:0x50])

	if sb.RevLevel >= 1 {
		sb.FirstIno = binary.LittleEndian.Uint32(buf[0x54:0x58])
		sb.InodeSize = binary.LittleEndian.Uint16(buf[0x58:0x5A])
		sb.FeatureCompat = binary.LittleEndian.Uint32(buf[0x5C:0x60])
		sb.FeatureIncompat = binary.LittleEndian.Uint32(buf[0x60:0x64])
		sb.FeatureROCompat = binary.LittleEndian.Uint32(buf[0x64:0x68])
	} else {
		sb.FirstIno = 11
		sb.InodeSize = 128
	}

	if sb.InodeSize == 0 {
		sb.InodeSize = 128
	}

	copy(sb.UUID[:], buf[0x68:0x78])
	sb.VolumeName = strings.TrimRight(string(buf[0x78:0x88]), "\x00 ")

	blockSize := uint32(1024) << sb.LogBlockSize
	if sb.BlocksPerGroup == 0 {
		return nil, errors.New("corrupt extfs: blocks_per_group is 0")
	}

	groupsCount := (sb.BlocksCount + sb.BlocksPerGroup - 1) / sb.BlocksPerGroup

	descSize := uint32(32)
	// INCOMPAT_64BIT is 0x80 in FeatureIncompat
	if sb.FeatureIncompat&0x80 != 0 {
		descSize = uint32(binary.LittleEndian.Uint16(buf[0xFE:0x100]))
		if descSize == 0 {
			descSize = 64
		}
	}

	return &ExtFS{
		Dev:         dev,
		PartOffset:  partOffset,
		Super:       sb,
		BlockSize:   blockSize,
		InodeSize:   uint32(sb.InodeSize),
		GroupsCount: groupsCount,
		DescSize:    descSize,
	}, nil
}

func (fs *ExtFS) Version() string {
	if fs.Super.FeatureIncompat&0x40 != 0 || fs.Super.FeatureROCompat&0x08 != 0 {
		return "ext4"
	}
	if fs.Super.FeatureCompat&0x04 != 0 {
		return "ext3"
	}
	return "ext2"
}
