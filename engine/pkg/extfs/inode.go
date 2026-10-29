package extfs

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	EXT4_EXTENTS_FL = 0x00080000
	EXT4_EXT_MAGIC  = 0xF30A
)

type BlockGroupDesc struct {
	BlockBitmap uint32
	InodeBitmap uint32
	InodeTable  uint32
	FreeBlocks  uint16
	FreeInodes  uint16
	UsedDirs    uint16
}

type Extent struct {
	LogicalBlock  uint32
	PhysicalBlock uint64
	Count         uint16
}

type Inode struct {
	Number      uint32
	Mode        uint16
	UID         uint16
	Size        uint64
	ATime       uint32
	CTime       uint32
	MTime       uint32
	DTime       uint32
	GID         uint16
	LinksCount  uint16
	Blocks512   uint32
	Flags       uint32
	IsExtent    bool
	Extents     []Extent
	DirectBlocks []uint32
	IsDeleted   bool
}

func (fs *ExtFS) ReadGroupDesc(group uint32) (*BlockGroupDesc, error) {
	if group >= fs.GroupsCount {
		return nil, errors.New("group out of bounds")
	}

	var gdtBlock int64
	if fs.BlockSize == 1024 {
		gdtBlock = 2
	} else {
		gdtBlock = 1
	}

	gdtOff := fs.PartOffset + gdtBlock*int64(fs.BlockSize) + int64(group)*int64(fs.DescSize)
	buf := make([]byte, 32)
	_, err := fs.Dev.ReadAt(buf, gdtOff)
	if err != nil {
		return nil, err
	}

	return &BlockGroupDesc{
		BlockBitmap: binary.LittleEndian.Uint32(buf[0x00:0x04]),
		InodeBitmap: binary.LittleEndian.Uint32(buf[0x04:0x08]),
		InodeTable:  binary.LittleEndian.Uint32(buf[0x08:0x0C]),
		FreeBlocks:  binary.LittleEndian.Uint16(buf[0x0C:0x0E]),
		FreeInodes:  binary.LittleEndian.Uint16(buf[0x0E:0x10]),
		UsedDirs:    binary.LittleEndian.Uint16(buf[0x10:0x12]),
	}, nil
}

func (fs *ExtFS) ReadInode(inoNum uint32) (*Inode, error) {
	if inoNum == 0 || inoNum > fs.Super.InodesCount {
		return nil, errors.New("invalid inode number")
	}

	group := (inoNum - 1) / fs.Super.InodesPerGroup
	index := (inoNum - 1) % fs.Super.InodesPerGroup

	bg, err := fs.ReadGroupDesc(group)
	if err != nil {
		return nil, err
	}

	inodeTableOff := fs.PartOffset + int64(bg.InodeTable)*int64(fs.BlockSize)
	inodeOff := inodeTableOff + int64(index)*int64(fs.InodeSize)

	raw := make([]byte, fs.InodeSize)
	_, err = fs.Dev.ReadAt(raw, inodeOff)
	if err != nil {
		return nil, err
	}

	mode := binary.LittleEndian.Uint16(raw[0x00:0x02])
	uid := binary.LittleEndian.Uint16(raw[0x02:0x04])
	sizeLow := binary.LittleEndian.Uint32(raw[0x04:0x08])
	atime := binary.LittleEndian.Uint32(raw[0x08:0x0C])
	ctime := binary.LittleEndian.Uint32(raw[0x0C:0x10])
	mtime := binary.LittleEndian.Uint32(raw[0x10:0x14])
	dtime := binary.LittleEndian.Uint32(raw[0x14:0x18])
	gid := binary.LittleEndian.Uint16(raw[0x18:0x1A])
	links := binary.LittleEndian.Uint16(raw[0x1A:0x1C])
	blocks512 := binary.LittleEndian.Uint32(raw[0x1C:0x20])
	flags := binary.LittleEndian.Uint32(raw[0x20:0x24])

	totalSize := uint64(sizeLow)
	// If regular file and inode size >= 128, check high 32 bits
	if (mode&0xF000 == 0x8000) && fs.InodeSize > 128 {
		sizeHigh := binary.LittleEndian.Uint32(raw[0x6C:0x70])
		totalSize |= (uint64(sizeHigh) << 32)
	}

	in := &Inode{
		Number:     inoNum,
		Mode:       mode,
		UID:        uid,
		Size:       totalSize,
		ATime:      atime,
		CTime:      ctime,
		MTime:      mtime,
		DTime:      dtime,
		GID:        gid,
		LinksCount: links,
		Blocks512:  blocks512,
		Flags:      flags,
		IsDeleted:  links == 0 || dtime > 0,
	}

	blockArea := raw[0x28 : 0x28+60]
	if flags&EXT4_EXTENTS_FL != 0 {
		in.IsExtent = true
		exts, err := fs.parseExtentBlock(blockArea)
		if err == nil {
			in.Extents = exts
		}
	} else {
		// Traditional block pointers (0-11 direct)
		for i := 0; i < 12; i++ {
			b := binary.LittleEndian.Uint32(blockArea[i*4 : (i+1)*4])
			if b != 0 {
				in.DirectBlocks = append(in.DirectBlocks, b)
			}
		}
	}

	return in, nil
}

func (fs *ExtFS) parseExtentBlock(data []byte) ([]Extent, error) {
	if len(data) < 12 {
		return nil, errors.New("extent data too short")
	}
	magic := binary.LittleEndian.Uint16(data[0:2])
	if magic != EXT4_EXT_MAGIC {
		return nil, errors.New("invalid extent magic")
	}
	entries := binary.LittleEndian.Uint16(data[2:4])
	depth := binary.LittleEndian.Uint16(data[6:8])

	var result []Extent
	if depth == 0 {
		// Leaf nodes
		for i := 0; i < int(entries); i++ {
			off := 12 + i*12
			if off+12 > len(data) {
				break
			}
			eeBlock := binary.LittleEndian.Uint32(data[off : off+4])
			eeLen := binary.LittleEndian.Uint16(data[off+4 : off+6])
			eeStartHi := binary.LittleEndian.Uint16(data[off+6 : off+8])
			eeStartLo := binary.LittleEndian.Uint32(data[off+8 : off+12])
			phys := (uint64(eeStartHi) << 32) | uint64(eeStartLo)

			result = append(result, Extent{
				LogicalBlock:  eeBlock,
				PhysicalBlock: phys,
				Count:         eeLen,
			})
		}
	} else {
		// Internal nodes (tree depth > 0)
		for i := 0; i < int(entries); i++ {
			off := 12 + i*12
			if off+12 > len(data) {
				break
			}
			eiLeafLo := binary.LittleEndian.Uint32(data[off+4 : off+8])
			eiLeafHi := binary.LittleEndian.Uint16(data[off+8 : off+10])
			childBlock := (uint64(eiLeafHi) << 32) | uint64(eiLeafLo)

			childBuf := make([]byte, fs.BlockSize)
			_, err := fs.Dev.ReadAt(childBuf, fs.PartOffset+int64(childBlock)*int64(fs.BlockSize))
			if err == nil {
				sub, _ := fs.parseExtentBlock(childBuf)
				result = append(result, sub...)
			}
		}
	}
	return result, nil
}

// ReadData streams all data bytes for an Inode
func (fs *ExtFS) ReadData(in *Inode) ([]byte, error) {
	if in.Size == 0 {
		return []byte{}, nil
	}

	out := make([]byte, in.Size)
	written := uint64(0)

	if in.IsExtent {
		for _, ext := range in.Extents {
			if written >= in.Size {
				break
			}
			runBytes := uint64(ext.Count) * uint64(fs.BlockSize)
			if written+runBytes > in.Size {
				runBytes = in.Size - written
			}
			physOff := fs.PartOffset + int64(ext.PhysicalBlock)*int64(fs.BlockSize)
			n, err := fs.Dev.ReadAt(out[written:written+runBytes], physOff)
			written += uint64(n)
			if err != nil && err != io.EOF {
				break
			}
		}
	} else {
		// Read direct blocks
		for _, blk := range in.DirectBlocks {
			if written >= in.Size {
				break
			}
			toRead := uint64(fs.BlockSize)
			if written+toRead > in.Size {
				toRead = in.Size - written
			}
			physOff := fs.PartOffset + int64(blk)*int64(fs.BlockSize)
			n, err := fs.Dev.ReadAt(out[written:written+toRead], physOff)
			written += uint64(n)
			if err != nil && err != io.EOF {
				break
			}
		}
	}

	return out[:written], nil
}

// ReadSlack extracts the cluster/block slack space of an Inode
func (fs *ExtFS) ReadSlack(in *Inode) ([]byte, error) {
	if in.Size == 0 {
		return nil, nil
	}

	rem := in.Size % uint64(fs.BlockSize)
	if rem == 0 {
		return nil, nil // No slack space
	}
	slackLen := uint64(fs.BlockSize) - rem

	var lastBlockPhys uint64
	if in.IsExtent && len(in.Extents) > 0 {
		lastExt := in.Extents[len(in.Extents)-1]
		numBlocks := (in.Size + uint64(fs.BlockSize) - 1) / uint64(fs.BlockSize)
		offsetInExt := numBlocks - 1 - uint64(lastExt.LogicalBlock)
		lastBlockPhys = lastExt.PhysicalBlock + offsetInExt
	} else if len(in.DirectBlocks) > 0 {
		lastBlockPhys = uint64(in.DirectBlocks[len(in.DirectBlocks)-1])
	} else {
		return nil, nil
	}

	slackBuf := make([]byte, slackLen)
	slackStart := fs.PartOffset + int64(lastBlockPhys)*int64(fs.BlockSize) + int64(rem)
	_, err := fs.Dev.ReadAt(slackBuf, slackStart)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return slackBuf, nil
}
