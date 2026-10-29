package extfs

import (
	"encoding/binary"
	"errors"
	"strings"
)

type DirEntry struct {
	InodeNumber uint32
	RecordLen   uint16
	NameLen     uint8
	FileType    uint8
	Name        string
	IsDeleted   bool
	SlackBytes  uint16
}

type FileMetadata struct {
	Name        string
	InodeNumber uint32
	Size        uint64
	IsDirectory bool
	IsDeleted   bool
	SlackSize   uint64
}

// ReadDirEntries parses both allocated and carved deleted directory entries from a directory inode
func (fs *ExtFS) ReadDirEntries(dirInode *Inode) ([]DirEntry, error) {
	if dirInode.Mode&0xF000 != 0x4000 {
		return nil, errors.New("not a directory inode")
	}

	data, err := fs.ReadData(dirInode)
	if err != nil {
		return nil, err
	}

	var entries []DirEntry
	off := 0

	for off < len(data) {
		if off+8 > len(data) {
			break
		}
		ino := binary.LittleEndian.Uint32(data[off : off+4])
		recLen := binary.LittleEndian.Uint16(data[off+4 : off+6])
		nameLen := data[off+6]
		fileType := data[off+7]

		if recLen < 8 || int(recLen) > len(data)-off {
			break
		}

		actualLen := 8 + int(nameLen)
		actualLenAligned := (actualLen + 3) & ^3 // 4-byte aligned
		slack := int(recLen) - actualLenAligned

		if ino != 0 && int(nameLen) <= int(recLen)-8 && off+8+int(nameLen) <= len(data) {
			name := string(data[off+8 : off+8+int(nameLen)])
			entries = append(entries, DirEntry{
				InodeNumber: ino,
				RecordLen:   recLen,
				NameLen:     nameLen,
				FileType:    fileType,
				Name:        name,
				IsDeleted:   false,
				SlackBytes:  uint16(slack),
			})
		}

		// Carve deleted entries hidden within recLen slack
		if slack >= 8 {
			deletedOff := off + actualLenAligned
			delIno := binary.LittleEndian.Uint32(data[deletedOff : deletedOff+4])
			delRecLen := binary.LittleEndian.Uint16(data[deletedOff+4 : deletedOff+6])
			delNameLen := data[deletedOff+6]
			delFileType := data[deletedOff+7]

			if delIno > 0 && delIno <= fs.Super.InodesCount && int(delNameLen) > 0 && int(delNameLen) <= slack-8 {
				delName := string(data[deletedOff+8 : deletedOff+8+int(delNameLen)])
				// Check for printable characters
				isPrintable := true
				for _, ch := range delName {
					if ch < 32 || ch > 126 {
						isPrintable = false
						break
					}
				}
				if isPrintable && !strings.Contains(delName, "\x00") {
					entries = append(entries, DirEntry{
						InodeNumber: delIno,
						RecordLen:   delRecLen,
						NameLen:     delNameLen,
						FileType:    delFileType,
						Name:        delName,
						IsDeleted:   true,
						SlackBytes:  0,
					})
				}
			}
		}

		off += int(recLen)
	}

	return entries, nil
}

// EnumerateFiles enumerates files starting from root directory (inode 2)
func (fs *ExtFS) EnumerateFiles() ([]FileMetadata, error) {
	rootInode, err := fs.ReadInode(2)
	if err != nil {
		return nil, err
	}

	entries, err := fs.ReadDirEntries(rootInode)
	if err != nil {
		return nil, err
	}

	var files []FileMetadata
	for _, e := range entries {
		if e.Name == "." || e.Name == ".." {
			continue
		}
		in, err := fs.ReadInode(e.InodeNumber)
		var sz uint64
		var isDir bool
		var isDel bool
		var slack uint64

		if err == nil {
			sz = in.Size
			isDir = (in.Mode&0xF000 == 0x4000)
			isDel = e.IsDeleted || in.IsDeleted
			if sz > 0 && fs.BlockSize > 0 {
				rem := sz % uint64(fs.BlockSize)
				if rem > 0 {
					slack = uint64(fs.BlockSize) - rem
				}
			}
		} else {
			isDel = true
		}

		files = append(files, FileMetadata{
			Name:        e.Name,
			InodeNumber: e.InodeNumber,
			Size:        sz,
			IsDirectory: isDir,
			IsDeleted:   isDel,
			SlackSize:   slack,
		})
	}

	return files, nil
}
