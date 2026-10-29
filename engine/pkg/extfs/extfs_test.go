package extfs

import (
	"encoding/binary"
	"testing"
)

// MockBlockDevice implements block.BlockDevice in-memory
type MockBlockDevice struct {
	data []byte
}

func (m *MockBlockDevice) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(m.data)) {
		return 0, nil
	}
	n := copy(p, m.data[off:])
	return n, nil
}

func (m *MockBlockDevice) Size() int64 {
	return int64(len(m.data))
}

func (m *MockBlockDevice) SectorSize() int64 {
	return 512
}

func (m *MockBlockDevice) Close() error {
	return nil
}

func TestExt4SuperblockAndInode(t *testing.T) {
	// Allocate a 1MB mock disk
	img := make([]byte, 1024*1024)

	// 1. Write Superblock at offset 1024
	sbOff := 1024
	binary.LittleEndian.PutUint32(img[sbOff+0x00:], 100)       // Inodes count
	binary.LittleEndian.PutUint32(img[sbOff+0x04:], 1024)      // Blocks count
	binary.LittleEndian.PutUint32(img[sbOff+0x18:], 0)         // LogBlockSize = 0 -> 1024 bytes/block
	binary.LittleEndian.PutUint32(img[sbOff+0x20:], 1024)      // Blocks per group
	binary.LittleEndian.PutUint32(img[sbOff+0x28:], 100)       // Inodes per group
	binary.LittleEndian.PutUint16(img[sbOff+0x38:], EXT_MAGIC) // 0xEF53
	binary.LittleEndian.PutUint32(img[sbOff+0x4C:], 1)         // RevLevel = 1
	binary.LittleEndian.PutUint16(img[sbOff+0x58:], 256)       // InodeSize = 256
	copy(img[sbOff+0x78:], []byte("FORENSIC_VOL"))

	// 2. Write Group Descriptor at Block 2 (offset 2048)
	gdtOff := 2048
	binary.LittleEndian.PutUint32(img[gdtOff+0x08:], 10) // Inode Table at Block 10 (offset 10240)

	// 3. Write Root Inode (Inode 2) at Inode Table + (2-1)*256 = 10240 + 256 = 10496
	rootInoOff := 10496
	binary.LittleEndian.PutUint16(img[rootInoOff+0x00:], 0x41ED) // Directory mode
	binary.LittleEndian.PutUint32(img[rootInoOff+0x04:], 1024)   // Size = 1024 bytes (1 block)
	binary.LittleEndian.PutUint16(img[rootInoOff+0x1A:], 2)      // LinksCount = 2
	binary.LittleEndian.PutUint32(img[rootInoOff+0x20:], EXT4_EXTENTS_FL)

	// Extent header inside root inode (offset 0x28)
	extHdrOff := rootInoOff + 0x28
	binary.LittleEndian.PutUint16(img[extHdrOff+0:], EXT4_EXT_MAGIC)
	binary.LittleEndian.PutUint16(img[extHdrOff+2:], 1) // 1 entry
	binary.LittleEndian.PutUint16(img[extHdrOff+4:], 4) // max 4
	binary.LittleEndian.PutUint16(img[extHdrOff+6:], 0) // depth 0

	// Extent 0: logical block 0 -> physical block 20 (offset 20480), length 1
	binary.LittleEndian.PutUint32(img[extHdrOff+12:], 0)  // ee_block = 0
	binary.LittleEndian.PutUint16(img[extHdrOff+16:], 1)  // ee_len = 1
	binary.LittleEndian.PutUint32(img[extHdrOff+20:], 20) // ee_start_lo = block 20

	// 4. Directory contents at Block 20 (offset 20480)
	dirOff := 20 * 1024
	// Entry 1: "." (inode 2, rec_len 12)
	binary.LittleEndian.PutUint32(img[dirOff:], 2)
	binary.LittleEndian.PutUint16(img[dirOff+4:], 12)
	img[dirOff+6] = 1 // name_len
	img[dirOff+7] = 2 // directory
	copy(img[dirOff+8:], ".")

	// Entry 2: ".." (inode 2, rec_len 12)
	binary.LittleEndian.PutUint32(img[dirOff+12:], 2)
	binary.LittleEndian.PutUint16(img[dirOff+16:], 12)
	img[dirOff+18] = 2 // name_len
	img[dirOff+19] = 2 // directory
	copy(img[dirOff+20:], "..")

	// Entry 3: "evidence.txt" (inode 12, rec_len 1000 - spans remaining block, leaving slack for deleted entry!)
	binary.LittleEndian.PutUint32(img[dirOff+24:], 12)
	binary.LittleEndian.PutUint16(img[dirOff+28:], 1000)
	img[dirOff+30] = 12 // name_len
	img[dirOff+31] = 1  // regular file
	copy(img[dirOff+32:], "evidence.txt")

	// In unallocated slack of entry 3 (at offset dirOff + 24 + 20 = dirOff + 44):
	// Embed a carved deleted entry "deleted_log.dat" (inode 15)
	delOff := dirOff + 44
	binary.LittleEndian.PutUint32(img[delOff:], 15)
	binary.LittleEndian.PutUint16(img[delOff+4:], 32)
	img[delOff+6] = 15 // name_len
	img[delOff+7] = 1
	copy(img[delOff+8:], "deleted_log.dat")

	// 5. Inode 12 ("evidence.txt") at Inode Table + 11*256 = 10240 + 2816 = 13056
	fileInoOff := 10240 + 11*256
	binary.LittleEndian.PutUint16(img[fileInoOff+0:], 0x81A4) // Regular file
	binary.LittleEndian.PutUint32(img[fileInoOff+4:], 25)     // 25 bytes
	binary.LittleEndian.PutUint16(img[fileInoOff+0x1A:], 1)   // LinksCount = 1
	// Direct block pointer at 0x28
	binary.LittleEndian.PutUint32(img[fileInoOff+0x28:], 30) // Block 30 (offset 30720)

	// Block 30: 25 bytes file content + slack data
	fileDataOff := 30 * 1024
	copy(img[fileDataOff:], []byte("Forensic Secret Message!!"))
	// Put slack data at offset 25
	copy(img[fileDataOff+25:], []byte("SLACK_EVIDENCE_FRAGMENT"))

	mockDev := &MockBlockDevice{data: img}
	fs, err := OpenExtFS(mockDev, 0)
	if err != nil {
		t.Fatalf("OpenExtFS failed: %v", err)
	}

	if fs.Version() != "ext2" && fs.Version() != "ext4" {
		t.Fatalf("Expected ext2/4, got %s", fs.Version())
	}

	files, err := fs.EnumerateFiles()
	if err != nil {
		t.Fatalf("EnumerateFiles failed: %v", err)
	}

	foundEvidence := false
	foundDeleted := false
	for _, f := range files {
		if f.Name == "evidence.txt" {
			foundEvidence = true
			if f.Size != 25 {
				t.Errorf("expected size 25, got %d", f.Size)
			}
			if f.SlackSize != 1024-25 {
				t.Errorf("expected slack %d, got %d", 1024-25, f.SlackSize)
			}
		}
		if f.Name == "deleted_log.dat" && f.IsDeleted {
			foundDeleted = true
		}
	}

	if !foundEvidence {
		t.Error("evidence.txt not found")
	}
	if !foundDeleted {
		t.Error("carved deleted_log.dat not found in directory slack")
	}

	// Test Search
	hits, err := fs.SearchExtFS("SLACK_EVIDENCE", false)
	if err != nil {
		t.Fatalf("SearchExtFS failed: %v", err)
	}
	if len(hits) == 0 {
		t.Error("expected hit for slack evidence")
	} else if hits[0].Context != "Slack" {
		t.Errorf("expected hit context Slack, got %s", hits[0].Context)
	}
}
