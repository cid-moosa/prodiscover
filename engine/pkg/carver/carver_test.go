package carver

import (
	"testing"
)

type MockDevice struct {
	data []byte
}

func (m *MockDevice) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(m.data)) {
		return 0, nil
	}
	n := copy(p, m.data[off:])
	return n, nil
}

func (m *MockDevice) Size() int64 {
	return int64(len(m.data))
}

func (m *MockDevice) SectorSize() int64 {
	return 512
}

func (m *MockDevice) Close() error {
	return nil
}

func TestCarverWildcardMatching(t *testing.T) {
	// 1. Test masked parsing of \xff\xd8\xff\xe?
	val, mask, err := parsePatternWithMask(`\xff\xd8\xff\xe?`)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(val) != 4 || len(mask) != 4 {
		t.Fatalf("expected length 4, got %d", len(val))
	}
	if mask[3] != 0xF0 {
		t.Errorf("expected mask 0xF0 for \\xe?, got 0x%02X", mask[3])
	}

	// 2. Test matching against EXIF JPEG (\xff\xd8\xff\xe1)
	jpegData := []byte{0x00, 0x11, 0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x22, 0xFF, 0xD9, 0x55}
	pos := IndexWithMask(jpegData, val, mask)
	if pos != 2 {
		t.Errorf("expected match at offset 2, got %d", pos)
	}

	// 3. Test Full Device Carving with rule
	ftrVal, ftrMask, _ := parsePatternWithMask(`\xff\xd9`)
	rules := []CarveRule{
		{
			HeaderVal:  val,
			HeaderMask: mask,
			FooterVal:  ftrVal,
			FooterMask: ftrMask,
			HasFooter:  true,
			Extension:  "jpg",
			MaxBytes:   1024,
		},
	}

	dev := &MockDevice{data: jpegData}
	carved, err := CarveDevice(dev, rules, "")
	if err != nil {
		t.Fatalf("CarveDevice failed: %v", err)
	}
	if len(carved) != 1 {
		t.Fatalf("expected 1 carved file, got %d", len(carved))
	}
	if carved[0].StartOffset != 2 {
		t.Errorf("expected start offset 2, got %d", carved[0].StartOffset)
	}
	if carved[0].Length != 8 { // from 0xFF 0xD8 ... through 0xFF 0xD9 is 8 bytes
		t.Errorf("expected length 8, got %d", carved[0].Length)
	}
}
