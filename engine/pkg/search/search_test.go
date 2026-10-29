package search

import (
	"bytes"
	"path/filepath"
	"testing"
	"prodiscover/pkg/block"
	"prodiscover/pkg/fat"
)

func TestDirectRead(t *testing.T) {
	imagePath, _ := filepath.Abs("../../../referance/prodiskovey/Sample Images/FATSearchTestImage.eve")
	dev, err := block.OpenFileDevice(imagePath)
	if err != nil {
		t.Fatalf("Failed to open test image: %v", err)
	}
	defer dev.Close()

	fs, err := fat.OpenFAT(dev, 0)
	if err != nil {
		t.Fatalf("Failed to parse FAT: %v", err)
	}

	t.Logf("BootSector: BytesPerSector=%d, SectorsPerCluster=%d, FirstDataSector=%d, TotalClusters=%d",
		fs.Boot.BytesPerSector, fs.Boot.SectorsPerCluster, fs.Boot.FirstDataSector, fs.Boot.TotalClusters)

	for c := uint32(2); c < 6; c++ {
		buf := make([]byte, 512)
		fs.ReadCluster(c, buf)
		sec := fs.ClusterToSector(c)
		off := fs.ClusterToOffset(c)
		t.Logf("Cluster %d: Sector=%d(0x%X), Offset=0x%X, first 16 bytes=%X", c, sec, sec, off, buf[:16])
		if idx := bytes.Index(buf, []byte("1slack1")); idx != -1 {
			t.Logf("--> Found '1slack1' in Cluster %d (Sector %d) at in-cluster offset 0x%X", c, sec, idx)
		}
	}
}

func TestBrianCarrierFATSearch(t *testing.T) {
	imagePath, _ := filepath.Abs("../../../referance/prodiskovey/Sample Images/FATSearchTestImage.eve")
	dev, err := block.OpenFileDevice(imagePath)
	if err != nil {
		t.Fatalf("Failed to open test image: %v", err)
	}
	defer dev.Close()

	fs, err := fat.OpenFAT(dev, 0)
	if err != nil {
		t.Fatalf("Failed to parse FAT: %v", err)
	}

	opts := SearchOptions{
		CaseSensitive: false,
		SearchSlack:   true,
		SearchUnalloc: true,
		SearchCross:   true,
	}

	testCases := []struct {
		term           string
		expectedSector uint32
		expectedOffset uint32
	}{
		{"first", 271, 0xA7},
		{"1cross1", 271, 0x1FC},
		{"2cross2", 273, 0x1FC},
		{"3cross3", 283, 0x1FC},
		{"1slack1", 272, 0x18C},
		{"2slack2", 274, 0x1FC},
		{"3slack3", 277, 0x181},
		{"deleted", 276, 0xE6},
		{"a?b\\c*d$e#f[g^", 279, 0xA0},
	}

	for _, tc := range testCases {
		hits, err := SearchFAT(fs, tc.term, opts)
		if err != nil {
			t.Errorf("Search failed for '%s': %v", tc.term, err)
			continue
		}
		t.Logf("Term '%s': found %d hits: %+v", tc.term, len(hits), hits)
		if len(hits) == 0 {
			t.Errorf("Expected hit for '%s' at Sector %d(0x%X), but found 0 hits", tc.term, tc.expectedSector, tc.expectedSector)
			continue
		}

		matched := false
		for _, h := range hits {
			if h.Sector == tc.expectedSector && h.OffsetInSector == tc.expectedOffset {
				matched = true
				t.Logf("PASS: Found '%s' at Sector %d (0x%X), Offset 0x%X (%s)",
					tc.term, h.Sector, h.Sector, h.OffsetInSector, h.Context)
				break
			}
		}

		if !matched {
			t.Errorf("FAIL '%s': expected Sector %d(0x%X) Off 0x%X, got %v",
				tc.term, tc.expectedSector, tc.expectedSector, tc.expectedOffset, hits)
		}
	}
}
