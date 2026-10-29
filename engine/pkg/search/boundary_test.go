package search

import (
	"path/filepath"
	"testing"
	"prodiscover/pkg/block"
	"prodiscover/pkg/fat"
)

func TestBoundary(t *testing.T) {
	imagePath, _ := filepath.Abs("../../../referance/prodiskovey/Sample Images/FATSearchTestImage.eve")
	dev, err := block.OpenFileDevice(imagePath)
	if err != nil {
		t.Fatalf("Open image: %v", err)
	}
	defer dev.Close()

	fs, err := fat.OpenFAT(dev, 0)
	if err != nil {
		t.Fatalf("Open FAT: %v", err)
	}

	opts := SearchOptions{
		CaseSensitive: false,
		SearchCross:   true,
	}

	hits, err := SearchFAT(fs, "2cross2", opts)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	t.Logf("2cross2 hits: %+v", hits)
}
