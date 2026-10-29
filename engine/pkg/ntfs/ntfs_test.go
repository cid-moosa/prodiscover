package ntfs

import (
	"bytes"
	"path/filepath"
	"testing"
	"prodiscover/pkg/block"
)

func TestBrianCarrierNTFSGroundTruth(t *testing.T) {
	imagePath, _ := filepath.Abs("../../../referance/prodiskovey/Sample Images/NTFSSearchTestImage.eve")
	dev, err := block.OpenFileDevice(imagePath)
	if err != nil {
		t.Fatalf("Open image: %v", err)
	}
	defer dev.Close()

	fs, err := OpenNTFS(dev, 0)
	if err != nil {
		t.Fatalf("Open NTFS: %v", err)
	}

	t.Logf("NTFS Volume: OEM=%s, ClusterSize=%d, MFTCluster=%d, TotalSectors=%d",
		fs.Boot.OEMName, fs.Boot.ClusterSizeBytes, fs.Boot.MFTCluster, fs.Boot.TotalSectors)

	files, err := fs.EnumerateFiles(64)
	if err != nil {
		t.Fatalf("Enumerate files: %v", err)
	}

	t.Logf("Found %d MFT file records", len(files))

	fileMap := make(map[string]*FileRecord)
	for _, f := range files {
		fileMap[f.FileName] = f
		status := "Allocated"
		if !f.IsAllocated {
			status = "DELETED"
		}
		adsNames := ""
		for _, ads := range f.AlternateStreams {
			adsNames += ":" + ads.Name
		}
		t.Logf("MFT[%2d]: %-15s [%-9s] Size=%-5d ADS=%s",
			f.RecordNumber, f.FileName, status, f.DefaultStreamSize(), adsNames)
	}

	// 1. Test r-alloc (file-r-1.dat)
	t.Run("1_ResidentAllocated", func(t *testing.T) {
		f := fileMap["file-r-1.dat"]
		if f == nil || !f.IsAllocated {
			t.Fatalf("file-r-1.dat not found or not allocated")
		}
		sr := fs.OpenStream(f.DefaultStream)
		buf := make([]byte, f.DefaultStream.RealSize)
		sr.ReadAt(buf, 0)
		if !bytes.Contains(buf, []byte("r-alloc")) {
			t.Errorf("r-alloc not found in file-r-1.dat")
		} else {
			t.Logf("PASS: found 'r-alloc' in resident allocated file-r-1.dat")
		}
	})

	// 2. Test r-unalloc (file-r-2.dat - deleted resident file)
	t.Run("2_ResidentUnallocatedDeleted", func(t *testing.T) {
		f := fileMap["file-r-2.dat"]
		if f == nil {
			t.Fatalf("file-r-2.dat not found")
		}
		if f.IsAllocated {
			t.Errorf("file-r-2.dat should be marked deleted/unallocated")
		}
		sr := fs.OpenStream(f.DefaultStream)
		buf := make([]byte, f.DefaultStream.RealSize)
		sr.ReadAt(buf, 0)
		if !bytes.Contains(buf, []byte("r-unalloc")) {
			t.Errorf("r-unalloc not found in file-r-2.dat")
		} else {
			t.Logf("PASS: found 'r-unalloc' in deleted resident file-r-2.dat")
		}
	})

	// 3. Test r-fads (file-r-3.dat:here - resident ADS in file)
	t.Run("3_ResidentFileADS", func(t *testing.T) {
		f := fileMap["file-r-3.dat"]
		if f == nil || len(f.AlternateStreams) == 0 {
			t.Fatalf("file-r-3.dat ADS not found")
		}
		found := false
		for _, ads := range f.AlternateStreams {
			if ads.Name == "here" {
				sr := fs.OpenStream(ads)
				buf := make([]byte, ads.RealSize)
				sr.ReadAt(buf, 0)
				if bytes.Contains(buf, []byte("r-fads")) {
					found = true
					t.Logf("PASS: found 'r-fads' in resident ADS file-r-3.dat:here")
				}
			}
		}
		if !found {
			t.Errorf("r-fads not found in file-r-3.dat:here")
		}
	})

	// 4. Test r-dads (dir-r-4:there - resident ADS in directory)
	t.Run("4_ResidentDirectoryADS", func(t *testing.T) {
		f := fileMap["dir-r-4"]
		if f == nil || len(f.AlternateStreams) == 0 {
			t.Fatalf("dir-r-4 ADS not found")
		}
		found := false
		for _, ads := range f.AlternateStreams {
			if ads.Name == "there" {
				sr := fs.OpenStream(ads)
				buf := make([]byte, ads.RealSize)
				sr.ReadAt(buf, 0)
				if bytes.Contains(buf, []byte("r-dads")) {
					found = true
					t.Logf("PASS: found 'r-dads' in resident directory ADS dir-r-4:there")
				}
			}
		}
		if !found {
			t.Errorf("r-dads not found in dir-r-4:there")
		}
	})

	// 5. Test n-alloc (file-n-1.dat - non-resident allocated)
	t.Run("5_NonResidentAllocated", func(t *testing.T) {
		f := fileMap["file-n-1.dat"]
		if f == nil || f.DefaultStream.IsResident {
			t.Fatalf("file-n-1.dat not found or is resident")
		}
		sr := fs.OpenStream(f.DefaultStream)
		buf := make([]byte, f.DefaultStream.RealSize)
		sr.ReadAt(buf, 0)
		if !bytes.Contains(buf, []byte("n-alloc")) {
			t.Errorf("n-alloc not found in file-n-1.dat")
		} else {
			t.Logf("PASS: found 'n-alloc' in non-resident allocated file-n-1.dat")
		}
	})

	// 6. Test n-frag (file-n-3.dat - crosses fragmented non-resident clusters!)
	t.Run("6_FragmentedClusterStream", func(t *testing.T) {
		f := fileMap["file-n-3.dat"]
		if f == nil || f.DefaultStream.IsResident {
			t.Fatalf("file-n-3.dat not found or is resident")
		}
		if len(f.DefaultStream.DataRuns) < 2 {
			t.Fatalf("file-n-3.dat expected at least 2 fragmented runs, got %d", len(f.DefaultStream.DataRuns))
		}
		sr := fs.OpenStream(f.DefaultStream)
		buf := make([]byte, f.DefaultStream.RealSize)
		n, err := sr.ReadAt(buf, 0)
		if err != nil && n != int(f.DefaultStream.RealSize) {
			t.Fatalf("reading fragmented stream: %v", err)
		}
		if !bytes.Contains(buf, []byte("n-frag")) {
			t.Errorf("CRITICAL FAIL: 'n-frag' not assembled across fragmented runs!")
		} else {
			t.Logf("PASS: Successfully reassembled 'n-frag' across %d fragmented clusters!", len(f.DefaultStream.DataRuns))
		}
	})

	// 7. Test n-slack (file-n-4.dat - slack space of non-resident file)
	t.Run("7_NonResidentSlackSpace", func(t *testing.T) {
		f := fileMap["file-n-4.dat"]
		if f == nil || f.DefaultStream.IsResident {
			t.Fatalf("file-n-4.dat not found or is resident")
		}
		sr := fs.OpenStream(f.DefaultStream)
		slack, err := sr.ReadSlack()
		if err != nil {
			t.Fatalf("reading slack: %v", err)
		}
		if !bytes.Contains(slack, []byte("n-slack")) {
			t.Errorf("n-slack not found in file-n-4.dat slack space (slack bytes: %d)", len(slack))
		} else {
			t.Logf("PASS: found 'n-slack' in %d bytes of non-resident slack space!", len(slack))
		}
	})

	// 8. Test n-fads (file-n-5.dat:here - non-resident ADS in file)
	t.Run("8_NonResidentFileADS", func(t *testing.T) {
		f := fileMap["file-n-5.dat"]
		if f == nil || len(f.AlternateStreams) == 0 {
			t.Fatalf("file-n-5.dat ADS not found")
		}
		found := false
		for _, ads := range f.AlternateStreams {
			if ads.Name == "here" {
				sr := fs.OpenStream(ads)
				buf := make([]byte, ads.RealSize)
				sr.ReadAt(buf, 0)
				if bytes.Contains(buf, []byte("n-fads")) {
					found = true
					t.Logf("PASS: found 'n-fads' in non-resident ADS file-n-5.dat:here")
				}
			}
		}
		if !found {
			t.Errorf("n-fads not found in file-n-5.dat:here")
		}
	})

	// 9. Test n-dads (dir-n-6:there - non-resident ADS in directory)
	t.Run("9_NonResidentDirectoryADS", func(t *testing.T) {
		f := fileMap["dir-n-6"]
		if f == nil || len(f.AlternateStreams) == 0 {
			t.Fatalf("dir-n-6 ADS not found")
		}
		found := false
		for _, ads := range f.AlternateStreams {
			if ads.Name == "there" {
				sr := fs.OpenStream(ads)
				buf := make([]byte, ads.RealSize)
				sr.ReadAt(buf, 0)
				if bytes.Contains(buf, []byte("n-dads")) {
					found = true
					t.Logf("PASS: found 'n-dads' in non-resident directory ADS dir-n-6:there")
				}
			}
		}
		if !found {
			t.Errorf("n-dads not found in dir-n-6:there")
		}
	})
}

func (f *FileRecord) DefaultStreamSize() uint64 {
	if f.DefaultStream == nil {
		return 0
	}
	return f.DefaultStream.RealSize
}
