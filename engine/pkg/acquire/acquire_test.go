package acquire

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

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

func TestAcquisition(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "acquire_test_*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Mock 2.5 MB disk
	testData := make([]byte, 2500*1024)
	for i := range testData {
		testData[i] = byte(i % 251)
	}

	hExpectedMd5 := md5.Sum(testData)
	hExpectedSha1 := sha1.Sum(testData)
	expectedMd5Str := hex.EncodeToString(hExpectedMd5[:])
	expectedSha1Str := hex.EncodeToString(hExpectedSha1[:])

	mockDev := &MockBlockDevice{data: testData}
	destPath := filepath.Join(tmpDir, "evidence.eve")

	opts := AcquisitionOptions{
		SourcePath:      "\\\\.\\PhysicalDriveMock",
		DestinationPath: destPath,
		Technician:      "CIDMOOSA",
		CaseNumber:      "CASE-2026-001",
		Description:     "Test Bit-Stream Acquisition",
		SplitSize:       1024 * 1024, // 1 MB split size -> should generate 3 segments
	}

	var progressCalls int
	progressFunc := func(cur, tot int64) {
		progressCalls++
	}

	res, err := AcquireDevice(mockDev, opts, progressFunc)
	if err != nil {
		t.Fatalf("AcquireDevice failed: %v", err)
	}

	if res.TotalBytes != int64(len(testData)) {
		t.Errorf("expected %d bytes, got %d", len(testData), res.TotalBytes)
	}

	if res.MD5 != expectedMd5Str {
		t.Errorf("MD5 mismatch: expected %s, got %s", expectedMd5Str, res.MD5)
	}

	if res.SHA1 != expectedSha1Str {
		t.Errorf("SHA1 mismatch: expected %s, got %s", expectedSha1Str, res.SHA1)
	}

	if len(res.OutputFiles) != 3 {
		t.Errorf("expected 3 split files, got %d", len(res.OutputFiles))
	}

	// Verify companion files exist
	if _, err := os.Stat(destPath + ".md5"); os.IsNotExist(err) {
		t.Error(".md5 checksum file not created")
	}
	if _, err := os.Stat(destPath + ".sha1"); os.IsNotExist(err) {
		t.Error(".sha1 checksum file not created")
	}
	if _, err := os.Stat(destPath + ".log"); os.IsNotExist(err) {
		t.Error(".log audit file not created")
	}
}
