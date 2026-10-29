package signatures

import (
	"os"
	"testing"
)

func TestSignatureMismatch(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "headersig_*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := `
4D5A,EXE;DLL;SYS,"DOS/Windows Executable"
FFD8FF,JPG;JPEG,"JPEG Image"
25504446,PDF,"Adobe Portable Document Format"
`
	tmpFile.WriteString(content)
	tmpFile.Close()

	db, err := LoadHeadersig(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to load signatures: %v", err)
	}

	if len(db.Signatures) != 3 {
		t.Fatalf("expected 3 signatures, got %d", len(db.Signatures))
	}

	// 1. Correct file: test.jpg with FFD8FFE0
	isMismatch, desc := db.CheckMismatch("test.jpg", []byte{0xFF, 0xD8, 0xFF, 0xE0})
	if isMismatch {
		t.Errorf("expected no mismatch for test.jpg, got mismatch with desc %s", desc)
	}

	// 2. Spoofed file: test.jpg with MZ header (4D 5A 90 00)
	isMismatch, desc = db.CheckMismatch("malware.jpg", []byte{0x4D, 0x5A, 0x90, 0x00})
	if !isMismatch {
		t.Error("expected mismatch for spoofed malware.jpg")
	}
	if desc != "DOS/Windows Executable" {
		t.Errorf("expected desc 'DOS/Windows Executable', got '%s'", desc)
	}
}
