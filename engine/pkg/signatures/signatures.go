package signatures

import (
	"bufio"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

type FileSignature struct {
	MagicHex   string
	MagicBytes []byte
	Extensions []string
	Desc       string
}

type SignatureDB struct {
	Signatures []FileSignature
}

func LoadHeadersig(path string) (*SignatureDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var sigs []FileSignature
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 3 {
			continue
		}

		magicStr := strings.TrimSpace(parts[0])
		magicBytes, err := hex.DecodeString(magicStr)
		if err != nil {
			continue
		}

		extStr := strings.TrimSpace(parts[1])
		rawExts := strings.FieldsFunc(extStr, func(r rune) bool {
			return r == ';' || r == '/' || r == ','
		})
		var cleanExts []string
		for _, e := range rawExts {
			cleaned := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(e, ".")))
			if cleaned != "" {
				cleanExts = append(cleanExts, cleaned)
			}
		}

		desc := strings.Trim(strings.TrimSpace(parts[2]), "\"")

		sigs = append(sigs, FileSignature{
			MagicHex:   magicStr,
			MagicBytes: magicBytes,
			Extensions: cleanExts,
			Desc:       desc,
		})
	}

	return &SignatureDB{Signatures: sigs}, scanner.Err()
}

// MatchExtension checks if the file header matches its claimed extension.
func (db *SignatureDB) CheckMismatch(fileName string, headerBytes []byte) (isMismatch bool, detectedDesc string) {
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(fileName), "."))
	if ext == "" {
		return false, ""
	}

	for _, sig := range db.Signatures {
		if len(headerBytes) >= len(sig.MagicBytes) {
			if string(headerBytes[:len(sig.MagicBytes)]) == string(sig.MagicBytes) {
				// Magic matches this signature!
				for _, expectedExt := range sig.Extensions {
					if expectedExt == ext || expectedExt == "??" {
						return false, sig.Desc // Match!
					}
				}
				// Magic matched, but extension differs!
				return true, sig.Desc
			}
		}
	}
	return false, ""
}
