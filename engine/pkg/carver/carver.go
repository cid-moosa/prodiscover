package carver

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"prodiscover/pkg/block"
	"strconv"
	"strings"
)

type CarveRule struct {
	HeaderVal  []byte
	HeaderMask []byte
	FooterVal  []byte
	FooterMask []byte
	HasFooter  bool
	Extension  string
	MaxBytes   int64
}

type CarvedFile struct {
	Rule        CarveRule
	StartOffset int64
	EndOffset   int64
	Length      int64
}

func parseNibble(c byte) (byte, bool) {
	if c >= '0' && c <= '9' {
		return c - '0', true
	}
	if c >= 'a' && c <= 'f' {
		return c - 'a' + 10, true
	}
	if c >= 'A' && c <= 'F' {
		return c - 'A' + 10, true
	}
	return 0, false
}

func parsePatternWithMask(s string) ([]byte, []byte, error) {
	s = strings.TrimSpace(s)
	if s == "NONE" || s == "" {
		return nil, nil, nil
	}
	var val []byte
	var mask []byte
	i := 0
	for i < len(s) {
		if strings.HasPrefix(s[i:], "\\x") && i+4 <= len(s) {
			hiChar := s[i+2]
			loChar := s[i+3]
			var v, m byte

			if hiChar == '?' {
				m &= 0x0F
			} else {
				hVal, ok := parseNibble(hiChar)
				if !ok {
					return nil, nil, fmt.Errorf("invalid hex nibble %c", hiChar)
				}
				v |= (hVal << 4)
				m |= 0xF0
			}

			if loChar == '?' {
				// mask low nibble remains 0
			} else {
				lVal, ok := parseNibble(loChar)
				if !ok {
					return nil, nil, fmt.Errorf("invalid hex nibble %c", loChar)
				}
				v |= lVal
				m |= 0x0F
			}

			val = append(val, v)
			mask = append(mask, m)
			i += 4
		} else {
			val = append(val, s[i])
			mask = append(mask, 0xFF)
			i++
		}
	}
	return val, mask, nil
}

func IndexWithMask(data []byte, val []byte, mask []byte) int {
	if len(val) == 0 || len(data) < len(val) {
		return -1
	}
	end := len(data) - len(val)
	firstVal := val[0]
	firstMask := mask[0]
	for i := 0; i <= end; i++ {
		if (data[i] & firstMask) != firstVal {
			continue
		}
		match := true
		for j := 1; j < len(val); j++ {
			if (data[i+j] & mask[j]) != val[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// LoadCarvConfigFile loads rules from CarvConfig.txt
func LoadCarvConfigFile(path string) ([]CarveRule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var rules []CarveRule
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 4 {
			continue
		}
		hVal, hMask, err := parsePatternWithMask(parts[0])
		if err != nil || len(hVal) == 0 {
			continue
		}
		fVal, fMask, _ := parsePatternWithMask(parts[1])
		ext := strings.TrimSpace(parts[2])
		maxLimit, _ := strconv.ParseInt(strings.TrimSpace(parts[3]), 10, 64)
		if maxLimit == 0 {
			maxLimit = 10 * 1024 * 1024 // 10 MB default per config
		}

		rules = append(rules, CarveRule{
			HeaderVal:  hVal,
			HeaderMask: hMask,
			FooterVal:  fVal,
			FooterMask: fMask,
			HasFooter:  len(fVal) > 0,
			Extension:  ext,
			MaxBytes:   maxLimit,
		})
	}
	return rules, scanner.Err()
}

// CarveDevice scans a BlockDevice and extracts carved files matching rules
func CarveDevice(dev block.BlockDevice, rules []CarveRule, outDir string) ([]CarvedFile, error) {
	if outDir != "" {
		if err := os.MkdirAll(outDir, 0755); err != nil {
			return nil, err
		}
	}

	var carved []CarvedFile
	chunkSize := int64(1024 * 1024) // 1 MB scan buffer
	totalSize := dev.Size()
	buf := make([]byte, chunkSize)

	for off := int64(0); off < totalSize; off += (chunkSize - 4096) {
		readLen := chunkSize
		if off+readLen > totalSize {
			readLen = totalSize - off
		}
		n, err := dev.ReadAt(buf[:readLen], off)
		if err != nil && err != io.EOF {
			break
		}
		data := buf[:n]

		for _, r := range rules {
			hdrIdx := 0
			for {
				pos := IndexWithMask(data[hdrIdx:], r.HeaderVal, r.HeaderMask)
				if pos == -1 {
					break
				}
				matchStart := off + int64(hdrIdx+pos)
				fileLen := r.MaxBytes

				if r.HasFooter {
					// Search for footer within MaxBytes
					maxSearch := r.MaxBytes
					if matchStart+maxSearch > totalSize {
						maxSearch = totalSize - matchStart
					}
					ftrBuf := make([]byte, maxSearch)
					fn, _ := dev.ReadAt(ftrBuf, matchStart)
					ftrPos := IndexWithMask(ftrBuf[:fn], r.FooterVal, r.FooterMask)
					if ftrPos != -1 {
						fileLen = int64(ftrPos + len(r.FooterVal))
					}
				}

				if matchStart+fileLen > totalSize {
					fileLen = totalSize - matchStart
				}

				if outDir != "" {
					outPath := fmt.Sprintf("%s/carved_0x%X.%s", outDir, matchStart, r.Extension)
					outFile, err := os.Create(outPath)
					if err == nil {
						fileData := make([]byte, fileLen)
						dev.ReadAt(fileData, matchStart)
						outFile.Write(fileData)
						outFile.Close()
					}
				}

				carved = append(carved, CarvedFile{
					Rule:        r,
					StartOffset: matchStart,
					EndOffset:   matchStart + fileLen,
					Length:      fileLen,
				})

				hdrIdx += pos + len(r.HeaderVal)
			}
		}
	}

	return carved, nil
}
