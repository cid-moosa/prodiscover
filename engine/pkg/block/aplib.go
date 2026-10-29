package block

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
)

var (
	ErrCorruptAPLib = errors.New("corrupt aPLib compressed data")
	ErrAPLibHeader  = errors.New("invalid aPLib safe header")
)

type aPLibReader struct {
	src      []byte
	srcPos   int
	tag      byte
	bitCount int
}

func (r *aPLibReader) getBit() (int, bool) {
	if r.bitCount == 0 {
		if r.srcPos >= len(r.src) {
			return 0, false
		}
		r.tag = r.src[r.srcPos]
		r.srcPos++
		r.bitCount = 8
	}
	bit := int((r.tag >> 7) & 1)
	r.tag <<= 1
	r.bitCount--
	return bit, true
}

func (r *aPLibReader) getByte() (byte, bool) {
	if r.srcPos >= len(r.src) {
		return 0, false
	}
	b := r.src[r.srcPos]
	r.srcPos++
	return b, true
}

func (r *aPLibReader) getGamma() (int, bool) {
	val := 1
	for {
		b, ok := r.getBit()
		if !ok {
			return 0, false
		}
		val = (val << 1) + b
		cont, ok := r.getBit()
		if !ok {
			return 0, false
		}
		if cont == 0 {
			break
		}
	}
	return val, true
}

// DecompressAPLib decompresses raw aPLib bitstream or an aP9a safe-packed chunk.
func DecompressAPLib(src []byte) ([]byte, error) {
	if len(src) < 4 {
		return nil, ErrCorruptAPLib
	}

	payload := src
	var expectedOrigLen int
	var expectedOrigCRC uint32
	hasHeader := false

	// Check for aP9a safe container header
	if string(src[:4]) == "aP9a" && len(src) >= 24 {
		hasHeader = true
		headerLen := binary.LittleEndian.Uint32(src[4:8])
		packedLen := binary.LittleEndian.Uint32(src[8:12])
		packedCRC := binary.LittleEndian.Uint32(src[12:16])
		origLen := binary.LittleEndian.Uint32(src[16:20])
		origCRC := binary.LittleEndian.Uint32(src[20:24])

		if int(headerLen+packedLen) <= len(src) {
			actualPackedCRC := crc32.ChecksumIEEE(src[headerLen : headerLen+packedLen])
			if actualPackedCRC == packedCRC {
				payload = src[headerLen : headerLen+packedLen]
				expectedOrigLen = int(origLen)
				expectedOrigCRC = origCRC
			}
		}
	}

	r := &aPLibReader{src: payload}
	var dst []byte
	if hasHeader && expectedOrigLen > 0 {
		dst = make([]byte, 0, expectedOrigLen)
	}

	rpos := 0
	_ = rpos
	lastMatchLen := 0
	lastMatchOff := 0

	// First byte is always literal
	b0, ok := r.getByte()
	if !ok {
		return nil, ErrCorruptAPLib
	}
	dst = append(dst, b0)

	for {
		bit, ok := r.getBit()
		if !ok {
			break
		}

		if bit == 0 {
			// Literal byte
			b, ok := r.getByte()
			if !ok {
				break
			}
			dst = append(dst, b)
			lastMatchLen = 0
			continue
		}

		// Match tag 1
		bit2, ok := r.getBit()
		if !ok {
			break
		}

		if bit2 == 0 {
			// Block match (1 0)
			gamma, ok := r.getGamma()
			if !ok {
				break
			}
			matchOff := gamma - 2
			matchLen := 0

			if matchOff == 0 && lastMatchLen != 0 {
				// Repeat last match offset
				matchOff = lastMatchOff
				gLen, ok := r.getGamma()
				if !ok {
					break
				}
				matchLen = gLen
			} else {
				highByte, ok := r.getByte()
				if !ok {
					break
				}
				matchOff = (matchOff << 8) + int(highByte)
				gLen, ok := r.getGamma()
				if !ok {
					break
				}
				matchLen = gLen
				if matchOff >= 32000 {
					matchLen++
				}
				if matchOff >= 1280 {
					matchLen++
				}
				if matchOff < 128 {
					matchLen += 2
				}
			}

			if matchOff <= 0 || matchOff > len(dst) {
				return nil, ErrCorruptAPLib
			}

			start := len(dst) - matchOff
			for i := 0; i < matchLen; i++ {
				dst = append(dst, dst[start+i])
			}
			lastMatchOff = matchOff
			lastMatchLen = matchLen

		} else {
			// Sub-match tag (1 1)
			bit3, ok := r.getBit()
			if !ok {
				break
			}

			if bit3 == 0 {
				// Short match (1 1 0): length 2 or 3, small offset
				offByte, ok := r.getByte()
				if !ok {
					break
				}
				matchOff := int(offByte >> 1)
				matchLen := 2 + int(offByte&1)

				if matchOff == 0 {
					// End of bitstream marker
					break
				}

				if matchOff > len(dst) {
					return nil, ErrCorruptAPLib
				}

				start := len(dst) - matchOff
				for i := 0; i < matchLen; i++ {
					dst = append(dst, dst[start+i])
				}
				lastMatchOff = matchOff
				lastMatchLen = matchLen

			} else {
				// Single byte match (1 1 1): 4-bit offset
				matchOff := 0
				for i := 0; i < 4; i++ {
					b, ok := r.getBit()
					if !ok {
						break
					}
					matchOff = (matchOff << 1) + b
				}

				if matchOff == 0 {
					dst = append(dst, 0x00)
				} else {
					if matchOff > len(dst) {
						return nil, ErrCorruptAPLib
					}
					dst = append(dst, dst[len(dst)-matchOff])
				}
				lastMatchLen = 0
			}
		}
	}

	if hasHeader && expectedOrigLen > 0 {
		if len(dst) == expectedOrigLen && expectedOrigCRC != 0 {
			if crc32.ChecksumIEEE(dst) != expectedOrigCRC {
				return dst, ErrCorruptAPLib
			}
		}
	}

	return dst, nil
}
