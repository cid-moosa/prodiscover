package ntfs

import (
	"bytes"
	"fmt"
	"strings"
	"unicode/utf16"
)

type SearchHit struct {
	Term           string
	FileName       string
	StreamName     string
	IsADS          bool
	IsDeleted      bool
	OffsetInStream int64
	Context        string
}

func (h SearchHit) String() string {
	target := h.FileName
	if h.IsADS {
		target += ":" + h.StreamName
	}
	return fmt.Sprintf("Hit '%s' in %s (Offset: 0x%X, Context: %s)", h.Term, target, h.OffsetInStream, h.Context)
}

func asciiToLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			out[i] = c + ('a' - 'A')
		} else {
			out[i] = c
		}
	}
	return out
}

// SearchNTFS searches all files, alternate data streams, and slack space.
func (fs *NTFSFS) SearchNTFS(term string, caseSensitive bool) ([]SearchHit, error) {
	var hits []SearchHit
	files, err := fs.EnumerateFiles(256)
	if err != nil {
		return nil, err
	}

	pat := []byte(term)
	lowerPat := asciiToLower(pat)

	u16 := utf16.Encode([]rune(term))
	u16Pat := make([]byte, len(u16)*2)
	for i, v := range u16 {
		u16Pat[i*2] = byte(v)
		u16Pat[i*2+1] = byte(v >> 8)
	}
	u16Lower := utf16.Encode([]rune(strings.ToLower(term)))
	u16LowerPat := make([]byte, len(u16Lower)*2)
	for i, v := range u16Lower {
		u16LowerPat[i*2] = byte(v)
		u16LowerPat[i*2+1] = byte(v >> 8)
	}

	matchBytes := func(data []byte) []int {
		var res []int
		if len(pat) == 0 || len(data) < len(pat) {
			return res
		}
		searchBuf := data
		targetPat := pat
		if !caseSensitive {
			searchBuf = asciiToLower(data)
			targetPat = lowerPat
		}
		off := 0
		for {
			idx := bytes.Index(searchBuf[off:], targetPat)
			if idx == -1 {
				break
			}
			res = append(res, off+idx)
			off += idx + 1
		}
		return res
	}

	for _, f := range files {
		checkStream := func(st *Stream, isADS bool) {
			if st == nil || st.RealSize == 0 {
				return
			}
			sr := fs.OpenStream(st)
			buf := make([]byte, st.RealSize)
			sr.ReadAt(buf, 0)

			// 1. Search in stream content (handles fragmented runs seamlessly!)
			for _, idx := range matchBytes(buf) {
				ctx := "Resident File"
				if !st.IsResident {
					ctx = "Non-Resident File"
					if len(st.DataRuns) > 1 {
						ctx = "Fragmented File Stream"
					}
				}
				if isADS {
					ctx += " (Alternate Data Stream)"
				}
				if !f.IsAllocated {
					ctx += " [Deleted]"
				}

				hits = append(hits, SearchHit{
					Term:           term,
					FileName:       f.FileName,
					StreamName:     st.Name,
					IsADS:          isADS,
					IsDeleted:      !f.IsAllocated,
					OffsetInStream: int64(idx),
					Context:        ctx,
				})
			}

			// 2. Search in slack space of non-resident stream
			if !st.IsResident && st.SlackBytes > 0 {
				slack, _ := sr.ReadSlack()
				for _, idx := range matchBytes(slack) {
					ctx := fmt.Sprintf("Slack Space (%d bytes)", st.SlackBytes)
					if isADS {
						ctx += " (Alternate Data Stream)"
					}
					if !f.IsAllocated {
						ctx += " [Deleted]"
					}
					hits = append(hits, SearchHit{
						Term:           term,
						FileName:       f.FileName,
						StreamName:     st.Name,
						IsADS:          isADS,
						IsDeleted:      !f.IsAllocated,
						OffsetInStream: int64(st.RealSize) + int64(idx),
						Context:        ctx,
					})
				}
			}
		}

		if f.DefaultStream != nil {
			checkStream(f.DefaultStream, false)
		}
		for _, ads := range f.AlternateStreams {
			checkStream(ads, true)
		}
	}

	return hits, nil
}
