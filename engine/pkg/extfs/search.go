package extfs

import (
	"bytes"
	"fmt"
	"unicode/utf16"
)

type ExtSearchHit struct {
	InodeNumber uint32
	FileName    string
	Context     string // "Allocated", "Slack", "Deleted"
	Offset      int64
	SnippetHex  string
	SnippetText string
}

func (h ExtSearchHit) String() string {
	return fmt.Sprintf("ExtFS [%s] Inode: %d  File: %-20s  Offset: 0x%08X  Snippet: %s",
		h.Context, h.InodeNumber, h.FileName, h.Offset, h.SnippetText)
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

func toUTF16LE(s string) []byte {
	runes := []rune(s)
	u16s := utf16.Encode(runes)
	b := make([]byte, len(u16s)*2)
	for i, u := range u16s {
		b[i*2] = byte(u & 0xFF)
		b[i*2+1] = byte(u >> 8)
	}
	return b
}

func (fs *ExtFS) SearchExtFS(term string, caseSensitive bool) ([]ExtSearchHit, error) {
	var hits []ExtSearchHit
	needle := []byte(term)
	needleLower := asciiToLower(needle)
	needleU16 := toUTF16LE(term)

	rootInode, err := fs.ReadInode(2)
	if err != nil {
		return nil, err
	}

	entries, err := fs.ReadDirEntries(rootInode)
	if err != nil {
		return nil, err
	}

	for _, e := range entries {
		in, err := fs.ReadInode(e.InodeNumber)
		if err != nil {
			continue
		}

		ctx := "Allocated"
		if e.IsDeleted || in.IsDeleted {
			ctx = "Deleted"
		}

		// 1. Search file contents
		data, err := fs.ReadData(in)
		if err == nil && len(data) > 0 {
			searchBuf := data
			if !caseSensitive {
				searchBuf = asciiToLower(data)
			}

			idx := 0
			for {
				pos := bytes.Index(searchBuf[idx:], needleLower)
				if pos == -1 {
					break
				}
				matchOff := idx + pos
				snippetStart := matchOff
				snippetEnd := matchOff + len(needle) + 8
				if snippetEnd > len(data) {
					snippetEnd = len(data)
				}

				hits = append(hits, ExtSearchHit{
					InodeNumber: in.Number,
					FileName:    e.Name,
					Context:     ctx,
					Offset:      int64(matchOff),
					SnippetText: string(data[snippetStart:snippetEnd]),
				})
				idx = matchOff + 1
			}

			// Search UTF-16
			idx = 0
			for {
				pos := bytes.Index(data[idx:], needleU16)
				if pos == -1 {
					break
				}
				matchOff := idx + pos
				hits = append(hits, ExtSearchHit{
					InodeNumber: in.Number,
					FileName:    e.Name,
					Context:     ctx + "-Unicode",
					Offset:      int64(matchOff),
					SnippetText: term,
				})
				idx = matchOff + 2
			}
		}

		// 2. Search block slack
		slack, err := fs.ReadSlack(in)
		if err == nil && len(slack) > 0 {
			searchBuf := slack
			if !caseSensitive {
				searchBuf = asciiToLower(slack)
			}
			pos := bytes.Index(searchBuf, needleLower)
			if pos != -1 {
				hits = append(hits, ExtSearchHit{
					InodeNumber: in.Number,
					FileName:    e.Name,
					Context:     "Slack",
					Offset:      int64(pos),
					SnippetText: string(slack[pos : pos+len(needle)]),
				})
			}
		}
	}

	return hits, nil
}
