package search

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf16"
	"prodiscover/pkg/fat"
)

type MatchType string

const (
	MatchAllocated   MatchType = "Allocated"
	MatchSlack       MatchType = "Slack"
	MatchUnallocated MatchType = "Unallocated"
	MatchMetadata    MatchType = "Metadata"
	MatchCrossCluster MatchType = "CrossCluster"
)

type SearchHit struct {
	Term            string
	Sector          uint32
	Cluster         uint32
	OffsetInSector  uint32
	AbsoluteOffset  int64
	Context         MatchType
	AssociatedFile  string
	Length          int
}

func (h SearchHit) String() string {
	return fmt.Sprintf("Hit '%s': Cluster=%d, Sector=%d(0x%X), Offset=0x%X, Abs=0x%X, Context=%s, File=%s",
		h.Term, h.Cluster, h.Sector, h.Sector, h.OffsetInSector, h.AbsoluteOffset, h.Context, h.AssociatedFile)
}

type SearchOptions struct {
	CaseSensitive bool
	SearchSlack   bool
	SearchUnalloc bool
	SearchCross   bool
	AsUnicode     bool
}

func asciiToLower(data []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		if b >= 'A' && b <= 'Z' {
			out[i] = b + ('a' - 'A')
		} else {
			out[i] = b
		}
	}
	return out
}

// SearchTerm runs a search for a pattern across a FAT filesystem image.
func SearchFAT(fs *fat.FATFS, term string, opts SearchOptions) ([]SearchHit, error) {
	var hits []SearchHit

	pattern := []byte(term)
	lowerPattern := asciiToLower(pattern)

	// Build UTF-16LE pattern if requested or dual search
	var u16Pattern []byte
	var lowerU16Pattern []byte
	if opts.AsUnicode {
		u16 := utf16.Encode([]rune(term))
		u16Pattern = make([]byte, len(u16)*2)
		for i, v := range u16 {
			u16Pattern[i*2] = byte(v)
			u16Pattern[i*2+1] = byte(v >> 8)
		}
		u16Lower := utf16.Encode([]rune(strings.ToLower(term)))
		lowerU16Pattern = make([]byte, len(u16Lower)*2)
		for i, v := range u16Lower {
			lowerU16Pattern[i*2] = byte(v)
			lowerU16Pattern[i*2+1] = byte(v >> 8)
		}
	}

	matchBytes := func(data []byte, pat []byte, lowerPat []byte) []int {
		var res []int
		if len(pat) == 0 || len(data) < len(pat) {
			return res
		}
		searchBuf := data
		targetPat := pat
		if !opts.CaseSensitive {
			searchBuf = asciiToLower(data)
			targetPat = lowerPat
		}
		offset := 0
		for {
			idx := bytes.Index(searchBuf[offset:], targetPat)
			if idx == -1 {
				break
			}
			res = append(res, offset+idx)
			offset += idx + 1
		}
		return res
	}

	bps := int(fs.Boot.BytesPerSector)
	clusterSize := int(fs.Boot.ClusterSizeBytes)

	// Read entire filesystem data area cluster by cluster
	cBuf := make([]byte, clusterSize)
	prevCBuf := make([]byte, clusterSize)
	hasPrev := false

	// Gather directory entries for association
	dirEntries, _ := fs.ReadRootDirEntries()
	clusterToFile := make(map[uint32]string)
	lastClusterSlack := make(map[uint32]uint32)

	for _, fe := range dirEntries {
		for i, c := range fe.ClusterChain {
			clusterToFile[c] = fe.Name
			if i == len(fe.ClusterChain)-1 && fe.SlackSizeBytes > 0 {
				lastClusterSlack[c] = fe.SlackSizeBytes
			}
		}
	}

	// Scan clusters from 2 to TotalClusters+1
	for c := uint32(2); c < fs.Boot.TotalClusters+2; c++ {
		if err := fs.ReadCluster(c, cBuf); err != nil {
			break
		}

		sec := fs.ClusterToSector(c)
		isAlloc := fs.IsClusterAllocated(c)
		fileName := clusterToFile[c]

		// Search in cluster
		findIndices := matchBytes(cBuf, pattern, lowerPattern)
		if opts.AsUnicode {
			findIndices = append(findIndices, matchBytes(cBuf, u16Pattern, lowerU16Pattern)...)
		}

		for _, offInCluster := range findIndices {
			matchContext := MatchAllocated
			if !isAlloc {
				matchContext = MatchUnallocated
			} else if slackBytes, ok := lastClusterSlack[c]; ok {
				slackStart := uint32(clusterSize) - slackBytes
				if uint32(offInCluster) >= slackStart {
					matchContext = MatchSlack
				}
			}

			secOffset := uint32(offInCluster) / uint32(bps)
			hitSector := sec + secOffset
			hitOffInSec := uint32(offInCluster) % uint32(bps)
			absOffset := fs.ClusterToOffset(c) + int64(offInCluster)

			hits = append(hits, SearchHit{
				Term:           term,
				Sector:         hitSector,
				Cluster:        c,
				OffsetInSector: hitOffInSec,
				AbsoluteOffset: absOffset,
				Context:        matchContext,
				AssociatedFile: fileName,
				Length:         len(pattern),
			})
		}

		// 3. Cross-cluster boundary search
		if opts.SearchCross && hasPrev {
			// Boundary window: last 64 bytes of prev + first 64 bytes of current
			boundarySize := len(pattern) * 2
			if boundarySize > 256 {
				boundarySize = 256
			}
			if boundarySize < 64 {
				boundarySize = 64
			}

			prevTail := prevCBuf[clusterSize-boundarySize:]
			currHead := cBuf[:boundarySize]
			window := make([]byte, boundarySize*2)
			copy(window[:boundarySize], prevTail)
			copy(window[boundarySize:], currHead)

			boundaryHits := matchBytes(window, pattern, lowerPattern)
			for _, wOff := range boundaryHits {
				// We only care about hits that cross the midpoint
				if wOff < boundarySize && wOff+len(pattern) > boundarySize {
					// Hit spans boundary!
					offInPrev := (clusterSize - boundarySize) + wOff
					prevSec := fs.ClusterToSector(c-1) + uint32(offInPrev)/uint32(bps)
					prevSecOff := uint32(offInPrev) % uint32(bps)
					absOffset := fs.ClusterToOffset(c-1) + int64(offInPrev)

					hits = append(hits, SearchHit{
						Term:           term,
						Sector:         prevSec,
						Cluster:        c - 1,
						OffsetInSector: prevSecOff,
						AbsoluteOffset: absOffset,
						Context:        MatchCrossCluster,
						AssociatedFile: clusterToFile[c-1],
						Length:         len(pattern),
					})
				}
			}
		}

		copy(prevCBuf, cBuf)
		hasPrev = true
	}

	return hits, nil
}

// RegexSearchFAT executes regular expression search across the filesystem.
func RegexSearchFAT(fs *fat.FATFS, patternStr string) ([]SearchHit, error) {
	re, err := regexp.Compile(patternStr)
	if err != nil {
		return nil, fmt.Errorf("invalid regex: %w", err)
	}

	var hits []SearchHit
	clusterSize := int(fs.Boot.ClusterSizeBytes)
	bps := int(fs.Boot.BytesPerSector)
	cBuf := make([]byte, clusterSize)

	for c := uint32(2); c < fs.Boot.TotalClusters+2; c++ {
		if err := fs.ReadCluster(c, cBuf); err != nil {
			break
		}

		matches := re.FindAllIndex(cBuf, -1)
		sec := fs.ClusterToSector(c)
		isAlloc := fs.IsClusterAllocated(c)

		for _, loc := range matches {
			start := loc[0]
			matchedBytes := cBuf[start:loc[1]]
			secOffset := uint32(start) / uint32(bps)
			hitSector := sec + secOffset
			hitOffInSec := uint32(start) % uint32(bps)
			absOffset := fs.ClusterToOffset(c) + int64(start)

			ctx := MatchAllocated
			if !isAlloc {
				ctx = MatchUnallocated
			}

			hits = append(hits, SearchHit{
				Term:           string(matchedBytes),
				Sector:         hitSector,
				Cluster:        c,
				OffsetInSector: hitOffInSec,
				AbsoluteOffset: absOffset,
				Context:        ctx,
				Length:         loc[1] - loc[0],
			})
		}
	}

	return hits, nil
}
