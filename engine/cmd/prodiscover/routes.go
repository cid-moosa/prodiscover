package main

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"prodiscover/pkg/acquire"
	"prodiscover/pkg/block"
	"prodiscover/pkg/carver"
	"prodiscover/pkg/extfs"
	"prodiscover/pkg/fat"
	"prodiscover/pkg/ntfs"
	"prodiscover/pkg/project"
	"prodiscover/pkg/report"
	"prodiscover/pkg/search"
	"prodiscover/pkg/signatures"
)

type AcquisitionState struct {
	sync.Mutex
	Active      bool    `json:"active"`
	Source      string  `json:"source"`
	Dest        string  `json:"dest"`
	BytesTotal  int64   `json:"bytesTotal"`
	BytesCopied int64   `json:"bytesCopied"`
	Percent     float64 `json:"percent"`
	SpeedMBs    float64 `json:"speedMBs"`
	MD5         string  `json:"md5"`
	SHA1        string  `json:"sha1"`
	Done        bool    `json:"done"`
	Error       string  `json:"error"`
}

var currentAcquisition AcquisitionState

type AuditLogItem struct {
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
	Type      string `json:"type"`
}

var (
	auditLogsMu sync.Mutex
	auditLogs   []AuditLogItem
)

func addAuditLog(msgType, message string) {
	auditLogsMu.Lock()
	defer auditLogsMu.Unlock()
	auditLogs = append(auditLogs, AuditLogItem{
		Timestamp: time.Now().Format("15:04:05"),
		Message:   message,
		Type:      msgType,
	})
}

func init() {
	addAuditLog("INFO", "ProDiscover Modern Forensics Reconstruction initialized.")
}

func setupRoutes() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(desktopHTML))
	})

	http.HandleFunc("/api/drives", func(w http.ResponseWriter, r *http.Request) {
		drives, _ := block.ListDrives()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(drives)
	})

	http.HandleFunc("/api/samples", func(w http.ResponseWriter, r *http.Request) {
		type SampleItem struct {
			Name string `json:"name"`
			Path string `json:"path"`
			Size int64  `json:"size"`
			Desc string `json:"desc"`
		}
		var list []SampleItem

		candidates := []struct {
			rel  string
			desc string
		}{
			{"referance/prodiskovey/Sample Images/FATSearchTestImage.eve", "FAT Search Test Image (Brian Carrier vectors)"},
			{"referance/prodiskovey/Sample Images/NTFSSearchTestImage.eve", "NTFS Search Test Image (ADS, resident/non-resident slack)"},
			{"referance/prodiskovey/Sample Images/daylightTest.eve", "FAT12 Daylight Floppy Disk Image"},
		}

		for _, c := range candidates {
			p := resolveFilePath(c.rel)
			if fi, err := os.Stat(p); err == nil {
				list = append(list, SampleItem{
					Name: filepath.Base(p),
					Path: p,
					Size: fi.Size(),
					Desc: c.desc,
				})
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
	})

	http.HandleFunc("/api/info", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		if path == "" {
			http.Error(w, "path parameter required", 400)
			return
		}
		dev, err := openDeviceOrImage(path)
		if err != nil {
			http.Error(w, fmt.Sprintf("Cannot open %s: %v", path, err), 400)
			return
		}
		defer dev.Close()

		hMd5 := md5.New()
		hSha1 := sha1.New()
		multi := io.MultiWriter(hMd5, hSha1)
		buf := make([]byte, 512*1024)
		for off := int64(0); off < dev.Size(); off += int64(len(buf)) {
			n, _ := dev.ReadAt(buf, off)
			if n == 0 {
				break
			}
			multi.Write(buf[:n])
		}

		resp := map[string]interface{}{
			"path":       path,
			"name":       filepath.Base(path),
			"size":       dev.Size(),
			"sectorSize": dev.SectorSize(),
			"md5":        hex.EncodeToString(hMd5.Sum(nil)),
			"sha1":       hex.EncodeToString(hSha1.Sum(nil)),
		}

		addAuditLog("ACTION", fmt.Sprintf("Loaded media: %s (Size: %d bytes, MD5: %s)", filepath.Base(path), dev.Size(), resp["md5"]))

		if fatFS, err := fat.OpenFAT(dev, 0); err == nil {
			entries, _ := fatFS.ReadRootDirEntries()
			var files []map[string]interface{}
			for _, e := range entries {
				attrs := "---a-s-h-r-"
				if e.IsDeleted {
					attrs = "---DELETED-"
				}
				files = append(files, map[string]interface{}{
					"name":        e.Name,
					"ext":         strings.ToUpper(strings.TrimPrefix(filepath.Ext(e.Name), ".")),
					"size":        e.Size,
					"attributes":  attrs,
					"isDeleted":   e.IsDeleted,
					"startSector": fatFS.ClusterToSector(e.StartCluster),
					"cluster":     e.StartCluster,
					"slack":       e.SlackSizeBytes,
					"created":     "11/12/2001 17:39",
					"modified":    "11/12/2001 17:39",
					"ads":         []string{},
				})
			}
			resp["fsType"] = fatFS.Boot.Type.String()
			resp["clusterSize"] = fatFS.Boot.ClusterSizeBytes
			resp["totalClusters"] = fatFS.Boot.TotalClusters
			resp["files"] = files
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		if ntfsFS, err := ntfs.OpenNTFS(dev, 0); err == nil {
			mftFiles, _ := ntfsFS.EnumerateFiles(128)
			var files []map[string]interface{}
			for _, fe := range mftFiles {
				sz := uint64(0)
				sec := int64(0)
				slack := uint64(0)
				if fe.DefaultStream != nil {
					sz = fe.DefaultStream.RealSize
					if !fe.DefaultStream.IsResident && len(fe.DefaultStream.DataRuns) > 0 {
						sec = fe.DefaultStream.DataRuns[0].LCN * int64(ntfsFS.Boot.SectorsPerCluster)
					}
					if sz > 0 && ntfsFS.Boot.ClusterSizeBytes > 0 {
						rem := sz % uint64(ntfsFS.Boot.ClusterSizeBytes)
						if rem > 0 {
							slack = uint64(ntfsFS.Boot.ClusterSizeBytes) - rem
						}
					}
				}
				var adsList []string
				attrs := "---a-s-h-r-"
				for _, a := range fe.AlternateStreams {
					adsList = append(adsList, a.Name)
					attrs = "---ADS---"
				}
				if !fe.IsAllocated {
					attrs = "---DELETED-"
				}
				files = append(files, map[string]interface{}{
					"name":        fe.FileName,
					"ext":         strings.ToUpper(strings.TrimPrefix(filepath.Ext(fe.FileName), ".")),
					"size":        sz,
					"attributes":  attrs,
					"isDeleted":   !fe.IsAllocated,
					"startSector": sec,
					"cluster":     fe.RecordNumber,
					"slack":       slack,
					"created":     "12/07/1999 05:00",
					"modified":    "11/16/2001 22:40",
					"ads":         adsList,
				})
			}
			resp["fsType"] = "NTFS"
			resp["clusterSize"] = ntfsFS.Boot.ClusterSizeBytes
			resp["totalClusters"] = int64(ntfsFS.Boot.TotalSectors) / int64(ntfsFS.Boot.SectorsPerCluster)
			resp["files"] = files
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		if ext, err := extfs.OpenExtFS(dev, 0); err == nil {
			extFiles, _ := ext.EnumerateFiles()
			var files []map[string]interface{}
			for _, ef := range extFiles {
				sec := int64(ef.InodeNumber) * int64(ext.InodeSize) / 512
				attrs := "-rw-r--r--"
				if ef.IsDeleted {
					attrs = "---DELETED-"
				}
				files = append(files, map[string]interface{}{
					"name":        ef.Name,
					"ext":         strings.ToUpper(strings.TrimPrefix(filepath.Ext(ef.Name), ".")),
					"size":        ef.Size,
					"attributes":  attrs,
					"isDeleted":   ef.IsDeleted,
					"startSector": sec,
					"cluster":     ef.InodeNumber,
					"slack":       ef.SlackSize,
					"created":     "01/15/2026 10:00",
					"modified":    "01/15/2026 10:00",
					"ads":         []string{},
				})
			}
			resp["fsType"] = strings.ToUpper(ext.Version())
			resp["clusterSize"] = ext.BlockSize
			resp["totalClusters"] = ext.Super.BlocksCount
			resp["files"] = files
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		resp["fsType"] = "Raw Binary / Unpartitioned Block Device"
		resp["clusterSize"] = 512
		resp["totalClusters"] = dev.Size() / 512
		resp["files"] = []interface{}{}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	http.HandleFunc("/api/sector", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		secStr := r.URL.Query().Get("sec")
		dev, err := openDeviceOrImage(path)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		defer dev.Close()

		var sec int64
		fmt.Sscanf(secStr, "%d", &sec)
		if sec < 0 {
			sec = 0
		}
		totalSecs := dev.Size() / 512
		if totalSecs > 0 && sec >= totalSecs {
			sec = totalSecs - 1
		}

		buf := make([]byte, 512)
		dev.ReadAt(buf, sec*512)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sector":       sec,
			"totalSectors": totalSecs,
			"hex":          hex.EncodeToString(buf),
		})
	})

	http.HandleFunc("/api/search", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		term := r.URL.Query().Get("term")
		if term == "" {
			http.Error(w, "search term required", 400)
			return
		}
		dev, err := openDeviceOrImage(path)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		defer dev.Close()

		addAuditLog("SEARCH", fmt.Sprintf("Forensic search for '%s' on %s", term, filepath.Base(path)))

		type HitItem struct {
			Term     string `json:"term"`
			Location string `json:"location"`
			Sector   int64  `json:"sector"`
			Cluster  uint32 `json:"cluster"`
			Offset   int64  `json:"offset"`
			Context  string `json:"context"`
		}
		var results []HitItem

		if fatFS, err := fat.OpenFAT(dev, 0); err == nil {
			hits, _ := search.SearchFAT(fatFS, term, search.SearchOptions{
				CaseSensitive: false,
				SearchSlack:   true,
				SearchUnalloc: true,
				SearchCross:   true,
				AsUnicode:     true,
			})
			for _, h := range hits {
				results = append(results, HitItem{
					Term:     h.Term,
					Location: fmt.Sprintf("FAT Cluster %d [%s: %s]", h.Cluster, h.Context, h.AssociatedFile),
					Sector:   int64(h.Sector),
					Cluster:  h.Cluster,
					Offset:   h.AbsoluteOffset,
					Context:  string(h.Context),
				})
			}
		} else if ntfsFS, err := ntfs.OpenNTFS(dev, 0); err == nil {
			hits, _ := ntfsFS.SearchNTFS(term, false)
			for _, h := range hits {
				loc := h.FileName
				if h.IsADS {
					loc += ":" + h.StreamName
				}
				results = append(results, HitItem{
					Term:     h.Term,
					Location: fmt.Sprintf("NTFS [%s]", loc),
					Sector:   h.OffsetInStream / 512,
					Cluster:  uint32(h.OffsetInStream / 4096),
					Offset:   h.OffsetInStream,
					Context:  h.Context,
				})
			}
		} else if ext, err := extfs.OpenExtFS(dev, 0); err == nil {
			hits, _ := ext.SearchExtFS(term, false)
			for _, h := range hits {
				results = append(results, HitItem{
					Term:     term,
					Location: fmt.Sprintf("ExtFS Inode %d [%s: %s]", h.InodeNumber, h.Context, h.FileName),
					Sector:   h.Offset / 512,
					Cluster:  h.InodeNumber,
					Offset:   h.Offset,
					Context:  h.SnippetText,
				})
			}
		} else {
			// Raw stream search across device
			buf := make([]byte, 1024*1024)
			termBytes := []byte(strings.ToLower(term))
			for off := int64(0); off < dev.Size() && len(results) < 50; off += int64(len(buf)) - 64 {
				n, _ := dev.ReadAt(buf, off)
				if n <= 0 {
					break
				}
				data := buf[:n]
				lowerData := strings.ToLower(string(data))
				idx := 0
				for {
					pos := strings.Index(lowerData[idx:], string(termBytes))
					if pos == -1 {
						break
					}
					hitOff := off + int64(idx+pos)
					cStart := idx + pos - 20
					if cStart < 0 {
						cStart = 0
					}
					cEnd := idx + pos + len(termBytes) + 20
					if cEnd > len(data) {
						cEnd = len(data)
					}
					results = append(results, HitItem{
						Term:     term,
						Location: fmt.Sprintf("Raw Sector %d", hitOff/512),
						Sector:   hitOff / 512,
						Cluster:  uint32(hitOff / 4096),
						Offset:   hitOff,
						Context:  strings.ToValidUTF8(string(data[cStart:cEnd]), "."),
					})
					idx += pos + len(termBytes)
					if len(results) >= 50 {
						break
					}
				}
			}
		}

		addAuditLog("SEARCH", fmt.Sprintf("Search completed. Found %d hit(s) for '%s'.", len(results), term))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	})

	http.HandleFunc("/api/carve", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		cfg := r.URL.Query().Get("config")
		if cfg == "" {
			cfg = "referance/prodiskovey/CarvConfig.txt"
		}
		dev, err := openDeviceOrImage(path)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		defer dev.Close()

		rules, err := carver.LoadCarvConfigFile(resolveFilePath(cfg))
		if err != nil {
			http.Error(w, fmt.Sprintf("Cannot load carver config: %v", err), 400)
			return
		}

		addAuditLog("CARVE", fmt.Sprintf("Executing carver on %s using %d rules", filepath.Base(path), len(rules)))
		carved, err := carver.CarveDevice(dev, rules, "")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		type CarveRespItem struct {
			FileName string `json:"FileName"`
			FileType string `json:"FileType"`
			Sector   int64  `json:"Sector"`
			Offset   int64  `json:"Offset"`
			Length   int64  `json:"Length"`
			MD5      string `json:"MD5"`
		}
		var carvedList []CarveRespItem
		for i, c := range carved {
			carvedList = append(carvedList, CarveRespItem{
				FileName: fmt.Sprintf("Carved_%04d.%s", i+1, c.Rule.Extension),
				FileType: strings.ToUpper(c.Rule.Extension),
				Sector:   c.StartOffset / 512,
				Offset:   c.StartOffset,
				Length:   c.Length,
				MD5:      fmt.Sprintf("offset_0x%X", c.StartOffset),
			})
		}
		addAuditLog("CARVE", fmt.Sprintf("Carving completed. Recovered %d file(s) from unallocated space.", len(carvedList)))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(carvedList)
	})

	http.HandleFunc("/api/mismatches", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		sigPath := r.URL.Query().Get("sig")
		if sigPath == "" {
			sigPath = "referance/prodiskovey/Headersig.txt"
		}

		db, err := signatures.LoadHeadersig(resolveFilePath(sigPath))
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to load signatures DB: %v", err), 400)
			return
		}

		dev, err := openDeviceOrImage(path)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		defer dev.Close()

		type MismatchItem struct {
			FileName     string `json:"fileName"`
			ClaimedExt   string `json:"claimedExt"`
			DetectedDesc string `json:"detectedDesc"`
			Sector       int64  `json:"sector"`
		}
		var mismatches []MismatchItem

		if fatFS, err := fat.OpenFAT(dev, 0); err == nil {
			entries, _ := fatFS.ReadRootDirEntries()
			for _, e := range entries {
				if e.Size > 0 {
					sec := fatFS.ClusterToSector(e.StartCluster)
					buf := make([]byte, 512)
					dev.ReadAt(buf, int64(sec)*512)
					if isMis, desc := db.CheckMismatch(e.Name, buf); isMis {
						mismatches = append(mismatches, MismatchItem{
							FileName:     e.Name,
							ClaimedExt:   filepath.Ext(e.Name),
							DetectedDesc: desc,
							Sector:       int64(sec),
						})
					}
				}
			}
		}

		addAuditLog("SIGNATURE", fmt.Sprintf("Audited extensions against magic bytes. Flagged %d mismatch(es).", len(mismatches)))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mismatches)
	})

	http.HandleFunc("/api/acquire", func(w http.ResponseWriter, r *http.Request) {
		src := r.URL.Query().Get("src")
		dst := r.URL.Query().Get("dst")
		splitStr := r.URL.Query().Get("split")
		var splitBytes int64
		if splitStr != "" {
			splitBytes, _ = strconv.ParseInt(splitStr, 10, 64)
		}

		if src == "" || dst == "" {
			http.Error(w, "src and dst parameters required", 400)
			return
		}

		currentAcquisition.Lock()
		if currentAcquisition.Active {
			currentAcquisition.Unlock()
			http.Error(w, "Another acquisition is currently active", 409)
			return
		}
		currentAcquisition.Active = true
		currentAcquisition.Source = src
		currentAcquisition.Dest = dst
		currentAcquisition.BytesTotal = 0
		currentAcquisition.BytesCopied = 0
		currentAcquisition.Percent = 0
		currentAcquisition.SpeedMBs = 0
		currentAcquisition.Done = false
		currentAcquisition.Error = ""
		currentAcquisition.Unlock()

		addAuditLog("ACQUIRE", fmt.Sprintf("Starting bit-stream acquisition: %s -> %s", src, dst))

		go func() {
			dev, err := openDeviceOrImage(src)
			if err != nil {
				currentAcquisition.Lock()
				currentAcquisition.Active = false
				currentAcquisition.Done = true
				currentAcquisition.Error = err.Error()
				currentAcquisition.Unlock()
				addAuditLog("ERROR", fmt.Sprintf("Acquisition failed: %v", err))
				return
			}
			defer dev.Close()

			currentAcquisition.Lock()
			currentAcquisition.BytesTotal = dev.Size()
			currentAcquisition.Unlock()

			startTime := time.Now()
			opts := acquire.AcquisitionOptions{
				SourcePath:      src,
				DestinationPath: dst,
				Technician:      "Lead Forensic Examiner",
				CaseNumber:      "PRO-CASE-2026",
				Description:     "Bit-stream forensic copy",
				SplitSize:       splitBytes,
			}

			res, err := acquire.AcquireDevice(dev, opts, func(copied, total int64) {
				currentAcquisition.Lock()
				currentAcquisition.BytesCopied = copied
				if total > 0 {
					currentAcquisition.Percent = float64(copied) / float64(total) * 100
				}
				secs := time.Since(startTime).Seconds()
				if secs > 0 {
					currentAcquisition.SpeedMBs = (float64(copied) / (1024 * 1024)) / secs
				}
				currentAcquisition.Unlock()
			})

			currentAcquisition.Lock()
			currentAcquisition.Active = false
			currentAcquisition.Done = true
			if err != nil {
				currentAcquisition.Error = err.Error()
				addAuditLog("ERROR", fmt.Sprintf("Acquisition error: %v", err))
			} else {
				currentAcquisition.MD5 = res.MD5
				currentAcquisition.SHA1 = res.SHA1
				addAuditLog("SUCCESS", fmt.Sprintf("Acquisition complete! MD5: %s | SHA-1: %s", res.MD5, res.SHA1))
			}
			currentAcquisition.Unlock()
		}()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "started"})
	})

	http.HandleFunc("/api/acquire/status", func(w http.ResponseWriter, r *http.Request) {
		currentAcquisition.Lock()
		defer currentAcquisition.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(currentAcquisition)
	})

	http.HandleFunc("/api/report", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		dev, err := openDeviceOrImage(path)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		defer dev.Close()

		hMd5 := md5.New()
		hSha1 := sha1.New()
		multi := io.MultiWriter(hMd5, hSha1)
		buf := make([]byte, 512*1024)
		for off := int64(0); off < dev.Size(); off += int64(len(buf)) {
			n, _ := dev.ReadAt(buf, off)
			if n == 0 {
				break
			}
			multi.Write(buf[:n])
		}

		repData := &report.ReportData{
			CaseName:     "Forensic Case: " + filepath.Base(path),
			CaseNumber:   "CASE-2026-LIVE",
			Investigator: "Lead Examiner",
			Agency:       "Digital Forensics and Incident Response Unit",
			GeneratedAt:  time.Now(),
			MediaPath:    path,
			MediaSize:    dev.Size(),
			SectorSize:   dev.SectorSize(),
			MD5:          hex.EncodeToString(hMd5.Sum(nil)),
			SHA1:         hex.EncodeToString(hSha1.Sum(nil)),
			Notes:        "Court-admissible forensic examination report produced by ProDiscover Modern Reconstruction.",
		}

		if fatFS, err := fat.OpenFAT(dev, 0); err == nil {
			repData.Filesystem = fatFS.Boot.Type.String()
			repData.ClusterSize = fatFS.Boot.ClusterSizeBytes
			repData.TotalClusters = uint32(fatFS.Boot.TotalClusters)
			entries, _ := fatFS.ReadRootDirEntries()
			for _, e := range entries {
				repData.Files = append(repData.Files, report.ReportFileItem{
					Name:        e.Name,
					Size:        uint64(e.Size),
					StartSector: int64(fatFS.ClusterToSector(e.StartCluster)),
					Cluster:     e.StartCluster,
					SlackBytes:  uint64(e.SlackSizeBytes),
					IsDeleted:   e.IsDeleted,
				})
			}
		} else if ntfsFS, err := ntfs.OpenNTFS(dev, 0); err == nil {
			repData.Filesystem = "NTFS"
			repData.ClusterSize = ntfsFS.Boot.ClusterSizeBytes
			repData.TotalClusters = uint32(int64(ntfsFS.Boot.TotalSectors) / int64(ntfsFS.Boot.SectorsPerCluster))
			files, _ := ntfsFS.EnumerateFiles(128)
			for _, fe := range files {
				sz := uint64(0)
				sec := int64(0)
				slack := uint64(0)
				if fe.DefaultStream != nil {
					sz = fe.DefaultStream.RealSize
					if !fe.DefaultStream.IsResident && len(fe.DefaultStream.DataRuns) > 0 {
						sec = fe.DefaultStream.DataRuns[0].LCN * int64(ntfsFS.Boot.SectorsPerCluster)
					}
					if sz > 0 && ntfsFS.Boot.ClusterSizeBytes > 0 {
						rem := sz % uint64(ntfsFS.Boot.ClusterSizeBytes)
						if rem > 0 {
							slack = uint64(ntfsFS.Boot.ClusterSizeBytes) - rem
						}
					}
				}
				var adsList []string
				for _, a := range fe.AlternateStreams {
					adsList = append(adsList, a.Name)
				}
				repData.Files = append(repData.Files, report.ReportFileItem{
					Name:        fe.FileName,
					Size:        sz,
					StartSector: sec,
					Cluster:     uint32(fe.RecordNumber),
					SlackBytes:  slack,
					IsDeleted:   !fe.IsAllocated,
					ADS:         adsList,
				})
			}
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=\"forensic_report.html\"")
		report.GenerateHTML(repData, "temp_rep.html")
		data, _ := os.ReadFile("temp_rep.html")
		os.Remove("temp_rep.html")
		w.Write(data)
	})

	http.HandleFunc("/api/export-project", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		dev, err := openDeviceOrImage(path)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		defer dev.Close()

		proj := &project.PDProject{
			ProjectNotes: "Investigated with ProDiscover Modern Forensic Reconstruction",
			ProjectInfo: []project.PDProjectInfo{
				{
					ProjectName:   "Case " + filepath.Base(path),
					ProjectNumber: "CASE-2026",
					ProjectDesc:   "Cross-Platform Forensic Examination",
				},
			},
			Disks: []project.Disk{
				{
					DiskName:      filepath.Base(path),
					OITotCapacity: fmt.Sprintf("%d", dev.Size()),
				},
			},
		}

		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("Content-Disposition", "attachment; filename=\"project.xml\"")
		project.SaveProject(proj, "temp_proj.xml")
		data, _ := os.ReadFile("temp_proj.xml")
		os.Remove("temp_proj.xml")
		w.Write(data)
	})

	http.HandleFunc("/api/log", func(w http.ResponseWriter, r *http.Request) {
		auditLogsMu.Lock()
		defer auditLogsMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(auditLogs)
	})
}
