package main

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"prodiscover/pkg/block"
	"prodiscover/pkg/carver"
	"prodiscover/pkg/extfs"
	"prodiscover/pkg/fat"
	"prodiscover/pkg/ntfs"
	"prodiscover/pkg/project"
	"prodiscover/pkg/search"
	"prodiscover/pkg/acquire"
	"prodiscover/pkg/report"
	"prodiscover/pkg/signatures"
	"time"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		runNativeGUI("")
		return
	}

	cmd := os.Args[1]
	switch cmd {
	case "help", "-h", "--help":
		printUsage()
		return
	case "gui":
		path := ""
		if len(os.Args) > 2 {
			path = os.Args[2]
		}
		runNativeGUI(path)
		return
	}
	switch cmd {
	case "info":
		handleInfo(os.Args[2:])
	case "search":
		handleSearch(os.Args[2:])
	case "carve":
		handleCarve(os.Args[2:])
	case "verify-mismatches":
		handleVerifyMismatches(os.Args[2:])
	case "export-project":
		handleExportProject(os.Args[2:])
	case "drives":
		handleDrives()
	case "acquire":
		handleAcquire(os.Args[2:])
	case "report":
		handleReport(os.Args[2:])
	case "serve":
		handleServe(os.Args[2:])
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println("================================================================================")
	fmt.Println("ProDiscover Modern Reconstruction & Port (Cross-Platform Win/Linux)")
	fmt.Println("================================================================================")
	fmt.Println("Usage:")
	fmt.Println("  prodiscover info   <image-path>                 Inspect image/device geometry & files")
	fmt.Println("  prodiscover search <image-path> <search-term>   Forensic multi-stream search")
	fmt.Println("  prodiscover carve  <image-path> <config> <out>  Carve deleted files using signatures")
	fmt.Println("  prodiscover verify-mismatches <img-path> <sig>  Audit file extensions against magic bytes")
	fmt.Println("  prodiscover export-project <img-path> <out.xml> Export project conforming to XML schema")
	fmt.Println("  prodiscover acquire <src-path> <dest.eve> [s]  Bit-stream disk acquisition with checksums")
	fmt.Println("  prodiscover report  <img-path> <report.html>   Generate comprehensive court-ready report")
	fmt.Println("  prodiscover drives                              Enumerate attached storage devices")
	fmt.Println("  prodiscover serve  [port]                       Launch modern interactive DFIR dashboard")
	fmt.Println("================================================================================")
}

func resolveFilePath(path string) string {
	if _, err := os.Stat(path); err == nil {
		return path
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		for _, rel := range []string{"", "..", "../..", "../../.."} {
			cand := filepath.Join(exeDir, rel, path)
			if _, err := os.Stat(cand); err == nil {
				return cand
			}
		}
	}
	for _, rel := range []string{"..", "../..", "../../.."} {
		cand := filepath.Join(rel, path)
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return path
}

func openDeviceOrImage(path string) (block.BlockDevice, error) {
	if strings.HasPrefix(path, `\\.\PhysicalDrive`) || strings.HasPrefix(path, `/dev/`) || strings.HasPrefix(path, `\\.\`) {
		return block.OpenDrivePath(path)
	}
	return block.OpenFileDevice(resolveFilePath(path))
}

func handleDrives() {
	drives, err := block.ListDrives()
	if err != nil {
		fmt.Printf("Error enumerating drives: %v\n", err)
		return
	}
	fmt.Printf("Found %d attached storage device(s):\n", len(drives))
	for _, d := range drives {
		fmt.Printf(" [%d] %-20s Size: %12d bytes (%.2f GB)  Path: %s\n",
			d.Index, d.Name, d.Size, float64(d.Size)/(1024*1024*1024), d.DevicePath)
	}
}

func handleInfo(args []string) {
	if len(args) < 1 {
		fmt.Println("Error: path to disk image or block device required")
		return
	}
	imgPath := args[0]
	dev, err := openDeviceOrImage(imgPath)
	if err != nil {
		fmt.Printf("Error opening image/device: %v\n", err)
		return
	}
	defer dev.Close()

	fmt.Printf("=== Target: %s ===\n", filepath.Base(imgPath))
	fmt.Printf("Device Size: %d bytes (%.2f MB)\n", dev.Size(), float64(dev.Size())/(1024*1024))
	fmt.Printf("Sector Size: %d bytes\n", dev.SectorSize())

	hMd5 := md5.New()
	hSha1 := sha1.New()
	multi := io.MultiWriter(hMd5, hSha1)
	buf := make([]byte, 1024*1024)
	for off := int64(0); off < dev.Size(); off += int64(len(buf)) {
		n, _ := dev.ReadAt(buf, off)
		if n == 0 {
			break
		}
		multi.Write(buf[:n])
	}
	fmt.Printf("MD5 Checksum:  %s\n", hex.EncodeToString(hMd5.Sum(nil)))
	fmt.Printf("SHA1 Checksum: %s\n", hex.EncodeToString(hSha1.Sum(nil)))

	// Check FAT
	fatFS, err := fat.OpenFAT(dev, 0)
	if err == nil {
		fmt.Printf("\n=== Filesystem: %s ===\n", fatFS.Boot.Type)
		fmt.Printf("OEM Name:            %s\n", fatFS.Boot.OEMName)
		fmt.Printf("Cluster Size:        %d bytes\n", fatFS.Boot.ClusterSizeBytes)
		fmt.Printf("First Data Sector:   %d (0x%X)\n", fatFS.Boot.FirstDataSector, fatFS.Boot.FirstDataSector)
		fmt.Printf("Total Clusters:      %d\n", fatFS.Boot.TotalClusters)

		entries, err := fatFS.ReadRootDirEntries()
		if err == nil {
			fmt.Printf("\n--- Files in Root Directory (%d entries) ---\n", len(entries))
			for _, fe := range entries {
				status := "Allocated"
				if fe.IsDeleted {
					status = "DELETED"
				}
				fmt.Printf("%-22s Size: %6d bytes  StartCluster: %4d  Slack: %4d bytes  [%s]\n",
					fe.Name, fe.Size, fe.StartCluster, fe.SlackSizeBytes, status)
			}
		}
		return
	}

	// Check NTFS
	ntfsFS, err := ntfs.OpenNTFS(dev, 0)
	if err == nil {
		fmt.Printf("\n=== Filesystem: NTFS ===\n")
		fmt.Printf("OEM Name:            %s\n", ntfsFS.Boot.OEMName)
		fmt.Printf("Cluster Size:        %d bytes\n", ntfsFS.Boot.ClusterSizeBytes)
		fmt.Printf("MFT Cluster (LCN):   %d\n", ntfsFS.Boot.MFTCluster)
		fmt.Printf("MFT Record Size:     %d bytes\n", ntfsFS.Boot.MFTRecordSize)

		files, err := ntfsFS.EnumerateFiles(128)
		if err == nil {
			fmt.Printf("\n--- Files in MFT (%d records parsed) ---\n", len(files))
			for _, fe := range files {
				status := "Allocated"
				if !fe.IsAllocated {
					status = "DELETED"
				}
				ads := ""
				for _, a := range fe.AlternateStreams {
					ads += " [ADS :" + a.Name + "]"
				}
				sz := uint64(0)
				if fe.DefaultStream != nil {
					sz = fe.DefaultStream.RealSize
				}
				fmt.Printf("%-25s Size: %6d bytes  MFT[%2d]  [%s]%s\n",
					fe.FileName, sz, fe.RecordNumber, status, ads)
			}
		}
		return
	}

	// Check ExtFS
	ext, err := extfs.OpenExtFS(dev, 0)
	if err == nil {
		fmt.Printf("\n=== Filesystem: %s ===\n", strings.ToUpper(ext.Version()))
		fmt.Printf("Volume Name:         %s\n", ext.Super.VolumeName)
		fmt.Printf("Block Size:          %d bytes\n", ext.BlockSize)
		fmt.Printf("Total Inodes:        %d\n", ext.Super.InodesCount)
		fmt.Printf("Total Blocks:        %d\n", ext.Super.BlocksCount)
		fmt.Printf("Block Groups:        %d\n", ext.GroupsCount)

		files, err := ext.EnumerateFiles()
		if err == nil {
			fmt.Printf("\n--- Files in Root Directory (%d entries) ---\n", len(files))
			for _, f := range files {
				status := "Allocated"
				if f.IsDeleted {
					status = "DELETED"
				}
				dirTag := ""
				if f.IsDirectory {
					dirTag = " [DIR]"
				}
				fmt.Printf("%-22s Size: %6d bytes  Inode: %4d  Slack: %4d bytes  [%s]%s\n",
					f.Name, f.Size, f.InodeNumber, f.SlackSize, status, dirTag)
			}
		}
		return
	}

	fmt.Println("\nFilesystem: Unknown / Raw")
}

func handleSearch(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: prodiscover search <image-path> <term>")
		return
	}
	imgPath := args[0]
	term := args[1]

	dev, err := openDeviceOrImage(imgPath)
	if err != nil {
		fmt.Printf("Error opening image/device: %v\n", err)
		return
	}
	defer dev.Close()

	// Check FAT
	fatFS, err := fat.OpenFAT(dev, 0)
	if err == nil {
		opts := search.SearchOptions{
			CaseSensitive: false,
			SearchSlack:   true,
			SearchUnalloc: true,
			SearchCross:   true,
			AsUnicode:     true,
		}
		fmt.Printf("Searching FAT volume for '%s' across allocated, slack, unallocated, and cross-cluster boundaries...\n", term)
		hits, err := search.SearchFAT(fatFS, term, opts)
		if err != nil {
			fmt.Printf("Search error: %v\n", err)
			return
		}
		fmt.Printf("Total Hits Found: %d\n\n", len(hits))
		for i, h := range hits {
			fmt.Printf("[%2d] %s\n", i+1, h.String())
		}
		return
	}

	// Check NTFS
	ntfsFS, err := ntfs.OpenNTFS(dev, 0)
	if err == nil {
		fmt.Printf("Searching NTFS volume for '%s' across resident, non-resident fragmented streams, ADS, and slack...\n", term)
		hits, err := ntfsFS.SearchNTFS(term, false)
		if err != nil {
			fmt.Printf("Search error: %v\n", err)
			return
		}
		fmt.Printf("Total Hits Found: %d\n\n", len(hits))
		for i, h := range hits {
			fmt.Printf("[%2d] %s\n", i+1, h.String())
		}
		return
	}

	// Check ExtFS
	ext, err := extfs.OpenExtFS(dev, 0)
	if err == nil {
		fmt.Printf("Searching %s volume for '%s' across files, block slack, and deleted entries...\n", ext.Version(), term)
		hits, err := ext.SearchExtFS(term, false)
		if err != nil {
			fmt.Printf("Search error: %v\n", err)
			return
		}
		fmt.Printf("Total Hits Found: %d\n\n", len(hits))
		for i, h := range hits {
			fmt.Printf("[%2d] %s\n", i+1, h.String())
		}
		return
	}

	fmt.Println("Error: Unsupported filesystem for indexed search on target")
}

func handleCarve(args []string) {
	if len(args) < 3 {
		fmt.Println("Usage: prodiscover carve <image-path> <carvconfig-path> <out-dir>")
		return
	}
	imgPath := args[0]
	cfgPath := args[1]
	outDir := args[2]

	dev, err := openDeviceOrImage(imgPath)
	if err != nil {
		fmt.Printf("Error opening image/device: %v\n", err)
		return
	}
	defer dev.Close()

	rules, err := carver.LoadCarvConfigFile(resolveFilePath(cfgPath))
	if err != nil {
		fmt.Printf("Error loading carving rules: %v\n", err)
		return
	}

	fmt.Printf("Loaded %d carving rules. Scanning %d bytes...\n", len(rules), dev.Size())
	carved, err := carver.CarveDevice(dev, rules, outDir)
	if err != nil {
		fmt.Printf("Carving error: %v\n", err)
		return
	}

	fmt.Printf("Carving completed: %d files carved to %s\n", len(carved), outDir)
	for i, c := range carved {
		fmt.Printf(" [%2d] Ext: .%-4s Offset: 0x%-8X Length: %d bytes\n",
			i+1, c.Rule.Extension, c.StartOffset, c.Length)
	}
}

func handleVerifyMismatches(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: prodiscover verify-mismatches <image-path> <headersig-path>")
		return
	}
	imgPath := args[0]
	sigPath := args[1]

	dev, err := openDeviceOrImage(imgPath)
	if err != nil {
		fmt.Printf("Error opening image/device: %v\n", err)
		return
	}
	defer dev.Close()

	db, err := signatures.LoadHeadersig(resolveFilePath(sigPath))
	if err != nil {
		fmt.Printf("Error loading signature database: %v\n", err)
		return
	}

	fmt.Printf("Loaded %d file signatures from %s. Auditing filesystem...\n", len(db.Signatures), filepath.Base(sigPath))

	mismatchCount := 0
	if fatFS, err := fat.OpenFAT(dev, 0); err == nil {
		entries, _ := fatFS.ReadRootDirEntries()
		for _, e := range entries {
			if e.Size == 0 || e.StartCluster < 2 {
				continue
			}
			header := make([]byte, 32)
			off := fatFS.ClusterToOffset(e.StartCluster)
			dev.ReadAt(header, off)
			isMismatch, detected := db.CheckMismatch(e.Name, header)
			if isMismatch {
				mismatchCount++
				fmt.Printf(" [MISMATCH] File '%s' has claimed extension .%s but magic header matches '%s'\n",
					e.Name, filepath.Ext(e.Name), detected)
			}
		}
	}

	if ntfsFS, err := ntfs.OpenNTFS(dev, 0); err == nil {
		files, _ := ntfsFS.EnumerateFiles(128)
		for _, fe := range files {
			if fe.DefaultStream == nil || fe.DefaultStream.RealSize == 0 {
				continue
			}
			reader := ntfsFS.OpenStream(fe.DefaultStream)
			header := make([]byte, 32)
			reader.ReadAt(header, 0)
			isMismatch, detected := db.CheckMismatch(fe.FileName, header)
			if isMismatch {
				mismatchCount++
				fmt.Printf(" [MISMATCH] File '%s' has claimed extension .%s but magic header matches '%s'\n",
					fe.FileName, filepath.Ext(fe.FileName), detected)
			}
		}
	}

	if mismatchCount == 0 {
		fmt.Println("No extension mismatches detected. All file headers match declared extensions.")
	} else {
		fmt.Printf("Audit finished: Detected %d suspicious file extension mismatch(es)!\n", mismatchCount)
	}
}

func handleExportProject(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: prodiscover export-project <image-path> <out-xml>")
		return
	}
	imgPath := args[0]
	outXML := args[1]

	dev, err := openDeviceOrImage(imgPath)
	if err != nil {
		fmt.Printf("Error opening image/device: %v\n", err)
		return
	}
	defer dev.Close()

	fsName := "Unknown"
	var eoiFiles []project.EvidenceFile

	if fatFS, err := fat.OpenFAT(dev, 0); err == nil {
		fsName = fatFS.Boot.Type.String()
		entries, _ := fatFS.ReadRootDirEntries()
		for _, e := range entries {
			eoiFiles = append(eoiFiles, project.EvidenceFile{
				EOIFileName:  e.Name,
				EOIFStartSec: fmt.Sprintf("%d", fatFS.ClusterToSector(e.StartCluster)),
				EOIFSize:     fmt.Sprintf("%d", e.Size),
			})
		}
	} else if ntfsFS, err := ntfs.OpenNTFS(dev, 0); err == nil {
		fsName = "NTFS"
		files, _ := ntfsFS.EnumerateFiles(128)
		for _, fe := range files {
			sz := uint64(0)
			if fe.DefaultStream != nil {
				sz = fe.DefaultStream.RealSize
			}
			eoiFiles = append(eoiFiles, project.EvidenceFile{
				EOIFileName:  fe.FileName,
				EOIFSize:     fmt.Sprintf("%d", sz),
				EOIComments:  fmt.Sprintf("MFT Record %d", fe.RecordNumber),
			})
		}
	}

	proj := &project.PDProject{
		ProjectNotes: "Exported automatically from ProDiscover Modern Reconstruction",
		ProjectInfo: []project.PDProjectInfo{
			{
				ProjectName:   "Forensic Case " + filepath.Base(imgPath),
				ProjectNumber: "CASE-001",
				ProjectDesc:   "Cross-Platform Win/Linux Forensic Investigation",
			},
		},
		Disks: []project.Disk{
			{
				DiskName:          filepath.Base(imgPath),
				TypeOfDiskOrImage: "Disk Image",
				OITotSec:          fmt.Sprintf("%d", dev.Size()/dev.SectorSize()),
				OITotCapacity:     fmt.Sprintf("%d", dev.Size()),
				Drives: []project.Drive{
					{
						DiskName:     "Partition 1",
						OIFileSystem: fsName,
						OIBPS:        fmt.Sprintf("%d", dev.SectorSize()),
						Evidence: []project.EvidenceOfInterest{
							{
								Files: eoiFiles,
							},
						},
					},
				},
			},
		},
	}

	if err := project.SaveProject(proj, outXML); err != nil {
		fmt.Printf("Error saving project: %v\n", err)
		return
	}
	fmt.Printf("Project successfully exported to %s conforming to ProjectFileSchema.xsd\n", outXML)
}

func handleAcquire(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: prodiscover acquire <source-path> <dest-image> [split-bytes]")
		return
	}
	src := args[0]
	dst := args[1]
	split := int64(0)
	if len(args) > 2 {
		fmt.Sscanf(args[2], "%d", &split)
	}

	dev, err := openDeviceOrImage(src)
	if err != nil {
		fmt.Printf("Error opening source media: %v\n", err)
		return
	}
	defer dev.Close()

	opts := acquire.AcquisitionOptions{
		SourcePath:      src,
		DestinationPath: dst,
		Technician:      "Lead Examiner",
		CaseNumber:      "PD-CASE-ACQ",
		Description:     "Bit-Stream Disk Image Acquisition",
		SplitSize:       split,
	}

	fmt.Printf("Starting bit-stream acquisition: %s -> %s (Size: %d bytes)...\n", src, dst, dev.Size())
	lastPct := -1
	res, err := acquire.AcquireDevice(dev, opts, func(cur, tot int64) {
		pct := int(float64(cur) / float64(tot) * 100)
		if pct != lastPct && pct%10 == 0 {
			fmt.Printf("Progress: %3d%% (%d / %d bytes)\r", pct, cur, tot)
			lastPct = pct
		}
	})
	if err != nil {
		fmt.Printf("\nAcquisition failed: %v\n", err)
		return
	}
	fmt.Printf("\nAcquisition successful in %s!\n", res.Duration)
	fmt.Printf("MD5:    %s\n", res.MD5)
	fmt.Printf("SHA1:   %s\n", res.SHA1)
	fmt.Printf("Output: %s (plus companion .md5, .sha1, and .log files created)\n", dst)
}

func handleReport(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: prodiscover report <image-path> <out-report.html>")
		return
	}
	imgPath := args[0]
	outHTML := args[1]

	dev, err := openDeviceOrImage(imgPath)
	if err != nil {
		fmt.Printf("Error opening image/device: %v\n", err)
		return
	}
	defer dev.Close()

	hMd5 := md5.New()
	hSha1 := sha1.New()
	multi := io.MultiWriter(hMd5, hSha1)
	buf := make([]byte, 1024*1024)
	for off := int64(0); off < dev.Size(); off += int64(len(buf)) {
		n, _ := dev.ReadAt(buf, off)
		if n == 0 {
			break
		}
		multi.Write(buf[:n])
	}
	md5Str := hex.EncodeToString(hMd5.Sum(nil))
	sha1Str := hex.EncodeToString(hSha1.Sum(nil))

	repData := &report.ReportData{
		CaseName:     "Forensic Case: " + filepath.Base(imgPath),
		CaseNumber:   "CASE-2026-PD",
		Investigator: "Lead DFIR Investigator",
		Agency:       "Digital Forensics Laboratory",
		GeneratedAt:  time.Now(),
		MediaPath:    imgPath,
		MediaSize:    dev.Size(),
		SectorSize:   dev.SectorSize(),
		MD5:          md5Str,
		SHA1:         sha1Str,
		Notes:        "Automated comprehensive artifact examination conforming to ProDiscover standards.",
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
	} else if ext, err := extfs.OpenExtFS(dev, 0); err == nil {
		repData.Filesystem = strings.ToUpper(ext.Version())
		repData.ClusterSize = ext.BlockSize
		repData.TotalClusters = ext.Super.BlocksCount
		extFiles, _ := ext.EnumerateFiles()
		for _, ef := range extFiles {
			sec := int64(ef.InodeNumber) * int64(ext.InodeSize) / 512
			repData.Files = append(repData.Files, report.ReportFileItem{
				Name:        ef.Name,
				Size:        ef.Size,
				StartSector: sec,
				Cluster:     ef.InodeNumber,
				SlackBytes:  ef.SlackSize,
				IsDeleted:   ef.IsDeleted,
			})
		}
	}

	err = report.GenerateHTML(repData, outHTML)
	if err != nil {
		fmt.Printf("Error generating report: %v\n", err)
		return
	}
	fmt.Printf("Forensic report successfully generated at %s\n", outHTML)
}

func handleServe(args []string) {
	port := "8080"
	if len(args) > 0 {
		port = args[0]
	}
	setupRoutes()
	fmt.Println("================================================================================")
	fmt.Printf("ProDiscover Forensics Server active at http://localhost:%s\n", port)
	fmt.Println("Clean native DFIR suite running without host driver or kernel modifications")
	fmt.Println("================================================================================")
	_ = http.ListenAndServe(":"+port, nil)
}
