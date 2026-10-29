package report

import (
	"fmt"
	"html"
	"os"
	"strings"
	"time"
)

func sanitizeText(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r >= 32 && r <= 126 {
			sb.WriteRune(r)
		} else if r == '\t' || r == '\n' || r == '\r' {
			sb.WriteRune(' ')
		} else {
			sb.WriteString(fmt.Sprintf("[0x%02X]", byte(r)))
		}
	}
	return html.EscapeString(sb.String())
}

type ReportFileItem struct {
	Name        string
	Size        uint64
	StartSector int64
	Cluster     uint32
	SlackBytes  uint64
	IsDeleted   bool
	ADS         []string
}

type ReportSearchHit struct {
	Term        string
	Context     string // "Allocated", "Slack", "Deleted", "CrossCluster"
	FileName    string
	Sector      int64
	Offset      int64
	SnippetText string
}

type ReportCarvedItem struct {
	Extension   string
	StartOffset int64
	Length      int64
}

type ReportMismatchItem struct {
	FileName         string
	ClaimedExtension string
	DetectedType     string
}

type ReportData struct {
	CaseName      string
	CaseNumber    string
	Investigator  string
	Agency        string
	GeneratedAt   time.Time
	MediaPath     string
	MediaSize     int64
	SectorSize    int64
	Filesystem    string
	ClusterSize   uint32
	TotalClusters uint32
	MD5           string
	SHA1          string
	Files         []ReportFileItem
	SearchHits    []ReportSearchHit
	CarvedFiles   []ReportCarvedItem
	Mismatches    []ReportMismatchItem
	Notes         string
}

func GenerateHTML(data *ReportData, outPath string) error {
	var fileRows strings.Builder
	for _, f := range data.Files {
		status := "<span style=\"color:#2e7d32; font-weight:bold;\">Allocated</span>"
		if f.IsDeleted {
			status = "<span style=\"color:#c62828; font-weight:bold;\">DELETED</span>"
		}
		ads := ""
		if len(f.ADS) > 0 {
			ads = fmt.Sprintf(" <small style=\"color:#6a1b9a;\">[ADS: %s]</small>", strings.Join(f.ADS, ", "))
		}
		fileRows.WriteString(fmt.Sprintf(`<tr>
<td><b>%s</b>%s</td>
<td>%d</td>
<td>%d</td>
<td>%d</td>
<td>%d</td>
<td>%s</td>
</tr>`, sanitizeText(f.Name), ads, f.Size, f.StartSector, f.Cluster, f.SlackBytes, status))
	}

	var searchRows strings.Builder
	for i, h := range data.SearchHits {
		searchRows.WriteString(fmt.Sprintf(`<tr>
<td>%d</td>
<td><b>%s</b></td>
<td><span class="badge">%s</span></td>
<td>%s</td>
<td>%d</td>
<td>0x%X</td>
<td><code>%s</code></td>
</tr>`, i+1, sanitizeText(h.Term), sanitizeText(h.Context), sanitizeText(h.FileName), h.Sector, h.Offset, sanitizeText(h.SnippetText)))
	}

	var carveRows strings.Builder
	for i, c := range data.CarvedFiles {
		carveRows.WriteString(fmt.Sprintf(`<tr>
<td>%d</td>
<td><b>.%s</b></td>
<td>0x%X</td>
<td>%d</td>
</tr>`, i+1, sanitizeText(strings.ToUpper(c.Extension)), c.StartOffset, c.Length))
	}

	var mismatchRows strings.Builder
	for _, m := range data.Mismatches {
		mismatchRows.WriteString(fmt.Sprintf(`<tr>
<td><b>%s</b></td>
<td>.%s</td>
<td><span style="color:#d32f2f; font-weight:bold;">%s</span></td>
</tr>`, sanitizeText(m.FileName), sanitizeText(m.ClaimedExtension), sanitizeText(m.DetectedType)))
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Forensic Investigation Report - %s</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #222; margin: 40px; line-height: 1.5; }
h1 { color: #0d47a1; border-bottom: 2px solid #0d47a1; padding-bottom: 8px; margin-bottom: 4px; }
h2 { color: #1565c0; border-bottom: 1px solid #ccc; padding-bottom: 6px; margin-top: 28px; font-size: 18px; }
.meta-table, table { width: 100%%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
th, td { border: 1px solid #ddd; padding: 8px 10px; text-align: left; }
th { background-color: #f5f5f5; color: #333; }
.badge { background: #e3f2fd; color: #0d47a1; padding: 3px 6px; border-radius: 4px; font-weight: bold; font-size: 11px; }
code { background: #f4f4f4; padding: 2px 5px; border-radius: 3px; font-family: monospace; }
.summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-top: 16px; }
.card { background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 6px; padding: 14px; text-align: center; }
.card .val { font-size: 20px; font-weight: bold; color: #0d47a1; margin-top: 4px; }
.card .lbl { font-size: 11px; color: #666; text-transform: uppercase; font-weight: 600; }
.footer { margin-top: 50px; border-top: 1px solid #ddd; padding-top: 20px; font-size: 12px; color: #666; }
@media print { body { margin: 20px; } .card { border: 1px solid #bbb; } }
</style>
</head>
<body>
<h1>ProDiscover Forensics &bull; Investigation Report</h1>
<div style="font-size: 13px; color: #555;">Generated: %s &bull; Tool: ProDiscover Modern Reconstruction (Cross-Platform Win/Linux)</div>

<div class="summary-grid">
  <div class="card"><div class="lbl">Media Size</div><div class="val">%.2f MB</div></div>
  <div class="card"><div class="lbl">Filesystem</div><div class="val">%s</div></div>
  <div class="card"><div class="lbl">Total Files</div><div class="val">%d</div></div>
  <div class="card"><div class="lbl">Search Hits</div><div class="val">%d</div></div>
</div>

<h2>1. Case &amp; Investigator Identification</h2>
<table class="meta-table">
  <tr><th style="width:25%%;">Case Name</th><td>%s</td><th style="width:25%%;">Case Number</th><td>%s</td></tr>
  <tr><th>Lead Investigator</th><td>%s</td><th>Agency / Organization</th><td>%s</td></tr>
  <tr><th>Examination Notes</th><td colspan="3">%s</td></tr>
</table>

<h2>2. Evidence Media &amp; Integrity Hashes</h2>
<table class="meta-table">
  <tr><th style="width:25%%;">Target Media</th><td colspan="3"><code>%s</code></td></tr>
  <tr><th>Total Capacity</th><td>%d bytes (%.2f MB)</td><th>Sector Size</th><td>%d bytes</td></tr>
  <tr><th>Filesystem Architecture</th><td>%s</td><th>Cluster Size</th><td>%d bytes</td></tr>
  <tr><th>MD5 Verification Hash</th><td colspan="3"><code>%s</code></td></tr>
  <tr><th>SHA-1 Verification Hash</th><td colspan="3"><code>%s</code></td></tr>
</table>

<h2>3. Filesystem Inventory &amp; Slack Space Allocations</h2>
<table>
  <thead>
    <tr><th>File Name</th><th>Size (Bytes)</th><th>Start Sector</th><th>Cluster</th><th>Slack Space</th><th>Status</th></tr>
  </thead>
  <tbody>
    %s
  </tbody>
</table>

<h2>4. Keyword &amp; Signature Search Findings</h2>
<table>
  <thead>
    <tr><th>#</th><th>Query Term</th><th>Context</th><th>File Name / Stream</th><th>Sector</th><th>Offset</th><th>Matched Snippet</th></tr>
  </thead>
  <tbody>
    %s
  </tbody>
</table>

<h2>5. Data Carving &amp; Extension Mismatch Audits</h2>
<h3>Carved File Inventory</h3>
<table>
  <thead>
    <tr><th>#</th><th>Format</th><th>Byte Offset</th><th>Carved Length</th></tr>
  </thead>
  <tbody>
    %s
  </tbody>
</table>

<h3>Extension Mismatch Detections (Spoofed Files)</h3>
<table>
  <thead>
    <tr><th>File Name</th><th>Claimed Extension</th><th>Detected Header Signature</th></tr>
  </thead>
  <tbody>
    %s
  </tbody>
</table>

<div class="footer">
  <p><b>Examiner Affirmation:</b> The forensic acquisition, hashing, and analysis represented in this report were performed using verified bit-stream reconstruction algorithms maintaining strict chain of custody without host operating system driver modification.</p>
  <div style="margin-top: 40px; display: flex; justify-content: space-between;">
    <div>____________________________________________<br>Investigator Signature</div>
    <div>____________________________________________<br>Date &amp; Time</div>
  </div>
</div>
</body>
</html>`,
		data.CaseName,
		data.GeneratedAt.Format(time.RFC1123),
		float64(data.MediaSize)/(1024*1024),
		data.Filesystem,
		len(data.Files),
		len(data.SearchHits),
		data.CaseName, data.CaseNumber,
		data.Investigator, data.Agency,
		data.Notes,
		data.MediaPath,
		data.MediaSize, float64(data.MediaSize)/(1024*1024), data.SectorSize,
		data.Filesystem, data.ClusterSize,
		data.MD5,
		data.SHA1,
		fileRows.String(),
		searchRows.String(),
		carveRows.String(),
		mismatchRows.String(),
	)

	return os.WriteFile(outPath, []byte(html), 0644)
}
