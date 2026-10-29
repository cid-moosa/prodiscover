package report

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestReportGeneration(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "report_test_*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	outHTML := tmpDir + "/forensic_report.html"
	data := &ReportData{
		CaseName:     "State v. Evidence",
		CaseNumber:   "CASE-9921",
		Investigator: "CIDMOOSA",
		Agency:       "DFIR Digital Forensics",
		GeneratedAt:  time.Now(),
		MediaPath:    "/evidence/FATSearchTestImage.eve",
		MediaSize:    15728640,
		SectorSize:   512,
		Filesystem:   "FAT16",
		ClusterSize:  512,
		MD5:          "bac12239bd466fa6c86ceb0b0426da0a",
		SHA1:         "89adda53ed132c84865a22f156897fc09794dacb",
		Files: []ReportFileItem{
			{Name: "file1.dat", Size: 512, StartSector: 271, Cluster: 2, SlackBytes: 0, IsDeleted: false},
			{Name: "file2.dat", Size: 400, StartSector: 272, Cluster: 3, SlackBytes: 112, IsDeleted: false},
			{Name: "deleted.log", Size: 120, StartSector: 276, Cluster: 7, SlackBytes: 392, IsDeleted: true},
		},
		SearchHits: []ReportSearchHit{
			{Term: "1cross1", Context: "CrossCluster", FileName: "file1.dat", Sector: 271, Offset: 0x1FC, SnippetText: "1cross1"},
			{Term: "3slack3", Context: "Slack", FileName: "file4.dat", Sector: 277, Offset: 0x181, SnippetText: "3slack3"},
		},
		Notes: "Full multi-stream forensic examination conducted.",
	}

	err = GenerateHTML(data, outHTML)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	content, err := os.ReadFile(outHTML)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if !strings.Contains(string(content), "State v. Evidence") {
		t.Error("report missing CaseName")
	}
	if !strings.Contains(string(content), "bac12239bd466fa6c86ceb0b0426da0a") {
		t.Error("report missing MD5")
	}
	if !strings.Contains(string(content), "3slack3") {
		t.Error("report missing search hit")
	}
}
