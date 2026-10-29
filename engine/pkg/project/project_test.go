package project

import (
	"os"
	"strings"
	"testing"
)

func TestProjectSaveAndLoad(t *testing.T) {
	proj := &PDProject{
		ProjectNotes: "Incident Investigation 2026",
		ProjectInfo: []PDProjectInfo{
			{
				ProjectName:   "Case-Alpha",
				ProjectNumber: "CASE-001",
				ProjectDesc:   "Modern Forensic Reconstruction Test",
			},
		},
		Disks: []Disk{
			{
				DiskName:          "Disk 0",
				DiskDesc:          "Target Storage Media",
				TypeOfDiskOrImage: "Physical Drive",
				Drives: []Drive{
					{
						DiskName:     "Partition 1",
						OIFileSystem: "NTFS",
						OIBPS:        "512",
						Evidence: []EvidenceOfInterest{
							{
								Files: []EvidenceFile{
									{
										EOIFileName:  "evidence_log.txt",
										EOIFCheckSum: "d41d8cd98f00b204e9800998ecf8427e",
										EOIFSize:     "1024",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	tmpFile, err := os.CreateTemp("", "proj_*.xml")
	if err != nil {
		t.Fatalf("temp file error: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	if err := SaveProject(proj, tmpFile.Name()); err != nil {
		t.Fatalf("SaveProject failed: %v", err)
	}

	loaded, err := LoadProject(tmpFile.Name())
	if err != nil {
		t.Fatalf("LoadProject failed: %v", err)
	}

	if loaded.ProjectNotes != proj.ProjectNotes {
		t.Errorf("expected notes %s, got %s", proj.ProjectNotes, loaded.ProjectNotes)
	}
	if len(loaded.ProjectInfo) != 1 || loaded.ProjectInfo[0].ProjectName != "Case-Alpha" {
		t.Errorf("project info mismatch: %+v", loaded.ProjectInfo)
	}
	if len(loaded.Disks) != 1 || len(loaded.Disks[0].Drives) != 1 {
		t.Fatalf("disks structure mismatch: %+v", loaded.Disks)
	}
	if loaded.Disks[0].Drives[0].Evidence[0].Files[0].EOIFileName != "evidence_log.txt" {
		t.Errorf("evidence file mismatch")
	}

	// Verify XML header and namespace
	data, _ := os.ReadFile(tmpFile.Name())
	if !strings.Contains(string(data), `xmlns="http://tempuri.org/Total1.xsd"`) {
		t.Errorf("missing standard XML namespace in project file")
	}
}
