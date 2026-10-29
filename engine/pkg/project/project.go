package project

import (
	"encoding/xml"
	"os"
)

type PDProject struct {
	XMLName      xml.Name        `xml:"PDProject"`
	Xmlns        string          `xml:"xmlns,attr"`
	ProjectNotes string          `xml:"ProjectNotes,omitempty"`
	ProjectInfo  []PDProjectInfo `xml:"PDProjectInfo,omitempty"`
	Disks        []Disk          `xml:"Disk,omitempty"`
}

type PDProjectInfo struct {
	ProjectName   string `xml:"ProjectName,omitempty"`
	ProjectNumber string `xml:"ProjectNumber,omitempty"`
	ProjectDesc   string `xml:"ProjectDesc,omitempty"`
}

type Disk struct {
	DiskName          string  `xml:"DiskName,omitempty"`
	DiskDesc          string  `xml:"DiskDesc,omitempty"`
	TypeOfDiskOrImage string  `xml:"TypeOfDiskOrImage,omitempty"`
	OIDiskMake        string  `xml:"OIDiskMake,omitempty"`
	OITotSec          string  `xml:"OITotSec,omitempty"`
	OITotCapacity     string  `xml:"OITotCapacity,omitempty"`
	DITotalFolders    string  `xml:"DITotalFolders,omitempty"`
	DITotalFiles      string  `xml:"DITotalFiles,omitempty"`
	Drives            []Drive `xml:"Drive,omitempty"`
}

type Drive struct {
	DiskName          string               `xml:"DiskName,omitempty"`
	DiskDesc          string               `xml:"DiskDesc,omitempty"`
	TypeOfDiskOrImage string               `xml:"TypeOfDiskOrImage,omitempty"`
	OIDriveType       string               `xml:"OIDriveType,omitempty"`
	OIVolName         string               `xml:"OIVolName,omitempty"`
	OIFileSystem      string               `xml:"OIFileSystem,omitempty"`
	OIBPS             string               `xml:"OIBPS,omitempty"`
	OITotClust        string               `xml:"OITotClust,omitempty"`
	OITotSec          string               `xml:"OITotSec,omitempty"`
	Evidence          []EvidenceOfInterest `xml:"EvidenceOfInterest,omitempty"`
}

type EvidenceOfInterest struct {
	Files []EvidenceFile `xml:"File,omitempty"`
}

type EvidenceFile struct {
	EOIFileName     string `xml:"EOIFileName,omitempty"`
	EOIFCheckSum    string `xml:"EOIFCheckSum,omitempty"`
	EOICreated      string `xml:"EOICreated,omitempty"`
	EOIModified     string `xml:"EOIModified,omitempty"`
	EOIAccessed     string `xml:"EOIAccessed,omitempty"`
	EOIFStartSec    string `xml:"EOIFStartSec,omitempty"`
	EOIFSize        string `xml:"EOIFSize,omitempty"`
	EOIComments     string `xml:"EOIComments,omitempty"`
	EOIClusterChain string `xml:"EOIClusterChain,omitempty"`
}

func SaveProject(p *PDProject, path string) error {
	p.Xmlns = "http://tempuri.org/Total1.xsd"
	data, err := xml.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	header := []byte(xml.Header)
	fullData := append(header, data...)
	return os.WriteFile(path, fullData, 0644)
}

func LoadProject(path string) (*PDProject, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var proj PDProject
	if err := xml.Unmarshal(data, &proj); err != nil {
		return nil, err
	}
	return &proj, nil
}
