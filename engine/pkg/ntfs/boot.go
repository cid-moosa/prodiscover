package ntfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"prodiscover/pkg/block"
)

var (
	ErrNotNTFS = errors.New("not a valid NTFS volume")
)

type BootSector struct {
	OEMName           string
	BytesPerSector    uint16
	SectorsPerCluster uint8
	ClusterSizeBytes  uint32
	TotalSectors      uint64
	MFTCluster        int64
	MFTMirrCluster    int64
	MFTRecordSize     int
	IndexRecordSize   int
	VolumeSerial      uint64
}

type NTFSFS struct {
	dev    block.BlockDevice
	offset int64
	Boot   BootSector
}

func OpenNTFS(dev block.BlockDevice, partOffset int64) (*NTFSFS, error) {
	sector := make([]byte, 512)
	if _, err := dev.ReadAt(sector, partOffset); err != nil {
		return nil, fmt.Errorf("reading NTFS boot sector: %w", err)
	}

	oem := string(sector[3:11])
	if oem != "NTFS    " {
		return nil, ErrNotNTFS
	}

	bps := binary.LittleEndian.Uint16(sector[11:13])
	spc := sector[13]
	if bps == 0 || spc == 0 {
		return nil, ErrNotNTFS
	}

	clusterSize := uint32(bps) * uint32(spc)
	totSec := binary.LittleEndian.Uint64(sector[40:48])
	mftLCN := int64(binary.LittleEndian.Uint64(sector[48:56]))
	mftMirrLCN := int64(binary.LittleEndian.Uint64(sector[56:64]))

	cPerMFT := int8(sector[64])
	var mftRecordSize int
	if cPerMFT < 0 {
		mftRecordSize = 1 << (-cPerMFT)
	} else {
		mftRecordSize = int(cPerMFT) * int(clusterSize)
	}

	cPerIdx := int8(sector[68])
	var idxRecordSize int
	if cPerIdx < 0 {
		idxRecordSize = 1 << (-cPerIdx)
	} else {
		idxRecordSize = int(cPerIdx) * int(clusterSize)
	}

	volSerial := binary.LittleEndian.Uint64(sector[72:80])

	return &NTFSFS{
		dev:    dev,
		offset: partOffset,
		Boot: BootSector{
			OEMName:           oem,
			BytesPerSector:    bps,
			SectorsPerCluster: spc,
			ClusterSizeBytes:  clusterSize,
			TotalSectors:      totSec,
			MFTCluster:        mftLCN,
			MFTMirrCluster:    mftMirrLCN,
			MFTRecordSize:     mftRecordSize,
			IndexRecordSize:   idxRecordSize,
			VolumeSerial:      volSerial,
		},
	}, nil
}

func (fs *NTFSFS) LCNToOffset(lcn int64) int64 {
	return fs.offset + (lcn * int64(fs.Boot.ClusterSizeBytes))
}

func (fs *NTFSFS) LCNToSector(lcn int64) int64 {
	return lcn * int64(fs.Boot.SectorsPerCluster)
}
