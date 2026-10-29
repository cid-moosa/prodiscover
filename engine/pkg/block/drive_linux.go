//go:build linux

package block

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const BLKGETSIZE64 = 0x80081272

type PhysicalDrive struct {
	file       *os.File
	size       int64
	sectorSize int64
	path       string
}

func OpenDrivePath(path string) (*PhysicalDrive, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open linux block device %s: %w", path, err)
	}

	pd := &PhysicalDrive{
		file:       f,
		sectorSize: 512,
		path:       path,
	}

	size, err := pd.queryDiskSize()
	if err == nil && size > 0 {
		pd.size = size
	} else {
		// Fallback to stat if not a raw block device
		if fi, serr := f.Stat(); serr == nil {
			pd.size = fi.Size()
		}
	}

	return pd, nil
}

func OpenPhysicalDrive(index int) (*PhysicalDrive, error) {
	// Traditional /dev/sd* mapping: 0 -> sda, 1 -> sdb
	devChar := rune('a' + index)
	path := fmt.Sprintf("/dev/sd%c", devChar)
	return OpenDrivePath(path)
}

func OpenLogicalDrive(name string) (*PhysicalDrive, error) {
	path := filepath.Join("/dev", name)
	return OpenDrivePath(path)
}

func (pd *PhysicalDrive) queryDiskSize() (int64, error) {
	var size uint64
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		pd.file.Fd(),
		BLKGETSIZE64,
		uintptr(unsafe.Pointer(&size)),
	)
	if errno != 0 {
		return 0, errno
	}
	return int64(size), nil
}

func (pd *PhysicalDrive) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if pd.size > 0 && off >= pd.size {
		return 0, io.EOF
	}
	return pd.file.ReadAt(p, off)
}

func (pd *PhysicalDrive) Size() int64 {
	return pd.size
}

func (pd *PhysicalDrive) SectorSize() int64 {
	return pd.sectorSize
}

func (pd *PhysicalDrive) Close() error {
	return pd.file.Close()
}

func ListDrives() ([]DriveInfo, error) {
	var drives []DriveInfo
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil, err
	}

	idx := 0
	for _, entry := range entries {
		name := entry.Name()
		// Filter out loop, ram, and dm devices
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "dm-") {
			continue
		}

		devPath := filepath.Join("/dev", name)
		pd, err := OpenDrivePath(devPath)
		if err == nil {
			drives = append(drives, DriveInfo{
				Index:       idx,
				DevicePath:  devPath,
				Name:        name,
				Size:        pd.size,
				SectorSize:  pd.sectorSize,
				IsPhysical:  true,
				Description: fmt.Sprintf("Linux Block Storage %s (%.2f GB)", name, float64(pd.size)/(1024*1024*1024)),
			})
			pd.Close()
			idx++
		}
	}
	return drives, nil
}
