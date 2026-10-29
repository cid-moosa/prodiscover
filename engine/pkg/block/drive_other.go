//go:build !windows && !linux

package block

import (
	"errors"
	"io"
)

type PhysicalDrive struct{}

func OpenPhysicalDrive(index int) (*PhysicalDrive, error) {
	return nil, errors.New("physical drives not supported on this operating system")
}

func OpenLogicalDrive(name string) (*PhysicalDrive, error) {
	return nil, errors.New("logical drives not supported on this operating system")
}

func OpenDrivePath(path string) (*PhysicalDrive, error) {
	return nil, errors.New("direct drive paths not supported on this operating system")
}

func (pd *PhysicalDrive) ReadAt(p []byte, off int64) (int, error) {
	return 0, io.EOF
}

func (pd *PhysicalDrive) Size() int64 {
	return 0
}

func (pd *PhysicalDrive) SectorSize() int64 {
	return 512
}

func (pd *PhysicalDrive) Close() error {
	return nil
}

func ListDrives() ([]DriveInfo, error) {
	return []DriveInfo{}, nil
}
