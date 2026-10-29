//go:build windows

package block

import (
	"errors"
	"fmt"
	"io"
	"syscall"
	"unsafe"
)

const (
	IOCTL_DISK_GET_LENGTH_INFO       = 0x00074059
	IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x000700A0
)

type DISK_GEOMETRY struct {
	Cylinders         int64
	MediaType         uint32
	TracksPerCylinder uint32
	SectorsPerTrack   uint32
	BytesPerSector    uint32
}

type DISK_GEOMETRY_EX struct {
	Geometry DISK_GEOMETRY
	DiskSize int64
	Data     [1]byte
}

type PhysicalDrive struct {
	handle     syscall.Handle
	size       int64
	sectorSize int64
	path       string
}

func OpenDrivePath(path string) (*PhysicalDrive, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	handle, err := syscall.CreateFile(
		pathPtr,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open drive %s: %w", path, err)
	}

	pd := &PhysicalDrive{
		handle:     handle,
		sectorSize: 512,
		path:       path,
	}

	size, err := pd.queryDiskSize()
	if err == nil && size > 0 {
		pd.size = size
	}

	return pd, nil
}

func OpenPhysicalDrive(index int) (*PhysicalDrive, error) {
	path := fmt.Sprintf(`\\.\PhysicalDrive%d`, index)
	return OpenDrivePath(path)
}

func OpenLogicalDrive(letter string) (*PhysicalDrive, error) {
	if len(letter) == 1 {
		letter = letter + ":"
	}
	path := fmt.Sprintf(`\\.\%s`, letter)
	return OpenDrivePath(path)
}

func (pd *PhysicalDrive) queryDiskSize() (int64, error) {
	var lengthInfo int64
	var bytesReturned uint32

	err := syscall.DeviceIoControl(
		pd.handle,
		IOCTL_DISK_GET_LENGTH_INFO,
		nil,
		0,
		(*byte)(unsafe.Pointer(&lengthInfo)),
		uint32(unsafe.Sizeof(lengthInfo)),
		&bytesReturned,
		nil,
	)
	if err == nil && lengthInfo > 0 {
		return lengthInfo, nil
	}

	// Fallback to DISK_GEOMETRY_EX
	var geom DISK_GEOMETRY_EX
	err = syscall.DeviceIoControl(
		pd.handle,
		IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
		nil,
		0,
		(*byte)(unsafe.Pointer(&geom)),
		uint32(unsafe.Sizeof(geom)),
		&bytesReturned,
		nil,
	)
	if err == nil {
		if geom.Geometry.BytesPerSector > 0 {
			pd.sectorSize = int64(geom.Geometry.BytesPerSector)
		}
		if geom.DiskSize > 0 {
			return geom.DiskSize, nil
		}
	}

	return 0, errors.New("unable to determine disk size")
}

func (pd *PhysicalDrive) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if pd.size > 0 && off >= pd.size {
		return 0, io.EOF
	}

	secSz := pd.sectorSize
	if secSz <= 0 {
		secSz = 512
	}

	alignedOff := (off / secSz) * secSz
	delta := off - alignedOff
	needed := int64(len(p)) + delta
	alignedLen := ((needed + secSz - 1) / secSz) * secSz

	high := int32(alignedOff >> 32)
	low := int32(alignedOff & 0xFFFFFFFF)
	_, err := syscall.SetFilePointer(pd.handle, low, &high, syscall.FILE_BEGIN)
	if err != nil {
		return 0, fmt.Errorf("seek error at %d: %w", alignedOff, err)
	}

	buf := make([]byte, alignedLen)
	var bytesRead uint32
	err = syscall.ReadFile(pd.handle, buf, &bytesRead, nil)
	if err != nil {
		return 0, fmt.Errorf("read error at %d: %w", alignedOff, err)
	}

	if int64(bytesRead) <= delta {
		return 0, io.EOF
	}

	avail := int64(bytesRead) - delta
	toCopy := int64(len(p))
	if toCopy > avail {
		toCopy = avail
	}

	copy(p, buf[delta:delta+toCopy])
	if toCopy < int64(len(p)) {
		return int(toCopy), io.EOF
	}
	return int(toCopy), nil
}

func (pd *PhysicalDrive) Size() int64 {
	return pd.size
}

func (pd *PhysicalDrive) SectorSize() int64 {
	return pd.sectorSize
}

func (pd *PhysicalDrive) Close() error {
	return syscall.CloseHandle(pd.handle)
}

func ListDrives() ([]DriveInfo, error) {
	var drives []DriveInfo
	// Check PhysicalDrive 0 to 16
	for i := 0; i < 16; i++ {
		pd, err := OpenPhysicalDrive(i)
		if err == nil {
			drives = append(drives, DriveInfo{
				Index:       i,
				DevicePath:  pd.path,
				Name:        fmt.Sprintf("PhysicalDrive%d", i),
				Size:        pd.size,
				SectorSize:  pd.sectorSize,
				IsPhysical:  true,
				Description: fmt.Sprintf("Physical Hard Disk %d (%.2f GB)", i, float64(pd.size)/(1024*1024*1024)),
			})
			pd.Close()
		} else if errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
			drives = append(drives, DriveInfo{
				Index:       i,
				DevicePath:  fmt.Sprintf(`\\.\PhysicalDrive%d`, i),
				Name:        fmt.Sprintf("PhysicalDrive%d", i),
				IsPhysical:  true,
				Description: fmt.Sprintf("Physical Hard Disk %d (Requires Admin Privileges to Read Raw Sectors)", i),
			})
		}
	}

	// Enumerate logical drives (C:, D:, etc.)
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getLogicalDrives := kernel32.NewProc("GetLogicalDrives")
	mask, _, _ := getLogicalDrives.Call()
	for ch := 'A'; ch <= 'Z'; ch++ {
		bit := uintptr(1 << (ch - 'A'))
		if mask&bit != 0 {
			vol := fmt.Sprintf("%c:", ch)
			drives = append(drives, DriveInfo{
				Index:       int(ch - 'A' + 100),
				DevicePath:  fmt.Sprintf(`\\.\%s`, vol),
				Name:        vol,
				IsPhysical:  false,
				Description: fmt.Sprintf("Logical Volume %s", vol),
			})
		}
	}

	return drives, nil
}
