package block

import (
	"errors"
	"io"
	"os"
)

var (
	ErrOutOfBounds = errors.New("read out of device bounds")
	ErrInvalidImage = errors.New("invalid disk image format")
)

// BlockDevice represents an abstract physical disk, partition, or disk image.
type BlockDevice interface {
	io.ReaderAt
	io.Closer
	Size() int64
	SectorSize() int64
}

// FileDevice implements BlockDevice for disk image files (.eve, .dd, .raw, .iso).
type FileDevice struct {
	file       *os.File
	size       int64
	sectorSize int64
}

// OpenFileDevice opens a raw or uncompressed .eve disk image.
func OpenFileDevice(path string) (*FileDevice, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	stat, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}

	return &FileDevice{
		file:       f,
		size:       stat.Size(),
		sectorSize: 512, // Standard sector size
	}, nil
}

func (fd *FileDevice) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= fd.size {
		return 0, io.EOF
	}
	return fd.file.ReadAt(p, off)
}

func (fd *FileDevice) Size() int64 {
	return fd.size
}

func (fd *FileDevice) SectorSize() int64 {
	return fd.sectorSize
}

func (fd *FileDevice) SetSectorSize(sz int64) {
	if sz > 0 {
		fd.sectorSize = sz
	}
}

func (fd *FileDevice) Close() error {
	return fd.file.Close()
}
