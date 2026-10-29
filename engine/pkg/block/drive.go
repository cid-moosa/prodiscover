package block

// DriveInfo represents metadata about an attached physical or logical drive.
type DriveInfo struct {
	Index       int    `json:"index"`
	DevicePath  string `json:"devicePath"`
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	SectorSize  int64  `json:"sectorSize"`
	IsPhysical  bool   `json:"isPhysical"`
	Description string `json:"description"`
}
