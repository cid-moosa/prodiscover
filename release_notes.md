### ProDiscover Basic & IR v1.0.0 (64-bit Windows Setup)

#### Downloads
- **Standalone Setup File:** [ProDiscover_Setup.exe](https://github.com/cid-moosa/prodiscover/releases/download/v1.0.0/ProDiscover_Setup.exe) (40.7 MB - Digitally Signed Authenticode Installer)
- **Zip Package:** [ProDiscover_Setup_v1.0.0.zip](https://github.com/cid-moosa/prodiscover/releases/download/v1.0.0/ProDiscover_Setup_v1.0.0.zip) (40.1 MB - Standalone installer archive)

---

### Why Does Windows Show a Blue SmartScreen Warning?
When you launch ProDiscover_Setup.exe, Microsoft Defender SmartScreen may display a standard warning for newly released software.

**This is 100% normal and expected for new releases.** Windows displays this generic screen for downloads where Windows has not yet built a global cloud reputation for the author/version.

#### How to Install:
On the blue SmartScreen screen, click **More info**, then click **Run anyway**. (Verified publisher displays as Technology Pathways, LLC (ProDiscover Forensic Systems)).

---

### Key Capabilities in this Forensic Release:
- **Live Physical Memory (RAM Bit-Stream) Capture**: Real-time acquisition of live physical RAM and process working sets with live MD5/SHA-1 hashing, companion audit logs, and automatic project loading.
- **Bit-Stream Disk Acquisition (.dd / .eve)**: Exact 1:1 bit-stream physical and volume imaging with concurrent checksums and audit logs.
- **Deep Filesystem Analysis**: Native parsing of NTFS ( records 0..255, resident & non-resident streams, ADS), FAT12/16/32 with LFN reconstruction, and Ext2/3/4.
- **Advanced EXIF Metadata Inspector**: 2-pane media inspector with thumbnail rendering, camera EXIF extraction, and GPS geolocation decoding.
- **Recovering Evidence**: Automatic recovery of deleted directory records and file carving via CarvConfig.txt.
- **Slack & Unallocated Space Search**: Multi-stream forensic search across allocated clusters, slack space, and unallocated gaps.
- **Classic MFC Forensic Workspace**: Faithful recreation of the 3-pane ProDiscover interface with dual-pane Hex/ASCII data inspector.

---

### 🧪 Community Testing & Error Reporting
We invite forensic examiners, students, and practitioners to test ProDiscover across a wide variety of disk images and evidence targets.
If you encounter **any error, crash, corrupt cluster reading, or parsing failure**:
- Open an issue on GitHub: **[Report an Issue / Bug](https://github.com/cid-moosa/prodiscover/issues/new)**
- Or inside the application, select **Help -> Report an Issue or Bug (GitHub)...** or **Help -> About ProDiscover Basic & IR...** to copy diagnostic information and report in 1 click!
