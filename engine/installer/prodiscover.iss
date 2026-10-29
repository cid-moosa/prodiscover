[Setup]
AppId={{C6287003-8B35-4A92-9844-075A1B82FD26}
AppName=ProDiscover Basic & IR
AppVersion=7.0.0.3
AppVerName=ProDiscover Basic 7.0 (64-bit)
AppPublisher=Technology Pathways / Modern Reconstruction
AppPublisherURL=https://github.com/cid-moosa/prodiscover
AppSupportURL=https://github.com/cid-moosa/prodiscover
AppUpdatesURL=https://github.com/cid-moosa/prodiscover/releases
DefaultDirName={autopf}\ProDiscover Basic
DefaultGroupName=ProDiscover Basic
AllowNoIcons=yes
OutputDir=..\..\builds\installer
OutputBaseFilename=ProDiscover_Setup
SetupIconFile=..\gui\assets\prodiscover.ico
WizardImageFile=wizard_large.bmp
WizardSmallImageFile=wizard_small.bmp
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ChangesAssociations=yes
UninstallDisplayIcon={app}\assets\prodiscover.ico
DisableProgramGroupPage=auto

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "associate"; Description: "Associate ProDiscover with .eve, .dd, and .pds evidence files"; GroupDescription: "File associations:"

[Files]
Source: "..\..\builds\bin\prodiscover.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\gui\assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme

[Icons]
Name: "{group}\ProDiscover Basic"; Filename: "{app}\prodiscover.exe"; IconFilename: "{app}\assets\prodiscover.ico"; WorkingDir: "{app}"
Name: "{group}\{cm:UninstallProgram,ProDiscover Basic}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\ProDiscover Basic"; Filename: "{app}\prodiscover.exe"; IconFilename: "{app}\assets\prodiscover.ico"; WorkingDir: "{app}"; Tasks: desktopicon

[Registry]
Root: HKA; Subkey: "Software\Classes\.eve"; ValueType: string; ValueName: ""; ValueData: "ProDiscover.ForensicImage"; Flags: uninsdeletevalue; Tasks: associate
Root: HKA; Subkey: "Software\Classes\.dd"; ValueType: string; ValueName: ""; ValueData: "ProDiscover.ForensicImage"; Flags: uninsdeletevalue; Tasks: associate
Root: HKA; Subkey: "Software\Classes\.pds"; ValueType: string; ValueName: ""; ValueData: "ProDiscover.Project"; Flags: uninsdeletevalue; Tasks: associate
Root: HKA; Subkey: "Software\Classes\ProDiscover.ForensicImage"; ValueType: string; ValueName: ""; ValueData: "ProDiscover Forensic Evidence Image"; Flags: uninsdeletekey; Tasks: associate
Root: HKA; Subkey: "Software\Classes\ProDiscover.ForensicImage\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\assets\prodiscover.ico,0"; Flags: uninsdeletekey; Tasks: associate
Root: HKA; Subkey: "Software\Classes\ProDiscover.ForensicImage\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\prodiscover.exe"" ""%1"""; Flags: uninsdeletekey; Tasks: associate

[Run]
Filename: "{app}\prodiscover.exe"; Description: "{cm:LaunchProgram,ProDiscover Basic}"; Flags: nowait postinstall skipifsilent

