[Setup]
AppId={{C6287003-8B35-4A92-9844-075A1B82FD26}
AppName=ProDiscover Basic & IR
AppVersion=7.0.0.3
AppVerName=ProDiscover Basic 7.0 (64-bit)
AppPublisher=Technology Pathways, LLC
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
PrivilegesRequired=admin
ChangesAssociations=yes
UninstallDisplayName=ProDiscover Basic & IR (64-bit)
UninstallDisplayIcon={app}\assets\prodiscover.ico
CloseApplications=yes
RestartApplications=no
DisableProgramGroupPage=auto

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "associate"; Description: "Associate ProDiscover with .eve, .dd, and .pds evidence files"; GroupDescription: "File associations:"

[Files]
Source: "..\..\builds\bin\prodiscover.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\builds\bin\prodiscover-engine.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\gui\assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\ProDiscover Basic"; Filename: "{app}\prodiscover.exe"; IconFilename: "{app}\assets\prodiscover.ico"; WorkingDir: "{app}"
Name: "{group}\{cm:UninstallProgram,ProDiscover Basic}"; Filename: "{uninstallexe}"; IconFilename: "{app}\assets\prodiscover.ico"
Name: "{autodesktop}\ProDiscover Basic"; Filename: "{app}\prodiscover.exe"; IconFilename: "{app}\assets\prodiscover.ico"; WorkingDir: "{app}"; Tasks: desktopicon

[Registry]
Root: HKA; Subkey: "Software\Classes\.eve"; ValueType: string; ValueName: ""; ValueData: "ProDiscover.ForensicImage"; Flags: uninsdeletevalue; Tasks: associate
Root: HKA; Subkey: "Software\Classes\.dd"; ValueType: string; ValueName: ""; ValueData: "ProDiscover.ForensicImage"; Flags: uninsdeletevalue; Tasks: associate
Root: HKA; Subkey: "Software\Classes\.pds"; ValueType: string; ValueName: ""; ValueData: "ProDiscover.Project"; Flags: uninsdeletevalue; Tasks: associate
Root: HKA; Subkey: "Software\Classes\ProDiscover.ForensicImage"; ValueType: string; ValueName: ""; ValueData: "ProDiscover Forensic Evidence Image"; Flags: uninsdeletekey; Tasks: associate
Root: HKA; Subkey: "Software\Classes\ProDiscover.ForensicImage\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\assets\prodiscover.ico,0"; Flags: uninsdeletekey; Tasks: associate
Root: HKA; Subkey: "Software\Classes\ProDiscover.ForensicImage\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\prodiscover.exe"" ""%1"""; Flags: uninsdeletekey; Tasks: associate
Root: HKA; Subkey: "Software\Classes\ProDiscover.Project"; ValueType: string; ValueName: ""; ValueData: "ProDiscover Forensic Project File"; Flags: uninsdeletekey; Tasks: associate
Root: HKA; Subkey: "Software\Classes\ProDiscover.Project\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\assets\prodiscover.ico,0"; Flags: uninsdeletekey; Tasks: associate
Root: HKA; Subkey: "Software\Classes\ProDiscover.Project\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\prodiscover.exe"" ""%1"""; Flags: uninsdeletekey; Tasks: associate

[UninstallDelete]
Type: filesandordirs; Name: "{app}\assets"
Type: filesandordirs; Name: "{app}\Sample Images"
Type: filesandordirs; Name: "{app}\carved_files"
Type: filesandordirs; Name: "{app}\reports"
Type: filesandordirs; Name: "{app}\exports"
Type: files; Name: "{app}\*.log"
Type: files; Name: "{app}\*.pds"
Type: files; Name: "{app}\*.dd"
Type: files; Name: "{app}\*.eve"
Type: dirifempty; Name: "{app}"

[Run]
Filename: "{app}\prodiscover.exe"; Description: "{cm:LaunchProgram,ProDiscover Basic}"; Flags: nowait postinstall skipifsilent shellexec

[Code]
procedure InitializeWizard;
var
  i: Integer;
begin
  // Ensure "Create a desktop icon" is checked by default
  for i := 0 to WizardForm.TasksList.Items.Count - 1 do
  begin
    if Pos('desktop', Lowercase(WizardForm.TasksList.ItemCaption[i])) > 0 then
      WizardForm.TasksList.Checked[i] := True;
  end;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpFinished then
  begin
    // Restore ProDiscover fedora branding logo on Finish page
    WizardForm.WizardBitmapImage2.Visible := True;
    WizardForm.WizardBitmapImage2.Left := WizardForm.WizardBitmapImage.Left;
    WizardForm.WizardBitmapImage2.Top := WizardForm.WizardBitmapImage.Top;
    WizardForm.WizardBitmapImage2.Width := WizardForm.WizardBitmapImage.Width;
    WizardForm.WizardBitmapImage2.Height := WizardForm.WizardBitmapImage.Height;
    WizardForm.FinishedHeadingLabel.Left := WizardForm.WelcomeLabel1.Left;
    WizardForm.FinishedHeadingLabel.Width := WizardForm.WelcomeLabel1.Width;
    WizardForm.FinishedLabel.Left := WizardForm.WelcomeLabel2.Left;
    WizardForm.FinishedLabel.Width := WizardForm.WelcomeLabel2.Width;
    if Assigned(WizardForm.RunList) then
    begin
      WizardForm.RunList.Left := WizardForm.WelcomeLabel2.Left;
      WizardForm.RunList.Width := WizardForm.WelcomeLabel2.Width;
    end;
  end;
end;
