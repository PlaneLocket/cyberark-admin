$ca_path = "E:\\CyberArk\\PSM\\Components"

#determine existing version
$orig_version = (Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe').'(Default)').VersionInfo.ProductVersion

#rename existing driver
Rename-Item -Path "$ca_path\\chromedriver.exe" -NewName "chromedriver$orig_version.exe"

#install new chrome version
$Path = $env:TEMP;
$Installer = "chrome_installer.exe";

Write-Output "Updating chrome from $orig_version"

Invoke-WebRequest "http://dl.google.com/chrome/install/latest/chrome_installer.exe" -OutFile $Path\$Installer;
Start-Process -FilePath $Path\$Installer -Args "/silent /install" -Verb RunAs -Wait;
#delete the installer
Remove-Item $Path\$Installer

#get the version of the newly installed chrome
$upgr_version = (Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe').'(Default)').VersionInfo.ProductVersion

Write-Output "Updated chrome to $upgr_version"

$ChromeVersion = $upgr_version.Substring(0, $upgr_version.LastIndexOf("."));
$ChromeDriverVersion = Invoke-WebRequest "https://googlechromelabs.github.io/chrome-for-testing/LATEST_RELEASE_$ChromeVersion" `
  -ContentType 'text/plain' |
  Select-Object -ExpandProperty Content;
$ChromeDriverVersion = [System.Text.Encoding]::UTF8.GetString($ChromeDriverVersion);
Write-Output "Latest matching version of Chrome Driver is $ChromeDriverVersion";

$DownloadUrl = Invoke-WebRequest 'https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json' | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty versions | Where-Object { $_.version -eq $ChromeDriverVersion } | Select-Object -ExpandProperty downloads | Select-Object -ExpandProperty chromedriver | Where-Object { $_.platform -eq "win32" } | Select-Object -ExpandProperty url;
Write-Output $DownloadUrl
#download the new driver
Invoke-WebRequest $DownloadUrl -OutFile "$ca_Path\chromedriver.zip";

#unzip and copy the new driver into the components directory
Expand-Archive "$ca_Path\chromedriver.zip" -DestinationPath $Path -Force
Copy-Item "$Path\\chromedriver-win32\\chromedriver.exe" -Destination $ca_path -Force

#run app locker
cd "E:\\CyberArk\\PSM\\Hardening"
& "E:\\CyberArk\\PSM\\Hardening\\PSMConfigureAppLocker.ps1"
