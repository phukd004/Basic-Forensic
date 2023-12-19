$screen = @"

 __     __   __     ______     __     ______     __  __     ______   __     ______   __  __    
/\ \   /\ "-.\ \   /\  ___\   /\ \   /\  ___\   /\ \_\ \   /\__  _\ /\ \   /\  ___\ /\ \_\ \   
\ \ \  \ \ \-.  \  \ \___  \  \ \ \  \ \ \__ \  \ \  __ \  \/_/\ \/ \ \ \  \ \  __\ \ \____ \  
 \ \_\  \ \_\\"\_\  \/\_____\  \ \_\  \ \_____\  \ \_\ \_\    \ \_\  \ \_\  \ \_\    \/\_____\ 
  \/_/   \/_/ \/_/   \/_____/   \/_/   \/_____/   \/_/\/_/     \/_/   \/_/   \/_/     \/_____/ 
                                                                                               
                                                                                                                                                                                                                                                                                                                                                                                                                                                  
"@

Write-Host $screen

$OriginPath = Get-Location

#Setting .html Output and Location
$currentDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$resultPath = Join-Path -Path $currentDir -ChildPath "webapp/myapp/templates/myapp"
Set-Location -Path $resultPath

$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8' #Use with PowerShell v7.1 or Higher

$SystemHtml     = 'system.html'
$ProcessesHtml  = 'processes.html'
$NetworkHtml    = 'network.html'
$OtherHtml      = 'other.html'

#Clear Content in .html Output if exist

Clear-Content $SystemHtml
Clear-Content $ProcessesHtml
Clear-Content $NetworkHtml
Clear-Content $OtherHtml

#Gathering System Info from Current Computer

Write-Host -Fore Yellow "[*] Gathering System Information."

$SystemInfo = Get-CimInstance -Class Win32_ComputerSystem  | Select-Object -Property Name,Caption,SystemType,Manufacturer,Model,DNSHostName,Domain,PartOfDomain,WorkGroup,CurrentTimeZone,PCSystemType,HyperVisorPresent | ConvertTo-Html -Fragment 
$OSInfo = Get-CimInstance -Class Win32_OperatingSystem   | Select-Object -Property Name, Description,Version,BuildNumber,InstallDate,SystemDrive,SystemDevice,WindowsDirectory,LastBootupTime,Locale,LocalDateTime,NumberofUsers,RegisteredUser,Organization,OSProductSuite | ConvertTo-Html -Fragment
$Hotfixes = Get-Hotfix | Select-Object -Property CSName, Caption,Description, HotfixID, InstalledBy, InstalledOn | ConvertTo-Html -Fragment 
$WinDefender = Get-MpComputerStatus | ConvertTo-Html -Fragment
$EnvSetting = Get-ChildItem ENV: | Select name, value | convertto-html -fragment 
$InstallProgs = Get-CimInstance -ClassName win32_product | Select-Object Name, Version, Vendor, InstallDate, InstallSource, PackageName, LocalPackage | ConvertTo-Html -Fragment
$InstalledApps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | ConvertTo-Html -Fragment

Write-Host -Fore Green "[!] Done."

#Gathering Running Processes and Tasks

Write-Host -Fore Yellow "[*] Gathering Processes and Tasks"

$Processes = Get-Process | Select Handle, StartTime, PM, VM, SI, id, ProcessName, Path, Product, FileVersion | ConvertTo-Html -Fragment
$StartupProg = Get-CimInstance Win32_StartupCommand | Select Command, User, Caption | ConvertTo-Html -Fragment
$ScheduledTask = Get-ScheduledTask | ? State -eq Running | ConvertTo-Html -Fragment
$ScheduledState = Get-ScheduledTask | ? State -eq running | Get-ScheduledTaskInfo | ConvertTo-Html -Fragment 
$Services = Get-Service | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Html -Fragment 

Write-Host -Fore Green "[!] Done."

#Gathering Network Information

Write-Host -Fore Yellow "[*] Gathering Network Informationn"

$NetworkAdapter = Get-CimInstance -class Win32_NetworkAdapter  | Select-Object -Property AdapterType,ProductName,Description,MACAddress,Availability,NetconnectionStatus,NetEnabled,PhysicalAdapter | ConvertTo-Html -Fragment
$IPConfiguration = Get-CimInstance Win32_NetworkAdapterConfiguration |  Select Description, @{Name='IpAddress';Expression={$_.IpAddress -join '; '}}, @{Name='IpSubnet';Expression={$_.IpSubnet -join '; '}}, MACAddress, @{Name='DefaultIPGateway';Expression={$_.DefaultIPGateway -join '; '}}, DNSDomain, DNSHostName, DHCPEnabled, ServiceName | convertTo-Html -fragment
$NetIPAddress = Get-NetIPaddress | Select InterfaceAlias, IPaddress, EnabledState, OperatingStatus | ConvertTo-Html -fragment 
$NetConnectProfile = Get-NetConnectionProfile | Select Name, InterfaceAlias, NetworkCategory, IPV4Connectivity, IPv6Connectivity | ConvertTo-Html -fragment 
$NetTCPConnect = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}| ConvertTo-Html -Fragment
Write-Host -Fore Green "[!] Done."

# Other Information

Write-Host -Fore Yellow "[*] Gathering Other Informationn"

$USBDevices = Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Enum\USB*\*\* | Select FriendlyName, Driver, mfg, DeviceDesc | ConvertTo-Html -fragment  
$UPNPDevices = Get-PnpDevice -PresentOnly -class 'USB', 'DiskDrive', 'Mouse', 'Keyboard', 'Net', 'Image', 'Media', 'Monitor' | ConvertTo-Html -Fragment
$FilesCreate = Get-CimInstance Win32_ShortcutFile | Select Filename, Caption, @{NAME='CreationDate';Expression={$_.ConvertToDateTime($_.CreationDate)}}, @{Name='LastAccessed';Expression={$_.ConvertToDateTime($_.LastAccessed)}}, @{Name='LastModified';Expression={$_.ConvertToDateTime($_.LastModified)}}, Target | Where-Object {$_.LastModified -gt ((Get-Date).AddDays(-180)) } | sort LastModified -Descending | ConvertTo-Html -Fragment 
$ExecDownloads = Get-ChildItem C:\Users\*\Downloads\* -recurse  |  Select  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | where {$_.extension -eq '.exe'} | ConvertTo-Html -Fragment
$ExecAppdata = Get-ChildItem C:\Users\*\AppData\Local\Temp\* -recurse  |  Select  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | where {$_.extension -eq '.exe'} | ConvertTo-Html -Fragment
$ExecTemp = Get-ChildItem C:\Windows\Temp\* -Recurse | Where-Object { $_.Extension -eq '.exe' } | Select-Object PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | ConvertTo-Html -Fragment
$ExecPerfLogs = Get-ChildItem C:\PerfLogs\* -recurse  |  Select  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | where {$_.extension -eq '.exe'} | ConvertTo-Html -Fragment
$ExecDocument = Get-ChildItem C:\Users\*\Documents\* -recurse  |  Select  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | where {$_.extension -eq '.exe'} | ConvertTo-Html -Fragment

Write-Host -Fore Green "[!] Done."

#----- Output Part-----#

#Create system.html file

Write-Host -Fore Yellow "[*] Create .html Files Output."

$head = '<head><meta charset="UTF-8"></head><style>
BODY{font-family: Courier New, Courier, monospace;}
TABLE{border-width: 1px;border-style: solid;border-color: white;border-collapse: collapse;}
TH{font-size:1.1em;color: white; border-width: 1px;padding: 2px;border-style: solid;border-color: white}
TD{border-width:1px;padding: 2px;border-style: solid;border-color: white;background-color: #212121}
details > summary {
  padding: 4px;
  width: 200px;
  background-color: #212121;
  border: none;
  box-shadow: 1px 1px 2px #394032;
  cursor: pointer;
}
</style>'


'<details>' >> $SystemHtml
$head >> $SystemHtml

echo "<summary><b>Computer Information</b></summary>" >> $SystemHtml

'<details>' >> $SystemHtml
echo "<summary>System Information</summary>" >> $SystemHtml
if($SystemInfo) {
  echo "<table>$SystemInfo</table>" >> $SystemHtml
}'</details>'>> $SystemHtml
'<br><br>' >> $SystemHtml

'<details>' >> $SystemHtml
echo "<summary>Operating System Information</summary>" >> $SystemHtml
if($OSInfo) {
  echo "<table>$OSInfo</table>" >> $SystemHtml
}'</details>'>> $SystemHtml
'<br><br>' >> $SystemHtml

'<details>' >> $SystemHtml
echo "<summary>Hotfixes</summary>" >> $SystemHtml
if($Hotfixes) {
  echo "<table>$Hotfixes</table>" >> $SystemHtml
}'</details>'>> $SystemHtml
'<br><br>' >> $SystemHtml

'<details>' >> $SystemHtml
echo "<summary>Windows Defender Status</summary>" >> $SystemHtml
if($WinDefender) {
  echo "<table>$WinDefender</table>" >> $SystemHtml
}'</details>'>> $SystemHtml
'<br><br>' >> $SystemHtml

'<details>' >> $SystemHtml
echo "<summary>Installed Programs</summary>" >> $SystemHtml
if($InstallProgs) {
  echo "<table>$InstallProgs</table>" >> $SystemHtml
}'</details>'>> $SystemHtml
'<br><br>' >> $SystemHtml

'<details>' >> $SystemHtml
echo "<summary>Installed Programs - from Registry</summary>" >> $SystemHtml
if($InstalledApps) {
  echo "<table>$InstalledApps</table>" >> $SystemHtml
}'</details>'>> $SystemHtml
'<br><br>' >> $SystemHtml

'<details>' >> $SystemHtml
echo "<summary>Environment Variables</summary>" >> $SystemHtml
if($EnvSetting) {
  echo "<table>$EnvSetting</table>" >> $SystemHtml
}'</details>'>> $SystemHtml
'<br><br>' >> $SystemHtml

'</details>'>> $SystemHtml
'<br><br>' >> $SystemHtml

#Create processes.html file

'<details>' >> $ProcessesHtml
$head >> $ProcessesHtml

echo "<summary><b>Processes</b></summary>" >> $ProcessesHtml

'<details>' >> $ProcessesHtml
echo "<summary>Processes</summary>" >> $ProcessesHtml
if($Processes) {
  echo "<table>$Processes</table>" >> $ProcessesHtml
}'</details>'>> $ProcessesHtml
'<br><br>' >> $ProcessesHtml

'<details>' >> $ProcessesHtml
echo "<summary>Startup</summary>" >> $ProcessesHtml
if($StartupProg) {
  echo "<table>$StartupProg</table>" >> $ProcessesHtml
}'</details>'>> $ProcessesHtml
'<br><br>' >> $ProcessesHtml

'<details>' >> $ProcessesHtml
echo "<summary>Schedule Tasks</summary>" >> $ProcessesHtml
if($ScheduledTask) {
  echo "<table>$ScheduledTask</table>" >> $ProcessesHtml
}'</details>'>> $ProcessesHtml
'<br><br>' >> $ProcessesHtml

'<details>' >> $ProcessesHtml
echo "<summary>Schedule Tasks State</summary>" >> $ProcessesHtml
if($ScheduledState) {
  echo "<table>$ScheduledState</table>" >> $ProcessesHtml
}'</details>'>> $ProcessesHtml
'<br><br>' >> $ProcessesHtml

'<details>' >> $ProcessesHtml
echo "<summary>Service</summary>" >> $ProcessesHtml
if($Services) {
  echo "<table>$Services</table>" >> $ProcessesHtml
}'</details>'>> $ProcessesHtml
'<br><br>' >> $ProcessesHtml

'</details>'>> $ProcessesHtml
'<br><br>' >> $ProcessesHtml

#Create network.html file

'<details>' >> $NetworkHtml

$head >> $NetworkHtml

echo "<summary><b>Network Infomation</b></summary>" >> $NetworkHtml

'<details>' >> $NetworkHtml
echo "<summary>Network Adapter Information</summary>" >> $NetworkHtml
if($NetworkAdapter) {
  echo "<table>$NetworkAdapter</table>" >> $NetworkHtml
}'</details>'>> $NetworkHtml
'<br><br>' >> $NetworkHtml

'<details>' >> $NetworkHtml
echo "<summary>Current IP Configutation</summary>" >> $NetworkHtml
if($IPConfiguration) {
  echo "<table>$IPConfiguration</table>" >> $NetworkHtml
}'</details>'>> $NetworkHtml
'<br><br>' >> $NetworkHtml

'<details>' >> $NetworkHtml
echo "<summary>Network Adapter IP Address</summary>" >> $NetworkHtml
if($NetIPAddress) {
  echo "<table>$NetIPAddress</table>" >> $NetworkHtml
}'</details>'>> $NetworkHtml
'<br><br>' >> $NetworkHtml

'<details>' >> $NetworkHtml
echo "<summary>Current Connection Profiles</summary>" >> $NetworkHtml
if($NetConnectProfile) {
  echo "<table>$NetConnectProfile</table>" >> $NetworkHtml
}'</details>'>> $NetworkHtml
'<br><br>' >> $NetworkHtml

'<details>' >> $NetworkHtml
echo "<summary>Current TCP Connections and Associated Processes</summary>" >> $NetworkHtml
if($NetTCPConnect) {
  echo "<table>$NetTCPConnect</table>" >> $NetworkHtml
}'</details>'>> $NetworkHtml
'<br><br>' >> $NetworkHtml

'</details>'>> $NetworkHtml
'<br><br>' >> $NetworkHtml

# Create other.html file

'<details>' >> $OtherHtml

$head >> $OtherHtml
echo "<summary><b>Other Infomation</b></summary>" >> $OtherHtml

'<details>' >> $OtherHtml
echo "<summary>USB Devices</summary>" >> $OtherHtml
if($USBDevices) {
  echo "<table>$USBDevices</table>" >> $OtherHtml
}'</details>'>> $OtherHtml
'<br><br>' >> $OtherHtml

'<details>' >> $OtherHtml
echo "<summary>UPNP Devices</summary>" >> $OtherHtml
if($UPNPDevices) {
  echo "<table>$UPNPDevices</table>" >> $OtherHtml
}'</details>'>> $OtherHtml
'<br><br>' >> $OtherHtml

'<details>' >> $OtherHtml
echo "<summary>All Files is Create in Last 180 days</summary>" >> $OtherHtml
if($FilesCreate) {
  echo "<table>$FilesCreate</table>" >> $OtherHtml
}'</details>'>> $OtherHtml
'<br><br>' >> $OtherHtml

'<details>' >> $OtherHtml
echo "<summary>Executables in Download</summary>" >> $OtherHtml
if($ExecDownloads) {
  echo "<table>$ExecDownloads</table>" >> $OtherHtml
}'</details>'>> $OtherHtml
'<br><br>' >> $OtherHtml

'<details>' >> $OtherHtml
echo "<summary>Executables in Appdata</summary>" >> $OtherHtml
if($ExecAppdata) {
  echo "<table>$ExecAppdata</table>" >> $OtherHtml
}'</details>'>> $OtherHtml
'<br><br>' >> $OtherHtml

'<details>' >> $OtherHtml
echo "<summary>Executables in Temp</summary>" >> $OtherHtml
if($ExecTemp) {
  echo "<table>$ExecTemp</table>" >> $OtherHtml
}'</details>'>> $OtherHtml
'<br><br>' >> $OtherHtml

'<details>' >> $OtherHtml
echo "<summary>Executables in Perflogs</summary>" >> $OtherHtml
if($ExecPerfLogs) {
  echo "<table>$ExecPerfLogs</table>" >> $OtherHtml
}'</details>'>> $OtherHtml
'<br><br>' >> $OtherHtml

'<details>' >> $OtherHtml
echo "<summary>Executables In Documents Folder</summary>" >> $OtherHtml
if($ExecDocument) {
  echo "<table>$ExecDocument</table>" >> $OtherHtml
}'</details>'>> $OtherHtml
'<br><br>' >> $OtherHtml

'</details>'>> $OtherHtml
'<br><br>' >> $OtherHtml

Write-Host -Fore Green "[!] Done."

Set-Location -Path $originPath

$computerName   = $env:COMPUTERNAME
$osArchitecture = (Get-CimInstance -ClassName Win32_OperatingSystem).OSArchitecture
$volatilityPath = ".\tools\volatility3\vol.py"

$winpmem64 = ".\tools\winpmem_mini_x64_rc2.exe"
if(Test-Path $winpmem64 -PathType Leaf){
  Write-Host -Fore Green "[!] winpmem_mini_x64_rc.exe exist."
} else {
  Write-Host -Fore Red "[!] winpmem_mini_x64_rc.exe is not exist."
}

$winpmem86 = ".\tools\winpmem_mini_x86.exe"
if(Test-Path $winpmem86 -PathType Leaf){
  Write-Host -Fore Green "[!] winpmem_mini_x86.exe exist."
} else {
  Write-Host -Fore Red "[!] winpmem_mini_x86.exe is not exist."
}

$vol3 = $volatilityPath
if(Test-Path $vol3 -PathType Leaf){
  Write-Host -Fore Green "[!] Volatility 3 exist."
} else {
  Write-Host -Fore Red "[!] Volatility 3 is not exist."
}

Write-Host -Fore Yellow "[*] Memory Capturing in Process..."
function dump {
  if ($osArchitecture -eq "64-bit"){
    Start-Process -FilePath ".\tools\winpmem_mini_x64_rc2.exe" -ArgumentList "$computerName.raw" -Wait
  }
  else{
    Start-Process -FilePath ".\tools\winpmem_mini_x86.exe" -ArgumentList "$computerName.raw" -Wait
  }
  Write-Host -Fore Green "[!]Done." 
  do {
    $PIDinput = Read-Host "Enter Process ID (or type 'exit' to quit)"

    if ($PIDinput -eq 'exit') {
        Write-Host -Fore Yellow "[!] Exiting..."
        break
    }
    Write-Host -Fore Yellow "[!] Process ID : $PIDinput Dump Files on Process..."
    $volatilityPIDDumpFiles = "python $volatilityPath -f $computerName.raw -q windows.dumpfiles.DumpFiles --pid $PIDinput"
    Invoke-Expression $volatilityPIDDumpFiles
    $volatilityPIDDllList = "python $volatilityPath -f $computerName.raw -q windows.dlllist.DllList --pid $PIDinput --dump"
    Invoke-Expression $volatilityPIDDllList
    Write-Host -Fore Green "[!] Dump Files in $PIDinput is Complete"
  }while ($true)
}

dump