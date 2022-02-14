#Windows Privilege Escalation Enum Commands:

+---------------------+
|About OperatingSystem|
+---------------------+
	
#	Information of OS and architecture and is it patched?
```
		systeminfo

		wmic qfe
```

#	what the interesting in environments variables?
```	
		set

		Get-ChildItem Env: | ft Key,Value

```
#	other devices has connected in drive?
```
		net use
		
		wmic logicaldisk get caption,description,providername

		Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
+----+
|User|
+----+

#	about of you
```
		whoami

		echo %USERNAME%
	
		$env:UserName
```
#	interesting UserAccount
```
		whoami /priv
```
#	is system user in? and old user profile is remainning?
```
		net users
	
		dir /b /ad "C:\Users\"

		dir /b /ad "C:\Documents and Settings\" # Windows XP and below

		Get-LocalUser | ft Name,Enabled,LastLogon

		Get-ChildItem C:\Users-Force | select Name
```
#	other user is login?
```
		qwinsta
```
#	which group in system?
```
		net localgroup

		Get-LocalGroup | ft Name
```
#	Find the Administrators group user
```
		net localgroup Administrators

		Get-LocalGroupMember Administrators | ft Name, PrincipalSource 
```
#	Search to Suspiciousy something in Auto Logon registory 
```
		reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | fidstr "DefaultUserName DefaultDomainName DefaultPassword"	
		
		Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' | select "Default*"
```
#	Search to Suspiciousy Somethings in Credential Manager
```
		cmdkey /list

		dir C:\Users\username\AppData\Local\Microsoft\Credentials\

		dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\				

		Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
	
		Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
#	Can Access to SAM file and System File??
```		
		%SYSTEMROOT%\repair\SAM

		%SYSTEMROOT%\System32\config\RegBack\SAM

		%SYSTEMROOT%\System32\config\SAM
		
		%SYSTEMROOT%\repair\system

		%SYSTEMROOT%\System32\config\SYSTEM

		%SYSTEMROOT%\System32\config\RegBack\system

```
+-------------------------+
|Program, Process, Service|
+-------------------------+
	
#	which software installed?
```
		dir /a "C:\Program Files"

		dir /a "C:\Program Files (x86)"

		reg query HKEY_LOCAL_MACHINE\SOFTWARE

		Get-childItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime

		Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
#	week folder or file access allowed file
```
		icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone"

		icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone"

		icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users"

		icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" 

		icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "Everyone"

		icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "Everyone"

		icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 

		icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 

		Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}} 

		Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}} 

	Upload the accesschk.exe via Sysintenals and execute it

		accesschk.exe -qwsu "Everyone" *

		accesschk.exe -qwsu "Authenticated Users" *

		accesschk.exe -qwsu "Users" *	

		tasklist /svc
	
		tasklist /v
		
		net start
		
		sc query

		Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id

		Get-Service

		Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

		accesschk.exe -uwcqv "Everyone" *

		accesschk.exe -uwcqv "Authenticated Users" *

		accesschk.exe -uwcqv "Users" *

		wmic service get name,displayname,pathname,startmode 2>nul |findstr /i "Auto" 2>nul |findstr /i /v "C:\Windows\\" 2>nul |findstr /i /v """	

		gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name

		schtasks /query /fo LIST 2>nul | findstr TaskName

		dir C:\windows\tasks

		Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

		wmic startup get caption,command

		reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run

		reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce

		reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run

		reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce

		dir "C:\Documents and Settings\All Users\Start Menu\Programs\Startup"

		dir "C:\Documents and Settings\%username%\Start Menu\Programs\Startup"		

		Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl

		Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'

		Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'

		Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'

		Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'

		Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"

		Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"

		reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

		ipconfig /all

		Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address

		Get-DnsClientServerAddress -AddressFamily IPv4 | ft

		route print

		Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex

		arp -a

		Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State

		netstat -ano

		C:\WINDOWS\System32\drivers\etc\hosts

		netsh firewall show state

		netsh firewall show config

		netsh advfirewall firewall show rule name=all

		netsh advfirewall export "firewall.txt"
				
		netsh dump
				
		reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s

		Get-ChildItem -path HKLM:\SYSTEM\CurrentControlSet\Services\SNMP -Recurse

		reg query HKCU /f password /t REG_SZ /s

		reg query HKLM /f password /t REG_SZ /s

		dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
		
		Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}

		dir /a C:\inetpub\

		dir /s web.config

		C:\Windows\System32\inetsrv\config\applicationHost.config

		Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue

		C:\inetpub\logs\LogFiles\W3SVC1\u_ex[YYMMDD].log

		C:\inetpub\logs\LogFiles\W3SVC2\u_ex[YYMMDD].log

		C:\inetpub\logs\LogFiles\FTPSVC1\u_ex[YYMMDD].log

		C:\inetpub\logs\LogFiles\FTPSVC2\u_ex[YYMMDD].log

		dir /s php.ini httpd.conf httpd-xampp.conf my.ini my.cnf

		Get-Childitem –Path C:\ -Include php.ini,httpd.conf,httpd-xampp.conf,my.ini,my.cnf -File -Recurse -ErrorAction SilentlyContinue
		
		dir /s access.log error.log

		Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue

		dir /s *pass* == *vnc* == *.config* 2>nul

		Get-Childitem –Path C:\Users\ -Include *password*,*vnc*,*.config -File -Recurse -ErrorAction SilentlyContinue

		findstr /si password *.xml *.ini *.txt *.config 2>nul

		Get-ChildItem C:\* -include *.xml,*.ini,*.txt,*.config -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password"
```		

		
		
				
