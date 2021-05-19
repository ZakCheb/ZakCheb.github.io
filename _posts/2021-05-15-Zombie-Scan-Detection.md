---
layout: post
title: "Detecting and enhancing Zombie scan"
date: 2021-05-15
categories: jekyll update
---

# Introduction
This is a small post about how to detect zombie scan attack, aka idle-scan.
You can quickly hop-in and download the PCAP of the example explained <a href="/asset/files/idle-scan.pcap">HERE</a>, its recommended to follow along and enjoy it don't be lazy ;) 

Try to check it for a few moments see what you can deduce.


# Notes of what is happening

1- a6 claiming 103

2- 71 claiming 102

3- b4 claiming 101

4- 103 `SYN ACK` Scan 101?

5- 101 Spoofed by 103? 

6- Another `SYN ACK` Scan?

## Theories
Firewall bypassing attempt 103 claimed to be 102, because there is an ACL that deny 103 but allow 102?


# Zombie Scan
![410c7d0e10bc89ed03c111dc69a575b5.png](/asset/images/Zombie/07fc97364ad74d989b6ca14b755f6ede.png)
- Zombie =>  101
- Target  =>  102
- Attacker => 103

To filter the important indicator in wireshark, add `ip.id` as a filter in a column.

![f8fbbf7e1559087c4411d5e80d537cdc.png](/asset/images/Zombie/39f61b163d484e80a2499705b7bc0554.png)
## Step 1
![807a2317926b32921924387a707edde8.png](/asset/images/Zombie/1cb79cd950324ceaadcc9546c72f7937.png)

To be able to enumerate open ports using Zombie Scan technique, you need to have a network interaction with a machine that has very low network traffic with other equipment, thus the ID field in the IP header will be predictable enough.
Each time a host send a `RST` to another host, the sender increase his ID field.
The attacker will spam the Zombie host with multiple `SYN ACK` packets and checks that its behaving with good prediction, in this case, its incremented from 120 to 130.
And more importantly, the attacker records the last ID value.


![f548d151cabaf587e9e37e5f82e5eaa5.png](/asset/images/Zombie/029187f35f634dee85b930fc07374093.png)

## Step 2 

![7e0594c284a2bf5fbd7c974964bedcc3.png](/asset/images/Zombie/9e15cd98552c43419b920614ec498ec1.png)

![052fc6580a64d69cec1df149df81398b.png](/asset/images/Zombie/fb71fa59f20a4eb297089ea58ac08015.png)

The attacker spoof the zombie host and send it to the target, aiming that the port that he want to enumerate (80 in this case) with a `SYN` packet.

![9f3ebca2f36ff6f78892d9531a410f24.png](/asset/images/Zombie/c4f7025357cc4557824bc59ddb03b460.png)

![2689802a05fea21545cdfa75d77e4b77.png](/asset/images/Zombie/79d1b1e9daf4427784cbe6cf8164363d.png)


The target then respond back to the zombie:

- if the port was open, its a `SYN ACK`, and the zombie is not expecting this communication, so he sends a `RST` back to the Target and increase his IP ID field  by one (130+1).

- if the port was closed, its a `RST`, the zombie's IP ID field stays the same (130), recall : the host that sends the `RST` gets his ID field increased, receiving it will not change anything.

The attacker is not able to capture the response from the Target to the Zombie, and cannot deduce if the port was open yet.

## Step 3
![f2ac34f72883310f50958cd75dd75ddc.png](/asset/images/Zombie/541a441d476b4ca39f13e95e9745f466.png)

Finally, the attacker will interrogate the zombie by sending another `SYN ACK`, the zombie will respond with `RST`, increases by 1 his IP ID field again.

- If the Zombie IP ID field is (130+1+1), the Attacker deduce that the port 80 is open on the Target to the Zombie (NO ACL Restriction).

- If the Zombie IP ID field is (130+1), the Attacker deduce that the port 80 is closed on the Target to the Zombie.

In our case its ID=131, the port was closed.

![85b394db1345207391b2dd7b7bdfae2c.png](/asset/images/Zombie/7c6529ff2623408f9b6346baedcba0b7.png)


# Enhancement attempt
The choice of the zombie for the attacker are old machines may be a printer during lunch time, or any unpatched host, since the latest OS are making the IPID unpredictable.
The attacker probably ran the following nmap command:

```bash
nmap -Pn -p 80 -sI 192.168.100.101 192.168.100.102
```


If we continue about our scenario about the printer, we can may be increase the stealthiness of the scan by asking nmap to use randomly manually selected high dst port (63021) and  9100 as a source port when asking the zombie to throw off analysts thinking that "its just a printer trying communicate with another printer".

```bash
nmap -Pn -p 80 -g 9099 -sI 192.168.100.101:63021 192.168.100.102
```

>  ManPage TLDR : Scan 102 on port 80, using a zombie where you communicate with him like this  9099 --> 63021 

![tweak](/asset/images/Zombie/tweak.png)

This technique is an amazing way to enumerate network trust between old running machines and a target, often ACLs are applied to them are long forgotten and may allowed more than needed.

This is the result of a good teacher who taught us a lot, and this exercise was one of his.

