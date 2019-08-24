---
layout: post
categories: jekyll update
title:  "Automating CLI interactions with expect"
---


I decided today to automate my interaction with my home router, a DSL-2750U, I usually use the web interface, but found out that a telnet management session is possible, of course, only accessible from the LAN, after some google search, I discovered this great program named [*expect*](https://linux.die.net/man/1/expect), that automate interaction with any other CLI based programs.


{% highlight bash %}
#!/usr/bin/expect
spawn telnet Router 
# Show hosts of DSL-2750U home router.
expect "Login: " { send "USERNAME\r" }
expect "Password: " { send "PASSWORD\r" }
expect "> " { send "lanhosts show all\r" }
expect "> " { send "exit\r" }
interact
{% endhighlight %}


This simple script "expect" a value from the router, then push information, in our case the credentials and the command to execute.
Now, I can simply parse the hosts with grep, and have a better overview of my network.
