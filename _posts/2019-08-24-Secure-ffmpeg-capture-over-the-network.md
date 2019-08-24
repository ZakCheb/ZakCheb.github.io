---
layout: post
categories: jekyll update
title:  "Screen video capture with ffmpeg and secure transfer over the network"
---

Unix creators set up a design philosophy based around simplicity : specific pieces of software should be built to do **one thing** and do that one thing **well**.
I wanted to toy around ffmpeg and netcat on my free time, and came up with a train pipe that stream the output of the screen, compress it, and encrypt it with Rijndael cypher, its like AES but with 256bit block instead (Yes I'm extremely paranoid), and finally send it over the network with netcat.
Each block will be explained separately then reassembled at the end.

1- The screen capture is performed with **fmpeg** and stream read with **ffplay**. 
{% highlight bash %}
ffmpeg -video_size 1366x768 -framerate 60 -f x11grab -i :0 -f avi - | ffplay -
{% endhighlight %}
NB: The "**-**" symbol replace a file in general, and instead of I/O on a file, it does it on pipe.

2- Compression is done with the classic gzip.
{% highlight bash %}
echo "Compression and decompression with gzip" | gzip | gzip -d  
{% endhighlight %}

3- ccrypt is doing the encryption here.
{% highlight bash %}
echo "Attack at dawn." | ccrypt -efK ZakChebIsTheKey | ccrypt -dfK ZakChebIsTheKey
{% endhighlight %}

<iframe src="https://explainshell.com/explain?cmd=echo+%22Attack+at+dawn.%22+%7C+ccrypt+-efK+ZakChebIsTheKey+%7C+ccrypt+-dfK+ZakChebIsTheKey" width="110%" height="300px"  ></iframe>

NB: Of course, never use plain text keys on prod, just for demonstration purposes.

4- netcat finally which just opens a socket connection.
{% highlight bash %}
echo "Knock Knock" | sudo nc -lvvp 8000 

nc localhost 8000
{% endhighlight %}
Thats how you capture video with ffmpeg and secure transfer over the network with just unix commands.
#### Server
{% highlight bash %}
sudo ffmpeg -video_size 1366x768 -framerate 60 -f x11grab -i :0 -f avi - \
| gzip | ccrypt -vefK ZakCheb | nc -lvvp 8000
{% endhighlight %}

#### Client
{% highlight bash %}
nc localhost 8000 | ccrypt -vdfK ZakCheb | gzip -d | ffplay -i - 
{% endhighlight %}

