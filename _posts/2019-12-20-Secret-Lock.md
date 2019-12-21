---
layout: post
title: "[24/7CTF] The Secret Lock"
dat: 2019-07-20
categories: jekyll update
---

## Introduction
I will be sharing with you how to solved the The Secret Lock from [247CTF](https://247ctf.com).
Was a good analytical exercise and problem solving in general, learned a lot on the way.

## The Challenge
After unzipping the archive, we get a vanilla html page with some interesting javascript code.
![The Secret Lock](/asset/images/SecretLock/Web.png)


```javascript
class Lock {


  onChange() {
    this.code = this.getCode();
	this.flag = this.checkFlag(this.code);
  }

  getCode() {
	let flag = {};
    for (let i = 0, len = this.dom.rows.length; i < len; i++) {
	  flag[i] = this.dom.rows[i].querySelector('.is-selected .text').textContent;
    }
    return flag;
  }

  checkFlag(flag){
    let result = "LOCKED"
	this.dom.lock.classList.remove('verified');
    if (Object.keys(flag).length == 40 &&
 ((flag[37] - flag[37]) * flag[15] == 0) &&
 ((flag[3] + flag[31]) ^ (flag[29] + flag[8]) == 234) &&
 ((flag[32] - flag[12]) * flag[9] == -2332) &&
 ((flag[24] - flag[27] + flag[13]) ^ flag[6] == 114) &&
 ((flag[38] - flag[15]) * flag[33] == 800) &&
 ((flag[34] - flag[21]) * flag[26] == 98) &&
 ((flag[29] + flag[0]) ^ (flag[8] + flag[38]) == 248) &&
 ((flag[21] * flag[18]) ^ (flag[7] - flag[15]) == 2694) &&
 ((flag[28] * flag[23]) ^ (flag[19] - flag[5]) == -9813) &&
 ((flag[34] + flag[30]) ^ (flag[37] + flag[6]) == 72) &&
 ((flag[23] - flag[22]) * flag[12] == 4950) &&
 ((flag[9] * flag[28]) ^ (flag[20] - flag[11]) == 5143) &&
 ((flag[2] * flag[22]) ^ (flag[37] - flag[0]) == 2759) &&
 ((flag[26] - flag[12]) * flag[3] == -3350) &&
 ((flag[17] + flag[31]) ^ (flag[6] + flag[9]) == 36) &&

 ........................................
 ........................................
 ........................................

 ((flag[4] + flag[27]) ^ (flag[2] + flag[31]) == 208) &&
 ((flag[6] + flag[7]) ^ (flag[26] + flag[21]) == 206) &&
 ((flag[19] + flag[25]) ^ (flag[22] + flag[10]) == 10) &&
 ((flag[34] + flag[2]) ^ (flag[8] + flag[26]) == 2) &&
 ((flag[7] + flag[5]) ^ (flag[12] + flag[14]) == 237) &&
 ((flag[1] - flag[13]) * flag[38] == -112) &&
 ((flag[0] - flag[19] + flag[16]) ^ flag[0] == 80) &&
 ((flag[31] + flag[36]) ^ (flag[3] + flag[2]) == 227) &&
 ((flag[32] - flag[3] + flag[26]) ^ flag[4] == 113) &&
 ((flag[3] * flag[6]) ^ (flag[16] - flag[27]) == -8241) &&
 ((flag[24] + flag[15]) ^ (flag[2] + flag[30]) == 242) &&
 ((flag[11] + flag[21]) ^ (flag[31] + flag[20]) == 12) &&
 ((flag[9] - flag[26] + flag[23]) ^ flag[30] == 13)) {
	  result = "";
      for (var idx in flag) {
	    result += (String.fromCharCode(flag[idx]));
	  }
	  this.dom.lock.classList.add('verified');
    }
    return result;
  }
  
}

let lock = new Lock();
```


So the js code is creating a Lock object, that object parse the input on any combination change with :


```js
flag[i] = this.dom.rows[i].querySelector('.is-selected .text').textContent;
```

Then it's stored on flag array which will take the 40 lock combinations and test it on a big series of if test cases.
If the tests are valid, it prints the flag and it opens the lock.

So the goal is to find the right 40 combination of the numbers, which is in the same time the string that represent the flag.

```js
result += (String.fromCharCode(flag[idx]));
```

## Attempts

Initially, thinking brute-forcing the 40 digits might work with nesting multiple for loops, quickly realised that would take too much time and it's not an elegant solution.


Then I recalled that flag format to submit to the website is : "247CTF{[0-9a-f]+}"
With that knowledge, we could deduce the first 7 digits and the last one, maybe even deduce more if we replace them on the if test cases.
So I went for replacing manually each one until I reached the 5~6 last unknnown characters where the brute-force idea would be manageable, annnd it did not work. Probably made a mistake/typo when replacing, tideous and boring, not taking the same path.

After some research, I found a way better solution, let's think about problem here, we have 40 unknowns, each linked to one another with some contraints.

How are we supposed to get them? Using SAT solvers of course! Z3 is the likely condidate for the task.

Thanks to [LiveOverFlow video](https://www.youtube.com/watch?v=nI8Q1bqT8QU) that came back to me like a flash back, it's about a google CTF challenge where he had to parse a series of constrains from a minecraft clone world, then he used Z3 to solve it,  I highly recommend you to watch it's both entertaining and educational, since it was a true inspiration to solve this challenge.

### The Z3 SAT Solver
> Z3 is a theorem prover from Microsoft Research with support for bitvectors, booleans, arrays, floating point numbers, strings, and other data types.
In our case, we give Z3 our constraints and variables in a form of a model, Z3's solver will work on that model and outputs the correct combination to satisfy the constrains.

#### Example
To understand it's usage, we will take a look at a very basic example extracted from [stanford's paper on Z3](https://theory.stanford.edu/~nikolaj/programmingz3.html):

```python
from z3 import *
Tie = Bools('Tie')
Shirt = Bools('Shirt')
s = Solver()
s.add(

      Or(Tie, Shirt), 
      Or(Not(Tie), Shirt), 
      Or(Not(Tie), Not(Shirt))
)

print(s.check())
print(s.model())
```

The example code above represents two boolean variables, Tie and Shirt, and we are looking for the values that satisfy the following conditions:



[Tie OR Shirt]
[Not Tie OR Shirt]
[Not Tie OR Not Shirt]

```bash
root@Zakali:~/Secret_Lock# python3 Z3_Example.py 
sat
[Tie = False, Shirt = True]
```

The Solver then processed the input constraints, found a solution,  and outputed the right combination.

## Solution
So we will work on a python code that will take the constraints from javascript code, parse them and fit them on a Z3 solver.


Check this out:

<script id="asciicast-289565" src="https://asciinema.org/a/289565.js" async></script>


NOTE: I will not show the flag, it's the website's policy but they allowed writeups.

## Conclusion
We are barely scratching the surface of Z3 here, it's so powerful and effective, can't wait to do another challenge with it.
May share more writeups on [247CTF](https://247CTF.com), check it out its a great platform.


Managed to get 46th place amoung 1000+ players last november, that challenge was one of my favourites, it's nothing but proof of progress I guess!

![247CTF](/asset/images/SecretLock/247CTF_Rank.jpg)

Thanks for taking the time to read my work, constructive criticism are always welcome.
