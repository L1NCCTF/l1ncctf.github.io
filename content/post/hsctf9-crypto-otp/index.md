---
title: "HSCTF 9 - OTP"
date: 2022-06-14
author: tux
draft: false
description: >-
    Crypto challenge
categories:
  - Writeups
  - Crypto
tags:
  - HSCTF
  - Crypto
---

*Poorly generated random number that allows for a small range to check*

<!--more-->

### Description
> "the one-time pad (OTP) is an encryption technique that cannot be cracked" - Wikipedia

### Solution
Looking at the source code we see a couple of interesting things.

```python
import random
from Crypto.Util.number import bytes_to_long

def secure_seed():
	x = 0
	# x is a random integer between 0 and 100000000000
	for i in range(10000000000):
		x += random.randint(0, random.randint(0, 10))
	return x

flag = open('flag.txt','rb').read()
flag = bytes_to_long(flag)

random.seed(secure_seed())

l = len(bin(flag)) - 1
print(l)

k = random.getrandbits(l)
flag = flag ^ k # super secure encryption
print(flag)
```
The code encrypts the flag by generating random bits and does a bitwise XOR, the prints out the length of the flag in binary and the encrypted flag.
We also get this as output.txt
```
328
444466166004822947723119817789495250410386698442581656332222628158680136313528100177866881816893557
```

The "randomly" generated bits is gotten by using the [random.seed()](https://www.geeksforgeeks.org/random-seed-in-python/) method.
By default, this method uses the system time to set the starting number, but if you specify the seed value you actually get the same random number sequence.
So what we need to do is to find this seed number, generate the same random bits and XOR the cipher to get the original flag.

In this challenge the seed value is generated with the secure_seed() method.
Fortunately for us, this method is quite predictable. It loops ten billion times, generating a random integer each time and adding them together.
The more you do this, the closer to the average you get, and so the seed number will basically be close to 10000000000 * 2.5.

All we have to do is a for loop to test possible seed numbers and to be on the safe side start just just below 25000000000 and iterate up.
For each number we use it to start a new seed, generate 328 (the length we got from the output) random bits to XOR with the cipther, and if the result contains "flag" we break out of the loop.
I added a timer to show how long the script takes to find the flag, as well as printing out the seed number used to get the random bits.

```python
import random
from Crypto.Util.number import bytes_to_long, long_to_bytes
import time

# Start timer
t0 = time.time()

l = 328
f = 444466166004822947723119817789495250410386698442581656332222628158680136313528100177866881816893557

for i in range(24999900000,25500000000):
    random.seed(i)
    k = random.getrandbits(328)
    g = f^k
    try:
        res = long_to_bytes(g).decode("utf8")
        if "flag" in res:
            print(res)
            print("seed value:", i)
            print("time:",time.time()-t0)
            break
    except: pass
```

Which generated the output

```
flag{c3ntr4l_l1m1t_th30r3m_15431008597}

seed number: 25000212790
time: 3.0835678577423096
```

