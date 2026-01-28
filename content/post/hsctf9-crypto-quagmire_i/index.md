---
title: "HSCTF 9 - Quagmire-I"
date: 2022-06-13
draft: false
author: tux
description: >-
    Crypto challenge
categories:
  - Writeups
  - Crypto
tags:
  - HSCTF
  - Crypto
---

*Easy crypto that can be solved manually.*

<!--more-->

### Description
>Bob was on his way to school and go to Mr. Connolly’s first period AP CSA class, but it was a rainy day and he got stuck in the quagmire in his town, making him late to school (specifically the first closest to his home, there are apparently four quagmires in his town)! Could you figure out what Mr. Connolly told Bob’s class? His classmate Alice sent this text message after class (written in Quagmire I):
>
>Plaintext keyword: CONNOLLYROCKS
>
>Indicator keyword: HSCTF
>
>Indicator position: A
>
>Ciphertext: LZXORNZBUYWNRARNOVGCLSQWJEFJFE
>
>(Please wrap the flag in the flag format “flag{}”, and use only uppercase letters within the braces.)

### Solution

I had never done a Quagmire crypto before, but after a duckduckgo search I found [this link](https://sites.google.com/site/cryptocrackprogram/user-guide/cipher-types/substitution/quagmire) which does a good job in explaining how Quagmire cryptos work.
And since this is a Quagmire I, the simplest kind, I opted to just solve it manually.

What you do is to take the plaintext keyword, remove any duplicate characters and then append the rest of the characters of the alphabet (excluding, of course the ones already in the keyword).
Next, you make one line for each letter in the indicator keyword and line up the offset so that the letters of the indicator keyword so that is below the indicator position.
Lastly, divide the ciphertext into groups of the same length as the indicator keyword.

Now you are ready to decipher. The firs letter of each group of the cipher corresponds to the first line, the second letter to the second line, and so forth.
Just find the letter in the line and the original letter is the one straight above it in the top line (the one that starts with the plaintext keyword).

Below you can see the the solution and the deciphered flag.

```
             *
    CONLYRKS A BDEFGHIJMPQTUVWXZ
1 H ZABCDEFG H IJKLMNOPQRSTUVWXY
2 S KLMNOPQR S TUVWXYZABCDEFGHIJ
3 C UVWXYZAB C DEFGHIJKLMNOPQRST
4 T LMNOPQRS T UVWXYZABCDEFGHIJK
5 F XYZABCDE F GHIJKLMNOPQRSTUVW

12345 12345 12345 12345 12345 12345
LZXOR NZBUY WNRAR NOVGC LSQWJ EFJFE
FILLT HISBO WLWIT HYOUR FAVEF RUITS

flag{FILLTHISBOWLWITHYOURFAVEFRUITS}
```
