# The Many Hats Club CTF
The CTF was active from 14 Dec 2019 00:00 until 15 Dec 2019 23:59.

![](writeupfiles/ctfscore.png)

## Overview

 Title          | Category      | Points        | Flag         |
| ------------- | ------------- | ------------- | ------------- |
| Shitter       | Web           | 300           |               |             
| Hackbot       | Web           | 400           |               |
| BoneChewerCon | Web           | 125           |
| Lotto-win     | Crypto        | 150           | TMHC{Lucki3r_th4n_Pelayo}         
| matrix_madness| Crypto        | 200           |               | 
| C4n_I_h4z_c0d3_n_crypt0 | Misc| 100           |               |
| DESk          | Misc          | 125           | TMHC{1_kn0w_d35cr1pt1v3_n0t4t10n}             
| Beeeep_Beeeep | Misc          | 175           | TMHC{0f5ee61ef3fbb4bb066df8c286ec84b07a7a5d95}
| flagthebox    | Misc          | 400           |               |
| the bain of chiv| Misc        | 200           |               |             
| miniPWN       | Pwn           | 200           |               | 
| overdosed     | Pwn           | 150           |               |
| w00ter        | Pwn           | 600           |               |             
| Operation     | Reversing     | 100           |               | 
| DeNuevo       | Reversing     | 125           |               |
| Quack         | Reversing     | 400           |               |             
| QuackQuack    | Reversing     | 600           |               | 
| WANTED        | Stego         | 425           | TMHC{Th1sIsY0u1sntIt} 
| HelpSomeoneIsTryingToBeMe| OSINT        | 225 |TMHC{Y0u_F0uNd_My_S3cR3t_1ts_StU}|
| quoted        | Mobile        | 400           |               | 



## Lotto-win

Connect to the docker with netcat to start the lottery.

    nc -v docker.hackthebox.eu 31182


We are given the source code, and upon inspection we make the following observations which turn to a hunch:

 1) The "next" function plays an important part since we only got that piece of code
 2) The "next" function takes a "seed" as input and produces a list of the "new seed" and the winning number
 3) A "seed" variable exists in the global scope, but is not in this code known to be updated since then

Hunch:
What if the seed can be found, by checking all possible seed inputs and looking for any of the winning numbers? It will take a little while to calculate, but it's only CPU power, so who cares.


We start a python3 process in the terminal and copy in the function:

    root@kali:~/htb/ctf/tmhc-dec-2019/crypto/lotto# python3
    Python 3.7.5 (default, Oct 27 2019, 15:43:29) 
    [GCC 9.2.1 20191022] on linux
    Type "help", "copyright", "credits" or "license" for more information.
    >>> def next(seed):
    ...     # Max winner number
    ...     MAX = 2000000000
    ...     # Min winner number
    ...     MIN = 1
    ...     # Change of the seed
    ...     seed = seed * seed + seed
    ...     # Truncation of the seed
    ...     if (seed > 0xFFFFFFFF):
    ...             seed = int(hex(seed)[-8:], 16)
    ...     # Return of [new seed, new winner number]
    ...     return [seed, seed % (MAX - MIN) + MIN]
    ... 
    >>> 


Then we write a small script that will check all possible inputs and tell us when it finds the winning numbers. Note the added "progress" part here as well, just to keep track of how far it has gone.

    >>> for i in range(0x1336, 0xFFFFFFFF):
    ...   if next(i)[1] == 1694266428:
    ...     print(f'Found it! Seed is: {i}')
    ...   if i % 10000000 == 0:
    ...     print(i)
    ... 
    10000000
    20000000
    30000000


This goes on for a while until it finds the seed that produces the example winning number "1694266428" from the code above:

    # ...
    1400000000
    1410000000
    Found it! Seed is: 1419577513


Nice! We can confirm that this works by calculating the next winning number based on the seed, and checking the winning number we calculate up againt that which the HTB service gave us. It works!

At this point all we have to do is calculate the winning numbers and seeds until we reach the winning number which has not yet been announced, and input this as our number to win!

    >>> next(1419577513)
    [3694266426, 1694266428]
    >>> next(3694266426)
    [3273504094, 1273504096]
    >>> next(3273504094)
    [2397553634, 397553636]
    >>> next(2397553634)
    [1587926886, 1587926887]


Bingo! We input "1587926887" as our winning number and get our prize :)

    Last Lottery numbers:
    410384963
    762245959
    1234130540
    310725200
    1491642900
    875389784
    1694266428
    1273504096
    397553636
    Wait 5 minutes to play the next round of lottery...
    Enter your lottery number: 1587926887
    WOW! YOU WON THE LOTTERY!! GET YOUR REWARD WITH THE CODE 'TMHC{Lucki3r_th4n_Pelayo}'!!!1!11!
    

## DESk
DESk was a fun challenge with a bit of Google searching and history involved.

![](writeupfiles/desk.png)
 
The challenge info gives us almost what seems like a hint

![](writeupfiles/chall.png)
 
unzipping the challenge gives us an image of a computer where the user is trying to login as “ken”. We also see a chestboard piece of paper just above the keyboard

<image>
 
zooming in, we see a chest board where it looks like a chest move has been performed

![](writeupfiles/screenie.png)
 
Googling the “description” of the challenge (password 39 years) gives us an article which explains how someone created an interesting password from a chest move
https://en.chessbase.com/post/after-39-years-chess-password-cracked

![](writeupfiles/39yrs.png)

in the article, we see a snippet which states the password may be: p/q2-q4!

![](writeupfiles/pq2q4.png)

we try the password, but it is incorrect:

![](writeupfiles/unzip.png)

we also see another interesting code snippet:

![](writeupfiles/pawnq4.png)

Google image searching this gives us a chest move as an image: p = pawn
q2 - q4 = move queen position 2 to position 4

![](writeupfiles/googleserch.png)

I Google searched the chest board location to see if we can find an image of a chest board

![](writeupfiles/location.png)

I found this image:

![](writeupfiles/board2.png)

the chestboard piece of paper shows the king performing a very similar move to the queen. That should mean:
p = pawn
k2 - k4 = move king position 2 to position 4

![](writeupfiles/board.png)

That should give us a string: p/k2-k4!
Lets try unzipping it using p/k2-k4! as the password:

![](writeupfiles/flag.png)

It worked, we got the flag! TMHC{1_kn0w_d35cr1pt1v3_n0t4t10n}

## HelpSomeoneIsTryingToBeMe

This OSINT challenge is an easy one. The concept of the challenge is looking into messages sent in collaboration platforms. It ends with decoding a Estoteric language to get the flag.

# The Challenge:

So one of the owners of TMHC Dave @Dav is having an identity crisis, can you find the fake account and their secret? You’ll need to join TMHC discord to start this challenge. https://discord.gg/infosec
By clicking the Discord link, you will be directed to The Many Hats Club CTF discord server. Prior to this CTF, I am already a member of the Discord. I then searched for the string “dav” and it seems that there are 3 users with Dav on their name and handle.

![](writeupfiles/osint1.png)

I then checked the Dav#6825 because maybe the users are arranged by the date they are created or they joined the server. Checking its messages, I found his dialogue is interesting. I continued browsing.

![](writeupfiles/osint2.png)

![](writeupfiles/osint3.png)

In the earliest message of that account, there is a base64 string.

![](writeupfiles/osint4.png)

Decoding it leads to a URL:

```
$ echo -n YUhSMGNITTZMeTl3WVhOMFpXSnBiaTVqYjIwdmRTOUpZVzF1YjNSa1lYWmwgR28gQWdhaW4=| base64 -d
aHR0cHM6Ly9wYXN0ZWJpbi5jb20vdS9JYW1ub3RkYXZl Go Again
$ echo -n YUhSMGNITTZMeTl3WVhOMFpXSnBiaTVqYjIwdmRTOUpZVzF
1YjNSa1lYWmwgR28gQWdhaW4=| base64 -d | base64 -d
https://pastebin.com/u/Iamnotdavebase64: invalid input
```

The URL is:

```
https://pastebin.com/u/Iamnotdave
```

Visiting the URL, I see some pastes:

![](writeupfiles/osint5.png)

Checking the contents of the iamnotdave file:

```
---Garlang_Bread - you will never crack my code---
agarlicgonbreadagarlicagarlicagarlicgbgarbredgarlicgaaaargbagarlicogarbredagarlicagarlicagarlicagarlicagarlicagarlicagarlicogarbredagarlicagarlicagarlicagarlicagarlicogarbredagarlicagarlicagarlicagarlicagarlicogarbredagarlicagarlicagarlicagarlicagarlicgonbreadagarlicgbgarbredgarbredgarlicgaaaargbagarlicogarbredgbgarbredgonbreadagarlicagarlicagarlicgbgarbredgarbredgarlicgaaaargbgarbredgarbredgarbredogarbredgarbredgonbreadagarlicagarlicgbgarbredgarlicgaaaargbgarbredgarbredgarbredogarbredgarbredgonbreadagarlicagarlicagarlicgbgarbredgarbredgarlicgaaaargbagarlicogarbredgonbreadagarlicgbgarbredgarbredgarbredgarlicgaaaargbogarbredagarlicgonbreadagarlicagarlicagarlicagarlicagarlicgbgarbredgarlicgaaaargbogarbredgarbredgarbredgonbreadagarlicagarlicagarlicgbgarbredgarbredgarlicgaaaargbogarbredgarbredgonbreadagarlicagarlicagarlicgbgarbredgarbredgarlicgaaaargbagarlicogarbredgonbreadagarlicagarlicagarlicgbgarbredgarbredgarlicgaaaargbogarbredagarlicagarlicagarlicgonbreadagarlicagarlicagarlicgbgarbredgarbredgarbredgarbredgarlicgaaaargbogarbredagarlicagarlicagarlicagarlicagarlicogarbredgonbreadagarlicagarlicagarlicagarlicagarlicgbgarbredgarbredgarbredgarbredgarlicgaaaargbgarbredogarbredagarlicgonbreadgarbredgarbredgarbredgarbredgbagarlicagarlicagarlicgarlicgaaaargbogarbredgonbreadagarlicgbgarbredgarbredgarbredgarbredgarbredgarlicgaaaargbgarbredgarbredogarbredagarlicagarlicagarlicagarlicagarlicagarlicagarlicagarlicagarlicagarlicagarlicagarlicogarbredgbagarlicgonbreadagarlicagarlicagarlicagarlicagarlicgbgarbredgarlicgaaaargbogarbredagarlicgonbreadagarlicgbgarbredgarbredgarlicgaaaargbagarlicogarbredgonbreadagarlicgbgarbredgarbredgarbredgarbredgarbredgarbredgarlicgaaaargbogarbredgbagarlicgonbreadagarlicagarlicagarlicagarlicagarlicgbgarbredgarlicgaaaargbogarbredagarlicagarlicgonbreadagarlicagarlicagarlicgbgarbredgarbredgarlicgaaaargbagarlicagarlicogarbredgarbredgonbreadagarlicgbgarbredgarbredgarbredgarlicgaaaargbogarbredgarbredgonbreadagarlicagarlicgbgarbredgarlicgaaaargbgarbredogarbredgonbreadagarlicagarlicagarlicgbgarbredgarbredgarlicgaaaargbagarlicagarlicogarbredagarlicogarbredgarbredgarbredgonbreadagarlicgbgarbredgarbredgarbredgarlicgaaaargbogarbredagarlicagarlicagarlicagarlicagarlicagarlicagarlicagarlicagarlicagarlicagarlicagarlicogarbredgonbreadagarlicagarlicagarlicgbgarbredgarlicgaaaargbgarbredgarbredgarbredogarbredgbagarlicgonbreadagarlicagarlicagarlicgbgarbredgarlicgaaaargbogarbredagarlicgonbreadagarlicagarlicgbgarbredgarbredgarbredgarlicgaaaargbagarlicogarbred
```
I searched for the string “Garlang_Bread” and these are hits:

![](writeupfiles/osint6.png)

Visiting the Github page:

![](writeupfiles/osint7.png)

Another mention of Stu. I then clone the repository and run the java stuff against the string:

```
java garlicbread garlicCipherText.gbread result.txt
```

![](writeupfiles/osint8.png)

Saving the output to result.txt, I run the java program on result.txt:

![](writeupfiles/osint9.png)

And I can get the flag:

```
TMHC{Y0u_F0uNd_My_S3cR3t_1ts_StU}
```
I wanted to mention my teammate S1ckB0y! Thanks for fixing the Java part :)

## Wanted
After staring at the image for a little while, it was clear that the image had
some kind of reversible distortion. So, first of all, we tried to identify what
type of distortion we were dealing with. 

We started googling some terms like:
  * Vortex image distortion.
  * Winding image distortion.
  * Twirl image distortion.

After some unsuccessful searches, we found [this
blog](http://matzjb.se/2015/07/26/deconstructing-swirl-face/) when searching
for "swirl image distortion". It is a blog about how a pedophile tried to hide
his face using the same type of distortion that appears on the challenge.
Luckily for us (and unluckily for the pedophile), this type of distortion is
reversible to a degree. The blog showcases this technique using photoshop.

Since we did not have photoshop available, we started playing with the image
using **Gimp**, which has "Whirl and Pinch" distortion under Filters ->
Distorts.

This is the original image:  
![](writeupfiles/wanted.jpg)

We can start by making a selection around the affected portion of the image by using the ellipse select tool.  
![](writeupfiles/selection.png) 
![](writeupfiles/Editing.png)


The trial and error comes into play now.  I'm not sure if the image is fully recoverable, but image needs to be focused on in sections rather than trying to undo the image as a whole.  When I first started working on the image I used a negative swirl to undo most of the outter edges and slowly worked my way to the center.  Depending on your selection of the image your settings of the tool may vary, but the end result is the same.  Below is an example of my selection and tool settings to get a large part of the image visible.  Some guess work was required to get the correct characters for the flag.  
Once a section of the image was where I needed it to be I created a new layer with that selection and locked it so it could not be altered by further use of the Whirl tool.  Unfortunately I no longer have my final version of the image, but this is a close version of it.    
![](writeupfiles/somewhat_readable.png)

After a bit of guesswork, we come to the conclusion the flag is:
TMHC{Th1sIsY0u1sntIt}




