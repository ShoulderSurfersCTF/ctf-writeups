##The Many Hats Club CTF

The CTF was active from 14 Dec 2019 00:00 until 15 Dec 2019 23:59.


 Title          | Category      | Points        | Flag         |
| ------------- | ------------- | ------------- | ------------- |
| Shitter       | Web           | 300           |               |             
| Hackbot       | Web           | 400 |               |
| BoneChewerCon | Web           | 125 | ------------- |
| Lotto-win       | Crypto        | 150           |               |             
| matrix_madness| Crypto        | 200 |               | 
| C4n_I_h4z_c0d3_n_crypt0 | Misc          | 100 | ------------- |
| DESk       | Misc          | 125           | TMHC{1_kn0w_d35cr1pt1v3_n0t4t10n}              |             
| Beeeep_Beeeep  | Misc          | 175 | TMHC{0f5ee61ef3fbb4bb066df8c286ec84b07a7a5d95}              | 
| flagthebox | Misc          | 400 | |
| the bain of chiv       | Misc          | 200           |               |             
| miniPWN  | Pwn           | 200 |               | 
| overdosed | Pwn           | 150 | ------------- |
| w00ter       | Pwn           | 600           |               |             
| Operation  | Reversing     | 100 |               | 
| DeNuevo | Reversing     | 125 | ------------- |
| Quack       | Reversing     | 400           |               |             
| QuackQuack  | Reversing         | 600 |               | 
| WANTED  | Stego         | 425 |               | 
| HelpSomeoneIsTryingToBeMe  | OSINT        | 225 |               | 
| quoted  | Mobile        | 400 |               | 



##Lotto-win

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


