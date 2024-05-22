---
title: "TJCTF 2024"
date: 2024-05-19T13:35:02+07:00
draft: false
author: "Quanda"
authorLink: "https://quanda.github.io"
description: "Writeup for The Cryptography challenge."
tags: ["crypto", "lcg", "hill cipher"]
categories: ["Writeups"]
lightgallery: true
toc:
  enable: true
---

![image](https://hackmd.io/_uploads/SkW-Jmd7C.png)
# Write up for Cryptography challenges
<!--more-->
* Ở giải này mình giải được **5/12** chall trong thời gian diễn ra giải.
## 1. weird-crypto
![image](https://hackmd.io/_uploads/Sygn17OXA.png)

**Attachment:** [`a.py`](https://tjctf-2024.storage.googleapis.com/uploads/f52edecdb1b0e1a6909e1f5feee2116c90ca808845f5374c329466ea02176b23/a.py)   [`output.txt`](https://tjctf-2024.storage.googleapis.com/uploads/3889f951209e0a4786057e426af27d3d6379641fda4379fa63b2ad388e4036c2/output.txt)

---
```python
from math import lcm
from Crypto.Util.number import bytes_to_long, getPrime

with open('flag.txt', 'rb') as f:
    flag = bytes_to_long(f.read().strip())

oops = getPrime(20)
p1 = getPrime(512)
p2 = getPrime(512)

haha = (p1-1)*(p2-1)
crazy_number = pow(oops, -1, haha)
discord_mod = p1 * p2
hehe_secret = pow(flag, crazy_number, discord_mod)

#admin = 115527789319991047725489235818351464993028412126352156293595566838475726455437233607597045733180526729630017323042204168151655259688176759042620103271351321127634573342826484117943690874998234854277777879701926505719709998116539185109829000375668558097546635835117245793477957255328281531908482325475746699343
#hehe_secret = 10313360406806945962061388121732889879091144213622952631652830033549291457030908324247366447011281314834409468891636010186191788524395655522444948812334378330639344393086914411546459948482739784715070573110933928620269265241132766601148217497662982624793148613258672770168115838494270549212058890534015048102
#crazy number = 13961211722558497461053729553295150730315735881906397707707726108341912436868560366671282172656669633051752478713856363392549457910240506816698590171533093796488195641999706024628359906449130009380765013072711649857727561073714362762834741590645780746758372687127351218867865135874062716318840013648817769047

```

* Bài này khá đơn giải ta chỉ cần brute-force `oops`.

**script:**
```python
from Crypto.Util.number import *
from sympy import nextprime

admin = 115527789319991047725489235818351464993028412126352156293595566838475726455437233607597045733180526729630017323042204168151655259688176759042620103271351321127634573342826484117943690874998234854277777879701926505719709998116539185109829000375668558097546635835117245793477957255328281531908482325475746699343
hehe_secret = 10313360406806945962061388121732889879091144213622952631652830033549291457030908324247366447011281314834409468891636010186191788524395655522444948812334378330639344393086914411546459948482739784715070573110933928620269265241132766601148217497662982624793148613258672770168115838494270549212058890534015048102
crazy_number = 13961211722558497461053729553295150730315735881906397707707726108341912436868560366671282172656669633051752478713856363392549457910240506816698590171533093796488195641999706024628359906449130009380765013072711649857727561073714362762834741590645780746758372687127351218867865135874062716318840013648817769047
i = 2**19
while 1:
    try:
        flag = pow(hehe_secret, i, admin)
        if b'tjctf{' in long_to_bytes(flag):
            print(long_to_bytes(flag))
            break
        i = nextprime(i)
    except:
        continue
```

> *Flag: tjctf{congrats_on_rsa_e_djfkel2349!}*

## 2. accountleak
![image](https://hackmd.io/_uploads/ByfOb7_mA.png)
* Attachment: [`server.py`](https://tjctf-2024.storage.googleapis.com/uploads/e31a1ad02ba2db75ee6a9eb99d1a38b11e4259b4a14d8fa5f0a7212fdf85f5c4/server.py)
* `nc tjc.tf 31601`

```python
#!/usr/local/bin/python3.10 -u

import time
from Crypto.Util.number import getPrime, getRandomInteger, getRandomNBitInteger

flag = open("flag.txt").read().strip()
p = getPrime(512)
q = getPrime(512)

sub = getRandomInteger(20)

# hehe u cant guess it since its random :P
my_password = getRandomNBitInteger(256)

n = p*q
c = pow(my_password, 65537, n)
dont_leak_this = (p-sub)*(q-sub)

def gamechat():
    print("<Bobby> i have an uncrackable password maybe")
    print(f"<Bobby> i'll give you the powerful numbers, {c} and {n}")
    print("<Bobby> gl hacking into my account")
    print("<Bobby> btw do you want to get my diamond stash")
    resp = input("<You> ")
    if (resp.strip() == "yea"):
        print("<Bobby> i'll send coords")
        print(f"<Bobby> {dont_leak_this}")
        print("<Bobby> oop wasnt supposed to copypaste that")
        print("<Bobby> you cant crack my account tho >:)")
        tic = time.time()
        resp = input("<You> ")
        toc = time.time()
        if (toc-tic >= 2.5):
            print("<Bobby> you know I can reset my password faster than that lol")
        elif (resp.strip() != str(my_password)):
            print("<Bobby> lol nice try won't give password that easily")
        else:
            print("<Bobby> NANI?? Impossible?!?")
            print("<Bobby> I might as wel give you the flag")
            print(f"<Bobby> {flag}")
    else:
        print("<Bobby> bro what, who denies free diamonds?")
    print("Bobby has left the game")


gamechat()
```

Ta cần tìm `sub` để khôi phục lại $p$ và $q$. Vì `sub` cũng khá bé nên mình sẽ tiếp tục brute-force. Nhưng vấn đề ở đây là thời gian để tìm ra `password` chỉ là 2.5s nên ta cần tối ưu.

Ta có:
* $N = p*q$
* $(p-sub)*(q-sub) = leak$
$\to N - sub(p+q) + sub^2 = leak$
$\to N - leak = sub(p+q) - sub^2$

**funfact:** ban đầu mình định factor cho đống này để tìm `sub` nhưng mà bất thành vì nó ko factor được với lại nếu factor được thì cũng khó mà lấy chính xác được giá trị của `sub` (nó có phải prime đâu 🙉).

Mình chuyển qua giải phương trình nhưng cũng không được tối ưu nên mình cầu cứu anh Việt và có được một script hoàn chỉnh.

**Sage:**
```python
from sage.all import *
from Crypto.Util.number import *
from pwn import *

# io = process(["python3", "server.py"])
io = remote("tjc.tf", 31601)
io.recvuntil(b"<Bobby> i'll give you the powerful numbers, ")
c = Integer(io.recvuntil(b' and ', drop=True).decode())
n = Integer(io.recvuntil(b'\n', drop=True).decode())

io.recvuntil(b'<Bobby> btw do you want to get my diamond stash\n')
io.recvuntil(b'<You> ')
io.sendline(b'yea')
io.recvuntil(b"<Bobby> i'll send coords\n")
io.recvuntil(b"<Bobby> ")
l = Integer(io.recvuntil(b'\n', drop=True).decode())

for i in range(2**19 - 1, 2, -1):
    if (n - l + i ** 2) % i == 0:
        s = (n - l + i ** 2) // i
        x = var('x')
        result = solve(x**2 - s*x + n, x)
        result = str(result)
        if 'sqrt' not in result:
            result = eval(result)
            p = str(result[0])[5:]
            q = str(result[1])[5:]
            p = Integer(p)
            q = Integer(q)
            assert p * q == n
            d = inverse_mod(65537, (p - 1) * (q - 1))
            plain = pow(c, d, n)
            io.recvuntil(b'<You> ')
            io.sendline(str(plain).encode())
            io.interactive()
```

Chạy mở DEBUG lên để thấy flag nhá, cứ chạy cho đến khi nào thấy flag thì thôi.
## 3. assume
![image](https://hackmd.io/_uploads/BJ0GnXuQC.png)

* **Attachment:** [`main.sage`](https://tjctf-2024.storage.googleapis.com/uploads/1d22c5b1beac01221451479a49c48d1546743a468088cd345f8da7bbed251295/main.sage)  [`log.txt`](https://tjctf-2024.storage.googleapis.com/uploads/70877e11250f82945c8f6eba364c83c8b30e9882a21c2f3029cc9eb9c1e558de/log.txt)

Bài này mình lấy flag bằng tay nhé (do mình lười code 😅).

## 4. iodomethane
![image](https://hackmd.io/_uploads/SydQaQdmR.png)

**Attachment:** [`output.txt`](https://tjctf-2024.storage.googleapis.com/uploads/bc721e6e95e934475574351070fa70f74b48e0b78b39f189084b1acf361d1e45/out.txt) [`main.py`](https://tjctf-2024.storage.googleapis.com/uploads/6497e49446d3f2633e9bf3a6679a74c6803cfc7c00cd8b3e9e268afc805fbb23/main.py)
```python
import secrets

flag = "flagtextttttttttttttttttttttt"

matrix = [[],[],[]]

alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0192834756{}_!@#$%^&*()"

modulus = 15106021798142166691 #len(alphabet)

flag = [alphabet.index(a) for a in flag]


while len(flag) % 3 != 0:
    flag.append(secrets.randbelow(modulus))


def det(matrix):
    a = matrix[0][0]
    b = matrix[0][1]
    c = matrix[0][2]
    d = matrix[1][0]
    e = matrix[1][1]
    f = matrix[1][2]
    g = matrix[2][0]
    h = matrix[2][1]
    i = matrix[2][2]
    return ((a * e * i - a * f * h) + (b * f * g - b * d * i) + (c * d * h - c * e * g)) % modulus

def randkey():
    test = [[secrets.randbelow(modulus) for i in range(3)] for J in range(3)]
    while (not det(test)):
           test = [[secrets.randbelow(modulus) for i in range(3)] for J in range(3)]
    return test

def dot(a,b):
    return sum([a[i] * b[i] for i in range(len(a))]) % modulus

def mult(key, row):
    return [dot(key[i], row) for i in range(len(key))]

rows = list(zip(flag[::3], flag[1::3], flag[2::3]))
print(rows)

key = randkey()
print(key, det(key), modulus)
enc = [mult(key, snip) for snip in rows]

open("out.txt", "w+").write(str(enc))

```
**output:**

```python
[8103443654527565038, 9131436358818679900, 4957881569325453096, 10608823513649500284, 6675039786579943629, 6611905972844131155, 1244757961681113340, 7547487070745190563, 1913848887301325654, 9737862765813246630, 2820240734893834667, 4787888165190302097, 11681061051439179359, 11976272630379115896, 2884226871403054033, 13149362434991348085, 2676520484503789480, 6933002550284269375, 6634913706901406922, 3790038065981008837, 7593117393518680210, 1266282031812681717, 14297832010203960867, 6803759075981258244, 2235840587449302546, 9573113061825958419, 7208484535445728720, 3230648965441849617, 14844603229849620928, 2548590493342454145, 12648684202717570605, 8664656898390315577, 13502288186462622020, 8391628990279857365, 5501744205282111713, 5327399420219427046, 904912426181632886, 4805354280735678357, 12915117098149429818, 12340346813869037506, 9907136040657333887, 12822605127735793613]
```

Đây là mã hóa [Hill cipher](https://en.wikipedia.org/wiki/Hill_cipher). Ta sẽ recover lại `key` để giải mã được ciphertext.

Để lấy được key mình sẽ thực hiện như sau:
- Key là một ma trận $3 \times 3$ 
- Form flag là `tjctf{` ta đã có 6 ký tự chỉ còn thiếu 3 ký tự nữa là đủ một ma trận $3 \times 3$. 
- Ta sẽ brute-force 3 ký tự đó nó chỉ rơi vào khoảng $75*74*73 = 405150$ nên ta có thể brute một cách nhanh chóng.

**Sage**
```python
flag_enc = [8103443654527565038, 9131436358818679900, 4957881569325453096, 10608823513649500284, 6675039786579943629, 6611905972844131155, 1244757961681113340, 7547487070745190563, 1913848887301325654, 9737862765813246630, 2820240734893834667, 4787888165190302097, 11681061051439179359, 11976272630379115896, 2884226871403054033, 13149362434991348085, 2676520484503789480, 6933002550284269375, 6634913706901406922, 3790038065981008837, 7593117393518680210, 1266282031812681717, 14297832010203960867, 6803759075981258244, 2235840587449302546, 9573113061825958419, 7208484535445728720, 3230648965441849617, 14844603229849620928, 2548590493342454145, 12648684202717570605, 8664656898390315577, 13502288186462622020, 8391628990279857365, 5501744205282111713, 5327399420219427046, 904912426181632886, 4805354280735678357, 12915117098149429818, 12340346813869037506, 9907136040657333887, 12822605127735793613]
flag_enc = [flag_enc[i*3:(i+1)*3] for i in range(len(flag_enc)//3)]

print(len(flag_enc))
modulus = 15106021798142166691
alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0192834756{}_!@#$%^&*()"

import itertools
combinations = list(itertools.combinations(alphabet, 3))


for i in combinations:
    try:
        guess = "tjctf{" + ''.join(i)
        guess = [alphabet.index(a) for a in guess]
        rows = list(zip(guess[::3], guess[1::3], guess[2::3]))
        
        A = matrix(GF(modulus), rows)
        B = matrix(GF(modulus), flag_enc[:3])
        key = A.inverse()*B
        flag_mat = matrix(GF(modulus), flag_enc)
        flag_dec = flag_mat * key.inverse()
        # print(flag_dec)
        flag = ''
        for i in flag_dec:
            for j in i:
                if j < 76:
                    flag += alphabet[j]
        if flag[-1] == '}': 
            print(flag)
    except:
        continue

```
Mình chạy thì ra được như này
![image](https://hackmd.io/_uploads/SJEGs4d7R.png)

Thấy chữ hillll nên mình biết nó chính là flag :)))))))

Flag: `tjctf{aint_no_hillllll_55e4$S56a356^#@!$}`

## 5. lightweight-crypto-guard-system

![image](https://hackmd.io/_uploads/H1Hl24uQ0.png)

**Attachment:** [`out.txt`](https://tjctf-2024.storage.googleapis.com/uploads/449fcf7379f2d3f2ba3bf0fe8696be65872e48114fb2a10a098096cb3e21c302/out.txt) [`encode.py`](https://tjctf-2024.storage.googleapis.com/uploads/3b712257e0c28aee57b8db567d619a48fab68d915b707722c5e4cf9cda905a66/encode.py) 

```python
#!/usr/local/bin/python3.10 -u

from Crypto.Util.number import *
import random

a = getRandomNBitInteger(30)
c = getRandomNBitInteger(15)
m = getPrime(32)
x0 = getRandomNBitInteger(30)

n = random.randint(2**8, 2**10)

flag = open("flag.txt").read().strip()

class Random():
    global m, a, c

    def __init__(self, x0):
        self.x0 = x0

    def random(self):
        self.x0 = (a*self.x0+c) % m
        return self.x0


encryptor = Random(x0)

assert m < 2**32
assert isPrime(m)

x = [ord(i) for i in flag]

with open("out.txt", "w") as wfile:
    for ind in range(len(x)):
        next = encryptor.random()
        if ind < 6:
            print(str(next))
            wfile.write(str(next) + "\n")
        for __ in range(n-1):
            x[ind] ^= encryptor.random()
    print(f"n = {n}")
    print(" ".join([str(i) for i in x]))
    wfile.write("n = " + str(n) + "\n")
    wfile.write(" ".join([str(i) for i in x]) + "\n")

```
**output** hơi dài nên bạn có thể tải về rồi xem nhé. <br>

Đây là một bài về [Linear congruential generator(lcg)](https://en.wikipedia.org/wiki/Linear_congruential_generator) đọc qua nếu bạn chưa biết gì về nó.
Với giá trị $x_0$ ban đầu ta gen ra được các giá trị tiếp theo: <br>

$x_i = x_{i-1}*a +  c \pmod n$ <br>

Nhưng ở đây có điều đặc biệt là những số từ LCG mà ta nhận được không phải 6 số liên tiếp mà nó kiểu như thế này: <br>

$s = [x_1, x_{n +1}, x_{n*2 +1}, \dots x_{n*5 +1}], \text{với n = }987$

**Ta thấy rằng:**

$$\begin{align*}
x_1 & = (a x_0 + c) \bmod m \\
x_2 & = (a x_1 + c) \bmod m = (a \cdot (a x_0 + c) + c) = (a^2 x_0 + c \cdot (a+1))\bmod m \\ x_3 & = (a x_2 + c) \bmod m = \ldots = a^3 x_0 + a^2 c + ac + c = a^3 x_0 + c \cdot (1 + a + a^2) \cdot c \bmod m \\ \vdots\end{align*}$$

* Vì $1, (a+1), (1 + a + a^2)$ lần lượt là tổng các cấp số nhân nên ta sẽ có một công thức tổng quát như sau:
$$x_i = a^i \cdot x_0 + c \cdot \dfrac{a^i - 1}{a-1}$$

Với dãy mà đề bài cho ta có thể viết lại như sau:
$$X_{i+1} = A \cdot X_i + K \pmod m$$
Trong đó:
* $n = 987$
* $X_0 = x_1$
* $K = c \cdot \dfrac{a^n - 1}{a-1}$
* $A = a^n$

Giờ ta một LCG mới với hệ số là $a^n, K$ giải bình thường để tìm tìm $a^n, K$ sau đó là tìm $c$ và $a$.
### 5.1 Tìm m
Ở đây mình sẽ nêu cách tìm tổng quát nhé. Mình đọc được ở cái [link](https://math.stackexchange.com/questions/2724959/how-to-crack-a-linear-congruential-generator-lcg) này. <br>
Xét $Y_n = X_{n+1} - X_n$ <br>
- Ta có:
$Y_{n+1} = X_{n+2} - X_{n+2} = (A \cdot X_{n+1} + K) - (A \cdot X_n + K) = A \cdot (X_{n+1} - X_n) = A \cdot Y_n$
- Với $Y_n= A \cdot Y_{n-1}$ ta sẽ có:
$$\begin{split}\begin{align*}
Y_{n+1} &\equiv A \cdot Y_{n} \equiv A^2 \cdot Y_{n-1} \pmod m\\
Y_{n+2} &\equiv A \cdot Y_{n+1} \equiv A^3 \cdot Y_{n-1} \pmod m\\
\end{align*}\end{split}$$
- Suy ra:
$$Y_{n+2} \cdot Y_n - {Y_{n+1}}^2 \equiv Y_{n-1} \cdot (A^4-A^4) \equiv 0 \pmod m$$ 
Như vậy chúng ta đã tạo ra một bội của $m$, thực hiện gcd cho các bội này ta tìm được $m$.

```python
s = [123855601, 1877660078, 2332452388, 2265666365, 2173629406, 2460275121]
t = []
for i in range(5):
    t.append(s[i+1]-s[i])

u = []
for i in range(3):
    u.append(abs(t[i+2]*t[i] - t[i+1]**2))

m = gcd(u)
#m = 2584844783
```

### 5.2 Tìm $a, c, x_0$
Trước tiên ta đi tìm $A, K$
Ta có:
$$\begin{split}\begin{align*}
X_2 - X_1 = A \cdot (X_1 - X_0) \bmod m \\
\Rightarrow A = (X_2 - X_1) \cdot {(X_1 - X_0)}^{-1}
\end{align*}\end{split}$$

Thế $A$ vào $X_1 = A \cdot X_0 + K$ và tìm được $K$ <br>
**Tìm a:** <br>
$A = a^n \Rightarrow a = A^d \bmod m, \text{ với } d = n^{-1} \bmod (m-1)$ <br>
**Tìm c:** <br>
$K = c \cdot \dfrac{a^n - 1}{a-1} \Rightarrow c = K \cdot (a-1) \cdot {(a^n -1)}^{-1} \bmod m$

Có $a, c$ thế vào $x_1 = a \cdot x_0 + c \bmod m$ và giải ra $x_0$
```python
s = [GF(m)(i) for i in s]

A = (s[2] - s[1])*pow((s[1]-s[0]), -1, m)

a = pow(A, pow(987, -1, m-1), m)
#print(a)
k = (s[1] - A*s[0])
c = (k*(a-1)*pow(pow(a, 987, m) -1, -1, m)) % m
x0 = (s[0] -c) * pow(a, -1, m)

```

### 5.3 Lấy Flag
```python
m = 2584844783
a = 779849675 
c = 23327 
x0 = 579927320
class Random():
    global m, a, c

    def __init__(self, x0):
        self.x0 = x0

    def random(self):
        self.x0 = (a*self.x0+c) % m
        return self.x0

encryptor = Random(x0)

flag_enc = flag_enc = open("out.txt", "r").readlines()[-1]
flag_enc = [int(i) for i in flag_enc.split()]
n = 987
for ind in range(len(flag_enc)):
    next = encryptor.random()
    if ind < 6:
        print(str(next))
    for __ in range(n-1):
        flag_enc[ind] ^= encryptor.random()

print(''.join([chr(i) for i in flag_enc]))
```

> Flag: tjctf{1t_15_a_p3r1od_of_c1v1l_war5_1n_th3_galaxy._a_brav3_all1anc3_of_und3rground_fr33dom_f1ght3r5_ha5_chall3ng3d_th3_tyranny_and_oppr3551on_of_th3_aw35om3_galact1c_3mp1r3._5tr1k1ng_from_a_fortr355_h1dd3n_among_th3_b1ll1on_5tar5_of_th3_galaxy,_r3b3l_5pac35h1p5_hav3_won_th31r_f1r5t_v1ctory_1n_a_battl3_w1th_th3_pow3rful_1mp3r1al_5tarfl33t._th3_3mp1r3_f3ar5_that_anoth3r_d3f3at_coult5_compl3t1on_5p3ll5_c3rta1n_doom_for_th3_champ1on5_of_fr33dom.}

## Loading .........
