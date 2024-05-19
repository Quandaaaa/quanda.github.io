---
title: "KCSC CTF 2024"
date: 2024-05-19T13:35:02+07:00
draft: false
author: "Quanda"
authorLink: "https://quanda.github.io"
description: "Writeup for The Cryptography challenge."
tags: ["crypto"]
categories: ["Writeups"]
lightgallery: true
toc:
  enable: true
---

# KCSC CTF 2024
Trong giải mình chỉ giải được một bài Evil ECB và mình chỉ mới làm thêm được 2 chall nữa.
## Evil ECB
![image](https://hackmd.io/_uploads/BybKPkMXA.png)

* **Attachment:** [public.rar](https://kcsc.tf/files/fca7e615f94715717df8bfddf67a6e28/public.rar?token=eyJ1c2VyX2lkIjo2MCwidGVhbV9pZCI6MjAsImZpbGVfaWQiOjE0fQ.ZkRnbA.3lPP_n1IqBHEQn8fcEbgG25EeCM)
* nc 103.163.24.78 2003

**server.py**
```python=
from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad, unpad
from os import urandom
import json
import socket
import threading

flag = 'KCSC{s0m3_r3ad4ble_5tr1ng_like_7his}'

menu = ('\n\n|---------------------------------------|\n' +
            '| Welcome to Evil_ECB!                  |\n' +
            '| Maybe we can change the Crypto world  |\n' +
            '| with a physical phenomena :D          |\n' +
            '|---------------------------------------|\n' +
            '| [1] Login                             |\n' +
            '| [2] Register ^__^                     |\n' +
            '| [3] Quit X__X                         |\n' +
            '|---------------------------------------|\n')

bye = ( '[+] Closing Connection ..\n'+
        '[+] Bye ..\n')

class Evil_ECB:
    def __init__(self):
        self.key = urandom(16)
        self.cipher = AES.new(self.key, AES.MODE_ECB)
        self.users = ['admin']

    def login(self, token):
        try:
            data = json.loads(unpad(self.cipher.decrypt(bytes.fromhex(token)), 16).decode())
            if data['username'] not in self.users:
                return '[-] Unknown user'

            if data['username'] == "admin" and data["isAdmin"]:
                return '[+] Hello admin , here is your secret : %s\n' % flag

            return "[+] Hello %s , you don't have any secret in our database" % data['username']
        except:
            return '[-] Invalid token !'
        
    def register(self, user):
        if user in self.users:
            return '[-] User already exists'
 
        data = b'{"username": "%s", "isAdmin": false}' % (user.encode())
        token = self.cipher.encrypt(pad(data, 16)).hex()
        self.users.append(user)
        return '[+] You can use this token to access your account : %s' % token

class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self):
        self.sock.listen(5)
        while True:
            client, address = self.sock.accept()
            client.settimeout(60)
            threading.Thread(target = self.listenToClient,args = (client,address)).start()

    def listenToClient(self, client, address):
        size = 1024
        chal = Evil_ECB()
        client.send(menu.encode())
        for i in range(10):
            try:
                client.send(b'> ')
                choice = client.recv(size).strip()
                if choice == b'1':
                    client.send(b'Token: ')
                    token = client.recv(size).strip().decode()
                    client.send(chal.login(token).encode() + b'\n')
                elif choice == b'2':
                    client.send(b'Username: ')
                    user = client.recv(size).strip().decode()
                    client.send(chal.register(user).encode() + b'\n')
                elif choice == b'3':
                    client.send(bye.encode())
                    client.close()
                else:
                    client.send(b'Invalid choice!!!!\n')
                    client.close()
            except:
                client.close()
                return False
        client.send(b'No more rounds\n')
        client.close()

if __name__ == "__main__":
    ThreadedServer('',2003).listen()
```

Nếu như ta gửi vào `username` thì sẽ được trả về một `token` để có thể login.
```python=
def register(self, user):
        if user in self.users:
            return '[-] User already exists'
 
        data = b'{"username": "%s", "isAdmin": false}' % (user.encode())
        token = self.cipher.encrypt(pad(data, 16)).hex()
        self.users.append(user)
        return '[+] You can use this token to access your account : %s' % token
```

* `data = b'{"username": "%s", "isAdmin": false}'` phần Admin được để là `false` nên ta phải làm sao đưa nó về `true` để nhận flag.

Vì là mã hóa ECB nên các block được mã hóa độc lập với nhau.
Ta có:
* len("isAdmin": false}) = 16, vừa đẹp mình sẽ thế nó cho `"isAdmin":  true}` có 2 dấu cách nhé để đảm bảo độ dài của nó là 16.

Username sẽ để là `admin` nhưng ta không thể truyền `admin` vào một cách bình thường được.
![image](https://hackmd.io/_uploads/rJnucJGQ0.png?raw=true)

* Ta sẽ lợi dụng phương thức json, `name` sẽ được ném vào đây: 
`data = b'{"username": "%s", "isAdmin": false}'`. 
* Nên mình sẽ gửi thế này: `admin", "e":"a` khi đó:
`data = b'{"username": "admin", "e":"a", "isAdmin": false}'`. 
* Mình đã tính toán để block này là 48 bytes vừa đủ 3 block, tại vì ta cần phải để ý đến hàm `pad` và `unpad`. Vì cái này mà mình mất khá nhiều thời gian mới lấy được flag.
* Khi len(data) = 48 thì hàm pad sẽ pad riêng cho ta một block mới. `\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10`
cái này bạn có thể xem lại cách mà hàm pad hoạt động. 

**script:**
```python
from pwn import *

io = remote("103.163.24.78", 2003)

payload = '''a"isAdmin":  true}'''

io.recvuntil(b'> ')
io.sendline(b"2")
io.recvuntil(b'Username: ')
io.sendline(payload.encode())
io.recvuntil(b'You can use this token to access your account : ')
Token = io.recvuntil(b'\n')[:-1]
print(len(Token))
target = Token.decode()[32:64]
#{"username": "admin", "e":"a", "isAdmin": false}
# print(len('''{"username": "admin", "e":"a", "'''))
payload = '''admin", "e":"a'''
io.recvuntil(b'> ')
io.sendline(b"2")
io.recvuntil(b'Username: ')
io.sendline(payload.encode())
io.recvuntil(b'You can use this token to access your account : ')
Token = io.recvuntil(b'\n')[:-1]
# print(len(Token))
new_token = Token[:64].decode() + target + Token[96:].decode()

io.recvuntil(b'> ')
io.sendline(b"1")
io.recvuntil(b'Token: ')
io.sendline(new_token.encode())
io.interactive()
```
![image](https://hackmd.io/_uploads/SkNrpkz7R.png?raw=true)


> Flag: *KCSC{eCb_m0de_1s_4lways_1nSecUre_:))}*

## Miscrypt
![image](https://hackmd.io/_uploads/r1fcpyG7R.png)

**Attachment:** [Miscrypt.zip](https://kcsc.tf/files/ced8fa249230852a878c2e430713a63e/Miscrypt.zip?token=eyJ1c2VyX2lkIjo2MCwidGVhbV9pZCI6MjAsImZpbGVfaWQiOjI2fQ.ZkRtfA.08tAMfqF43GMPabtgIGag3Prluk)

Flag được embed trong QR code. Mã QR được mã hóa như sau:
```python
from PIL import Image
import numpy as np
import galois
GF256 = galois.GF(2**8)

img = Image.open('qr_flag_rgb.png')
pixels = img.load()
width, height = img.size

M = GF256(np.random.randint(0, 256, size=(3, 3), dtype=np.uint8))

# scan full height -> weight
for x in range(width):
    for y in range(0,height,3):
        A = GF256([pixels[x, y], pixels[x, y+1], pixels[x, y+2]])
        M = np.add(A, M)
        pixels[x, y], pixels[x, y+1], pixels[x, y+2] = [tuple([int(i) for i in j]) for j in M]

img.save('qr_flag_encrypt.png')
```
Xếp 3 pixels thành một ma trận và mã hóa như sau:
- $A_0' = A_0 + M$
- $A_1' = A_1 + A_0 + M$
- ...
- Các trận này thuộc $GF(256)$

Đây là một cái mã QR code cho ai chưa biết :))))
![image](https://hackmd.io/_uploads/BJSHCJGQ0.png?raw=true)
* Pixel màu trắng sẽ có giá trị là: `[255, 255, 255]`
* Pixel màu đen sẽ có giá trị là: `[0, 0, 0]`

Ta nhận thấy những pixel ngoài cùng là màu trắng. Suy ra ta có:

$A_0 = \begin{bmatrix}
255 & 255 & 255\\
255 & 255 & 255\\
255 & 255 & 255
\end{bmatrix}$

Có $A_0$ ta tính được $M = A'_0 - A_0$ và các giá trị còn lại.

**script:**
```python
from PIL import Image
import numpy as np
import galois

GF256 = galois.GF(2**8)

img = Image.open('qr_flag_encrypt.png')
pixels = img.load()
width, height = img.size

M = GF256([[215, 251, 129],
           [56, 221, 204],
           [140, 28, 117]])
# k = GF256([[255, 255, 255],
#            [255, 255, 255],
#            [255, 255, 255]])
tmp = M

# scan full height -> weight
for x in range(width):
    for y in range(0,height,3):
        A = GF256([pixels[x, y], pixels[x, y+1], pixels[x, y+2]])
        B = np.subtract(A, tmp)
        pixels[x, y], pixels[x, y+1], pixels[x, y+2] = [tuple([int(i) for i in j]) for j in B]
        tmp += B

img.save('qr_flag_decrypt.png')
```

![image](https://hackmd.io/_uploads/Bkcz-gGXA.png)

> Flag: KCSC{CrYpt0-l1k3-St3g4n0???}

## Don Copper
![image](https://hackmd.io/_uploads/B1eYbgMQ0.png?raw=true)

**Attachment:** [public.rar](https://kcsc.tf/files/a8f1210aa420a3a49ab4ee1932a7d21f/public.rar?token=eyJ1c2VyX2lkIjo2MCwidGVhbV9pZCI6MjAsImZpbGVfaWQiOjEyfQ.ZkRxbg.oObjYWKG5iBKbkBf-75ujMNmPvA)

**chall.py**

```python
import random
from Crypto.Util.number import getPrime

NBITS = 2048

def pad(msg, nbits):
    """msg -> trash | 0x00 | msg"""
    pad_length = nbits - len(msg) * 8 - 8
    assert pad_length >= 0
    pad = random.getrandbits(pad_length).to_bytes((pad_length+7) // 8, "big")
    return pad + b"\x00" + msg


if __name__ == '__main__':
    p = getPrime(NBITS//2)
    q = getPrime(NBITS//2)
    n = p*q
    e = 3
    print('n =',n)

    flag = b'KCSC{s0m3_r3ad4ble_5tr1ng_like_7his}'
    flag1 = int.from_bytes(pad(flag[:len(flag)//2], NBITS-1), "big")
    flag2 = int.from_bytes(pad(flag[len(flag)//2:], NBITS-1), "big")
    print('c1 =', pow(flag1, e, n))
    print('c2 =', pow(flag2, e, n))
    print('c3 =', pow(flag1 + flag2 + 2024, e, n))

'''
n = 20309506650796881616529290664036466538489386425747108847329314416833872927305399144955238770343216928093685748677981345624111315501596571108286475815937548732237777944966756121878930547704154830118623697713050651175872498696886388591990290649008566165706882183536432074074093989165129982027471595363186012032012716786766898967178702932387828604019583820419525077836905310644900660107030935400863436580408288191459013552406498847690908648207805504191001496170310089546275003489343333654260825796730484675948772646479183783762309135891162431343426271855443311093315537542013161936068129247159333498199039105461683433559
c1 = 4199114785395079527708590502284487952499260901806619182047635882351235136067066118088238258758190817298694050837954512048540738666568371021705303034447643372079128117357999230662297600296143681452520944664127802819585723070008246552551484638691165362269408201085933941408723024036595945680925114050652110889316381605080307039620210609769392683351575676103028568766527469370715488668422245141709925930432410059952738674832588223109550486203200795541531631718435391186500053512941594901330786938768706895275374971646539833090714455557224571309211063383843267282547373014559640119269509932424300539909699047417886111314
c2 = 15650490923019220133875152059331365766693239517506051173267598885807661657182838682038088755247179213968582991397981250801642560325035309774037501160195325905859961337459025909689911567332523970782429751122939747242844779503873324022826268274173388947508160966345513047092282464148309981988907583482129247720207815093850363800732109933366825533141246927329087602528196453603292618745790632581329788674987853984153555891779927769670258476202605061744673053413682672209298008811597719866629672869500235237620887158099637238077835474668017416820127072548341550712637174520271022708396652014740738238378199870687994311904
c3 = 18049611726836505821453817372562316794589656109517250054347456683556431747564647553880528986894363034117226538032533356275073007558690442144224643000621847811625558231542435955117636426010023056741993285381967997664265021610409564351046101786654952679193571324445192716616759002730952101112316495837569266130959699342032640740375761374993415050076510886515944123594545916167183939520495851349542048972495703489407916038504032996901940696359461636008398991990191156647394833667609213829253486672716593224216112049920602489681252392770813768169755622341704890099918147629758209742872521177691286126574993863763318087398
'''
```

Đọc source ta có:
* $f = x_1^3 - c_1  \pmod n$
* $g = y^3 - c_2  \pmod n$
* $h = ({x_1 + y + 2024})^3 - c_3  \pmod n$

Ban đầu mình định sử dụng gcd để tìm nghiệm chung của $(f_1$, $f_3)$, $(f_2$, $f_3)$. Nhưng nó có 2 ẩn nên mình không thể gcd được. 
End giải thì anh Jella có gửi hint là cái [link](https://en.wikipedia.org/wiki/Resultant) này. Đọc qua thì mình biết thêm về **THE RESULTANT OF TWO POLYNOMIALS**


### Sylvester matrix
Xét 2 đa thức trên một trường(**field**) hoặc một vành giao hoán(**commutative ring**).
Cho $p$ và $q$ là hai đa thức khác không có bậc lần lượt là $m$ và $n$.

$${\displaystyle p(z)=p_{0}+p_{1}z+p_{2}z^{2}+\cdots +p_{m}z^{m},\;q(z)=q_{0}+q_{1}z+q_{2}z^{2}+\cdots +q_{n}z^{n}.}$$

Ta sẽ sử dụng **Sylvester matrix** để liên kết 2 đa thức này với nhau.
Khi đó ma trận với kích thước $(n + m) \times (n + m)$ có cấu trúc như sau:

* Nếu n > 0, thi hàng đầu tiên của ma trận là:
$${\displaystyle {\begin{pmatrix}p_{m}&p_{m-1}&\cdots &p_{1}&p_{0}&0&\cdots &0\end{pmatrix}}.}$$
* Hàng thứ hai là hàng đầu tiên, dịch sang phải một cột; phần tử đầu tiên của hàng bằng 0.
* Tiếp tục cho $n -2$ hàng còn lại. Các hàng tiếp theo được lấy theo cách tương tự, mỗi lần dịch chuyển các hệ số sang phải một cột và đặt các mục khác trong hàng thành 0.
* Nếu m > 0 thì hàng $n+1$ là:
$${\displaystyle {\begin{pmatrix}q_{n}&q_{n-1}&\cdots &q_{1}&q_{0}&0&\cdots &0\end{pmatrix}}.}$$
* Tiếp tục cho các hàng tiếp theo như ở trên.

Ví dụ $m = 4$ và $n = 3$ thì ma trận sẽ là:

${\displaystyle S_{p,q}={\begin{pmatrix}p_{4}&p_{3}&p_{2}&p_{1}&p_{0}&0&0\\0&p_{4}&p_{3}&p_{2}&p_{1}&p_{0}&0\\0&0&p_{4}&p_{3}&p_{2}&p_{1}&p_{0}\\q_{3}&q_{2}&q_{1}&q_{0}&0&0&0\\0&q_{3}&q_{2}&q_{1}&q_{0}&0&0\\0&0&q_{3}&q_{2}&q_{1}&q_{0}&0\\0&0&0&q_{3}&q_{2}&q_{1}&q_{0}\end{pmatrix}}.}$

Khi đó định thức của **Sylvester matrix** ($det(S)$) chính là *resultant* của 2 đa thức.
Nếu 2 đa thức có nghiệm chung thì:
$$Res(p, q) = det(S) = 0$$.


Quay lại với challenge
Giả sử ta cho $y$ cố định $y = y_0$:
* $f_{y_0}(x) = 0 = f(x, y_0)$
* $h_{y_0}(x) = 0 = h(x, y_0)$
* $g_{y_0}(x) = 0 = g(x, y_0)$

Vì chúng có nghiệm chung nên ta sẽ có:
- $Res(f_{y_0}(x), h_{y_0}(x)) = 0$
- $Res(g_{y_0}(x), h_{y_0}(x)) = 0$

Từ đây ta đã có 2 phương trình đơn biến theo ẩn là $y_0$. Và mình sẽ dùng **gcd** để tìm ra nghiệm của chung của 2 phương trình này nó chính là Flag.

Solution:
Thật may là Sagemath đã có sẵn hàm **resultant** nên cùng triển thôi

```python
from Crypto.Util.number import *

e = 3
n = ...
c1 = ...
c2 = ...
c3 = ...

P.<x, y> = PolynomialRing(ZZ, 2)
f = x**3 - c1
g = y**3 - c2
h = (x + y + 2024)**3 - c3

a = h.resultant(f)
b = h.resultant(g)
# ở chỗ này mình thấy ra 2 phương trình chứa ẩn y
A = PolynomialRing(Zmod(n), names='y')

# print(A(a))
# print(A(b))

def gcd(a,b) :
    while b :
        a , b = b , a%b 
    return a.monic()

ans = gcd(A(a), A(b))
print(ans)
```
Mình được kết quả như sau:
```python
y + 10850063064215786153306327148990924788438984598023598141431813572034023665508993022819406328531276035415236463762473907444014785919774345550388745382570351421234382216484857722363728432223575478904468786551137995573395304260701532033474455590992994546092536998679869622456414388329561594251029715255159436038660362296817381481412123357555319521172263012404519048712465622333028074769426400066439085668811357134225445548178218655872653355541146025686046192241356344100333096851330334054858073508194708777534526473121314794434611660370071725086052980875155623377312829194652529259245234592714291772331661063675437706202
```

Vậy là ta có được $y$

Đổi tên biến cho 2 phương trình ta được nghiệm khác:
```python
y + 13735276216480234294706359844820346892092177215553901414391761850858882460635783205472406746662036273971992070607261796127119688947318559763272879567995396491115716121316753574975647148161690034108438505248524970885551589159652876676870846257287752279898736691564266993215011110767376345954955541741948634680315084968263393711859569144349753495551546569343780951427789448111710124904988309966385084377510291750050932987581798768855247780396174181337264410175133260701357189505301070362322065230989981704250274145256779438951189476596306356433095883900881070769915283761198556147219781991864498300605360624190735499303
```

Lấy 2 nghiệm và chuyển về bytes ta được flag.
> Flag: `KCSC{W0rk1ng_w1th_p0lyn0m14ls_1s_34sy_:D}`

## Square
![image](https://hackmd.io/_uploads/SycmCJHXR.png?raw=true)

* **Attachment:** [public.rar](https://kcsc.tf/files/2ff351ccda1e15d3e5226ae4125214bc/public.rar?token=eyJ1c2VyX2lkIjo2MCwidGVhbV9pZCI6MjAsImZpbGVfaWQiOjE3fQ.ZkduMw.FmTSujQdilsN8_sVjsT8uPDU09c)
* `nc 103.163.24.78 2004`


