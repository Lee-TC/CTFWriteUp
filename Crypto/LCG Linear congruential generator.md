# LCG Linear congruential generator

介绍：[https://en.wikipedia.org/wiki/Linear_congruential_generator](https://en.wikipedia.org/wiki/Linear_congruential_generator)

简单来说就是一个线性同余的随机数迭代生成器

## 题目

```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
from secret import flag

class LCG:
    def __init__(self, bit_length):
        m = getPrime(bit_length)
        a = getRandomRange(2, m)
        b = getRandomRange(2, m)
        seed = getRandomRange(2, m)
        self._key = {'a':a, 'b':b, 'm':m}
        self._state = seed
        
    def next(self):
        self._state = (self._key['a'] * self._state + self._key['b']) % self._key['m']
        return self._state
    
    def export_key(self):
        return self._key


def gen_lcg():
    rand_iter = LCG(128)
    key = rand_iter.export_key()
    f = open("key", "w")
    f.write(str(key))
    return rand_iter


def leak_data(rand_iter):
    f = open("old", "w")
    for i in range(20):
        f.write(str(rand_iter.next() >> 64) + "\n")
    return rand_iter


def encrypt(rand_iter):
    f = open("ct", "wb")
    key = rand_iter.next() >> 64
    key = (key << 64) + (rand_iter.next() >> 64)
    key = long_to_bytes(key).ljust(16, b'\x00')
    iv = long_to_bytes(rand_iter.next()).ljust(16, b'\x00')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = flag + (16 - len(flag) % 16) * chr(16 - len(flag) % 16)
    ct = cipher.encrypt(pt.encode())
    f.write(ct)


def main():
    rand_iter = gen_lcg()
    rand_iter = leak_data(rand_iter)
    encrypt(rand_iter)


if __name__ == "__main__":
    main()
```

## 思路 

观察知，题目使用了128位的LCG，并且泄露了20组随机数的64位MSB，最后继续使用该LCG进行随机数生成，并使用AES加密

GitHub上有针对LCG的攻击，并且有三种攻击方式，分别为：

- 参数恢复
- 参数部分位泄露
- 生成数部分位泄露

显而易见此题为第三种，直接调用攻击代码：

```python
from attacks.lcg import truncated_state_recovery

key={'b': 153582801876235638173762045261195852087, 'a': 107763262682494809191803026213015101802, 'm': 226649634126248141841388712969771891297}

m=key['m']
c=key['b']
a=key['a']

y=[7800489346663478448,
    11267068470666042741,
    5820429484185778982,
    6151953690371151688,
    548598048162918265,
    1586400863715808041,
    7464677042285115264,
    4702115170280353188,
    5123967912274624410,
    8517471683845309964,
    2106353633794059980,
    11042210261466318284,
    4280340333946566776,
    6859855443227901284,
    3149000387344084971,
    7055653494757088867,
    5378774397517873605,
    8265548624197463024,
    2898083382910841577,
    4927088585601943730,
]

k=128
s=64
print(truncated_state_recovery.attack(y,k,s,m,a,c)[19])
```

得到最后一个生成的数，根据LCG的性质，将其设为seed继续迭代，很容易就能写出解密脚本：

```python
from Crypto.Util.number import *
from Crypto.Cipher import AES

class LCG:
    def __init__(self, bit_length):
        m = 226649634126248141841388712969771891297
        a = 107763262682494809191803026213015101802
        b = 153582801876235638173762045261195852087
        seed = 90888742167094632308617091277078238483
        self._key = {'a':a, 'b':b, 'm':m}
        self._state = seed
        
    def next(self):
        self._state = (self._key['a'] * self._state + self._key['b']) % self._key['m']
        return self._state
    
    def export_key(self):
        return self._key


def decrypt(rand_iter):
    f = open("ct","rb")
    key = rand_iter.next() >> 64
    key = (key << 64) + (rand_iter.next() >> 64)
    key = long_to_bytes(key).ljust(16, b'\x00')
    iv = long_to_bytes(rand_iter.next()).ljust(16, b'\x00')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = f.read()
    pt = cipher.decrypt(ct)
    return pt

def main():
    rand_iter = LCG(128)
    print(decrypt(rand_iter))


if __name__ == "__main__":
    main()

```

得到flag