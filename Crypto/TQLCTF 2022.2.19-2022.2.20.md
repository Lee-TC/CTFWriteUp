# TQLCTF 2022.2.19-2022.2.20

## hardrsa

### 题目源码：

```python
from sage.all import *
from Crypto.Util.number import bytes_to_long
from secret import flag

assert flag.startswith("TQLCTF{")
assert flag.endswith("}")

beta  = 0.223
delta = 0.226
gama  = 0.292
n_size = 1024
bound_q = 2**int(n_size*beta)
bound_p = 2**int(n_size*(1-beta))

while True:
    p = random_prime(bound_p, proof=False)
    q = random_prime(bound_q, proof=False)
    N = p * q
    if q < pow(N, beta) and gcd(p-1, (q-1)/2) == 1:
        break
        
assert p.is_prime()
assert q.is_prime()

while True:
    dp = randint(0, 2**int(n_size * delta))
    dq = randint(0, (q-1))
    if gcd(dp, p-1) == 1 and gcd(dq, (q-1)/2) == 1:
        break
        
d = crt([dp, dq], [p-1, (q-1)/2])
e = inverse_mod(d, (p-1)*(q-1)/2)
assert d > 2 * N ** gama

m = bytes_to_long(flag.encode())
print(f"N={N}\ne={e}")
print(f"c={pow(m,e,N)}")

#N=17898692915537057253027340409848777379525990043216176404521845629792286203459681133425615460580210961931628383718238208402935069434512008997422795968676635886265184398587211149645171148089263697198308448184434844310802022336492929706736607458307830462086477073132852687216229392067680807130235274969547247389
#e=7545551830675702855400776411651853827548700298411139797799936263327967930532764763078562198672340967918924251144028131553633521880515798926665667805615808959981427173796925381781834763784420392535231864547193756385722359555841096299828227134582178397639173696868619386281360614726834658925680670513451826507
#c=2031772143331409088299956894510278261053644235222590973258899052809440238898925631603059180509792948749674390704473123551866909789808259315538758248037806795516031585011977710042943997673076463232373915245996143847637737207984866535157697240588441997103830717158181959653034344529914097609427019775229834115

```

### 思路

观察到脚本中有`beta` 、`delta` 、`gama`等参数，猜测本题应该会与coppersmith攻击和lattice相关

同时可以观察到加密脚本中使用了CRT对RSA的使用

并且p,q两素数位数相差过大，故根据关键词*coppersmith、lattice、CRT、RSA*进行检索，搜索到 Alexander May在2002年发表的一篇论文*Cryptanalysis of Unbalanced RSA with Small CRT-Exponent*

发现其中情况与题目中描述的完全一致，并且满足**section 5** 中**An approach modulo e**的情况，故仔细阅读该部分，实现其攻击方法。

### 实现

```python
def attack(mm=2,tt=1,debug=False):
    beta  = 0.233
    delta = 0.226
    gama  = 0.292

    # print(1-2/3*(beta+sqrt(3*beta+beta^2)))
    #原题的数据
    N=17898692915537057253027340409848777379525990043216176404521845629792286203459681133425615460580210961931628383718238208402935069434512008997422795968676635886265184398587211149645171148089263697198308448184434844310802022336492929706736607458307830462086477073132852687216229392067680807130235274969547247389
    e=7545551830675702855400776411651853827548700298411139797799936263327967930532764763078562198672340967918924251144028131553633521880515798926665667805615808959981427173796925381781834763784420392535231864547193756385722359555841096299828227134582178397639173696868619386281360614726834658925680670513451826507
    c=2031772143331409088299956894510278261053644235222590973258899052809440238898925631603059180509792948749674390704473123551866909789808259315538758248037806795516031585011977710042943997673076463232373915245996143847637737207984866535157697240588441997103830717158181959653034344529914097609427019775229834115
    
    Y=floor(pow(N,delta+beta))
    Z=floor(pow(N,beta))
    
    dd=(mm+1)*(mm+2)/2+tt*(mm+1)
    P.<y,z> = PolynomialRing(ZZ)
    pol=y*(N-z)+N
    
    # print(pol(y=k-1,z=q)%e)

    G = []
    for ii in range(mm+1):
        for jj in range(mm-ii+1):
            G.append(e**(mm-ii)*(y)**jj*pol(y,z)**ii)
    for ii in range(mm+1):
        for jj in range(1,tt+1):
            G.append(e**(mm-ii)*(z)**jj*pol(y,z)**ii)

    monomials = []
    for i in G:
        for j in i.monomials():
            if j not in monomials:
                monomials.append(j)
    monomials.sort()

    # Construct lattice spanned by polynomials with yY and zZ
    L = matrix(ZZ,len(monomials))
    for i in range(len(monomials)):
        for j in range(len(monomials)):
            L[i,j] = G[i](Y*y,Z*z).monomial_coefficient(monomials[j])

    # makes lattice upper triangular
    L = matrix(ZZ,L)
    if debug:
        print("Bitlengths of matrix elements (before reduction):")
        print(L.apply_map(lambda x: x.nbits()).str())

    L = L.LLL()
    if debug:
        print("Bitlengths of matrix elements (after reduction):")
        print(L.apply_map(lambda x: x.nbits()).str())

    roots = []

    pol1 = P(sum(map(mul, zip(L[0],monomials)))(y/Y,z/Z))
    pol2 = P(sum(map(mul, zip(L[1],monomials)))(y/Y,z/Z))
    # print(pol1(y=k-1,z=q)%e)

    if L[0].norm() > (e^mm)/sqrt(dd):
        raise ValueError("Can't attack,plz try bigger m,t")
    r = pol2.resultant(pol1, y)
    if r.is_constant():
        return 
    for z0, _ in r.univariate_polynomial().roots():
        roots.append(z0)
        if debug:
            print("Potential z0:",z0)
    return roots
print(attack(mm=6,tt=4))

```

其中，将参数mm和tt提升到（6，4）的时候，运行一小段时间后可以得到结果

即`q=169137218869484728712814942277531819318585090563481420862437016566714151`

```python
from gmpy2 import powmod,invert
from Crypto.Util.number import long_to_bytes
N=17898692915537057253027340409848777379525990043216176404521845629792286203459681133425615460580210961931628383718238208402935069434512008997422795968676635886265184398587211149645171148089263697198308448184434844310802022336492929706736607458307830462086477073132852687216229392067680807130235274969547247389
e=7545551830675702855400776411651853827548700298411139797799936263327967930532764763078562198672340967918924251144028131553633521880515798926665667805615808959981427173796925381781834763784420392535231864547193756385722359555841096299828227134582178397639173696868619386281360614726834658925680670513451826507
c=2031772143331409088299956894510278261053644235222590973258899052809440238898925631603059180509792948749674390704473123551866909789808259315538758248037806795516031585011977710042943997673076463232373915245996143847637737207984866535157697240588441997103830717158181959653034344529914097609427019775229834115
    
q=169137218869484728712814942277531819318585090563481420862437016566714151
p=N//q

d=invert(e,(p-1)*(q-1)//2)

print(long_to_bytes(powmod(c,d,N)))
```

可以得到flag