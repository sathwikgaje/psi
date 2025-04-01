from mpyc.runtime import mpc
import sys
import time
import random
from Crypto import Random
from Crypto.Util import number
import sys
import collections
import hashlib
import random
import binascii
import sys

#OPRF Code
EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')
curve = EllipticCurve(
    'secp256k1',
    # Field characteristic.
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    # Curve coefficients.
    a=0,
    b=7,
    # Base point.
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    # Subgroup order.
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    # Subgroup cofactor.
    h=1,
)


# Modular arithmetic ##########################################################

def inverse_mod(k, p):
    """Returns the inverse of k modulo p.
    This function returns the only integer x such that (x * k) % p == 1.
    k must be non-zero and p must be a prime.
    """
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)

    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    gcd, x, y = old_r, old_s, old_t

    assert gcd == 1
    assert (k * x) % p == 1

    return x % p


# Functions that work on curve points #########################################

def is_on_curve(point):
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        # None represents the point at infinity.
        return True

    x, y = point

    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


def point_add(point1, point2):
    """Returns the result of point1 + point2 according to the group law."""
    assert is_on_curve(point1)
    assert is_on_curve(point2)

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        return None

    if x1 == x2:
        # This is the case point1 == point2.
        m = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)
    else:
        # This is the case point1 != point2.
        m = (y1 - y2) * inverse_mod(x1 - x2, curve.p)

    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p,
              -y3 % curve.p)

    assert is_on_curve(result)

    return result


def scalar_mult(k, point):
    """Returns k * point computed using the double and point_add algorithm."""
    assert is_on_curve(point)

    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        # k * point = -k * (-point)
        return scalar_mult(-k, point)

    result = None
    addend = point

    while k:
        if k & 1:
            # Add.
            result = point_add(result, addend)

        # Double.
        addend = point_add(addend, addend)

        k >>= 1

    assert is_on_curve(result)

    return result


# Keypair generation ################################################

def make_keypair():
    """Generates a random private-public key pair."""
    private_key = 50
    public_key = scalar_mult(private_key, curve.g)

    return private_key, public_key


#Commitment Code
def key_gen(param):
        g = param[2]
        key = random.randrange(g)
        return key

def generate(param):
        q = param[1]
        g = param[2]
        h = param[3]
        return q,g,h


class verifier:
    def setup(self):
        p = 1358681087066403584589411319055703169133224180159
        q = 2*p + 1


        g = 974802457164282411764922995832768961755224471620
        s = 2031280428051917415213041116355108373036188909536
        h = pow(g,s,q)
        
        param = (p,q,g,h)
        return param

    def open(self, param, c, x, *r):
        result = "False"
        q,g,h = generate(param)

        sum = 0
        for i in r:
            sum += i

        res = (pow(g,x,q) * pow(h,sum,q)) % q

        if(c == res):
            result = "True"
        return result  

    def add(self, param, *cm):
        addCM = 1
        for x in cm:
            addCM *= x
        addCM = addCM % param[1]
        return addCM
        
class prover: 
    def commit(self, param, x):
        q,g,h = generate(param)
        
        r = number.getRandomRange(1, q-1)
        c = (pow(g,x,q) * pow(h,r,q)) % q
        return c, r

#Proposed Algorithm Code
async def main():
    await mpc.start()
    party = 0
    other_party = 1
    set = [10,20]
    commucation_time = 0
    computation_time = 0
    v = verifier()
    p = prover()
    param = v.setup()
    bobMacKey = key_gen(param)
    bobSecretKey, bobPublicKey = make_keypair()
    bobCommitment, bobR = p.commit(param, bobMacKey)
    temp = [bobCommitment,bobR,bobPublicKey]
    co_eff = await mpc.transfer(temp)
    temp1 = co_eff[other_party]
    aliceCommitment = temp1[0]
    aliceR = temp1[1]
    alicePublicKey = temp1[2]
    transfer_set = []
    ts = time.time()
    for i in set:
        transfer_set.append((bobMacKey*i)-(scalar_mult(i,bobPublicKey)[0])+(scalar_mult(i,alicePublicKey)[0]))
    computation_time = computation_time + (time.time() - ts)
    ti = await mpc.transfer(time.time())
    sets = await mpc.transfer(transfer_set)
    ma = await mpc.transfer(bobMacKey)
    aliceMacKey = ma[other_party]
    result1 = v.open(param, aliceCommitment, aliceMacKey, aliceR)
    if result1 == False:
        print("Mac key is changed")
        exit()
    commucation_time = commucation_time + (time.time() - ti[0])
    ts = time.time()
    PSI = []
    bobSet = sets[party]
    aliceSet = sets[other_party]
    for i in range(len(bobSet)):
        for j in range(len(aliceSet)):
            if bobSet[i]+aliceSet[j] == (bobMacKey+aliceMacKey)*set[i]:
                PSI.append(set[i])
    computation_time = computation_time + (time.time() - ts)
    print(PSI)
    print(f"Commucation Time:{commucation_time}")
    print(f"Computation Time:{computation_time}")
    await mpc.shutdown()

mpc.run(main())
