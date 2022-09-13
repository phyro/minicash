# Don't trust me with cryptography.

"""
Implementation of https://gist.github.com/RubenSomsen/be7a4760dd4596d06963d67baf140406

Alice:
A = a*G
return A

Bob:
Y = hash_to_curve(secret_message)
r = random blinding factor
B'= Y + r*G
return B'

Alice:
C' = a*B'
  (= a*Y + a*r*G)
return C'

Bob:
C = C' - r*A
 (= C' - a*r*G)
 (= a*Y)
return C, secret_message

Alice:
Y = hash_to_curve(secret_message)
C == a*Y

If true, C must have originated from Alice
"""

import hashlib
from secp256k1 import PrivateKey, PublicKey


# We extend the public and private key to define some operations on points
# Picked from https://github.com/WTRMQDev/secp256k1-zkp-py/blob/master/secp256k1_zkp/__init__.py
def _int_to_bytes(n, length, endianess='big'):
    try:
        return n.to_bytes(length, endianess)
    except:
        h = '%x' % n
        s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
        return s if endianess == 'big' else s[::-1]

def _bytes_to_int(bt, endianess='big'):
    try:
        return int.from_bytes(bt, endianess)
    except:
        bt = bt if endianess == 'big' else bt[::-1]
        bt = bytearray(bt)
        n=0
        for m in bt:
          n *= 256
          n+=int(m)
        return n

class PublicKeyExt(PublicKey):
    def __add__(self, pubkey2):
        if isinstance(pubkey2, PublicKey):
            new_pub = PublicKey()
            new_pub.combine([self.public_key, pubkey2.public_key])
            return new_pub
        else:
            raise TypeError("Cant add pubkey and %s"%pubkey2.__class__)

    def __neg__(self):
        serialized=self.serialize()
        first_byte, remainder = serialized[:1], serialized[1:]
        first_byte = {b'\x03':b'\x02', b'\x02':b'\x03'}[first_byte]
        return PublicKey(first_byte+ remainder, raw=True)

    def __sub__(self, pubkey2):
        if isinstance(pubkey2, PublicKey):
            return self + (-pubkey2)
        else:
            raise TypeError("Cant add pubkey and %s"%pubkey2.__class__)
    
    def mult(self, privkey):
        if isinstance(privkey, PrivateKey):
            return self.tweak_mul(privkey.private_key)
        else:
            raise TypeError("Can't multiply nonbyte scalar")
    
    def __eq__(self, pubkey2):
        if isinstance(pubkey2, PublicKey):
            seq1 = self.to_data()
            seq2 = pubkey2.to_data()
            return seq1 == seq2
        else:
            raise TypeError("Can't compare pubkey and %s" % pubkey2.__class__)
    
    def to_data(self):
        return [self.public_key.data[i] for i in range(64)]

class PrivateKeyExt(PrivateKey):
    def __add__(self, privkey2):
      if not isinstance(privkey2, PrivateKey):
        raise TypeError("Cant summarize privkey and %s"%privkey2.__class__)
      return PrivateKey(self.tweak_add(privkey2.private_key), raw = True)

    def __mul__(self, privkey2):
      if isinstance(privkey2, PrivateKey):
        return PrivateKey(self.tweak_mul(privkey2.private_key), raw = True)
      else:
        return PrivateKey(self.tweak_mul(_int_to_bytes(privkey2, 32)), raw = True)

    def __neg__(self):
      order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 #order of secp256k1 group
      neg_num=_int_to_bytes(order-_bytes_to_int(self.private_key, 'big'), 32, 'big')
      return PrivateKey(neg_num, raw=True)

    def __sub__(self, privkey2):
      return self + (-privkey2)


# Horrible monkey patch
PublicKey.__add__ = PublicKeyExt.__add__
PublicKey.__neg__ = PublicKeyExt.__neg__
PublicKey.__sub__ = PublicKeyExt.__sub__
PublicKey.mult = PublicKeyExt.mult
PublicKey.__eq__ = PublicKeyExt.__eq__
PublicKey.to_data = PublicKeyExt.to_data

PrivateKey.__add__ = PrivateKeyExt.__add__
PrivateKey.__neg__ = PrivateKeyExt.__neg__
PrivateKey.__sub__ = PrivateKeyExt.__sub__
PrivateKey.__mul__ = PrivateKeyExt.__mul__


def hash_to_curve(secret_msg):
    """Generates x coordinate from the message hash and checks if the point lies on the curve.
    If it does not, it tries computing again a new x coordinate from the hash of the coordinate."""
    # point = None
    # msg = secret_msg
    # while point is None:
    #     x_coord = int(hashlib.sha256(msg).hexdigest().encode("utf-8"), 16)
    #     y_coord = secp256k1.compute_y(x_coord)
    #     try:
    #         # Fails if the point is not on the curve
    #         point = Point(x_coord, y_coord, secp256k1)
    #     except:
    #         msg = str(x_coord).encode("utf-8")

    # return point

    # TODO: This one needs to be implemented, this isn't NUMS
    msg = secret_msg
    _hash = hashlib.sha256(msg).hexdigest().encode("utf-8")[:32]
    priv = PrivateKey(_hash)
    return priv.pubkey


def step1_bob(secret_msg):
    # secret_msg = secret_msg.encode("utf-8")
    # Y = hash_to_curve(secret_msg)
    # r, _ = gen_keypair(secp256k1)
    # B_ = Y + r*G
    # return B_, r
    secret_msg = secret_msg.encode("utf-8")
    Y = hash_to_curve(secret_msg)
    r = PrivateKey()
    B_ = Y + r.pubkey
    return B_, r


def step2_alice(B_, a):
    # C_ = a*B_
    # return C_
    C_ = B_.mult(a)
    return C_

def step3_bob(C_, r, A):
    # C = C_ - r*A
    # return C
    C = C_ - A.mult(r)
    return C

def verify(a, C, secret_msg):
    # Y = hash_to_curve(secret_msg.encode("utf-8"))
    # return C == a*Y
    Y = hash_to_curve(secret_msg.encode("utf-8"))
    return C == Y.mult(a)

### Below is a test of a simple positive and negative case

# Alice private key
# a, A = gen_keypair(secp256k1)
# secret_msg = "test"
# B_, r = step1_bob(secret_msg)
# C_ = step2_alice(B_, a)
# C = step3_bob(C_, r, A)
# print("C:{}, secret_msg:{}".format(C, secret_msg))

# assert verify(a, C, secret_msg)
# assert verify(a, C + 1*G, secret_msg) == False  # adding 1*G shouldn't pass

# a, A = gen_keypair(secp256k1)
a = PrivateKey()
A = a.pubkey
secret_msg = "test"
B_, r = step1_bob(secret_msg)
C_ = step2_alice(B_, a)
C = step3_bob(C_, r, A)
print("C:{}, secret_msg:{}".format(C, secret_msg))
assert verify(a, C, secret_msg)
assert verify(a, C + C, secret_msg) == False  # adding C twice shouldn't pass
assert verify(a, A, secret_msg) == False  # A shouldn't pass
