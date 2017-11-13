
from Crypto.Util import number

import utils
import blocks


class RSA:
    def __init__(self, keys=None, key_length=512):
        if keys is None:
            pub, prv = RSA._generate(key_length)
        else:
            pub, prv = keys
        self.pub = pub
        self.prv = prv

    @staticmethod
    def _get_d(e, phi):
        d = utils.extended_euclid(e, phi)
        while d < 0:
            d += phi
        return d

    @staticmethod
    def _generate(i, e=65537):
        p = 0
        q = 0
        n = 0
        while n.bit_length() != i * 2:
            p = number.getPrime(i)
            q = number.getPrime(i)
            n = p * q
        phi = (p - 1) * (q - 1)
        if e >= phi:
            e = number.getStrongPrime(i, phi)
        d = RSA._get_d(e, phi)
        if (d * e) % phi != 1 or e >= phi:
            raise ValueError("Error while generating, d={}, e={}, phi={}".format(d, e, phi))
        return (e, n), (d, n)

    def encrypt(self, text):
        e, n = self.pub
        block_list = blocks.pack(text, n)
        encrypted = [pow(block, e, n) for block in block_list]
        return encrypted

    def decrypt(self, block_list):
        d, n = self.prv
        decrypted = [pow(block, d, n) for block in block_list]
        return blocks.unpack(decrypted)
    
    
def test(st, rsa):
    enc = rsa.encrypt(st)
    dec = rsa.decrypt(enc)
    return dec == st


def test_str(st, rand_rsa, static_rsa, name=None):
    name = name or st
    print(name, "random", test(st, rand_rsa))
    print(name, "static", test(st, static_rsa))


def test_all():
    static_rsa = RSA(utils.read_keys("pub.pem", "prv.pem"))
    rand_rsa = RSA()
    test_str("asd", rand_rsa, static_rsa)
    big_str = ""
    for line in open('string.txt', "r"):
        big_str += line[:-1]
    test_str(big_str, rand_rsa, static_rsa, "big string")
    test_str("фыв", rand_rsa, static_rsa, "unicode")
    test_str("фыв asd", rand_rsa, static_rsa, "mixed")
    test_str("!@#$%&*", rand_rsa, static_rsa, "spec")
    test_str(big_str.replace('U', 'ф').replace('X', '@'), rand_rsa, static_rsa, "mixed big string")


big_str = ""
for line in open('string.txt', "r"):
    big_str += line[:-1]

test_all()

