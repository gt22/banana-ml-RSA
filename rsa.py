from Crypto.Util import number
from Crypto.PublicKey.RSA import importKey
import copy
import random

predicates = {
    0x00: (lambda part: part == 0x00, False),
    0x01: (lambda part: part == 0xFF, True),
    0x02: (lambda part: part != 0x00, True)
}


class RSA:
    def __init__(self, key_files=None, key_length=512):
        if key_files is None:
            pub, prv = RSA._generate(key_length)
        else:
            pub, prv = RSA._read_keys(*key_files)
        self.pub = pub
        self.prv = prv
        
    @staticmethod
    def _extended_euclid(a, b):
        r = a
        u = 1
        v = 0
        r2 = b
        u2 = 0
        v2 = 1

        while r2 != 0:
            q = r // r2
            (r, u, v, r2, u2, v2) = (r2, u2, v2, r - q * r2, u - q * u2, v - q * v2)
        return u
    
    @staticmethod
    def _get_d(e, phi):
        d = RSA._extended_euclid(e, phi)
        if d < 0:
            d += phi * (d % phi)
        return d

    @staticmethod
    def _generate(i, e=65537):
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

    @staticmethod
    def _read_key(file):
        return importKey(open(file, "r").read()).key

    @staticmethod
    def _read_keys(pubf, prvf):
        pubk = RSA._read_key(pubf)
        prvk = RSA._read_key(prvf)
        return (pubk.e, pubk.n), (prvk.d, prvk.n)

    @staticmethod
    def _get_size(n):
        return (n.bit_length() + 7) // 8

    @staticmethod
    def _create_padding_string(size, mod):
        if mod < size:
            return []  # No padding needed
        else:
            ps = []
            for _ in range((mod - (size % mod) - 3)):
                ps.append(random.randint(1, 0xFF))  # PS as for RFC 2313 8.1
            return ps

    @staticmethod
    def _pack(data, n):
        if isinstance(data, str):
            data = [ord(char) for char in data]
        blocks = []
        data = copy.copy(data)
        mod_size = RSA._get_size(n)
        while len(data) > 0:
            block = 0
            block_parts = []
            while len(data) > 0 and len(block_parts) < mod_size - 3:
                i = data.pop(0)
                i_size = i.bit_length()
                if i_size > 7:  # Non-Ascii, should be separated in multiple parts
                    while i.bit_length() > 7:
                        # Take last 8 bits, set 8th bit, indicating it's not last part
                        block_parts.append((i & 0xFF) | 0b10000000)
                        i >>= 7
                    block_parts.append(i & 0b01111111)  # Unset 8th bit, last part
                else:
                    block_parts.append(i)  # If bit_length <= 7 then 8th bit is unset, and we could simply add this num
            ps = RSA._create_padding_string(len(block_parts), mod_size)
            block_parts = [0, 2, *ps, 0] + block_parts  # 00 || BT (02) || PS || 00 || D (RFC 2313 8.1)
            for j in range(0, mod_size):
                block += block_parts.pop(0) << (8 * j)
            blocks.append(block)
        return blocks

    @staticmethod
    def _unpack_block(block):
        data_list = []
        block >>= 8  # Skip leading zero
        part = block % 256

        bt = part
        pred, should_skip = predicates[bt]
        block >>= 8

        while pred(block % 256):
            block >>= 8
        if should_skip:
            if block % 256 != 0:
                raise ValueError("Cannot find separator after padding, block type {type}, excepted 0x00, got {got}"
                                 .format(type=bt, got=hex(block % 256)))
            block >>= 8

        while block > 0:
            d = block % 256
            num = 0
            i = 0
            while d & 0b10000000 > 0:  # While 8th bit is set
                num += (d & 0b01111111) << (7 * i)
                i += 1
                block >>= 8
                d = block % 256
            num += d << (7 * i)
            data_list.append(num)
            block >>= 8
        return data_list
    
    @staticmethod
    def _unpack(blocks):
        ret = []
        for block in blocks:
            ret.extend(RSA._unpack_block(block))
        return ''.join([chr(i) for i in ret])

    def encrypt(self, text):
        e, n = self.pub
        blocks = RSA._pack(text, n)
        encrypted = [pow(block, e, n) for block in blocks]
        return encrypted

    def decrypt(self, blocks):
        d, n = self.prv
        decrypted = [pow(block, d, n) for block in blocks]
        return RSA._unpack(decrypted)
    
    
def test(st, rsa):
    enc = rsa.encrypt(st)
    dec = rsa.decrypt(enc)
    return dec == st


def test_str(st, rand_rsa, static_rsa, name=None):
    name = name or st
    print(name, "random", test(st, rand_rsa))
    print(name, "static", test(st, static_rsa))


def test_all():
    static_rsa = RSA(("pub.pem", "prv.pem"))
    rand_rsa = RSA()
    test_str("asd", rand_rsa, static_rsa)
    big_str = ""
    for line in open('string.txt', "r"):
        big_str += line[:-1]
    test_str(big_str, rand_rsa, static_rsa, "big string")
    test_str("фыв", rand_rsa, static_rsa, "unicode")
    test_str("фыв asd", rand_rsa, static_rsa, "mixed")
    test_str("!@#$%&*", rand_rsa, static_rsa, "spec")


test_all()

