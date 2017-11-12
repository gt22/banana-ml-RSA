predicates = {
    0x00: (lambda part: part == 0x00, False),
    0x01: (lambda part: part == 0xFF, True),
    0x02: (lambda part: part != 0x00, True)
}


class RSA:
    def __init__(self, keyFiles=None, keyLength=512):
        if keyFiles is None:
            pub, prv = RSA._generate(keyLength)
        else:
            pub, prv = RSA._readKeys(*keyFiles)
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
    def _getD(e, phi):
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
        d = RSA._getD(e, phi)
        if (d * e) % phi != 1:
            raise ValueError("Error while generating, d={}, e={}, phi={}".format(d, e, phi))
        return (e, n), (d, n)
    
    
    @staticmethod
    def _readKey(file):
        return importKey(open(file, "r").read()).key

    
    @staticmethod
    def _readKeys(pubf, prvf):
        pubk = readKey(pubf)
        prvk = readKey(prvf)
        return (pubk.e, pubk.n), (prvk.d, prvk.n)

    
    @staticmethod
    def _pack(data, n):
        if isinstance(data, str):
            data = [ord(char) for char in data]
        blocks = []
        data = copy.copy(data)
        modSize = getModSize(n)
        while len(data) > 0:
            block = 0
            PS = createPaddingString(len(data), modSize)
            data = [0, 2, *PS, 0] + data  # 00 || BT (02) || PS || 00 || D (RFC 2313 8.1)
            for j in range(0, modSize):
                block += data.pop(0) << (8 * j)
            blocks.append(block)
        return blocks
    
    
    @staticmethod
    def _unpackBlock(block):
        dataList = []
        block >>= 8  # Skip leading zero
        part = block % 256

        BT = part
        pred, shouldSkip = predicates[BT]
        block >>= 8

        while pred(block % 256):
            block >>= 8
        if shouldSkip:
            if block % 256 != 0:
                raise ValueError("Cannot find separator after padding, block type {type}, excepted 0x00, got {got}"
                                 .format(type=BT, got=hex(block % 256)))
            block >>= 8

        while block > 0:
            dataList.append(block % 256)
            block >>= 8
        return dataList
    
    
    @staticmethod
    def _unpack(blocks):
        ret = []
        for block in blocks:
            ret.extend(RSA._unpackBlock(block))
        return ''.join([chr(i) for i in ret])
    
    
    def encrypt(self, text):
        e, n = self.pub
        blocks = RSA._pack(text, n)
        encryptedBlocks = [pow(block, e, n) for block in blocks]
        return encryptedBlocks


    def decrypt(self, blocks):
        d, n = self.prv
        decryptedBlocks = [pow(block, d, n) for block in blocks]
        return RSA._unpack(decryptedBlocks)
    
    
    def test(st, rsa=RSA()):
    enc = rsa.encrypt(st)
    dec = rsa.decrypt(enc)
    return dec == st


def testAll():
    print("asd", test("asd"))
    print("asd, static", test("asd", RSA(("pub.pem", "prv.pem"))))
    bigStr = ""
    for line in open('string.txt', "r"):
        bigStr += line[:-1]
    print("bigstr", test(bigStr))
    print("bigstr, static", test(bigStr, RSA(("pub.pem", "prv.pem"))))
    
testAll()