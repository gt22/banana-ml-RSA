from Crypto.Util import number
from Crypto.PublicKey.RSA import importKey
import copy
import math
import random
import base64


def extended_euclid(a, b):

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


def getD(e, phi):
    d = extended_euclid(e, phi)
    if d < 0:
        d += phi * (d % phi)
    return d



def generateKeys(i, e=65537):
    p = number.getPrime(i)
    q = number.getPrime(i)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = getD(e, phi)
    if (d * e) % phi != 1:
        raise ValueError("Error while generating")
    return (e, n), (d, n)


def string2numList(strn):
    returnList = []
    for chars in strn:
        returnList.append(ord(chars))
    return returnList


def numList2string(L):
    returnString = ''
    for nums in L:
        returnString += chr(nums)
    return returnString


def createPaddingString(dataSize, modSize):
    if modSize < dataSize:
        return []  # No padding needed
    else:
        PS = []
        for _ in range((modSize - (dataSize % modSize) - 3)):
            PS.append(random.randint(1, 0xFF))  # PS as for RFC 2313 8.1
    return PS


def getModSize(n):
    return (n.bit_length() + 7) // 8


def numList2blocks(L, n):
    blocks = []
    data = copy.copy(L)
    modSize = getModSize(n)
    while len(data) > 0:
        block = 0
        PS = createPaddingString(len(data), modSize)
        data = [0, 2, *PS, 0] + data  # 00 || BT (02) || PS || 00 || D (RFC 2313 8.1)
        for j in range(0, modSize):
            block += data.pop(0) << (8 * j)
        blocks.append(block)
    return blocks


def getPredicate(BT):
    """:return (predicate, shouldSkipPart)"""
    if BT == 0x00:  # PS of 00 (00 also matches separator, so it shouldn't be skipped)
        return lambda part: part == 0x00, False
    elif BT == 0x01:  # PS of FF
        return lambda part: part == 0xFF, True
    elif BT == 0x02:  # PS of random numbers, wait for separator
        return lambda part: part != 0x00, True
    else:
        raise ValueError("Invalid block type {}".format(hex(BT)))


def extractData(block):
    dataList = []
    block >>= 8  # Skip leading zero
    part = block % 256

    BT = part
    pred, shouldSkip = getPredicate(BT)
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


def blocks2numList(blocks, n):
    returnList = []
    toProcess = copy.copy(blocks)
    for block in toProcess:
        decodedBlock = extractData(block)
        returnList.extend(decodedBlock)
    return returnList


def encryptS(text, pbkey):
    e, n = pbkey
    blocks = numList2blocks(string2numList(text), n)
    encryptedBlocks = [pow(block, e, n) for block in blocks]
    return encryptedBlocks


def decryptS(blocks, prkey):
    d, n = prkey
    decryptedBlocks = [pow(block, d, n) for block in blocks]
    return numList2string(blocks2numList(decryptedBlocks, n))

def readKey(file):
    return importKey(open(file, "r").read()).key


def readKeys(pubf, prvf):
    pubk = readKey(pubf)
    prvk = readKey(prvf)
    return (pubk.e, pubk.n), (prvk.d, prvk.n)

def getKeys():
    keys = readKeys("pub.pem", "prv.pem")
    #keys = generateKeys(512)
    return keys

def testAsd(pub, prv):
    enc = encryptS("asd", pub)
    dec = decryptS(enc, prv)
    print(dec)
    
def testBigStr(pub, prv):
    bigStr = ""
    for line in open("string.txt", "r"):
        bigStr += line[:-1]
    enc = encryptS(bigStr, pub)
    dec = decryptS(enc, prv)
    print(bigStr == dec)
    
keys = getKeys()
testAsd(*keys)