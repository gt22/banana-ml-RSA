import random
import copy

def pack(data, n):
    if isinstance(data, str):
        data = [ord(char) for char in data]
    blocks = []
    data = copy.copy(data)
    mod_size = (n.bit_length() + 7) // 8
    while len(data) > 0:
        block_parts = _break_block_to_parts(data, mod_size)
        ps = _create_padding_string(len(block_parts), mod_size)
        block_parts = [0, 2, *ps, 0] + block_parts  # 00 || BT (02) || PS || 00 || D (RFC 2313 8.1)
        block = 0
        for j in range(0, mod_size):
            block += block_parts.pop(0) << (8 * j)
        blocks.append(block)
    return blocks


def _break_block_to_parts(data, mod_size):
    block_parts = []
    while len(data) > 0 and len(block_parts) < mod_size - 3:
        i = data[0]  # Can't do pop now, because it's possible that we must left this char for next block
        if i.bit_length() > 7:  # Non-Ascii, should be separated in multiple parts
            if (i.bit_length() + 7) // 8 + len(block_parts) >= mod_size - 3:
                break
            while i.bit_length() > 7:
                # Take last 8 bits, set 8th bit, indicating it's not last part
                block_parts.append((i & 0xFF) | 0x80)
                i >>= 7
            block_parts.append(i & 0x7F)  # Unset 8th bit, last part
        else:
            block_parts.append(i)  # If bit_length <= 7 then 8th bit is unset, and we could simply add this num
        data.pop(0)  # Remove i from data
    return block_parts


def _create_padding_string(size, mod):
    if mod < size:
        return []  # No padding needed
    else:
        ps = []
        for _ in range((mod - (size % mod) - 3)):
            ps.append(random.randint(1, 0xFF))  # PS as for RFC 2313 8.1
        return ps


def unpack(blocks):
    ret = []
    for block in blocks:
        ret.extend(_unpack_block(block))
    return ''.join([chr(i) for i in ret])


predicates = {
    0x00: (lambda part: part == 0x00, False),
    0x01: (lambda part: part == 0xFF, True),
    0x02: (lambda part: part != 0x00, True)
}


def _unpack_block(block):
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

    return _extract_data(block)


def _extract_data(block):
    data = []
    while block > 0:
        d = block % 256
        num = 0
        i = 0

        while d & 0x80 > 0:  # While 8th bit is set, which means that this num is just part of the data
            num += (d & 0x7F) << (7 * i)  # Unset 8th bit, shift to position and add to number
            i += 1
            block >>= 8
            d = block % 256
        # Can use | instead of + because num length is 7i, and d has 7i unset bits to the right, because of the shift
        num |= d << (7 * i)
        data.append(num)
        block >>= 8
    return data
