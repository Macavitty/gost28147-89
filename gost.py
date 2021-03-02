import math

# статичный блок подстановок
s_box = (
    (4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3),
    (14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9),
    (5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11),
    (7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3),
    (6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2),
    (4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14),
    (13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12),
    (1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12),
)

BLOCK_SIZE_BYTES = 8


def get_num_bits(n):
    if n == 0:
        return 0
    return int((math.log(n) / math.log(2)) + 1)


def str_as_int(s):
    if s == '':
        return 0
    num = 0
    for i in range(len(s)):
        num <<= 8
        num |= ord(s[i])
    return num


def int_as_str(num):
    s = ''
    mask = 0xff
    i = 0
    l = num.bit_length()
    while i < l:
        s += chr(num & mask)
        num >>= 8
        i += 8
    s = s[::-1]
    return s


def make_block_string(block):
    if isinstance(block, str):
        block_bytes = len(block)
        needed_bits = int(BLOCK_SIZE_BYTES - block_bytes) * 8
        return str_as_int(block) << needed_bits

    raise ValueError('expected str')


def f(part, key):
    mod32 = 0x100000000
    # суммирование по модулю 2^32
    part += key
    if part >= mod32:
        part -= mod32

    tmp = part
    mask = 0xf0000000
    res = 0
    for i in range(8):
        ind = (tmp & mask) >> 28
        tmp <<= 4
        res <<= 4
        res |= s_box[i][ind]
    return ((res >> (32 - 11)) | (res << 11)) & 0xffffffff


def generate_gamma(block, sub_keys):
    left = block >> 32
    right = block & 0xffffffff

    for i in range(32):
        tmp_left = right ^ f(left, sub_keys[i])
        right = left
        left = tmp_left
    return (left << 32) | right


def get_sub_keys(key):
    key_list = []
    sub_keys = []
    i = 0
    while i < 32:
        key_list.append(str_as_int(key[i: i + 4]))
        sub_keys.insert(0, key_list[len(key_list) - 1])
        i += 4

    for i in range(0, 24):
        sub_keys.insert(0, key_list[(23 - i) % len(key_list)])

    return sub_keys


def gost(source, key, iv, operation='enc'):
    assert len(key) == 32, 'Your key is ' + str(len(key)) + ' bytes but must be 32 bytes'
    assert len(iv) == 8, 'iv must be 8 bytes'
    assert operation == 'enc' or operation == 'dec', 'Unsupported operation: ' + operation

    sub_keys = get_sub_keys(key)
    # if operation == 'dec':
    #     sub_keys.reverse()

    crypted = 0
    i = 0

    gamma = generate_gamma(str_as_int(iv), sub_keys)
    gamma ^= make_block_string(source[i:min(i + 8, len(source))])
    crypted |= gamma
    i += 8
    while i < len(source):
        gamma = generate_gamma(gamma, sub_keys)
        gamma ^= make_block_string(source[i:min(i + 8, len(source))])
        crypted <<= 64
        crypted |= gamma
        i += 8

    print(int_as_str(crypted))
    print(crypted)
    return int_as_str(crypted)
