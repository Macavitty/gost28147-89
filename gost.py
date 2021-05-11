import math

# S-boxes used by the Central Bank of RF
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
BLOCK_SIZE_BITS = BLOCK_SIZE_BYTES * 8
KEY_SIZE_BYTES = 32
IV_SIZE_BYTES = 8


### Counts the number of bits needed to represent the number.
# @type n:   int
# @param n:  number
# @rtype:    int
# @return:   the number of bits for n
###
def get_num_bits(n):
    if n == 0:
        return 0
    return int((math.log(n) / math.log(2)) + 1)


### Converts string to its int representation.
# For each character as utf-8 gets its bits
# representation and forms a number
#
# @type s:      str
# @param s:     string to be converted
# @rtype:       int
# @return:      int representation of s
###
def str_as_int(s):
    if s == '':
        return 0
    num = 0
    for i in range(len(s)):
        num <<= 8
        num |= ord(s[i])
    return num


### Converts integer to its string representation.
# For each 8 bits gets its utf-8
# representation and forms a string

# @type num:      int
# @param num:     integer to be converted
# @rtype:         str
# @return:        string representation of num
###
def int_as_str(num):
    s = ''
    mask = 0xff
    i = 0
    l = num.bit_length()
    # starting from the lower bits
    # in order nit to miss leading zeros
    while i < l:
        s += chr(num & mask)
        num >>= 8
        i += 8
    return s[::-1]  # reversed string


### Fills block with trailing zeros if it doesn't fit BLOCK_SIZE_BITS.
# @type block:   str
# @param block:  block to be filled
# @rtype:        str
# @return:       formatted block
###
def make_block(block):
    if isinstance(block, str):
        block_bytes = len(block)
        needed_bits = int(BLOCK_SIZE_BYTES - block_bytes) * 8
        return str_as_int(block) << needed_bits

    raise ValueError('expected str')


### The f function described in the gost.
# @type part:       int
# @param part:      left or right part of the block
# @type subkey:     int
# @param subkey:    subkey for current iteration
# @rtype:           int
# @return:          result of f
###
def f(part, subkey):
    mod32 = 0x100000000

    # sum modulo 2^32
    part += subkey
    if part >= mod32:
        part -= mod32

    # performing substitution with s-boxes nodes
    mask = 0xf0000000
    res = 0
    for i in range(8):
        ind = (part & mask) >> 28
        part <<= 4
        res <<= 4
        res |= s_box[i][ind]
    # result is shifted left by 11 bits
    return ((res >> (32 - 11)) | (res << 11)) & 0xffffffff


### Implementation of the Feistel cipher .
# @type block:      str
# @param block:     block to be ciphered
# @type sub_keys:   list
# @param sub_keys:  list of sub keys ordered for operation (encryption/decryption)
# @rtype:           int
# @return:          computed gamma
###
def compute_gamma(block, sub_keys):
    left = block >> 32
    right = block & 0xffffffff

    for i in range(32):
        tmp_left = right ^ f(left, sub_keys[i])
        right = left
        left = tmp_left
    return (left << 32) | right


### Creates subkeys from the key.
# Subkeys would be ordered for encryption like following:
# k0, k1, k2, k3, k4, k5, k6, k7,  k0, k1, k2, k3, k4, k5, k6, k7,
# k0, k1, k2, k3, k4, k5, k6, k7,  k7, k6, k5, k4, k3, k2, k1, k0

# @type key:   str
# @param key:  the key given by user
# @rtype:      list
# @return:     list of sub_keys
###
def get_sub_keys(key):
    key_list = []
    sub_keys = []
    i = 0
    while i < KEY_SIZE_BYTES:
        key_list.append(str_as_int(key[i: i + 4]))
        sub_keys.insert(0, key_list[len(key_list) - 1])
        i += 4

    for i in range(0, 24):
        sub_keys.insert(0, key_list[(23 - i) % len(key_list)])

    return sub_keys


### Performs encryption or decryption.
# @type source:     str
# @param source:    open or encrypted text, provided by user
# @type key:        str
# @param key:       the key, provided by user
# @type iv:         str
# @param iv:        "синхропосылка" - starting gamma, provided by user
# @type operation:  str
# @param operation: operation to perform must be "enc" or "dec"
# @rtype:           str
# @return:          encrypted or decrypted text
###
def gost(source, key, iv, operation='enc'):
    assert len(key) == KEY_SIZE_BYTES, f'Your key is {len(key)} bytes but must be {KEY_SIZE_BYTES} bytes'
    assert len(iv) == IV_SIZE_BYTES, f'iv must be {IV_SIZE_BYTES} bytes'
    assert operation == 'enc' or operation == 'dec', f'Unsupported operation: {operation}'

    sub_keys = get_sub_keys(key)
    # if operation == 'dec':
    #     sub_keys.reverse()

    result = 0
    i = 0

    # first iteration with iv
    gamma = compute_gamma(str_as_int(iv), sub_keys)
    gamma ^= make_block(source[i:min(i + BLOCK_SIZE_BYTES, len(source))])
    result |= gamma

    # for other part of text
    i += BLOCK_SIZE_BYTES
    while i < len(source):
        gamma = compute_gamma(gamma, sub_keys)
        gamma ^= make_block(source[i:min(i + BLOCK_SIZE_BYTES, len(source))])
        result <<= BLOCK_SIZE_BITS
        result |= gamma
        i += BLOCK_SIZE_BYTES

    return int_as_str(result)
