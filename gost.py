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

BLOCK_SIZE_BITS = 64
BLOCK_SIZE_BYTES = BLOCK_SIZE_BITS / 8
KEY_SIZE_BYTES = 32


def get_num_bits(n):
    if n == 0:
        return 0
    return int((math.log(n) / math.log(2)) + 1)


def str_to_int(string):
    if string == '':
        return 0
    return int(''.join(format(ord(i), 'd') for i in string))


def make_block_size(block):
    if isinstance(block, str):
        block = str_to_int(block)

    if isinstance(block, int):
        block_bits = get_num_bits(block)
        assert block_bits <= BLOCK_SIZE_BITS, 'Your block size is ' + str(block_bits) + ' bits but mush be ' + str(
            BLOCK_SIZE_BITS) + ' bits or less'
        return block << BLOCK_SIZE_BITS - block_bits

    raise ValueError('expected str or int')


def f(part, key):
    mod32 = 0x100000000
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
    return ((res >> 11) | (res << (32 - 11))) & 0xffffffff


def generate_gamma(block, sub_keys):
    block_bits = get_num_bits(block)
    assert block_bits <= BLOCK_SIZE_BITS, 'Your block size is ' + str(
        block_bits) + ' bits but mush be ' + str(
        BLOCK_SIZE_BITS) + ' bits or less'
    block <<= BLOCK_SIZE_BITS - block_bits
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
    key = int(key)
    for i in range(8):
        key_list.insert(0, key & 0xffffffff)
        sub_keys.append(key_list[0])
        key >>= 32

    for i in range(0, 24):
        sub_keys.insert(0, key_list[(23 - i) % len(key_list)])

    return sub_keys


def encrypt(source, key, starting_gamma):
    sub_keys = get_sub_keys(key)
    gamma = int(starting_gamma)
    encrypted = ''
    i = 0

    source_as_bits = ''.join(format(ord(i), 'b') for i in source)
    print('source_as_bits: ' + source_as_bits)

    # source_bits = get_num_bits(int((''.join(format(ord(i), 'd') for i in source))))
    #
    # print('source_bits: ' + str(source_bits))
    # print('len(source_as_bits): ' + str(len(source_as_bits)))

    gamma = generate_gamma(gamma, sub_keys)
    gamma |= make_block_size(source[i:min(i + BLOCK_SIZE_BITS, source_bits)])
    encrypted += str(gamma)
    i += BLOCK_SIZE_BITS
    while i < source_bits:
        gamma = generate_gamma(gamma, sub_keys)
        gamma |= make_block_size(source[i:min(i + BLOCK_SIZE_BITS, source_bits)])
        print('i: ' + str(i))
        print('i+BLOCK_SIZE: ' + str(i + BLOCK_SIZE_BITS))
        print("current block: '" + source[i:min(i + BLOCK_SIZE_BITS, source_bits)] + "'")
        print("current block as int: '" + str(str_to_int(source[i:min(i + BLOCK_SIZE_BITS, source_bits)])) + "'")
        print("current block size in bits: " + str(get_num_bits(str_to_int(source[i:min(i + BLOCK_SIZE_BITS, source_bits)]))))
        print("current block fitted: " + str(make_block_size(source[i:min(i + BLOCK_SIZE_BITS, source_bits)])))
        print("current block fitted size in bits: " + str(get_num_bits(make_block_size(source[i:min(i + BLOCK_SIZE_BITS, source_bits)]))))
        print(make_block_size(source[i:min(i + BLOCK_SIZE_BITS, source_bits)]))
        print(str_to_int(source[i:min(i + BLOCK_SIZE_BITS, source_bits)]))
        encrypted += str(gamma)
        i += BLOCK_SIZE_BITS

    return gamma


def decrypt():
    print('decrypt')
