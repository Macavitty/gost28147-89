from gost import *
import uuid


def read(path):
    f = open(path, 'r')
    content = f.read()
    f.close()
    return content


def write(path, content):
    f = open(path, 'w')
    f.write(str(content))
    f.close()


if __name__ == '__main__':
    source = read('source')
    key = read('key')

    # starting_gamma = uuid.uuid1().int >> 64
    iv = read('iv')
    print(source)
    write('encrypted', gost(source, key, iv, operation='enc'))
    encrypted = read('encrypted')
    write('decrypted', gost(encrypted, key, iv, operation='dec'))

