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


def get_key(keyfilepath):
    key = read(keyfilepath)
    assert len(key) != 0, 'Empty key file'
    return key


if __name__ == '__main__':
    source = read('source')
    key = get_key('key')
    i = 10
    starting_gamma = uuid.uuid1().int >> 64
    # print("Starting gamma is " + str(starting_gamma))
    write('encrypted',   encrypt(source, key, starting_gamma))
