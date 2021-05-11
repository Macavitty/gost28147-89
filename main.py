import filecmp
import os
import sys
from ggost import *
from gost import *


### Reads file safely.
# @type path:   str
# @param path:  the path to file to be read
# @rtype:       str or None
# @return:      file content if file exists and not empty, None otherwise
###
def read(path):
    if not os.path.exists(path):
        print(f'No such file: "{path}"')
        return None

    f = open(path, 'r')
    content = f.read()
    f.close()

    if content == '':
        print(f'File "{path}" is empty')
        return None

    return content


### Rewrites file safely.
# @type path:       str
# @param path:      the path to file to be rewritten
# @type content:    str
# @param content:   content to be written
###
def writе(path, content):
    f = open(path, 'w')
    f.write(str(content))
    f.close()


### Compares two files.
# @type f1:     str
# @param f1:    the first file to be compared
# @type f2:     str
# @param f2:    the second file to be compared
# @rtype:       boolean
# @return:      True if files contents are equal, False otherwise
###
def compare(f1, f2):
    return filecmp.cmp(f1, f2)


### Example of the gost28147-89 usage.
# Used files:
# file "source"         contains open text
# file "key"            contains 32-byte key
# file "iv"             contains 8-byte iv (named as "синхропосылка" in the gost)
# file "encrypted"      contains encrypted text
# file "decrypted"      contains decrypted text
###
if __name__ == '__main__':
    encrypted_file = 'encrypted'
    decrypted_file = 'decrypted'
    source_file = 'source'
    key_file = 'key'
    iv_file = 'iv'

    source = read(source_file)
    if source is None:
        sys.exit(2)

    key = read(key_file)
    if key is None:
        sys.exit(2)

    iv = read(iv_file)
    if iv is None:
        sys.exit(2)

    print(f'Encrypting file "{source_file}"...')
    write('encrypted', gost(source, key, iv, operation='enc'))
    print(f'Encryption completed successfully: result in file "{encrypted_file}"')

    encrypted = read('encrypted')
    if encrypted is None:
        print(f'Could not perform further decryption due to error above')
        sys.exit(2)

    print(f'Decrypting file "encrypted"')
    write('decrypted', gost(encrypted, key, iv, operation='dec'))
    if compare(source_file, decrypted_file):
        print(f'Decrypted successfully: files "{source_file}" and "{decrypted_file}" are equal')
    else:
        print(f'Decryption failed: files "{source_file}" and "{decrypted_file}" differ')
