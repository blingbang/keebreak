import struct
import binascii
import hashlib

class KbdxHeader():
    def __init__(self, data):
        self.entries = []
        self._read_entry(data)

    def _read_entry(self, entry):
        e_id = entry[0]
        e_len = struct.unpack('<H', entry[1:3])[0]
        e_data = entry[3:e_len + 3]

        if e_id != 0:
            self.entries.append((e_id, len(e_data), e_data))
            self._read_entry(entry[3 + e_len:])

with open('databases/Matthias_Kroell.kdbx', 'rb') as f:
    f_bytes = bytearray(f.read())
    f_body = f_bytes[3 * 4:]

    header = KbdxHeader(f_body)

    master_seed_tup = header.entries[2]
    master_seed_len = master_seed_tup[1]
    master_seed = master_seed_tup[2]
    master_seed_hex = binascii.hexlify(master_seed)

    trans_seed_tup = header.entries[3]
    trans_seed_len = trans_seed_tup[1]
    trans_seed = trans_seed_tup[2]
    trans_seed_hex = binascii.hexlify(trans_seed)

    trans_rounds = (header.entries[4])[2]
    trans_rounds_int = int.from_bytes(trans_rounds,byteorder='little')

#    crypt_init_vector_tup = header.entries[7]
#    crypt_init_vector_len = crypt_init_vector_tup[1]


    print("\n","Masterseed:",master_seed_hex,"\n","Transformationseed:",trans_seed_hex,"\n","Transformation rounds:",trans_rounds_int)


def gen_credentials(password):
    pw = password.encode("utf-8")
    credentials = hashlib.sha256(hashlib.sha256(pw))
    return credentials

#def gen_trans_credentials(credentials,trans_rounds,trans_seed):
#    while rounds > 0:
#        hashlib.

print(gen_credentials("1111"))