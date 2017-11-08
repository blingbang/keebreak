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





def gen_credentials(password):
    creds_a = hashlib.sha256()
    creds_a.update(password.encode("utf-8"))

    creds_b = hashlib.sha256()
    creds_b.update((creds_a.digest()))
    return creds_b.digest()

#def gen_trans_credentials(credentials,trans_rounds,trans_seed):
#    while rounds > 0:
#        hashlib.


print(binascii.hexlify(gen_credentials("4567")))
print("\n","Masterseed:",master_seed_hex,"\n","Transformationseed:",trans_seed_hex,"\n","Transformation rounds:",trans_rounds_int)