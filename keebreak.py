import argparse
import binascii
import struct
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

def gen_credentials(password):
    creds_a = SHA256.new()
    creds_a.update(password.encode("utf-8"))

    creds_b = SHA256.new()
    creds_b.update((creds_a.digest()))

    return creds_b.digest()

def gen_trans_credentials(rounds, credentials, trans_seed, init_vector):

    trans_creds = SHA256.new()
    aes_cipher = AES.new(bytes(trans_seed), AES.MODE_ECB)
    aes_a = aes_cipher.encrypt(credentials)

    while True:
        aes_a = aes_cipher.encrypt(aes_a)
        rounds -= 1
        if rounds == 0:
            break

    trans_creds.update(aes_a)

    return trans_creds.digest()

def gen_key(master_seed_hex, trans_creds_hex):

    key_a = SHA256.new()
    key_b = master_seed_hex
    key_c = trans_creds_hex

    key_a.update(key_b + key_c)

    return key_a.digest()

def decrypt(key, crypt_init_vector_hex, crypt_data_hex):

    decrypt_cipher = AES.new(key, AES.MODE_CBC, crypt_init_vector_hex)

    decrypt_a = decrypt_cipher.decrypt(crypt_data_hex)

    return decrypt_a


class KbdxHeader():
    def __init__(self, data):
        self.entries = []

        self._read_entry(data)

    def _read_entry(self, entry):
        e_id = entry[0]
        e_len = struct.unpack('<H', entry[1:3])[0]
        e_data = entry[3:e_len + 3]
        e_cryptdata = entry[3:e_len + 31]

        if e_id != 0:
            self.entries.append((e_id, len(e_data), e_data))
            self._read_entry(entry[3 + e_len:])

        if e_id == 0:
            self.entries.append((e_id, len(e_cryptdata), e_cryptdata))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Crack a KeePass-database')
    parser.add_argument('file', help='KeePass file')
    args = parser.parse_args()

    with open(args.file, 'rb') as f:
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
        trans_rounds_int = int.from_bytes(trans_rounds, byteorder='little')
    
        crypt_init_vector_tup = header.entries[5]
        crypt_init_vector_len = crypt_init_vector_tup[1]
        crypt_init_vector = crypt_init_vector_tup[2]
        crypt_init_vector_hex = binascii.hexlify(crypt_init_vector)
    
        start_bytes_tup = header.entries[6]
        start_bytes_len = start_bytes_tup[1]
        start_bytes = start_bytes_tup[2]
        start_bytes_hex = binascii.hexlify(start_bytes)
    
        crypt_data_tup = header.entries[9]
        crypt_data = crypt_data_tup[2]
        crypt_data_hex = binascii.hexlify(crypt_data)
    
    print(header.entries)
    print("\n", "Masterseed:", master_seed_hex, "\n", "Transformationseed:", trans_seed_hex, "\n", "Transformation rounds:",
          trans_rounds_int)
    print(' AES init vector', crypt_init_vector_hex)
    print(' First 32b decrypted data:', start_bytes_hex)
    print(' First 32b encrypted data:', crypt_data_hex)
    
    print(' GenCreds testoutput:', binascii.hexlify(gen_credentials("1111")))
    print(' GenTransCreds test:', binascii.hexlify(gen_trans_credentials(10000, gen_credentials("1111"), trans_seed, crypt_init_vector_hex)))
    print(' GenKey test:', binascii.hexlify(gen_key(master_seed_hex, gen_trans_credentials(10000, gen_credentials("1111"), trans_seed, crypt_init_vector_hex))))
    print('decrypt test: ')
