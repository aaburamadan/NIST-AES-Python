import numpy as np
from AES import key_expansion, cipher, print_hex

def xor_bytes(a, b):
    return np.bitwise_xor(a, b)

def increment_counter(counter):
    counter = counter.copy()
    for i in reversed(range(len(counter))):
        for j in reversed(range(len(counter[i]))):
            counter[i][j] += 1
            if counter[i][j] != 0:
                return counter
    return counter

def ctr_encrypt(plaintext, key, nonce, n_k, n_r):
    # Expand the key
    expanded_key = key_expansion(key, n_k=n_k, n_r=n_r)

    # Encrypt each block
    ciphertext = []
    counter = nonce
    for block in plaintext:
        encrypted_counter = cipher(counter, n_r=n_r, w=expanded_key)
        encrypted_block = xor_bytes(block, encrypted_counter)
        ciphertext.append(encrypted_block)
        counter = increment_counter(counter)

    return np.array(ciphertext)

def ctr_decrypt(ciphertext, key, nonce, n_k, n_r):
    # CTR decryption is the same as encryption
    return ctr_encrypt(ciphertext, key, nonce, n_k, n_r)

# Example usage
if __name__ == "__main__":
    # Example 128-bit key (16 bytes)
    key = np.array([
        [0x2b, 0x7e, 0x15, 0x16],
        [0x28, 0xae, 0xd2, 0xa6],
        [0xab, 0xf7, 0xcf, 0x5d],
        [0x22, 0x1f, 0x3b, 0x30]
    ]).transpose()

    # Example nonce (128-bit block)
    nonce = np.array([
        [0x00, 0x01, 0x02, 0x03],
        [0x04, 0x05, 0x06, 0x07],
        [0x08, 0x09, 0x0a, 0x0b],
        [0x0c, 0x0d, 0x0e, 0x0f]
    ]).transpose()

    # Example plaintext (multiple 128-bit blocks)
    plaintext = np.array([
        [
            [41, 52, 63, 74],
            [15, 26, 37, 88],
            [99, 10, 11, 12],
            [13, 14, 15, 16]
        ],
        [
            [17, 18, 19, 20],
            [21, 22, 23, 24],
            [25, 26, 27, 28],
            [29, 30, 31, 32]
        ]
    ]).transpose(0, 2, 1)

    n_k = 4  # Number of 32-bit words in the key (4 for 128-bit key)
    n_r = 10  # Number of rounds (10 for 128-bit key)

    ciphertext = ctr_encrypt(plaintext, key, nonce, n_k, n_r)
    decrypted_text = ctr_decrypt(ciphertext, key, nonce, n_k, n_r)

    print("CTR AES 128bit:")
    print("Plaintext:")
    for block in plaintext:
        print_hex(block)

    print("Ciphertext:")
    for block in ciphertext:
        print_hex(block)

    print("Decrypted text:")
    for block in decrypted_text:
        print_hex(block)