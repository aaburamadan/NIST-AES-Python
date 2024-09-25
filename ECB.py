import numpy as np
from AES import key_expansion, cipher, inverse_cipher, print_hex


def ecb_encrypt(plaintext, key, n_k, n_r):
    # Expand the key
    expanded_key = key_expansion(key, n_k=n_k, n_r=n_r)

    # Encrypt each block
    ciphertext = []
    for block in plaintext:
        encrypted_block = cipher(block, n_r=n_r, w=expanded_key)
        ciphertext.append(encrypted_block)

    return np.array(ciphertext)


def ecb_decrypt(ciphertext, key, n_k, n_r):
    # Expand the key
    expanded_key = key_expansion(key, n_k=n_k, n_r=n_r)

    # Decrypt each block
    decrypted_text = []
    for block in ciphertext:
        decrypted_block = inverse_cipher(block, n_r=n_r, w=expanded_key)
        decrypted_text.append(decrypted_block)

    return np.array(decrypted_text)


# Example usage
if __name__ == "__main__":
    # Example 128-bit key (16 bytes)
    key = np.array([
        [0x2b, 0x7e, 0x15, 0x16],
        [0x28, 0xae, 0xd2, 0xa6],
        [0xab, 0xf7, 0xcf, 0x5d],
        [0x22, 0x1f, 0x3b, 0x30]
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

    ciphertext = ecb_encrypt(plaintext, key, n_k, n_r)
    decrypted_text = ecb_decrypt(ciphertext, key, n_k, n_r)

    print("ECB AES 128bit:")
    print("Plaintext:")
    for block in plaintext:
        print_hex(block)

    print("Ciphertext:")
    for block in ciphertext:
        print_hex(block)

    print("Decrypted text:")
    for block in decrypted_text:
        print_hex(block)