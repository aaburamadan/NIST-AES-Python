import numpy as np
from AES import key_expansion, cipher, print_hex

"""
    OFB mode is similar to CFB mode, but instead of encrypting the previous block, we encrypt the IV again and again.
    The encrypted IV is XORed with the plaintext to produce the ciphertext.
    The decryption process is the same as the encryption process, so OFB mode is a stream cipher.
    The difference in decryption is that the CIPHERTEXT is XORed with the encrypted IV to recover the plaintext.
    OFB mode is parallelizable because each block can be encrypted independently.
    OFB mode is also random access, meaning that any block can be decrypted without having to decrypt the previous blocks.
"""


def xor_bytes(a, b):
    return np.bitwise_xor(a, b)

# input can be plaintext or ciphertext
def ofb_encrypt(input, key, iv, n_k, n_r):
    # Expand the key
    expanded_key = key_expansion(key, n_k=n_k, n_r=n_r)

    # Encrypt each block
    ciphertext = []
    feedback = iv # using iv nonce
    for block in input:
        feedback = cipher(feedback, n_r=n_r, w=expanded_key) # encrypt iv again and again
        encrypted_block = xor_bytes(block, feedback)
        ciphertext.append(encrypted_block)

    return np.array(ciphertext)

def ofb_decrypt(ciphertext, key, iv, n_k, n_r):
    # OFB decryption is the same as encryption
    # The difference is that the XOR operation is done to the ciphertext at decryption.
    return ofb_encrypt(ciphertext, key, iv, n_k, n_r)

# Example usage
if __name__ == "__main__":
    # Example 128-bit key (16 bytes)
    key = np.array([
        [0x2b, 0x7e, 0x15, 0x16],
        [0x28, 0xae, 0xd2, 0xa6],
        [0xab, 0xf7, 0xcf, 0x5d],
        [0x22, 0x1f, 0x3b, 0x30]
    ]).transpose()

    # Example IV (128-bit block)
    iv = np.array([
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

    ciphertext = ofb_encrypt(plaintext, key, iv, n_k, n_r)
    decrypted_text = ofb_decrypt(ciphertext, key, iv, n_k, n_r)

    print("OFB AES 128bit:")
    print("Plaintext:")
    for block in plaintext:
        print_hex(block)

    print("Ciphertext:")
    for block in ciphertext:
        print_hex(block)

    print("Decrypted text:")
    for block in decrypted_text:
        print_hex(block)