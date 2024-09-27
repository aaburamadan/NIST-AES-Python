import numpy as np
from AES import key_expansion, cipher, print_hex

"""
    CFB mode encrypts the plaintext by encrypting the IV
    The encrypted bits are divided as a set of s and b-s bits.
    The left-hand side s bits are selected along with the plaintext to which an XOR operation is applied. 
    The result is given as input to a shift register having b-s bits to left-hand-side,s bits to right-hand-side
    and the shift register is encrypted to get the next s bits.

    CFB mode is a stream cipher, so it encrypts one byte at a time and updating the shift register accordingly.
    CFB mode is not random access, meaning that each block must be decrypted in order.
    
    This implementation is using bytes as the smallest unit.
"""


def xor_bytes(a, b):
    return np.bitwise_xor(a, b)

def cfb_encrypt(plaintext, key, iv, n_k, n_r, s=16):
    # s is the number of bits per segment
    b = key.size * 8  # Length of the shift register in bits

    # Expand the key
    expanded_key = key_expansion(key, n_k=n_k, n_r=n_r)

    # Initialize shift register (flattened to a 1D array)
    shift_reg = iv.transpose().flatten()
    s_bytes = s // 8  # Number of bytes per segment

    # Flatten the plaintext to process s bits at a time
    plaintext_bytes = plaintext.transpose(0, 2, 1).flatten()

    # Encrypt each segment
    ciphertext = []
    for i in range(0, len(plaintext_bytes), s_bytes):
        # Encrypt the shift register
        sr_block = shift_reg.reshape(4, 4).transpose()
        encrypted_shift_reg = cipher(sr_block, n_r=n_r, w=expanded_key)
        # flatten to extract bytes easier
        encrypted_shift_reg_bytes = encrypted_shift_reg.transpose().flatten()

        # Extract the first s bytes from the encrypted shift register
        selected_bits = encrypted_shift_reg_bytes[:s_bytes]

        # Get s bytes from plaintext
        plaintext_segment = plaintext_bytes[i:i+s_bytes]

        # XOR with plaintext segment
        encrypted_segment = xor_bytes(plaintext_segment, selected_bits)
        ciphertext.extend(encrypted_segment)

        # Update the shift register
        shift_reg = np.concatenate((shift_reg[s_bytes:], encrypted_segment))

    # Reshape ciphertext back to original plaintext shape
    ciphertext_array = np.array(ciphertext, dtype=np.uint8)
    ciphertext_array = ciphertext_array.reshape(plaintext.shape)

    return ciphertext_array

def cfb_decrypt(ciphertext, key, iv, n_k, n_r, s=16):
    # s is the number of bits per segment
    b = key.size * 8  # Length of the shift register in bits

    # Expand the key
    expanded_key = key_expansion(key, n_k=n_k, n_r=n_r)

    # Initialize shift register (flattened to a 1D array)
    shift_reg = iv.transpose().flatten()
    s_bytes = s // 8  # Number of bytes per segment

    # Flatten the ciphertext to process s bits at a time
    ciphertext_bytes = ciphertext.flatten()

    # Decrypt each segment
    plaintext = []
    for i in range(0, len(ciphertext_bytes), s_bytes):
        # Encrypt the shift register
        sr_block = shift_reg.reshape(4, 4).transpose()
        encrypted_shift_reg = cipher(sr_block, n_r=n_r, w=expanded_key)
        encrypted_shift_reg_bytes = encrypted_shift_reg.transpose().flatten()

        # Extract the first s bytes
        selected_bits = encrypted_shift_reg_bytes[:s_bytes]

        # Get s bytes from ciphertext
        ciphertext_segment = ciphertext_bytes[i:i + s_bytes]

        # XOR with ciphertext segment to get plaintext segment
        plaintext_segment = xor_bytes(ciphertext_segment, selected_bits)
        plaintext.extend(plaintext_segment)

        # Update the shift register
        shift_reg = np.concatenate((shift_reg[s_bytes:], ciphertext_segment))

    # Reshape plaintext back to original shape
    plaintext_array = np.array(plaintext, dtype=np.uint8)
    plaintext_array = plaintext_array.reshape(ciphertext.shape)
    plaintext_array = plaintext_array.transpose(0, 2, 1)

    return plaintext_array


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

    # 8, 16, 32, 64 bits are used for s
    # shift register size is typically 128 bits in AES (key size)
    # in DES it is 64 bits
    ciphertext = cfb_encrypt(plaintext, key, iv, n_k, n_r, s=32)
    decrypted_text = cfb_decrypt(ciphertext, key, iv, n_k, n_r, s=32)

    print("CFB AES 128bit:")
    print("Plaintext:")
    for block in plaintext:
        print_hex(block)

    print("Ciphertext:")
    for block in ciphertext:
        print_hex(block)

    print("Decrypted text:")
    for block in decrypted_text:
        print_hex(block)

