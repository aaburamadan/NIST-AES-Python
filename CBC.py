import numpy as np
from AES import key_expansion, cipher, inverse_cipher, print_hex

"""
    CBC mode encrypts the plaintext by XORing it with the previous ciphertext block before encryption.
    The first block is XORed with an initialization vector (IV) instead of a ciphertext block.
    This chaining of blocks ensures that the same plaintext block will not encrypt to the same ciphertext block.
    CBC mode is not parallelizable because each block depends on the previous block.
    CBC mode is not random access, meaning that each block must be decrypted in order.
"""

def xor_bytes(a, b):
    return np.bitwise_xor(a, b)

def cbc_encrypt(plaintext, key, iv, n_k, n_r):
    # Expand the key
    expanded_key = key_expansion(key, n_k=n_k, n_r=n_r)

    # Encrypt each block
    ciphertext = []
    previous_block = iv
    for block in plaintext:
        block = xor_bytes(block, previous_block)
        encrypted_block = cipher(block, n_r=n_r, w=expanded_key)
        ciphertext.append(encrypted_block)
        previous_block = encrypted_block

    return np.array(ciphertext)

def cbc_decrypt(ciphertext, key, iv, n_k, n_r):
    # Expand the key
    expanded_key = key_expansion(key, n_k=n_k, n_r=n_r)

    # Decrypt each block
    decrypted_text = []
    previous_block = iv
    for block in ciphertext:
        decrypted_block = inverse_cipher(block, n_r=n_r, w=expanded_key)
        decrypted_block = xor_bytes(decrypted_block, previous_block)
        decrypted_text.append(decrypted_block)
        previous_block = block

    return np.array(decrypted_text)


def cbc_decrypt_with_error(ciphertext, key, iv, n_k, n_r, error_block_idx=0, error_bit_mask=0x01):
    # Introduce an error in the ciphertext
    corrupted_ciphertext = ciphertext.copy()
    corrupted_ciphertext[error_block_idx][0][0] ^= error_bit_mask  # Flip a bit in the first block

    expanded_key = key_expansion(key, n_k=n_k, n_r=n_r)
    decrypted_text = []
    previous_block = iv
    for block in corrupted_ciphertext:
        decrypted_block = inverse_cipher(block, n_r=n_r, w=expanded_key)
        decrypted_block = xor_bytes(decrypted_block, previous_block)
        decrypted_text.append(decrypted_block)
        previous_block = block
    return np.array(decrypted_text)


def print_error_comparison(title, decrypted_correct, decrypted_with_error):
    print(f"\n--- {title} ---")
    print(f"{'Block':<10}{'Decrypted (With Error introduced in Block 1)':<32}")
    print("-" * 42)

    for i in range(len(decrypted_correct)):
        dec_correct = ' '.join(f'{byte:02x}' for byte in decrypted_correct[i].flatten())
        dec_error = ' '.join(f'{byte:02x}' for byte in decrypted_with_error[i].flatten())

        print(f"Block {i:<4} (Correct)   {dec_correct:<32}")
        print(f"Block {i:<4} (With Error) {dec_error:<32}")
        print("-" * 42)  # separator between blocks


def print_error_comparison_with_highlight(title, decrypted_correct, decrypted_with_error):
    print(f"\n--- {title} ---")
    print(f"{'Block':<10}{'Decrypted (With Error introduced in Block 1)':<48}")
    print("-" * 100)

    for i in range(len(decrypted_correct)):
        dec_correct = decrypted_correct[i].flatten()
        dec_error = decrypted_with_error[i].flatten()

        correct_str = []
        error_str = []

        # Compare byte by byte and add red highlighting for differences
        for j in range(len(dec_correct)):
            correct_str.append(f'{dec_correct[j]:02x}')

            if dec_correct[j] == dec_error[j]:
                error_str.append(f'{dec_error[j]:02x}')  # No change
            else:
                # Highlight the error in red
                error_str.append(f'\033[31m{dec_error[j]:02x}\033[0m')

        # Join the byte lists into strings
        correct_str = ' '.join(correct_str)
        error_str = ' '.join(error_str)

        print(f"Block {i:<4} (Correct)   {correct_str:<48}")
        print(f"Block {i:<4} (With Error) {error_str:<48}")
        print("-" * 100)


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
        ],
        [
            [33, 34, 35, 36],
            [37, 38, 39, 40],
            [41, 42, 43, 44],
            [45, 46, 47, 48]
        ],
        [
            [49, 50, 51, 52],
            [53, 54, 55, 56],
            [57, 58, 59, 60],
            [61, 62, 63, 64]
        ]
    ]).transpose(0, 2, 1)

    n_k = 4  # Number of 32-bit words in the key (4 for 128-bit key)
    n_r = 10  # Number of rounds (10 for 128-bit key)

    ciphertext = cbc_encrypt(plaintext, key, iv, n_k, n_r)
    decrypted_text = cbc_decrypt(ciphertext, key, iv, n_k, n_r)

    print("CBC AES 128bit:")
    print("Plaintext:")
    for block in plaintext:
        print_hex(block)

    print("Ciphertext:")
    for block in ciphertext:
        print_hex(block)

    print("Decrypted text:")
    for block in decrypted_text:
        print_hex(block)


    # ---
    # Example usage for CBC with error
    ciphertext = cbc_encrypt(plaintext, key, iv, n_k, n_r)
    decrypted_text_with_error = cbc_decrypt_with_error(ciphertext, key, iv, n_k, n_r)

    # comparison
    print_error_comparison_with_highlight("Error Comparison with Highlight", decrypted_text, decrypted_text_with_error)
