# ADVANCED ENCRYPTION STANDARD (AES)
# NIST FIPS 197 - from https://doi.org/10.6028/NIST.FIPS.197-upd1
""" SPECIAL THANKS TO: https://legacy.cryptool.org/en/cto/aes-step-by-step"""
from typing import List, Any

import numpy
import os

from numpy import ndarray, dtype

# SBox() as 2D array
s_box = [
    [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
]

# inverse SBox() as 2D array
inv_s_box = [
    [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
    [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
    [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
    [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
    [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
    [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
    [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
    [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
    [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
    [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
    [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
    [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
    [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
    [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
    [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]
]

r_con: list[int] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A]


def print_hex(data):
    for row in data:
        hex_row = [f"{x:02x}" for x in row]  # Format each element as 2-digit hexadecimal
        print(" ".join(hex_row))  # Join the hex values with a space


def print_column_hex(data, col):
    column = data[:, col]  # Extract the column
    hex_column = [f'{x:02x}' for x in column]  # Convert each byte to 2-digit hex
    print(" ".join(hex_column))  # Print as a space-separated hex string


# applies a substitution table (S-box) to each byte.
def sub_bytes(state):
    for m in range(4):
        for n in range(4):
            hex_val = convert_dec_to_hex(state[m][n])

            # Extract x (row) and y (column) positions from the hex value
            x_hex = hex_val[0]  # Most significant hex digit (row)
            y_hex = hex_val[1]  # Least significant hex digit (column)

            # Convert hex positions to decimal
            x = int(x_hex, 16)
            y = int(y_hex, 16)

            state[m][n] = s_box[x][y]
    return state


# applies a substitution table (inverse S-box) to each byte.
def inverse_sub_bytes(state):
    for m in range(4):
        for n in range(4):
            hex_val = convert_dec_to_hex(state[m][n])

            # Extract x (row) and y (column) positions from the hex value
            x_hex = hex_val[0]  # Most significant hex digit (row)
            y_hex = hex_val[1]  # Least significant hex digit (column)

            # Convert hex positions to decimal
            x = int(x_hex, 16)
            y = int(y_hex, 16)

            state[m][n] = inv_s_box[x][y]
    return state


# shifts rows of the state array by different offsets.
def shift_rows(state):
    # shift state rows 2, 3, and 4
    state[1] = numpy.roll(state[1], -1)
    state[2] = numpy.roll(state[2], -2)
    state[3] = numpy.roll(state[3], -3)
    return state


# inverse shifts rows of the state array by different offsets.
def inverse_shift_rows(state):
    # shift state rows 2, 3, and 4
    state[1] = numpy.roll(state[1], 1)
    state[2] = numpy.roll(state[2], 2)
    state[3] = numpy.roll(state[3], 3)
    return state


# combines a round key with the state.
def add_roundkey(state, w):
    num_rows, num_cols = state.shape
    new_state = numpy.empty((num_rows, num_cols), dtype=int)

    for i in range(num_cols):
        new_state[:, i] = state[:, i] ^ w[:, i]
    return new_state


# shift word to left
def rot_word(word):
    return numpy.roll(word, -1)  # roll 1 to left


def convert_dec_to_hex(dec):
    # Convert decimal to hexadecimal (return a list of 2 elements)
    initial_value_hex = hex(dec)[2:]  # Remove '0x' prefix

    # Ensure the hex value is two digits (for x and y positions)
    if len(initial_value_hex) == 1:
        initial_value_hex = '0' + initial_value_hex

    return initial_value_hex


def sub_word(word):  # pass word as 4 elements array
    for i in range(4):
        hex_val = convert_dec_to_hex(word[i])

        # Extract x (row) and y (column) positions from the hex value
        x_hex = hex_val[0]  # Most significant hex digit (row)
        y_hex = hex_val[1]  # Least significant hex digit (column)

        # Convert hex positions to decimal
        x = int(x_hex, 16)
        y = int(y_hex, 16)

        new_val = s_box[x][y]  # lookup values in SBox
        word[i] = new_val  # replace by new values

    return word


def x_times(b):
    b = b & 0xFF  # Ensure b is within 0-255
    if b & 0x80:
        # If the most significant bit (MSB) is 1, perform modulus with AES polynomial
        return ((b << 1) ^ 0x1B) & 0xFF
    else:
        # If MSB is 0, just shift left by 1
        return (b << 1) & 0xFF


def multiply_by_2(b):
    return x_times(b)


def multiply_by_3(b):
    return x_times(b) ^ b


# Multiplication in GF(2^8) by 9, 11, 13, and 14 :: 09, 0b, 0d, 0e
def multiply_by_9(b):
    return x_times(x_times(x_times(b))) ^ b  # 9 = 2^3 + 1


def multiply_by_11(b):
    return x_times(x_times(x_times(b)) ^ b) ^ b  # 11 = 2^3 + 2 + 1


def multiply_by_13(b):
    return x_times(x_times(x_times(b) ^ b)) ^ b  # 13 = 2^3 + 2^2 + 1


def multiply_by_14(b):
    return x_times(x_times(x_times(b) ^ b) ^ b)  # 14 = 2^3 + 2^2 + 2


# MixColumns function for a single column
def mix_single_column(column):
    # matrix for reference:
    transform_matrix = numpy.array([
        [2, 3, 1, 1],
        [1, 2, 3, 1],
        [1, 1, 2, 3],
        [3, 1, 1, 2]
    ])

    return numpy.array([
        multiply_by_2(column[0]) ^ multiply_by_3(column[1]) ^ column[2] ^ column[3],
        column[0] ^ multiply_by_2(column[1]) ^ multiply_by_3(column[2]) ^ column[3],
        column[0] ^ column[1] ^ multiply_by_2(column[2]) ^ multiply_by_3(column[3]),
        multiply_by_3(column[0]) ^ column[1] ^ column[2] ^ multiply_by_2(column[3])
    ])


# Inverse MixColumns function for a single column
def inverse_mix_single_column(column):
    # matrix for reference:
    transform_matrix = numpy.array([
        [0x0e, 0x0b, 0x0d, 0x09],
        [0x09, 0x0e, 0x0b, 0x0d],
        [0x0d, 0x09, 0x0e, 0x0b],
        [0x0b, 0x0d, 0x09, 0x0e]
    ])  # 9, 11, 13, and 14 :: 09, 0b, 0d, 0e

    return numpy.array([
        multiply_by_14(column[0]) ^ multiply_by_11(column[1]) ^ multiply_by_13(column[2]) ^ multiply_by_9(column[3]),
        multiply_by_9(column[0]) ^ multiply_by_14(column[1]) ^ multiply_by_11(column[2]) ^ multiply_by_13(column[3]),
        multiply_by_13(column[0]) ^ multiply_by_9(column[1]) ^ multiply_by_14(column[2]) ^ multiply_by_11(column[3]),
        multiply_by_11(column[0]) ^ multiply_by_13(column[1]) ^ multiply_by_9(column[2]) ^ multiply_by_14(column[3])
    ])


# MixColumns for the entire state matrix (4x4 matrix)
def mix_columns(state):
    for i in range(4):
        # Apply mix_single_column to each column of the state matrix
        state[:, i] = mix_single_column(state[:, i])
    return state


# Inverse MixColumns for the entire state matrix (4x4 matrix)
def inverse_mix_columns(state):
    for i in range(4):
        state[:, i] = inverse_mix_single_column(state[:, i])
    return state


# a routine that is applied to the key to generate 4 ∗ (Nr + 1) words.
"""AES Key Expansion Algorithm.

    The AES key expansion algorithm takes as input a four-word (16-byte) key and produces a linear array of
    44 words (176 bytes).

    Args:
        key (bytes): 
            Key to expand
        
        n_k:
            key size: i.e.: NK is the number of four-byte words that are in the original cipher key (4, 6, or 8)

    Returns:
        w: Array of words of the expanded key

    n_r:
        number of rounds (10 for AES-128)

    r_con: Round Constants = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
        (can be computed from the algorithm: 2i-1 << 24 in Galois Field)
    """


def key_expansion(key, n_k, n_r):
    n_words = 4 * (n_r+1)
    w = numpy.empty((4, n_words), dtype=int)
    i = 0
    while i < n_k:  # for the first 4 words (1st subkey), the expanded key is identical
        w[:, i] = key[:, i]  # copy first 4 columns identically
        i = i + 1
    # after i = 4 (starting 2nd subkey), we don't do an identical copy.
    # instead, we do some extra steps: rotate, substitute and XOR with round constant r_con.
    while i < n_words:  # number of words in expanded key 44*4=176
        # XORing the previous word by the word at index i - nk
        temp = w[:, i - 1]  # the previous word
        if i % n_k == 0:
            temp = rot_word(temp)
            temp = sub_word(temp)
            temp[0] = temp[0] ^ r_con[i // n_k - 1]

        elif n_k > 6 and i % n_k == 4:
            temp = sub_word(temp)
        w[:, i] = w[:, i - n_k] ^ temp
        i = i + 1
    return w


def cipher(state, n_r, w):
    # initial round
    state = add_roundkey(state, w[:, 0:4])

    # nr-1 rounds in loop
    for round in range(1, n_r):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_roundkey(state, w[:, (4 * round):(4 * round) + 4])

    # final round
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_roundkey(state, w[:, 4 * n_r:(4 * n_r) + 4])

    return state


def inverse_cipher(state, n_r, w):
    state = add_roundkey(state, w[:, 4 * n_r:(4 * n_r) + 4])

    # n_r-1 rounds in loop
    for round in range(n_r - 1, 0, -1):
        state = inverse_shift_rows(state)
        state = inverse_sub_bytes(state)
        state = add_roundkey(state, w[:, (4 * round):(4 * round) + 4])
        state = inverse_mix_columns(state)

    # final round
    state = inverse_shift_rows(state)
    state = inverse_sub_bytes(state)
    state = add_roundkey(state, w[:, 0:4])

    return state


def aes_encrypt_decrypt(key_size_bits, key, state):
    # Determine n_k and n_r based on key_size_bits
    if key_size_bits == 128:
        n_k = 4
        n_r = 10  # AES-128 has 10 rounds, so n_r = 10 + 1
    elif key_size_bits == 192:
        n_k = 6
        n_r = 12  # AES-192 has 12 rounds, so n_r = 12 + 1
    elif key_size_bits == 256:
        n_k = 8
        n_r = 16  # AES-256 has 14 rounds, so n_r = 14 + 1
    else:
        raise ValueError("Invalid key size. Must be 128, 192, or 256 bits.")

    # Expand the key
    expanded_key = key_expansion(key, n_k=n_k, n_r=n_r)

    # Encrypt
    ciphertext = cipher(state.copy(), n_r=n_r, w=expanded_key)

    # Decrypt
    decrypted = inverse_cipher(ciphertext.copy(), n_r=n_r, w=expanded_key)

    return ciphertext, decrypted


if __name__ == '__main__':
    # ~~~~~~~~~~~~~~~128bit EXAMPLE~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    n_k = 4
    # get n_k
    if n_k == 4:
        n_r = 10
    elif n_k == 6:
        n_r = 12
    elif n_k == 8:
        n_r = 14

    # Example 128-bit state (16 bytes)
    # hex: 29 34 3f 4a 0f 1a 25 58 63 0a 0b 0c 0d 0e 0f 10
    state = numpy.array([[41, 52, 63, 74],
                         [15, 26, 37, 88],
                         [99, 10, 11, 12],
                         [13, 14, 15, 16]])
    state = state.transpose()

    # Example 128-bit key (16 bytes)
    # string: aesEncryptionKey
    key = numpy.array([[0x2b, 0x7e, 0x15, 0x16],
                       [0x28, 0xae, 0xd2, 0xa6],
                       [0xab, 0xf7, 0xcf, 0x5d],
                       [0x22, 0x1f, 0x3b, 0x30]])
    key = key.transpose()

    print("state:")
    print_hex(state)
    print("key:")
    print_hex(key)
    # Flatten the array and convert to hexadecimal string
    key_string = ''.join(f'{byte:02x}' for byte in key.flatten())
    print("key_string:", key_string)  # hex key: 2b7e151628aed2a6abf7cf5d221f3b30

    # ~~~~~~~~~~~~~~~GET THE EXPANDED KEY~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    expanded_key = key_expansion(key, n_k=n_k, n_r=n_r)
    print("expanded key:")
    print_hex(expanded_key)
    print(expanded_key.shape)
    # ~~~~~~~~~~~~~~~GET THE CIPHER~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    ciphertext = cipher(state, n_r=n_r, w=expanded_key)

    # ~~~~~~~~~~~~~~~DECRYPT THE CIPHER~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    decrypted = inverse_cipher(ciphertext, n_r=n_r, w=expanded_key)



    print("cipher:")
    print_hex(ciphertext)
    print("decrypted:")
    print_hex(decrypted)

    # ~~~~~~~~~~~~~~~192-bit EXAMPLE~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    n_k = 6
    n_r = 12  # AES-192 has 12 rounds, so n_r = 12 + 1 = 13

    # Example 192-bit key (24 bytes)
    key = numpy.array([
        [0x8e, 0x73, 0xb0, 0xf7],
        [0xda, 0x0e, 0x64, 0x52],
        [0xc8, 0x10, 0xf3, 0x2b],
        [0x80, 0x90, 0x79, 0xe5],
        [0x62, 0xf8, 0xea, 0xd2],
        [0x52, 0x2c, 0x6b, 0x7b]
    ])
    key = key.transpose()

    # Example state (can be the same as in the 128-bit example)
    state = numpy.array([
        [41, 52, 63, 74],
        [15, 26, 37, 88],
        [99, 10, 11, 12],
        [13, 14, 15, 16]
    ])
    state = state.transpose()

    expanded_key = key_expansion(key, n_k=n_k, n_r=n_r)

    ciphertext = cipher(state, n_r=n_r, w=expanded_key)
    decrypted = inverse_cipher(ciphertext, n_r=n_r, w=expanded_key)

    print("192-bit AES:")
    print("Input Text:")
    print_hex(state)
    print("Ciphertext:")
    print_hex(ciphertext)
    print("Decrypted:")
    print_hex(decrypted)

    # ~~~~~~~~~~~~~~~256-bit EXAMPLE~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    n_k = 8
    n_r = 14  # AES-256 has 14 rounds, so n_r = 14 + 1 = 15

    # Example 256-bit key (32 bytes)
    key = numpy.array([
        [0x60, 0x3d, 0xeb, 0x10],
        [0x15, 0xca, 0x71, 0xbe],
        [0x2b, 0x73, 0xae, 0xf0],
        [0x85, 0x7d, 0x77, 0x81],
        [0x1f, 0x35, 0x2c, 0x07],
        [0x3b, 0x61, 0x08, 0xd7],
        [0x2d, 0x98, 0x10, 0xa3],
        [0x09, 0x14, 0xdf, 0xf4]
    ])
    key = key.transpose()

    # Example state (can be the same as in the 128-bit example)
    state = numpy.array([
        [41, 52, 63, 74],
        [15, 26, 37, 88],
        [99, 10, 11, 12],
        [13, 14, 15, 16]
    ]).transpose()

    expanded_key = key_expansion(key, n_k=n_k, n_r=n_r)

    ciphertext = cipher(state, n_r=n_r, w=expanded_key)
    decrypted = inverse_cipher(ciphertext, n_r=n_r, w=expanded_key)

    print("256-bit AES:")
    print("Input Text:")
    print_hex(state)
    print("Ciphertext:")
    print_hex(ciphertext)
    print("Decrypted:")
    print_hex(decrypted)




    #print(os.urandom(16))