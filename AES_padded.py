import numpy as np
from AES import key_expansion, cipher, inverse_cipher, print_hex


# padding and unpadding functions using PKCS#7
def pad(plaintext, block_size=16):
    """ functionality:
        - pad: pads the input plaintext with PKCS#7 padding
            - calculates the padding length and appends the appropriate number of bytes to the input plaintext.
    """
    padding_len = block_size - (len(plaintext) % block_size)
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding


def unpad(padded_plaintext, block_size=16):
    """ unpad: removes PKCS#7 padding from the input padded plaintext
        - Functionality:
        Checks for empty input, validates the padding length,
            and ensures all padding bytes are correct before removing them.
        - Security:
        Properly validates padding to prevent padding oracle attacks.
    """
    if not padded_plaintext:
        raise ValueError("The input data is empty")
    padding_len = padded_plaintext[-1]
    if padding_len < 1 or padding_len > block_size:
        raise ValueError("Invalid padding length")
    if padded_plaintext[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid padding bytes")
    return padded_plaintext[:-padding_len]


def initialize_aes(input_string, key_size, mode):
    key_sizes = {128: 4, 192: 6, 256: 8}
    rounds = {128: 10, 192: 12, 256: 14}

    if key_size not in key_sizes:
        raise ValueError("Invalid key size. Choose from 128, 192, or 256.")

    n_k = key_sizes[key_size]
    n_r = rounds[key_size]

    key = np.random.randint(0, 256, (4, n_k), dtype=np.uint8)
    iv = np.random.randint(0, 256, (4, 4), dtype=np.uint8)

    plaintext = pad(input_string.encode('utf-8'))
    # Convert plaintext to 4x4 blocks
    # The input bytes are arranged column-wise into this state matrix.
    # By transposing the plaintext blocks, we're aligning the data correctly for AES operations.
    # necessary because of the way (cipher, inverse_cipher, etc.) functions are implemented.
    plaintext_blocks = np.frombuffer(plaintext, dtype=np.uint8).reshape(-1, 4, 4).transpose(0, 2, 1)

    return key, iv, plaintext_blocks, n_k, n_r, mode


def encrypt(plaintext, key, iv, n_k, n_r, mode):
    if mode == 'ECB':
        from ECB import ecb_encrypt
        return ecb_encrypt(plaintext, key, n_k, n_r)
    elif mode == 'CBC':
        from CBC import cbc_encrypt
        return cbc_encrypt(plaintext, key, iv, n_k, n_r)
    elif mode == 'CFB':
        from CFB import cfb_encrypt
        return cfb_encrypt(plaintext, key, iv, n_k, n_r)
    elif mode == 'OFB':
        from OFB import ofb_encrypt
        return ofb_encrypt(plaintext, key, iv, n_k, n_r)
    elif mode == 'CTR':
        from CTR import ctr_encrypt
        return ctr_encrypt(plaintext, key, iv, n_k, n_r)
    else:
        raise ValueError("Invalid mode. Choose from 'ECB', 'CBC', 'CFB', 'OFB', or 'CTR'.")


def decrypt(ciphertext, key, iv, n_k, n_r, mode):
    if mode == 'ECB':
        from ECB import ecb_decrypt
        return ecb_decrypt(ciphertext, key, n_k, n_r)
    elif mode == 'CBC':
        from CBC import cbc_decrypt
        return cbc_decrypt(ciphertext, key, iv, n_k, n_r)
    elif mode == 'CFB':
        from CFB import cfb_decrypt
        return cfb_decrypt(ciphertext, key, iv, n_k, n_r)
    elif mode == 'OFB':
        from OFB import ofb_decrypt
        return ofb_decrypt(ciphertext, key, iv, n_k, n_r)
    elif mode == 'CTR':
        from CTR import ctr_decrypt
        return ctr_decrypt(ciphertext, key, iv, n_k, n_r)
    else:
        raise ValueError("Invalid mode. Choose from 'ECB', 'CBC', 'CFB', 'OFB', or 'CTR'.")


# Function to run AES encryption and decryption
def run_aes(input_string, key_size, mode):
    key, iv, plaintext_blocks, n_k, n_r, mode = initialize_aes(input_string, key_size, mode)

    ciphertext = encrypt(plaintext_blocks, key, iv, n_k, n_r, mode)
    decrypted_blocks = decrypt(ciphertext, key, iv, n_k, n_r, mode)

    # Transpose back to original orientation
    decrypted_blocks = decrypted_blocks.transpose(0, 2, 1)

    # Flatten decrypted blocks and convert to bytes
    decrypted_blocks_flat = decrypted_blocks.reshape(-1)
    decrypted_blocks_flat = decrypted_blocks_flat.astype(np.uint8)
    decrypted_bytes = decrypted_blocks_flat.tobytes()

    # Unpad and decode
    try:
        decrypted_bytes_unpadded = unpad(decrypted_bytes, block_size=16)
        decrypted_text = decrypted_bytes_unpadded.decode('utf-8')
    except ValueError as e:
        print(f"Unpadding Error: {e}")
        decrypted_text = ""

    print(f"Input String: {input_string}")
    print("Ciphertext:")
    for block in ciphertext:
        print_hex(block)
    print(f"Decrypted Text: {decrypted_text}")


def run_aes_encryption(input_string, key_size, mode):
    key, iv, plaintext_blocks, n_k, n_r, mode = initialize_aes(input_string, key_size, mode)
    ciphertext = encrypt(plaintext_blocks, key, iv, n_k, n_r, mode)
    # Return necessary parameters for decryption
    return ciphertext, key, iv, n_k, n_r, mode


def run_aes_decryption(ciphertext, key, iv, n_k, n_r, mode):
    decrypted_blocks = decrypt(ciphertext, key, iv, n_k, n_r, mode)

    # Transpose back to original orientation
    decrypted_blocks = decrypted_blocks.transpose(0, 2, 1)

    # Flatten decrypted blocks and convert to bytes
    decrypted_blocks_flat = decrypted_blocks.reshape(-1)
    decrypted_blocks_flat = decrypted_blocks_flat.astype(np.uint8)
    decrypted_bytes = decrypted_blocks_flat.tobytes()

    # Unpad and decode
    try:
        decrypted_bytes_unpadded = unpad(decrypted_bytes, block_size=16)
        decrypted_text = decrypted_bytes_unpadded.decode('utf-8')
    except ValueError as e:
        print(f"Unpadding Error: {e}")
        decrypted_text = ""

    return decrypted_text


if __name__ == "__main__":
    # Test example AES encryption and decryption
    input_string = "This is a test string for AES encryption."
    key_size = 128  # Can be 128, 192, or 256
    mode = 'ECB'  # Can be 'ECB', 'CBC', 'CFB', 'OFB', or 'CTR'

    run_aes(input_string, key_size, mode)


