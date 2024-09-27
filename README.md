# NIST-AES-Python
Python implementation of NIST AES Encryption.

128-bit, 192-bit, and 256-bit key encryption and decryption using the NIST AES encryption algorithm. The implementation supports the following modes of operation:
- ECB, CBC, CFB, OFB, and CTR.

additional features include:
- Arbitrary input strings with padding (PKCS7).
- Random key generation.
- Testing of all the modes of operation on a custom string implemented with plotting.

# Brief
This is a Python implementation of the NIST AES encryption algorithm. The implementation is based on the NIST AES specification document (FIPS PUB 197 - Updated May 9, 2023). This publication is available free of charge from: https://doi.org/10.6028/NIST.FIPS.197-upd1 

The implementation has been tested in Python 3.9.


# Requirements
The main requirements are listed in the `requirements.txt` file. To install the requirements, run the following command:
```bash
pip install -r requirements.txt
```
or clone into your favorite IDE and install the requirements from the `requirements.txt` file using the IDE's own features.

# Key Sizes and Modes of Operation
The NIST AES specification supports three key sizes: 128, 192, and 256 bits. The key size is determined by the length of the key provided. The supported modes of operation are:
- ECB (Electronic Codebook)
- CBC (Cipher Block Chaining)
- CFB (Cipher Feedback)
- OFB (Output Feedback)
- CTR (Counter)

# Using arbitrary input strings with padding
The implementation supports arbitrary input strings. The input string is padded according to the padding scheme specified. The currently supported padding schemes are:
- PKCS7 

the padding is implemented and can be tested in the AES_padded.py file.

# Usage
The NIST AES implementation is done in the file `AES.py`.

The different modes of operation are implemented in separate files. The files are:
CBC.py, CFB.py, OFB.py, CTR.py, and ECB.py.

You can test each file separately for the respective methods. For example, to test the `AES.py` file, you can run the following commands:
```bash 
python AES.py
python CBC.py
python CFB.py
python ...
```
you can use the `test_aes.py` file to test all the methods at once on a custom string with padding, with random key generation. To do so, run the following command:
```bash
python test_AES.py
```

# License
This project can be used freely for all purposes. Authors must be credited.

Authors are not responsible for any misuse of the code, and give no warranty or guarantee of any kind.
