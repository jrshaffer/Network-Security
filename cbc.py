# Joseph Shaffer
# Shaffer.567
# CSE 5473
# Lab 2 cbc.py

# Import AES symmetric encryption cipher
from Crypto.Cipher import AES

# Import class for hexadecimal string processing
import binascii

# support command-line arguments
import sys

# define block size of AES encryption
BLOCK_SIZE = 16

# The 128-bit AES key
key = binascii.unhexlify('00112233445566778899aabbccddeeff')

# the 16-byte Initial Vector
IV = binascii.unhexlify('0f1e2d3c4b5a69788796a5b4c3d2e1f0')

# The function to apply PKCS #5 padding to a block
def pad(s):
    pad_len = BLOCK_SIZE - len(s) % BLOCK_SIZE
    if (pad_len == 0):
	pad_len = BLOCK_SIZE
    return (s + pad_len * chr(pad_len).encode('ascii'))

# The function to remove padding
def unpad(s):
    return s[:-ord(s[len(s) - 1:])]


# encrypt with AES ECB mode
def encrypt(key, raw):
    #print('Plaintext Block: ' + binascii.hexlify(raw))
    raw = pad(raw)
    print('Padded Plaintext Block: ' + binascii.hexlify(raw))
    ciphertext = ""
    xorString = IV
    while len(raw) > 0:
    	block = raw[:16]
        print('PlainText Block: ' + binascii.hexlify(block))
        raw = raw[16:]
        print('Rest of Plaintext: ' + binascii.hexlify(raw))
    	block = ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(block, xorString))
	cipher = AES.new(key, AES.MODE_ECB)
    	xorString = cipher.encrypt(block)
	print('Encrypted Block: ' + binascii.hexlify(xorString))
	ciphertext = ciphertext + xorString
        print('Ciphertext: ' + binascii.hexlify(ciphertext))
    return ciphertext


# decrypt with AES ECB mode
def decrypt(key, enc):
    plaintext = ""
    xorString = IV
    while len(enc) > 0:
    	block = enc[:16]
	enc = enc[16:]
        print('Ciphertext Block: ' + binascii.hexlify(block))
	print('Rest of Ciphertext: ' + binascii.hexlify(enc))
    	cipher = AES.new(key, AES.MODE_ECB)
	dec = cipher.decrypt(block)
        plaintext = plaintext + ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(dec, xorString))
        print('Plaintext Block: ' + binascii.hexlify(plaintext))
	xorString = block
    print('Padded Plaintext Block: ' + binascii.hexlify(plaintext))
    return unpad(plaintext)

# a function to parse command-line arguments
def getopts(argv):
    opts = {} # Empty dictionary to store key-value pairs
    while argv: # While there are arguments left to parse
        if argv[0][0] == '-':  # Found a "-name value" pair
	    opts[argv[0]] = argv[1] # Add key and value to the dictionary
	argv = argv[1:] # Reduce the argument list by copying it starting from index 1
    return opts

if __name__ == '__main__':
   # parse command-line arguments
   myargs = getopts(sys.argv)
   # print(myargs)
   if '-e' in myargs: # encryption with hexadecimal string as plaintext
       plaintext = binascii.unhexlify(myargs['-e'])
       ciphertext = encrypt(key, plaintext)
       print('Ciphertext: ' + binascii.hexlify(ciphertext))
   elif '-d' in myargs: # decryption with hexadecimal string as ciphertext
       ciphertext = binascii.unhexlify(myargs['-d'])
       plaintext = decrypt(key, ciphertext)
       print('Plaintext: ' + binascii.hexlify(plaintext))
   elif '-s' in myargs: 
       # encryption with ascii string as plaintext, output hexadecimal ciphertext
       plaintext = binascii.a2b_qp(myargs['-s'])
       ciphertext = encrypt(key, plaintext)
       print('Ciphertext: ' + binascii.hexlify(ciphertext))
   elif '-u' in myargs:
       # decryption with hexadecimal string as ciphertext, output ascii string
       ciphertext = binascii.unhexlify(myargs['-u'])
       plaintext = decrypt(key, ciphertext)
       print('Plaintext ' + binascii.b2a_qp(plaintext))
   else:
       print("python ecb.py -e 010203040506")
       print("python ecb.py -s 'this is cool'")
       print("python ecb.py -d d25a16fe349cded7f6a2f2446f6da1c2")
       print("python ecb.py -u 9b43953eeb6c3b7b7971a8bec1a90819")
