# Joseph Shaffer
# Shaffer.567
# CSE 5473
# Lab 2 Extra Credit

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
        #print('PlainText Block: ' + binascii.hexlify(block))
        raw = raw[16:]
        #print('Rest of Plaintext: ' + binascii.hexlify(raw))
    	block = ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(block, xorString))
	cipher = AES.new(key, AES.MODE_ECB)
    	xorString = cipher.encrypt(block)
	#print('Encrypted Block: ' + binascii.hexlify(xorString))
	ciphertext = ciphertext + xorString
        #print('Ciphertext: ' + binascii.hexlify(ciphertext))
    return ciphertext

def oracle(ciphertext):
    if len(ciphertext) % 16 != 0:
	print("Ciphertext contains at least one block that is not the size of 16")
    else:
	firstBlock = ciphertext[len(ciphertext)-32:len(ciphertext)-16]
	lastBlock = ciphertext[len(ciphertext)-16:]
	cipher = AES.new(key, AES.MODE_ECB)
	lastBlock = cipher.decrypt(lastBlock)
	lastBlock = ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(firstBlock, lastBlock))
	lastDigit = lastBlock[len(lastBlock)-1:]
	if ord(lastDigit) > 16 or ord(lastDigit) < 1:
		#print("No: Invalid Padding")
		return "No"
	else:
		for x in range(1, ord(lastDigit) + 1):
			#print(ord(lastBlock[len(lastBlock)-x: len(lastBlock)-x+1]))
			if ord(lastBlock[len(lastBlock)-x:len(lastBlock)-x+1]) != ord(lastDigit):
				#print("No: Invalid Padding")
				return "No"
		#print("Yes: Valid Padding")
		#print("Padding is: " + binascii.hexlify(lastBlock[len(lastBlock)-ord(lastDigit):]))
		return "Yes"

def attack(ciphertext):
	pn = ''
	ciphertext = IV + ciphertext
	cn = ''
	while len(ciphertext) > 16:
		cn1Prime = ''
		pnPrime = ''
		dk = ''
		cn = ciphertext[:16]
		ciphertext = ciphertext[16:]	
		cn1 = cn
		for y in range(1, 17):
			guess = ''
			for x in range(0, 256):
				cn1 = cn1[:len(cn1)-y] + chr(x) + cn1Prime
				if oracle(cn1 + ciphertext[:16]) == "Yes":
					#print(binascii.hexlify(chr(x)))
					cn1 = cn1[:len(cn1)-y-1] + chr(x) + chr(x) + cn1Prime
					if oracle(cn1 + ciphertext[:16]) == "Yes":
						guess = chr(x)
			#print('Guess ' + binascii.hexlify(guess))
			pnPrime = chr(y)
			dk = ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(guess, pnPrime)) + dk
			#print('DK Built up ' + binascii.hexlify(dk))
			pnPrime = chr(y+1)
			for i in range(1, y):
				pnPrime = pnPrime + chr(y+1)
			#print('Pn Prime ' + binascii.hexlify(pnPrime))
			cn1Prime = ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(pnPrime, dk))
			#print('CN1 Prime built up ' + binascii.hexlify(cn1Prime))
		pn = pn +''.join(chr(ord(a) ^ ord(b)) for a,b in zip(cn, dk))
	ciphertext = cn + ciphertext
	# check if there is padding in the block
	if oracle(ciphertext) == "Yes": 
		while len(ciphertext) > 16:
			cn = ciphertext[:16]
			ciphertext = ciphertext[16:]	
			cn1 = cn
			guess = 0
			for y in range(1, 17):
				x = cn[y-1:y]
				#print(binascii.hexlify(x))
				cn1 = cn1[:y-1] + chr(ord(x)+1) + cn1[y:]
				if oracle(cn1 + ciphertext[:16]) == "No":
					guess += 1
			#print(guess)
			pn = pn[:len(pn) - guess]	
	return pn

# decrypt with AES ECB mode
def decrypt(key, enc):
    plaintext = ""
    xorString = IV
    while len(enc) > 0:
    	block = enc[:16]
	enc = enc[16:]
        #print('Ciphertext Block: ' + binascii.hexlify(block))
	#print('Rest of Ciphertext: ' + binascii.hexlify(enc))
    	cipher = AES.new(key, AES.MODE_ECB)
	dec = cipher.decrypt(block)
        plaintext = plaintext + ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(dec, xorString))
        #print('Plaintext Block: ' + binascii.hexlify(plaintext))
	xorString = block
    #print('Padded Plaintext Block: ' + binascii.hexlify(plaintext))
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
       print('Attack Decryption Plaintext: ' + binascii.hexlify(attack(ciphertext)))
   elif '-d' in myargs: # decryption with hexadecimal string as ciphertext
       ciphertext = binascii.unhexlify(myargs['-d'])
       plaintext = decrypt(key, ciphertext)
       print('Plaintext: ' + binascii.hexlify(plaintext))
   elif '-s' in myargs: 
       # encryption with ascii string as plaintext, output hexadecimal ciphertext
       plaintext = binascii.a2b_qp(myargs['-s'])
       ciphertext = encrypt(key, plaintext)
       print('Ciphertext: ' + binascii.hexlify(ciphertext))
       print('Attack Decryption Plaintext: ' + binascii.b2a_qp(attack(ciphertext)))
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
