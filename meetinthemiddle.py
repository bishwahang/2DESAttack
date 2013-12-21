#!/usr/bin/env python
import binascii
import itertools
from pyDes import des
from pyDes import CBC
import sys

# Our IV is 5edcc504

# Instructions
# * Use the skeleton code provided here.
# * Use the DES library as shown in twodes.py
# * Use binascii's (un)hexlify to convert between bytes and hex
#   representation. We do not care if you do your comparisons on bytes
#   or hex - in our sample solution we have chosen hex for better
#   readability of debugging output. The only thing we require is that
#   the "ciphertext" input to lookupInTable() is in hex.
# * In your final solution, your last two lines that you print to the
#   screen MUST be the output of lookupInTable, exactly in the format
#   indicated!

# The following is your plaintext/ciphertext pair. We read it from 
# stdin:
plaintext = sys.argv[1]
ciphertext = sys.argv[2]

# Read in the effective keylength in number of hex digits. This value
# is either 3 or 4 in our case:
effKeyLength = int(sys.argv[3])

#Default IV as defined
iv='5edcc504'

#default pad 16 hex digit
def_pad="0000000000000000"

#the function handed to us to get the decryption done
def twodes(plain, keyOne, keyTwo):
    cipherOne = des(binascii.unhexlify(keyOne), CBC, "5edcc504", pad=None)
    cipherTwo = des(binascii.unhexlify(keyTwo), CBC, "5edcc504", pad=None)
    return cipherTwo.encrypt(cipherOne.encrypt(plain))

#This function generates and returns the total number of keys that could have been used
def generatePermutation():
    t=["".join(seq) for seq in itertools.product("0123456789abcdef", repeat=effKeyLength)]
    for x in t:
        yield x

#function to check and give the corrct padding
def checkPad(effKeyLength):
    if(effKeyLength > 4):
        #since the test scope is out of the condition print the warning
        print 'Key Length greater than 4 will take much time'
    return def_pad[0:-(effKeyLength)]

# Generate the "forward" table
# Input: plaintext in hex, effective key length in hex digits 
# (3 or 4, see above)
# Don't forget to use the IV (see above)
# Output: a representation of the forward table
def generateTable(plaintext, effKeyLength):
    #Call generate Permutation to yield all the possible combinations of key length
    perms=generatePermutation();
    #Check for the correct padding accoding to keylength
    pad=checkPad(effKeyLength);
    #initialize the dictionary to hold the values
    enctable={}    
    #Loop thorugh all possible keys
    for p in perms:
        #pad the possible keys to make it 16 Hex digit
        p=pad+p
        if(len(p) != 16):
            #Some logic has gone wrong
            print "padding gone wrong..."
        #Initate the key for single DES encryption
        k1 = des(binascii.unhexlify(p), CBC, "5edcc504", pad=None)
        #yield p+":"+binascii.hexlify(k1.encrypt(plaintext))
        
        #store the key, value pair for further inspection
        enctable[p]=binascii.hexlify(k1.encrypt(plaintext))
    return enctable

#return true if the guessed key pair gives correct ciphertext for the plaintext
def checkCipher(x, p):
    #Call the twodes function to check if the ciphertext is produced by the guess key values
    if(ciphertext==binascii.hexlify(twodes(plaintext,x,p))):
        return True
    return False
    


# Do the lookups.
# Input:
# * the representation of your forward table
# * the ciphertext as hex representation
# * the effective key length
# Don't forget to use the IV if you do crypto here (see above)
# Output:
# Key 1, Key 2 in *exactly* the format as below
def lookupInTable(enctable, ciphertext, effKeyLength):
    #the return variables
    key1,key2="",""
    #repeat the first initialization step as in encryption
    #Call generate Permutation to yield all the possible combinations of key length
    perms2=generatePermutation();
    #Check padding
    pad=checkPad(effKeyLength)
    #Set the flag false for matched keys
    flag= False
    for p in perms2:
        #pad the possible keys to make it 16 Hex digit
        p=pad+p
        if(len(p) != 16):
            #Some logic has gone wrong
            print "padding gone wrong..."
            return
        #Initialize the key for decryption
        k2 =  des(binascii.unhexlify(p), CBC, "5edcc504", pad=None)
        #decrypt the ciphertext
        pt=binascii.hexlify(k2.decrypt(binascii.unhexlify(ciphertext)))

        #Loop through lookup table
        for x in enctable:
            if (enctable[x]==pt):
                #If match is found do the final check for ciphertext and keypairs
                if checkCipher(x,p):
                    #Set the flag true,assing the keys, break the loop
                    flag=True
                    key1=x
                    key2=p
                    break
        #since the task is done break the loop
        if flag:
            break
    print "Key1:" + key1
    print "Key2:" + key2

#Start of main function
def main():
    enctable = generateTable(plaintext,effKeyLength)
    lookupInTable(enctable, ciphertext, effKeyLength)

main()
