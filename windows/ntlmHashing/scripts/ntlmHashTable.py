'''This program will output a table containing
   plain-text passwords as well as their hashed counterparts.
   The hashing algorithm used is that of NT Lan Manager (NTLM).
   
   The program is designed designed to parse list files containing collections of plain-text passwords.
   Passwords that are contained inside of the list file should be new-line delimited (\n).
   The list file may also contain comments which are denoted by a pound sign (#).
   
   ------------------------------------------------------------
   ------------------- Begin sampleFile.lst -------------------
   ------------------------------------------------------------
   #comment1\n
   #comment2\n
   #comment3\n
   password1\n
   password2\n
   password3\n
   ------------------------------------------------------------
   -------------------- End sampleFile.lst --------------------
   ------------------------------------------------------------

   Expected Command-Line Arguments:
   Arg1: <inputFile>
'''

import hashlib
import os
import sys

#The first command-line argument is always the name of the script that is being called
if len(sys.argv) is not 2:
    print("Invalid Number of Command-Line Arguments Were Specified: %d" % (len(sys.argv) - 1))
    print("\nExpected Command-Line Arguments:")
    print("Argv 1: <inputFile>")
    sys.exit("\nTerminating Program.")

inputFile = sys.argv[1]

#Validate input file
if not os.path.exists(inputFile):
    sys.exit("Input File Was Not Specified Argv 1: " + inputFile)

passwordDictionary = {}
hashObject = hashlib.new('md4')

#Open new context and open wordList File
with open(inputFile, 'r') as file:
    for line in file:
        #Ignore any lines that are comments
        if not line.startswith('#'):
            #Extract plain text password ensuring that leading and trailing spaces are ignored
            plainTextPassword = line.strip()

            #Create NTLM password
            hashObject.update(plainTextPassword.encode('utf_16_le'))
            ntlmPassword = hashObject.hexdigest()
            passwordDictionary[ntlmPassword] = plainTextPassword

#Sort every item in the dictionary and print it to the terminal
for item in sorted(passwordDictionary.keys()):
    print("%s:%s\n" % (item, passwordDictionary[item]))