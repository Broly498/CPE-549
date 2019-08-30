'''This program wil perform a dictionary attack on a set of
   passwords through the use of a text file containing a list
   of plain-text passwords.
   
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
   Arg2: <outputDirectory>
'''

import crypt
import os
import sys

print("Beginning Dictionary Attack Program...")

#The first command-line argument is always the name of the script that is being called
if len(sys.argv) is not 3:
    print("Invalid Number of Command-Line Arguments Were Specified: %d" % (len(sys.argv) - 1))
    print("\nExpected Command-Line Arguments:")
    print("Argv 1: <shadowFile>")
    print("Argv 2: <dictionaryFile>")
    sys.exit("\nTerminating Program.")

shadowFile = sys.argv[1]
dictionaryFile = sys.argv[2]

#Validate shadow file
if not os.path.exists(shadowFile):
    sys.exit("Shadow File Does Not Exist Argv 1: " + shadowFile)

#Validate dictionary file
if not os.path.exists(dictionaryFile):
    sys.exit("Dictionary File Does Not Exist Argv 2: " + dictionaryFile)

print("Parsing Shadow File: " + shadowFile)

plainTextPasswordList = []
crackedPasswordList = []

#Open new context and open shadow file
with open(shadowFile, 'r') as file:
    for line in file:
        #Ignore any lines that are comments
        if not line.startswith('#'):
            #Extract password contents
            xplainTextPassword = line.splitlines()[0]
            plainTextPasswordList.append(plainTextPassword)

            #Create NTLM password
            ntlmPassword = hashlib.new('md4', plainTextPassword.encode('utf_16_LE')).hexdigest()
            ntlmPasswordList.append(ntlmPassword)

#Open new context and create hashtable file
with open(outputDirectory + '/hashTable.lst', 'w+') as file:
    for i in range(len(ntlmPasswordList)):
        file.write("%s : %s\n" % (plainTextPasswordList[i], ntlmPasswordList[i]))

print("Output Hash Table File Was Created: " + outputFile)

print("NTLM Hashing Program Concluded...")
