'''This program will create a text file containing a table of 
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
   Arg2: <outputDirectory>
'''

import hashlib
import os
import sys
import datetime

print("Beginning NTLM Hashing Program...")

#The first command-line argument is always the name of the script that is being called
if len(sys.argv) is not 3:
    print("Invalid Number of Command-Line Arguments Were Specified: %d" % (len(sys.argv) - 1))
    print("\nExpected Command-Line Arguments:")
    print("Argv 1: <inputFile>")
    print("Argv 2: <outputDirectory>")
    sys.exit("\nTerminating Program.")

inputFile = sys.argv[1]
outputDirectory = sys.argv[2]
timeStamp = datetime.datetime.now()

outputFile = outputDirectory + "/%d%02d%02d%02d%02d%02d" % \
    (timeStamp.year, timeStamp.month, timeStamp.day, \
    timeStamp.hour, timeStamp.minute, timeStamp.second)

#Validate input file
if not os.path.exists(inputFile):
    sys.exit("Input File Was Not Specified Argv 1: " + inputFile)

#Validate output directory
if not os.path.exists(outputDirectory):
    os.makedirs(outputDirectory)

print("Parsing Input File: " + inputFile)

plainTextPasswordList = []
ntlmPasswordList = []

#Open new context and open wordList File
with open(inputFile, 'r') as file:
    for line in file:
        #Ignore any lines that are comments
        if not line.startswith('#'):
            #Extract plain text password
            plainTextPassword = line.splitlines()[0]
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