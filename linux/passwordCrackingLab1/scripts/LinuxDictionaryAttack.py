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

#import crypt
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

print("Parsing Dictionary File: " + dictionaryFile)

dictionaryEntries = []

#Open new context and open dictionary file
with open(dictionaryFile, 'r') as file:
    for line in file:
        #Ignore any lines that are comments
        if not line.startswith('#'):
            #Extract dictionary contents
            dictionaryEntry = line.splitlines()[0]
            dictionaryEntries.append(dictionaryEntry)

#Open new context and shadow file
with open(shadowFile, 'r') as file:
    for line in file:
        #Ignore any lines that are comments
        if not line.startswith('#'):
            #Extract password contents
            shadowEntry = line.splitlines()[0].split(':')
            hashInformation = shadowEntry[1].split('$')

print("Dictionary Attack Program Concluded...")