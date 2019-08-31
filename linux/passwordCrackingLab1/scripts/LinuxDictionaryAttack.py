'''The dictionary attack program is only supported on Linux platforms.
   This program wil perform a dictionary attack on a set of linux user passwords
   through the use of a dictionary file containing a list of commonly used passwords.
   The program will parse a condensed shadow file containing hashed passwords.
   Each password entry should be new-line delimited (\n).
   The shadow file may also contain comments which are denoted by a pound sign (#).
   
   ------------------------------------------------------------
   ------------------- Begin sampleShadowFile -----------------
   ------------------------------------------------------------
   #comment1\n
   #comment2\n
   #comment3\n
   username1:$digit$salt1$hash1:last:minimum:maximum:warn:inactive:expire:::\n
   username2:$digit$salt2$hash2:last:minimum:maximum:warn:inactive:expire:::\n
   username3:$digit$salt3$hash3:last:minimum:maximum:warn:inactive:expire:::\n
   ------------------------------------------------------------
   -------------------- End sampleShadowFile ------------------
   ------------------------------------------------------------

   Expected Command-Line Arguments:
   Arg1: <shadowFile>
   Arg2: <dictionaryFile>
'''

import hmac
import os
import sys
import crypt

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
            shadowInformation = shadowEntry[1].split('$')
            shadowUser = shadowEntry[0]
            shadowSalt = shadowEntry[1]
            shadowHash = shadowInformation[3]

            matchFound = False

            #Hash every item in the dictionary
            for item in dictionaryEntries:
                hashInformation = crypt.crypt(item, shadowSalt)
                computedHash = hashInformation.split('$')[3]
                
                #Compare hashes and see if a password match was found
                if hmac.compare_digest(shadowHash, computedHash):
                    matchFound = True
                    break

            if matchFound:
                print("Match found for userid [" + shadowUser + "]. Password = [" + item + "]")
            else:
                print("No match was found for userid [" + shadowUser + "].")

print("Dictionary Attack Program Concluded...")
