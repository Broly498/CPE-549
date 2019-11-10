import os
import sys
from Crypto.Hash import MD5

#The first command-line argument is always the name of the script that is being called
if len(sys.argv) is not 2:
    print("Invalid Number of Command-Line Arguments Were Specified: %d" % (len(sys.argv) - 1))
    print("\nExpected Command-Line Arguments:")
    print("Argv 1: <inputFile>")
    sys.exit("\nTerminating Program.")

binaryFile = sys.argv[1]

hashObject = MD5.new()

#Open new context and parse login file
with open(binaryFile, 'rb') as file:
    for line in file:
        hashObject.update(line)

print("%s: MD5 hash = %s" % (binaryFile, hashObject.hexdigest()))
