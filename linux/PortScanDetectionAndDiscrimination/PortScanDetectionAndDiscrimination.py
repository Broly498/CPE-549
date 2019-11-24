import os
import sys
import dpkt

expectedArguments = ['-i', '<inputFilename>']

#The first argument is always the name of the script
#that is being called; therefore, ignore the first one.
parsedArguments = sys.argv[1:]

#Ensure that the number of parsed arguments
#is equal to the number of expected arguments.

numberOfParsedArguments = len(parsedArguments)

if (numberOfParsedArguments) is not len(expectedArguments):
    print("Invalid Number of Command-Line Arguments Were Specified: %d" % (numberOfParsedArguments))
    print("\nExpected Command-Line Arguments:", " ", end='')
    for item in expectedArguments:
        print(item, " ", end='')
    sys.exit("\nTerminating Program.")

#The input file is the second parsed argument.
inputFile = parsedArguments[1]

#Validate input file
if not os.path.exists(inputFile):
    sys.exit("Input file was not found: " + inputFile)

#Open Input File and create PCAP object.
f = open(inputFile)
pcapObject = dpkt.pcap.Reader(f)

temp = 5