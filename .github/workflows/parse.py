#!/usr/bin/env python3
import os
import sys

if len(sys.argv) < 2:
    print("Usage: ./parse.py <filename>")
    sys.exit(1)

# Get the output filename
file_name = sys.argv[1]

# Read File Content
content = open(file_name).read()

# Check Content contains values
def contains(s):
    return content.find(s) != -1

# Pass ALL tests
assert contains("All is well in the universe")
# Kernel not paniced
assert not contains("rel4_kernel: PANICED")
