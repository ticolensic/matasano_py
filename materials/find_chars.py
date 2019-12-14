"""
This module takes a text, removes all "normal" symbols and outputs all "abnormal":
syntax signs and all stuff.

For the rating system.
"""

from string import ascii_letters, digits
from collections import Counter

with open("longread.txt") as f:
    text = f.read()
all_chars = list([x for x in Counter(text)])
filtered = filter(lambda x: x not in ascii_letters + digits, all_chars)
print(''.join(filtered))
