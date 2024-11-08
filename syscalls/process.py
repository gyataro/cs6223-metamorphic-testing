import re


lines = open("./x86_64.txt").read().splitlines()
for line in lines:
    tokens = re.split(r"\t{1,}", line)
    if len(tokens) == 4:
        print(tokens[2])