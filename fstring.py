import sys

if len(sys.argv) != 2:
    print("Usage: fstring.py <string>")
    exit(1)
print("{", end=" ")
for char in sys.argv[1]:
    print(f"'{char}', ", end="")

print(" 0x00 }",end="")
