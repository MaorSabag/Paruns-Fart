import sys

if len(sys.argv) != 2:
    print("Usage: wstring.py <string>")
    exit(1)
print("{", end=" ")
for char in sys.argv[1]:
    print(f"L'{char}', ", end="")

print(" L'\\n', 0x00 }",end="")