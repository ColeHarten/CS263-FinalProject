import sys
import struct

def main():
    if len(sys.argv) != 3:
        print("sys.argv: ", sys.argv)
        print("Usage: python3 <core-file> <hex-value>")
        sys.exit(1)

    core_file = sys.argv[1]
    hex_arg = sys.argv[2]

    if hex_arg.lower().startswith("0x"):
        hex_arg = hex_arg[2:]

    if len(hex_arg) % 2 != 0:
        print("Hex string must have an even length.")
        sys.exit(1)

    try:
        pattern = hex_arg.decode('hex')
    except (ValueError, TypeError):
        print("Invalid hex string.")
        sys.exit(1)

    print("Scanning " + core_file + " for 0x" + hex_arg.lower())
    print("Pattern bytes: " + ' '.join(['%02x' % ord(c) for c in pattern]))
    
    le_pattern = pattern[::-1] 
    if le_pattern != pattern:
        print("Also searching little-endian: " + ' '.join(['%02x' % ord(c) for c in le_pattern]))
    
    try:
        with open(core_file, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print("Error: File '" + core_file + "' not found")
        sys.exit(1)
    
    print("Core file size: " + str(len(data)) + " bytes")
    
    found = False
    
    # Seach for big-endian pattern
    pos = data.find(pattern)
    if pos != -1:
        print("\033[1;31mERROR: Found 0x" + hex_arg.upper() + " at file offset 0x" + hex(pos)[2:].upper() + "\033[0m")
        found = True
        
        # Show context
        start = max(0, pos - 16)
        end = min(len(data), pos + len(pattern) + 16)
        context_bytes = data[start:end]
        print("Context: " + ' '.join(['%02x' % ord(c) for c in context_bytes]))
    
    # Search for little-endian pattern
    if le_pattern != pattern:
        pos_le = data.find(le_pattern)
        if pos_le != -1:
            print("\033[1;31mERROR: Found 0x" + hex_arg.upper() + " (little-endian) at file offset 0x" + hex(pos_le)[2:].upper() + " \033[0m")
            found = True
            
            # Show context
            start = max(0, pos_le - 16)
            end = min(len(data), pos_le + len(le_pattern) + 16)
            context_bytes = data[start:end]
            print("Context: " + ' '.join(['%02x' % ord(c) for c in context_bytes]))
    
    if not found:
        print("\033[1;32mSuccess: Pattern not found.\033[0m")

    sys.exit(1 if found else 0)

if __name__ == "__main__":
    main()
