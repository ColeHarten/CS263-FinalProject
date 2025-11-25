import sys
import struct

""" ngl, I kinda chat gpt-ed the elf header parsing lol, so don't necessarily trust this """

def parse_elf_header(data):
    """Parse ELF header to get program header info"""
    if len(data) < 64:
        return None
    
    # Check ELF magic
    if data[:4] != b'\x7fELF':
        return None
    
    # Get architecture (32 or 64 bit)
    ei_class = data[4]
    if ei_class == 1:  # 32-bit
        fmt = '<'  # Little endian
        phoff_offset = 28
        phentsize_offset = 42
        phnum_offset = 44
        addr_size = 4
    elif ei_class == 2:  # 64-bit
        fmt = '<'  # Little endian
        phoff_offset = 32
        phentsize_offset = 54
        phnum_offset = 56
        addr_size = 8
    else:
        return None
    
    # Extract program header table info
    phoff = struct.unpack(fmt + ('I' if ei_class == 1 else 'Q'), data[phoff_offset:phoff_offset + addr_size])[0]
    phentsize = struct.unpack('<H', data[phentsize_offset:phentsize_offset + 2])[0]
    phnum = struct.unpack('<H', data[phnum_offset:phnum_offset + 2])[0]
    
    return {
        'is_64bit': ei_class == 2,
        'phoff': phoff,
        'phentsize': phentsize,
        'phnum': phnum
    }

def get_memory_mappings(data, elf_info):
    """Extract memory mappings from program headers"""
    mappings = []
    
    if not elf_info:
        return mappings
    
    fmt = '<' + ('Q' if elf_info['is_64bit'] else 'I')
    addr_size = 8 if elf_info['is_64bit'] else 4
    
    for i in range(elf_info['phnum']):
        ph_offset = elf_info['phoff'] + i * elf_info['phentsize']
        
        if ph_offset + elf_info['phentsize'] > len(data):
            break
        
        # Parse program header
        ph_data = data[ph_offset:ph_offset + elf_info['phentsize']]
        
        if len(ph_data) < 8:
            continue
            
        p_type = struct.unpack('<I', ph_data[0:4])[0]
        
        # Only interested in LOAD segments (type 1)
        if p_type != 1:
            continue
        
        if elf_info['is_64bit']:
            if len(ph_data) < 56:
                continue
            p_vaddr = struct.unpack('<Q', ph_data[16:24])[0]
            p_offset = struct.unpack('<Q', ph_data[8:16])[0]
            p_filesz = struct.unpack('<Q', ph_data[32:40])[0]
        else:
            if len(ph_data) < 32:
                continue
            p_vaddr = struct.unpack('<I', ph_data[8:12])[0]
            p_offset = struct.unpack('<I', ph_data[4:8])[0]
            p_filesz = struct.unpack('<I', ph_data[16:20])[0]
        
        mappings.append({
            'vaddr': p_vaddr,
            'offset': p_offset,
            'size': p_filesz
        })
    
    return mappings

def file_offset_to_vaddr(file_offset, mappings):
    """Convert file offset to virtual address"""
    for mapping in mappings:
        if mapping['offset'] <= file_offset < mapping['offset'] + mapping['size']:
            return mapping['vaddr'] + (file_offset - mapping['offset'])
    return None

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <core-file> <hex-value>")
        sys.exit(1)

    core_file = sys.argv[1]
    hex_arg = sys.argv[2]

    if hex_arg.lower().startswith("0x"):
        hex_arg = hex_arg[2:]

    if len(hex_arg) % 2 != 0:
        print("Hex string must have an even length.")
        sys.exit(1)

    try:
        pattern = bytes.fromhex(hex_arg)
    except ValueError:
        print("Invalid hex string.")
        sys.exit(1)

    print(f"Scanning {core_file} for 0x{hex_arg.lower()}")
    print(f"Pattern bytes: {pattern.hex(' ')}")
    
    le_pattern = pattern[::-1] 
    if le_pattern != pattern:
        print(f"Also searching little-endian: {le_pattern.hex(' ')}")
    
    try:
        with open(core_file, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Error: File '{core_file}' not found")
        sys.exit(1)
    
    print(f"Core file size: {len(data)} bytes")
    
    # Parse ELF header and get memory mappings
    elf_info = parse_elf_header(data)
    mappings = get_memory_mappings(data, elf_info)
    
    if mappings:
        print(f"Found {len(mappings)} memory segments")
    else:
        print("Warning: Could not parse memory mappings, showing file offsets only")
    
    found = False
    
    # Seach for big-endian pattern
    pos = data.find(pattern)
    if pos != -1:
        vaddr = file_offset_to_vaddr(pos, mappings)
        if vaddr:
            print(f"\033[1;31mERROR: Found 0x{hex_arg.upper()} at file offset 0x{pos:X} (virtual address 0x{vaddr:X})\033[0m")
        else:
            print(f"\033[1;31mERROR: Found 0x{hex_arg.upper()} at file offset 0x{pos:X} (virtual address unknown)\033[0m")
        found = True
        
        # Show context
        start = max(0, pos - 16)
        end = min(len(data), pos + len(pattern) + 16)
        print(f"Context: {data[start:end].hex(' ')}")
    
    # Search for little-endian pattern
    if le_pattern != pattern:
        pos_le = data.find(le_pattern)
        if pos_le != -1:
            vaddr_le = file_offset_to_vaddr(pos_le, mappings)
            if vaddr_le:
                print(f"\033[1;31mERROR: Found 0x{hex_arg.upper()} (little-endian) at file offset 0x{pos_le:X} (virtual address 0x{vaddr_le:X})\033[0m")
            else:
                print(f"\033[1;31mERROR: Found 0x{hex_arg.upper()} (little-endian) at file offset 0x{pos_le:X} (virtual address unknown)\033[0m")
            found = True
            
            # Show context
            start = max(0, pos_le - 16)
            end = min(len(data), pos_le + len(le_pattern) + 16)
            print(f"Context: {data[start:end].hex(' ')}")
    
    if not found:
        print("\033[1;32mSuccess: Pattern not found.\033[0m")

    sys.exit(1 if found else 0)

if __name__ == "__main__":
    main()
