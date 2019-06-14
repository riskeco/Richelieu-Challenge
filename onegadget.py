from one_gadget import generate_one_gadget

path_to_libc = 'libc-2.24.so'

for offset in generate_one_gadget(path_to_libc):
    print(hex(offset))
