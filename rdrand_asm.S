/*
 * Copyright (c) 2011-2014, Intel Corporation
 * Authors: Fenghua Yu <fenghua.yu@intel.com>,
 *          H. Peter Anvin <hpa@linux.intel.com>
 * PIC code by: Francisco Blas Izquierdo Riera (klondike) <klondike@gentoo.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#define ENTRY(x)	  \
	.balign	64	; \
	.globl	x	; \
x:

#define ENDPROC(x)		  \
	.size	x, .-x		; \
	.type	x, @function

#define RDRAND_RETRY_LIMIT	10

#ifdef __x86_64__

ENTRY(x86_rdrand_bytes)
	mov	%esi, %eax
1:
	mov	$RDRAND_RETRY_LIMIT, %ecx
2:
	rdrand	%rdx
	jnc	3f
	mov	%rdx, (%rdi)
	add	$8, %rdi
	sub	$8, %esi
	ja	1b
4:
	sub	%esi, %eax
	ret
3:
	dec	%ecx
	rep;nop
	jnz	2b
	jmp	4b
ENDPROC(x86_rdrand_bytes)

ENTRY(x86_rdseed_or_rdrand_bytes)
	mov	(%rsi), %r8d		/* RDSEED count */
	mov	(%rcx), %r9d		/* RDRAND count */
1:
	mov	$RDRAND_RETRY_LIMIT, %r10d
2:
	rdseed	%rax
	jnc	3f
	mov	%rax, (%rdi)
	add	$8, %rdi
	sub	$8, %r8d
	ja	1b
4:
	sub	%r8d, (%rsi)
	sub	%r9d, (%rcx)
	ret
3:
	rdrand	%rax
	jnc	5f
	mov	%rax, (%rdx)
	add	$8, %rdx
	sub	$8, %r9d
	ja	1b
	jmp	4b
5:
	dec	%r10d
	rep;nop
	jnz	2b
	jmp	4b
ENDPROC(x86_rdseed_or_rdrand_bytes)

#define SETPTR(var,ptr)	leaq var(%rip),ptr
#define PTR0	%rdi
#define PTR1	%rsi
#define PTR2	%rcx
#define CTR3	%eax
#define NPTR2	1	/* %rcx = %r1, only 0-7 valid here */

#elif defined(__i386__)

ENTRY(x86_rdrand_bytes)
	push	%ebp
	mov	%esp, %ebp
	push	%edi
	push	%esi
	movl	8(%ebp), %edi
	movl	12(%ebp), %esi

	mov	%esi, %eax
1:
	mov	$RDRAND_RETRY_LIMIT, %ecx
2:
	rdrand	%edx
	jnc	3f
	mov	%edx, (%edi)
	add	$4, %edi
	sub	$4, %esi
	ja	1b
4:
	sub	%esi, %eax
	pop	%esi
	pop	%edi
	pop	%ebp
	ret
3:
	dec	%ecx
	rep;nop
	jnz	2b
	jmp	4b
ENDPROC(x86_rdrand_bytes)


ENTRY(x86_rdseed_or_rdrand_bytes)
	push	%ebp
	mov	%esp, %ebp
	push	%edi
	push	%esi
	push	%ebx

	mov	12(%ebp), %ebx
	mov	20(%ebp), %esi
	mov	8(%ebp), %edi		/* RDSEED pointer */
	mov	16(%ebp), %edx		/* RDRAND pointer */
	mov	(%ebx), %ebx		/* RDSEED count */
	mov	(%esi), %esi		/* RDRAND count */
1:
	mov	$RDRAND_RETRY_LIMIT, %ecx
2:
	rdseed	%eax
	jnc	3f
	mov	%eax, (%edi)
	add	$4, %edi
	sub	$4, %ebx
	ja	1b
4:
	mov	12(%ebp), %edx
	mov	20(%ebp), %eax
	sub	%ebx, (%edx)		/* RDSEED count */
	sub	%esi, (%eax)		/* RDRAND count */

	pop	%ebx
	pop	%esi
	pop	%edi
	pop	%ebp
	ret
3:
	rdrand	%eax
	jnc	5f
	mov	%eax, (%edx)
	add	$4, %edx
	sub	$4, %esi
	jnz	1b
	ja	4b
5:
	dec	%ecx
	rep;nop
	jnz	2b
	jmp	4b
ENDPROC(x86_rdseed_or_rdrand_bytes)

#if defined(__PIC__)
#define INIT_PIC() \
	pushl	%ebx ; \
	call    __x86.get_pc_thunk.bx ; \
	addl    $_GLOBAL_OFFSET_TABLE_, %ebx
#define END_PIC() \
	popl	%ebx
#define SETPTR(var,ptr) leal (var)@GOTOFF(%ebx),ptr
#else
#define INIT_PIC()
#define END_PIC()
#define SETPTR(var,ptr)	movl $(var),ptr
#endif
#define PTR0	%eax
#define PTR1	%edx
#define PTR2	%ecx
#define CTR3	%esi
#define NPTR2	1	/* %rcx = %r1 */

#endif

ENTRY(x86_aes_mangle)
#ifdef __i386__
	push	%ebp
	mov	%esp, %ebp
	movl	8(%ebp), %eax
	movl	12(%ebp), %edx
	push	%esi
	INIT_PIC()
#endif
	movl	$512, CTR3	/* Number of rounds */
	
	movdqa	(0*16)(PTR1), %xmm0
	movdqa	(1*16)(PTR1), %xmm1
	movdqa	(2*16)(PTR1), %xmm2
	movdqa	(3*16)(PTR1), %xmm3
	movdqa	(4*16)(PTR1), %xmm4
	movdqa	(5*16)(PTR1), %xmm5
	movdqa	(6*16)(PTR1), %xmm6
	movdqa	(7*16)(PTR1), %xmm7

#ifdef __x86_64__
	SETPTR(aes_round_keys, PTR2)
1:
#else
1:
	SETPTR(aes_round_keys, PTR2)
#endif

	/* 8192 = 512 (rounds) * 16 (bytes) */
	pxor	(0*8192)(PTR0), %xmm0
	pxor	(1*8192)(PTR0), %xmm1
	pxor	(2*8192)(PTR0), %xmm2
	pxor	(3*8192)(PTR0), %xmm3
	pxor	(4*8192)(PTR0), %xmm4
	pxor	(5*8192)(PTR0), %xmm5
	pxor	(6*8192)(PTR0), %xmm6
	pxor	(7*8192)(PTR0), %xmm7
	add	$16, PTR0

offset = 0
	.rept 10
#ifdef __x86_64__
	movdqa	offset(PTR2), %xmm8
offset = offset + 16
	.byte	0x66,0x41,0x0f,0x38,0xdc,0xc0	/* aesenc %xmm8, %xmm0 */
	.byte	0x66,0x41,0x0f,0x38,0xdc,0xc8	/* aesenc %xmm8, %xmm1 */
	.byte	0x66,0x41,0x0f,0x38,0xdc,0xd0	/* aesenc %xmm8, %xmm2 */
	.byte	0x66,0x41,0x0f,0x38,0xdc,0xd8	/* aesenc %xmm8, %xmm3 */
	.byte	0x66,0x41,0x0f,0x38,0xdc,0xe0	/* aesenc %xmm8, %xmm4 */
	.byte	0x66,0x41,0x0f,0x38,0xdc,0xe8	/* aesenc %xmm8, %xmm5 */
	.byte	0x66,0x41,0x0f,0x38,0xdc,0xf0	/* aesenc %xmm8, %xmm6 */
	.byte	0x66,0x41,0x0f,0x38,0xdc,0xf8	/* aesenc %xmm8, %xmm7 */
#else
	.byte	0x66,0x0f,0x38,0xdc,0x00+NPTR2	/* aesenc (PTR2), %xmm0 */
	.byte	0x66,0x0f,0x38,0xdc,0x08+NPTR2	/* aesenc (PTR2), %xmm1 */
	.byte	0x66,0x0f,0x38,0xdc,0x10+NPTR2	/* aesenc (PTR2), %xmm2 */
	.byte	0x66,0x0f,0x38,0xdc,0x18+NPTR2	/* aesenc (PTR2), %xmm3 */
	.byte	0x66,0x0f,0x38,0xdc,0x20+NPTR2	/* aesenc (PTR2), %xmm4 */
	.byte	0x66,0x0f,0x38,0xdc,0x28+NPTR2	/* aesenc (PTR2), %xmm5 */
	.byte	0x66,0x0f,0x38,0xdc,0x30+NPTR2	/* aesenc (PTR2), %xmm6 */
	.byte	0x66,0x0f,0x38,0xdc,0x38+NPTR2	/* aesenc (PTR2), %xmm7 */
	add	$16, PTR2
#endif
	.endr

#ifdef __x86_64__
	movdqa	offset(PTR2), %xmm8
	.byte	0x66,0x41,0x0f,0x38,0xdd,0xc0	/* aesenclast %xmm8, %xmm0 */
	.byte	0x66,0x41,0x0f,0x38,0xdd,0xc8	/* aesenclast %xmm8, %xmm1 */
	.byte	0x66,0x41,0x0f,0x38,0xdd,0xd0	/* aesenclast %xmm8, %xmm2 */
	.byte	0x66,0x41,0x0f,0x38,0xdd,0xd8	/* aesenclast %xmm8, %xmm3 */
	.byte	0x66,0x41,0x0f,0x38,0xdd,0xe0	/* aesenclast %xmm8, %xmm4 */
	.byte	0x66,0x41,0x0f,0x38,0xdd,0xe8	/* aesenclast %xmm8, %xmm5 */
	.byte	0x66,0x41,0x0f,0x38,0xdd,0xf0	/* aesenclast %xmm8, %xmm6 */
	.byte	0x66,0x41,0x0f,0x38,0xdd,0xf8	/* aesenclast %xmm8, %xmm7 */
#else
	.byte	0x66,0x0f,0x38,0xdd,0x00+NPTR2	/* aesenclast (PTR2), %xmm0 */
	.byte	0x66,0x0f,0x38,0xdd,0x08+NPTR2	/* aesenclast (PTR2), %xmm1 */
	.byte	0x66,0x0f,0x38,0xdd,0x10+NPTR2	/* aesenclast (PTR2), %xmm2 */
	.byte	0x66,0x0f,0x38,0xdd,0x18+NPTR2	/* aesenclast (PTR2), %xmm3 */
	.byte	0x66,0x0f,0x38,0xdd,0x20+NPTR2	/* aesenclast (PTR2), %xmm4 */
	.byte	0x66,0x0f,0x38,0xdd,0x28+NPTR2	/* aesenclast (PTR2), %xmm5 */
	.byte	0x66,0x0f,0x38,0xdd,0x30+NPTR2	/* aesenclast (PTR2), %xmm6 */
	.byte	0x66,0x0f,0x38,0xdd,0x38+NPTR2	/* aesenclast (PTR2), %xmm7 */
#endif
	sub	$1, CTR3
	jnz	1b
	
	movdqa	%xmm0, (0*16)(PTR1)
	movdqa	%xmm1, (1*16)(PTR1)
	movdqa	%xmm2, (2*16)(PTR1)
	movdqa	%xmm3, (3*16)(PTR1)
	movdqa	%xmm4, (4*16)(PTR1)
	movdqa	%xmm5, (5*16)(PTR1)
	movdqa	%xmm6, (6*16)(PTR1)
	movdqa	%xmm7, (7*16)(PTR1)

#ifdef __i386__
	END_PIC()
	pop	%esi
	pop	%ebp
#endif
	ret
ENDPROC(x86_aes_mangle)

/* aeskeygenassist $imm,%xmm0,%xmm1 */
#define AESKEYGENASSIST(imm) .byte 0x66,0x0f,0x3a,0xdf,0xc8,imm

ENTRY(x86_aes_expand_key)
#ifdef __i386__
	push	%ebp
	mov	%esp, %ebp
	movl	8(%ebp), %eax
	INIT_PIC()
#endif

	SETPTR(aes_round_keys, PTR1)
	movdqu	(PTR0), %xmm0
	movdqa	%xmm0, (PTR1)	/* First slot = the plain key */
	add	$16, PTR1

	AESKEYGENASSIST(0x01)
	call	1f
	AESKEYGENASSIST(0x02)
	call	1f
	AESKEYGENASSIST(0x04)
	call	1f
	AESKEYGENASSIST(0x08)
	call	1f
	AESKEYGENASSIST(0x10)
	call	1f
	AESKEYGENASSIST(0x20)
	call	1f
	AESKEYGENASSIST(0x40)
	call	1f
	AESKEYGENASSIST(0x80)
	call	1f
	AESKEYGENASSIST(0x1b)
	call	1f
	AESKEYGENASSIST(0x36)
	call	1f

#ifdef __i386__
	END_PIC()
	pop	%ebp
#endif
	ret

1:
	pshufd	$0xff, %xmm1, %xmm1
	movdqa	%xmm0, %xmm2
	pslldq	$4, %xmm2
	pxor	%xmm2, %xmm0
	pslldq	$4, %xmm2
	pxor	%xmm2, %xmm0
	pslldq	$4, %xmm2
	pxor	%xmm2, %xmm0
	pxor	%xmm1, %xmm0
	movdqa	%xmm0, (PTR1)
	add	$16, PTR1
	ret

ENDPROC(x86_aes_expand_key)

#if defined(__i386__) && defined(__PIC__)
	.section	.text.__x86.get_pc_thunk.bx,"axG",@progbits,__x86.get_pc_thunk.bx,comdat
	.globl	__x86.get_pc_thunk.bx
	.hidden	__x86.get_pc_thunk.bx
	.type	__x86.get_pc_thunk.bx, @function
__x86.get_pc_thunk.bx:
	movl	(%esp), %ebx
	ret
#endif

	.bss
	.balign 64
aes_round_keys:
	.space	11*16
	.size	aes_round_keys, .-aes_round_keys

/*
 * This is necessary to keep the whole executable
 * from needing a writable stack.
 */
                .section        .note.GNU-stack,"",%progbits
