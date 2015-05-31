/* Begin TCG extension */

/* #define TCG_DEBUG */

#ifdef TCG_DEBUG
	.code16

/* BEGIN: adapted from GRUB-IMA: */

/* DEBUG: Display debug message */
debugmsg:
	push    %ax
	push    %bx
	cld
debugmsg_loop:
	lodsb
	cmpb    $0, %al
	je      debugmsg_ret
	movw    $0x0001, %bx
	movb    $0xe, %ah
	/* Display a byte */
	int     $0x10
	jmp     debugmsg_loop
debugmsg_ret:
	pop     %bx
	pop     %ax
	ret

#define MSG(x)  push %si; movw $(x), %si; call debugmsg; pop %si

ok_msg:                 .string "ok\r\n"
error_msg:                 .string "failed\r\n"
#else  /* TCG_DEBUG */
#define MSG(x)
#endif /* TCG_DEBUG */

/* END adapted from GRUB-IMA */

	.code32

/* int asm_tcg_passThroughToTPM( struct tcg_passThroughToTPM_args *args )

   Provides a pass-through capability from the caller to the system’s TPM

   struct tcg_passThroughToTPM_args {
  	u32 out_eax;
  	u32 in_ebx, in_ecx, in_edx, in_esi, in_edi, in_es, in_ds;
   } __attribute__ ((packed));

   in_ebx = 0x41504354 = "TCPA"
   in_ecx = 0
   in_edx = 0
   in_es  = Segment portion of the pointer to the TPM input parameter block
   in_edi = Offset portion of the pointer to the TPM input parameter block
   in_ds  = Segment portion of the pointer to the TPM output parameter block
   in_esi = Offset portion of the pointer to the TPM output parameter block

   out_eax = Return code
   DS:SI = Referenced buffer updated to provide return results.
 */
FUNCTION(asm_tcg_passThroughToTPM)
	push	%ebp
	movl	%esp, %ebp
	push	%ebx
	push	%ecx
	push	%edx
	push	%esi
	push	%edi

	/* preserve argument address */
	push 	%eax

	/* in_ebx  */
	movl	4(%eax), %ebx

	/*
	movl	8(%eax), %ecx	 in_ecx
	movl	12(%eax), %edx	 in_edx
	*/

	/* in_esi **/
	movl	16(%eax), %esi
	/* in_edi */
	movl	20(%eax), %edi

	/* TODO: Currently using dx and cx for taking es and ds values to realmode
	   Find out how to get es and ds values in realmode directly from 24(%eax) and 28(%eax) */

	/* Save es in dx  */
	movw	24(%eax), %dx
	/* Save ds in cx  */
	movw	28(%eax), %cx


	/* preserve %eax before switching to realmode
	movl %eax, %edx */

	/* messes up %eax and %ebp. */
	PROT_TO_REAL
	.code16

	/* restore %eax
	movl %edx, %eax */

	/* Save registers before creating a new segment */
	pushw %es
	pushw %ds

	/* Setting es,ds only in realmode possible?! */
	movw	%dx, %es
	movw	%cx, %ds

	/* FIXME: See TODO above */
	/* in_ecx = 0 */
	xorl %ecx, %ecx
	/* in_edx = 0 */
	xorl %edx, %edx

	/* TCG_PassThroughToTPM (AH) = BBh, (AL) = 02h */
	movl $0xBB02, %eax

	/* TCG interrupt call */
	int $0x1A

	/* Restore registers (go back to previous segment) */
	popw 	%ds
	popw 	%es

	/* returnCode != 0  => ERROR */
	test	%eax, %eax
	jnz     tcg_passThroughToTPM_error

	MSG(ok_msg)
	jmp		tcg_passThroughToTPM_end

tcg_passThroughToTPM_error:
	MSG(error_msg)

tcg_passThroughToTPM_end:
	/* preserve %eax before switching to protected mode */
	movl    %eax, %ebx

	REAL_TO_PROT
	.code32

	/* restore %eax */
	movl %ebx, %eax

	/* get argument address in esi */
	pop 	%esi

	/* set out_eax = returnCode */
	movl    %esi, %edi
	movl	%eax, (%edi)

	pop     %edi
	pop     %esi
	pop     %edx
	pop     %ecx
	pop     %ebx
	pop     %ebp
	ret

/* int asm_tcg_SetMemoryOverwriteRequestBit( struct tcg_SetMemoryOverwriteRequestBit_args *args )

   This function sets or clears the Memory Overwrite Request (MOR) bit.

   struct tcg_SetMemoryOverwriteRequestBit_args {
	u32 out_eax;
	u32 in_ebx, in_ecx, in_edx, in_edi, in_es;
	} __attribute__ ((packed));

   in_ebx = 0x41504354 = "TCPA"
   in_ecx = 0
   in_edx = 0
   in_es  = Segment portion of the pointer to the TPM input parameter block
   in_edi = Offset portion of the pointer to the TPM input parameter block

   out_eax = Return code
 */
FUNCTION(asm_tcg_SetMemoryOverwriteRequestBit)
	push	%ebp
	movl	%esp, %ebp
	push	%ebx
	push	%ecx
	push	%edx
	push	%esi
	push	%edi

	/* preserve argument address */
	push 	%eax

	/* in_ebx  */
	movl	4(%eax), %ebx

	/* in_ecx */
	movl	8(%eax), %ecx

	/*
	movl	12(%eax), %edx	 in_edx
	*/

	/* in_edi */
	movl	16(%eax), %edi

	/* TODO: Currently using dx for taking es value to realmode
	   Find out how to get es value in realmode directly from 20(%eax) */

	/* Save es in dx  */
	movw	20(%eax), %dx

	/* messes up %eax and %ebp. */
	PROT_TO_REAL
	.code16

	/* Save registers before creating a new segment */
	pushw %es

	/* Setting es only in realmode possible?! */
	movw	%dx, %es

	/* FIXME: See TODO above */
	/* in_edx = 0 */
	xorl %edx, %edx

	/* TCG_SetMemoryOverwriteRequestBit (AH) = BBh, (AL) = 08h */
	movl $0xBB08, %eax

	/* TCG interrupt call */
	int $0x1A

	/* Restore registers (go back to previous segment) */
	popw 	%es

	/* returnCode != 0  => ERROR */
	test	%eax, %eax
	jnz     tcg_SetMemoryOverwriteRequestBit_error

	MSG(ok_msg)
	jmp		tcg_SetMemoryOverwriteRequestBit_end

tcg_SetMemoryOverwriteRequestBit_error:
	MSG(error_msg)

tcg_SetMemoryOverwriteRequestBit_end:
	/* preserve %eax before switching to protected mode */
	movl    %eax, %ebx

	REAL_TO_PROT
	.code32

	/* restore %eax */
	movl %ebx, %eax

	/* get argument address in esi */
	pop 	%esi

	/* set out_eax = returnCode */
	movl    %esi, %edi
	movl	%eax, (%edi)

	pop     %edi
	pop     %esi
	pop     %edx
	pop     %ecx
	pop     %ebx
	pop     %ebp
	ret

/* End TCG extension */
