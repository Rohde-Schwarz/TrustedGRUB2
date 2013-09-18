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

status_check_msg:       .string "DEBUG: TCG_StatusCheck "
tcg_passthru_msg:       .string "DEBUG: TCG_PassThru "
logevent_msg:           .string "DEBUG: TCG_LogEvent "
hashlogevent_msg:       .string "DEBUG: TCG_HashLogExtendEvent "
compacthashlogevent_msg: .string "DEBUG: TCG_CompactHashLogExtendEvent "
hashall_msg:            .string "DEBUG: TCG_HashAll 0816 "
ok_msg:                 .string "ok\r\n"
error_msg:                 .string "failed\r\n"
        /* DEBUG: End of debug messages */
#else  /* TCG_DEBUG */
#define MSG(x)
#endif /* TCG_DEBUG */

/* END adapted from GRUB-IMA */

	.code32

/* Vars used by asm_tcg_statusCheck() */
VARIABLE(ebx_save)
	.long	0

VARIABLE(edi_save)
	.long	0

VARIABLE(esi_save)
	.long	0

/* int asm_tcg_statusCheck( struct tcg_statusCheck_args *args )

   Verifies the presence of the TCG BIOS interface and provides the caller
   with the version of this specification to which the implementation complies

   struct tcg_statusCheck_args {
  	u32 out_eax, out_ebx, out_ecx, out_edx, out_esi, out_edi;
   } __attribute__ ((packed));

   eax = Return code
   ebx = 0x41504354 = "TCPA"
   ecx = "Version and errata of the specification this BIOS supports.
   edx = "BIOS TCG Feature Flags (None currently defined. MUST be set to 0)"
   esi = "Absolute pointer to the beginning of the event log."
   edi = See spec.

   Return value of function and eax = 0 if TPM available
 */
FUNCTION(asm_tcg_statusCheck)
	push	%ebp
	movl	%esp, %ebp
	push	%ebx
	push	%ecx
	push	%edx
	push	%esi
	push	%edi

	/* first three arguments are passed in %eax, %edx, and %ecx */
	/* first argument */
	push %eax

	PROT_TO_REAL
	.code16

	/* TCG_StatusCheck
	(AH) = BBh, (AL) = 00h */
	movl $0xBB00, %eax

	/* TCG interrupt call */
	int $0x1A

	/* returnCode != 0  => ERROR */
	test	%eax, %eax
	jnz     tcg_statusCheck_error

	MSG(ok_msg)
	jmp    tcg_statusCheck_end

tcg_statusCheck_error:
	MSG(error_msg)

tcg_statusCheck_end:
	/* Preserve Register */
	movl	%ebx, EXT_C(ebx_save)
	movl	%esi, EXT_C(esi_save)
	movl	%edi, EXT_C(edi_save)
	movl    %eax, %ebx

	REAL_TO_PROT
	.code32

	/* Restore eax */
	movl    %ebx, %eax

	/* Restore ebx */
	movl	EXT_C(ebx_save), %ebx

	/* Move argument address to esi */
	pop 	%esi

	/* Set return values */
	/* eax = Return code */
	movl    %esi, %edi
	movl	%eax, (%edi)

	/* ebx = 0x41504354 = "TCPA" */
	addl	$4, %esi
	movl    %esi, %edi
	movl	%ebx, (%edi)

	/* ecx = "Version and errata of the specification this BIOS supports." */
	addl	$4, %esi
	movl    %esi, %edi
	movl	%ecx, (%edi)

	/* edx = "BIOS TCG Feature Flags (None currently defined. MUST be set to 0)" */
	addl	$4, %esi
	movl    %esi, %edi
	movl	%edx, (%edi)

	/* esi = "Absolute pointer to the beginning of the event log." */
	addl	$4, %esi
	movl    %esi, %edi
	push	%esi
	/* Restore esi */
	movl	EXT_C(esi_save), %esi
	movl	%esi, (%edi)
	pop 	%esi

	/* edi = See spec. */
	addl	$4, %esi
	movl    %esi, %ebx
	/* Restore edi */
	movl	EXT_C(edi_save), %edi
	movl	%edi, (%ebx)

	pop     %edi
	pop     %esi
	pop     %edx
	pop     %ecx
	pop     %ebx
	pop     %ebp
	ret

/* int asm_tcg_passThroughToTPM( struct tcg_passThroughToTPM_args *args )

   Provides a pass-through capability from the caller to the system’s TPM

   struct tcg_passThroughToTPM_args {
  	u32 out_eax;
  	u32 in_ebx, in_ecx, in_edx, in_esi, in_edi, in_es, in_ds;
   } __attribute__ ((packed));

   in_ebx = 0x41504354 = "TCPA"
   in_ecx = 0
   in_edx = 0
   in_esi = Segment portion of the pointer to the TPM input parameter block
   in_edi = Offset portion of the pointer to the TPM input parameter block
   in_es = Segment portion of the pointer to the TPM output parameter block
   in_ds = Offset portion of the pointer to the TPM output parameter block

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

/* End TCG extension */
