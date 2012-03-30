	.local  origmain
	.comm   origmain,4,4

	.section .rodata
dlsymstr:
	.string "__libc_start_main"

	.text

	.globl  jump_stack
	.type   jump_stack, @function
# void jump_stack (unsigned long bos, unsigned long newbos);
# it's cdecl. bos=bottom-of-stack (large address)
jump_stack:
	pushl   %ebp
	movl    %esp, %ebp
	pushl   %ebx
	pushl   %esi
	pushl   %edi

	movl    12(%ebp), %esi
	subl    8(%ebp), %esi # esi = delta

	# patch previous stack
	movl    %ebp, %eax  # eax have the current ebp iterator
patch_restart:
	movl    (%eax), %ebx # ebx have the next ebp iterator
	cmpl    %eax, %ebx
	jbe patch_finish
	cmpl    8(%ebp), %ebx
	jae patch_finish
	movl    %ebx, %ecx
	addl    %esi, %ecx
	movl    %ecx, (%eax)
	movl	%ebx, %eax
	jmp patch_restart
patch_finish:

	# call memcpy to copy
	movl    %esp, %eax       # eax = src = esp
	movl    8(%ebp), %ebx
	subl    %eax, %ebx       # ebx = size = bos - esp
	movl    12(%ebp), %ecx
	subl    %ebx, %ecx       # ecx = dst = newbos - size
	pushl   %ebx
	pushl   %eax
	pushl   %ecx
	call    memcpy # memcpy(esp + delta, esp, copysize)
	addl    $12, %esp

	# change esp and ebp
	addl    %esi, %ebp
	addl    %esi, %esp

	# restore registers
	popl    %edi
	popl    %esi
	popl    %ebx
	popl    %ebp
	ret

	.globl  call_varg_func
	.type   call_varg_func, @function
# void *call_varg_func (void *func, int argc, const void **argv);
call_varg_func:
	pushl   %ebp
	movl    %esp, %ebp
	pushl   %ebx
	movl    12(%ebp), %ecx  # ecx = argc
	movl    16(%ebp), %ebx  # ebx = argv
in1:
	testl   %ecx, %ecx
	jle out1
	decl    %ecx
	movl    (%ebx,%ecx,4), %edx
	pushl   %edx
	jmp in1
out1:
	call    *8(%ebp)
	movl    12(%ebp), %ecx  # ecx = argc
	leal    0(,%ecx,4),%edx
	addl    %edx, %esp
	popl    %ebx
	popl    %ebp
	ret

	.local  mymainstub
	.type   mymainstub, @function
mymainstub:
	movl    12(%esp), %eax
	pushl   %eax
	movl    12(%esp), %eax
	pushl   %eax
	movl    12(%esp), %eax
	pushl   %eax
	movl    origmain, %eax
	pushl   %eax
	call    hookmain
	addl    $16, %esp
	ret

	.globl  __libc_start_main
	.type   __libc_start_main, @function
# extern int BP_SYM (__libc_start_main) (int (*main) (int, char **, char **),
#     int argc,
#     char *__unbounded *__unbounded ubp_av,
#     void (*init) (void),
#     void (*fini) (void),
#     void (*rtld_fini) (void),
#     void *__unbounded stack_end)
# __attribute__ ((noreturn));
__libc_start_main:
	movl    4(%esp), %eax
	movl    %eax, origmain
	movl    $mymainstub, %eax
	movl    %eax, 4(%esp)
	pushl   $dlsymstr
	pushl   $-1
	call    dlsym
	addl    $8, %esp
#	movl    $0, (0)
	jmp     *%eax

# 	.globl	child_jail_entry
# 	.type	child_jail_entry, @function
# child_jail_entry:
# 	movl	-4(%esp), %edx # edx=func
# 	movl	-8(%esp), %eax # eax=pusha_addr
# 
# # save all jail registers except eax, edx and esp
# 	pushl	%ecx
# 	pushl	%ebx
# 	pushl	%ebp
# 	pushl	%esi
# 	pushl	%edi
# # save esp to saved_esp
# 	movl	%esp, saved_esp # FIXME
# 
# # set esp to new esp
# 	movl	16(%eax), %esp
# # set return address to ours. we don't need to save the original
# 	movl	$child_jail_exit, (%esp)
# # jump to target
# 	jmp	*%edx
# 
# child_jail_exit:
# # restore esp
# 	movl	saved_esp, %esp # FIXME
# # restore jail registers
# 	popl	%edi
# 	popl	%esi
# 	popl	%ebp
# 	popl	%ebx
# 	popl	%ecx
# 	ret
