
many_uses.so:     file format elf64-x86-64


Disassembly of section .init:

00000000000006b0 <_init>:
 6b0:	48 83 ec 08          	sub    $0x8,%rsp
 6b4:	48 8b 05 15 09 20 00 	mov    0x200915(%rip),%rax        # 200fd0 <_DYNAMIC+0x1d8>
 6bb:	48 85 c0             	test   %rax,%rax
 6be:	74 05                	je     6c5 <_init+0x15>
 6c0:	e8 3b 00 00 00       	callq  700 <k@plt+0x10>
 6c5:	48 83 c4 08          	add    $0x8,%rsp
 6c9:	c3                   	retq   

Disassembly of section .plt:

00000000000006d0 <e@plt-0x10>:
 6d0:	ff 35 32 09 20 00    	pushq  0x200932(%rip)        # 201008 <_GLOBAL_OFFSET_TABLE_+0x8>
 6d6:	ff 25 34 09 20 00    	jmpq   *0x200934(%rip)        # 201010 <_GLOBAL_OFFSET_TABLE_+0x10>
 6dc:	0f 1f 40 00          	nopl   0x0(%rax)

00000000000006e0 <e@plt>:
 6e0:	ff 25 32 09 20 00    	jmpq   *0x200932(%rip)        # 201018 <_GLOBAL_OFFSET_TABLE_+0x18>
 6e6:	68 00 00 00 00       	pushq  $0x0
 6eb:	e9 e0 ff ff ff       	jmpq   6d0 <_init+0x20>

00000000000006f0 <k@plt>:
 6f0:	ff 25 2a 09 20 00    	jmpq   *0x20092a(%rip)        # 201020 <_GLOBAL_OFFSET_TABLE_+0x20>
 6f6:	68 01 00 00 00       	pushq  $0x1
 6fb:	e9 d0 ff ff ff       	jmpq   6d0 <_init+0x20>

Disassembly of section .plt.got:

0000000000000700 <.plt.got>:
 700:	ff 25 ca 08 20 00    	jmpq   *0x2008ca(%rip)        # 200fd0 <_DYNAMIC+0x1d8>
 706:	66 90                	xchg   %ax,%ax
 708:	ff 25 ea 08 20 00    	jmpq   *0x2008ea(%rip)        # 200ff8 <_DYNAMIC+0x200>
 70e:	66 90                	xchg   %ax,%ax

Disassembly of section .text:

0000000000000710 <deregister_tm_clones>:
 710:	48 8d 3d 29 09 20 00 	lea    0x200929(%rip),%rdi        # 201040 <__TMC_END__>
 717:	48 8d 05 29 09 20 00 	lea    0x200929(%rip),%rax        # 201047 <c+0x3>
 71e:	55                   	push   %rbp
 71f:	48 29 f8             	sub    %rdi,%rax
 722:	48 89 e5             	mov    %rsp,%rbp
 725:	48 83 f8 0e          	cmp    $0xe,%rax
 729:	76 15                	jbe    740 <deregister_tm_clones+0x30>
 72b:	48 8b 05 86 08 20 00 	mov    0x200886(%rip),%rax        # 200fb8 <_DYNAMIC+0x1c0>
 732:	48 85 c0             	test   %rax,%rax
 735:	74 09                	je     740 <deregister_tm_clones+0x30>
 737:	5d                   	pop    %rbp
 738:	ff e0                	jmpq   *%rax
 73a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
 740:	5d                   	pop    %rbp
 741:	c3                   	retq   
 742:	0f 1f 40 00          	nopl   0x0(%rax)
 746:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
 74d:	00 00 00 

0000000000000750 <register_tm_clones>:
 750:	48 8d 3d e9 08 20 00 	lea    0x2008e9(%rip),%rdi        # 201040 <__TMC_END__>
 757:	48 8d 35 e2 08 20 00 	lea    0x2008e2(%rip),%rsi        # 201040 <__TMC_END__>
 75e:	55                   	push   %rbp
 75f:	48 29 fe             	sub    %rdi,%rsi
 762:	48 89 e5             	mov    %rsp,%rbp
 765:	48 c1 fe 03          	sar    $0x3,%rsi
 769:	48 89 f0             	mov    %rsi,%rax
 76c:	48 c1 e8 3f          	shr    $0x3f,%rax
 770:	48 01 c6             	add    %rax,%rsi
 773:	48 d1 fe             	sar    %rsi
 776:	74 18                	je     790 <register_tm_clones+0x40>
 778:	48 8b 05 71 08 20 00 	mov    0x200871(%rip),%rax        # 200ff0 <_DYNAMIC+0x1f8>
 77f:	48 85 c0             	test   %rax,%rax
 782:	74 0c                	je     790 <register_tm_clones+0x40>
 784:	5d                   	pop    %rbp
 785:	ff e0                	jmpq   *%rax
 787:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
 78e:	00 00 
 790:	5d                   	pop    %rbp
 791:	c3                   	retq   
 792:	0f 1f 40 00          	nopl   0x0(%rax)
 796:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
 79d:	00 00 00 

00000000000007a0 <__do_global_dtors_aux>:
 7a0:	80 3d 95 08 20 00 00 	cmpb   $0x0,0x200895(%rip)        # 20103c <_edata>
 7a7:	75 27                	jne    7d0 <__do_global_dtors_aux+0x30>
 7a9:	48 83 3d 47 08 20 00 	cmpq   $0x0,0x200847(%rip)        # 200ff8 <_DYNAMIC+0x200>
 7b0:	00 
 7b1:	55                   	push   %rbp
 7b2:	48 89 e5             	mov    %rsp,%rbp
 7b5:	74 0c                	je     7c3 <__do_global_dtors_aux+0x23>
 7b7:	48 8b 3d 6a 08 20 00 	mov    0x20086a(%rip),%rdi        # 201028 <__dso_handle>
 7be:	e8 45 ff ff ff       	callq  708 <k@plt+0x18>
 7c3:	e8 48 ff ff ff       	callq  710 <deregister_tm_clones>
 7c8:	5d                   	pop    %rbp
 7c9:	c6 05 6c 08 20 00 01 	movb   $0x1,0x20086c(%rip)        # 20103c <_edata>
 7d0:	f3 c3                	repz retq 
 7d2:	0f 1f 40 00          	nopl   0x0(%rax)
 7d6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
 7dd:	00 00 00 

00000000000007e0 <frame_dummy>:
 7e0:	48 8d 3d 09 06 20 00 	lea    0x200609(%rip),%rdi        # 200df0 <__JCR_END__>
 7e7:	48 83 3f 00          	cmpq   $0x0,(%rdi)
 7eb:	75 0b                	jne    7f8 <frame_dummy+0x18>
 7ed:	e9 5e ff ff ff       	jmpq   750 <register_tm_clones>
 7f2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
 7f8:	48 8b 05 e9 07 20 00 	mov    0x2007e9(%rip),%rax        # 200fe8 <_DYNAMIC+0x1f0>
 7ff:	48 85 c0             	test   %rax,%rax
 802:	74 e9                	je     7ed <frame_dummy+0xd>
 804:	55                   	push   %rbp
 805:	48 89 e5             	mov    %rsp,%rbp
 808:	ff d0                	callq  *%rax
 80a:	5d                   	pop    %rbp
 80b:	e9 40 ff ff ff       	jmpq   750 <register_tm_clones>

0000000000000810 <j>:
 810:	48 8b 05 c9 07 20 00 	mov    0x2007c9(%rip),%rax        # 200fe0 <_DYNAMIC+0x1e8>
 817:	48 63 ff             	movslq %edi,%rdi
 81a:	8b 04 b8             	mov    (%rax,%rdi,4),%eax
 81d:	c3                   	retq   
 81e:	66 90                	xchg   %ax,%ax

0000000000000820 <f>:
 820:	48 8b 05 a1 07 20 00 	mov    0x2007a1(%rip),%rax        # 200fc8 <_DYNAMIC+0x1d0>
 827:	48 63 ff             	movslq %edi,%rdi
 82a:	48 63 14 b8          	movslq (%rax,%rdi,4),%rdx
 82e:	48 8b 05 ab 07 20 00 	mov    0x2007ab(%rip),%rax        # 200fe0 <_DYNAMIC+0x1e8>
 835:	8b 3c 90             	mov    (%rax,%rdx,4),%edi
 838:	e9 a3 fe ff ff       	jmpq   6e0 <e@plt>
 83d:	0f 1f 00             	nopl   (%rax)

0000000000000840 <g>:
 840:	48 8b 05 91 07 20 00 	mov    0x200791(%rip),%rax        # 200fd8 <_DYNAMIC+0x1e0>
 847:	89 38                	mov    %edi,(%rax)
 849:	48 8b 05 70 07 20 00 	mov    0x200770(%rip),%rax        # 200fc0 <_DYNAMIC+0x1c8>
 850:	48 63 10             	movslq (%rax),%rdx
 853:	48 8b 05 6e 07 20 00 	mov    0x20076e(%rip),%rax        # 200fc8 <_DYNAMIC+0x1d0>
 85a:	8b 04 90             	mov    (%rax,%rdx,4),%eax
 85d:	c3                   	retq   
 85e:	66 90                	xchg   %ax,%ax

0000000000000860 <h>:
 860:	48 8b 05 59 07 20 00 	mov    0x200759(%rip),%rax        # 200fc0 <_DYNAMIC+0x1c8>
 867:	89 38                	mov    %edi,(%rax)
 869:	48 8b 05 68 07 20 00 	mov    0x200768(%rip),%rax        # 200fd8 <_DYNAMIC+0x1e0>
 870:	8b 38                	mov    (%rax),%edi
 872:	eb 9c                	jmp    810 <j>
 874:	66 90                	xchg   %ax,%ax
 876:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
 87d:	00 00 00 

0000000000000880 <k>:
 880:	48 8b 05 59 07 20 00 	mov    0x200759(%rip),%rax        # 200fe0 <_DYNAMIC+0x1e8>
 887:	48 63 ff             	movslq %edi,%rdi
 88a:	8b 04 b8             	mov    (%rax,%rdi,4),%eax
 88d:	c3                   	retq   
 88e:	66 90                	xchg   %ax,%ax

0000000000000890 <m>:
 890:	e9 5b fe ff ff       	jmpq   6f0 <k@plt>

Disassembly of section .fini:

0000000000000898 <_fini>:
 898:	48 83 ec 08          	sub    $0x8,%rsp
 89c:	48 83 c4 08          	add    $0x8,%rsp
 8a0:	c3                   	retq   
