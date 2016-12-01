
bitpuzzle:     file format elf32-i386


Disassembly of section .init:

0804837c <.init>:
 804837c:	53                   	push   ebx
 804837d:	83 ec 08             	sub    esp,0x8
 8048380:	e8 00 00 00 00       	call   8048385 <printf@plt-0x3b>
 8048385:	5b                   	pop    ebx
 8048386:	81 c3 6f 1c 00 00    	add    ebx,0x1c6f
 804838c:	8b 83 fc ff ff ff    	mov    eax,DWORD PTR [ebx-0x4]
 8048392:	85 c0                	test   eax,eax
 8048394:	74 05                	je     804839b <printf@plt-0x25>
 8048396:	e8 65 00 00 00       	call   8048400 <__gmon_start__@plt>
 804839b:	e8 20 01 00 00       	call   80484c0 <__libc_start_main@plt+0xa0>
 80483a0:	e8 db 03 00 00       	call   8048780 <__libc_start_main@plt+0x360>
 80483a5:	83 c4 08             	add    esp,0x8
 80483a8:	5b                   	pop    ebx
 80483a9:	c3                   	ret    

Disassembly of section .plt:

080483b0 <printf@plt-0x10>:
 80483b0:	ff 35 f8 9f 04 08    	push   DWORD PTR ds:0x8049ff8
 80483b6:	ff 25 fc 9f 04 08    	jmp    DWORD PTR ds:0x8049ffc
 80483bc:	00 00                	add    BYTE PTR [eax],al
	...

080483c0 <printf@plt>:
 80483c0:	ff 25 00 a0 04 08    	jmp    DWORD PTR ds:0x804a000
 80483c6:	68 00 00 00 00       	push   0x0
 80483cb:	e9 e0 ff ff ff       	jmp    80483b0 <printf@plt-0x10>

080483d0 <fgets@plt>:
 80483d0:	ff 25 04 a0 04 08    	jmp    DWORD PTR ds:0x804a004
 80483d6:	68 08 00 00 00       	push   0x8
 80483db:	e9 d0 ff ff ff       	jmp    80483b0 <printf@plt-0x10>

080483e0 <__stack_chk_fail@plt>:
 80483e0:	ff 25 08 a0 04 08    	jmp    DWORD PTR ds:0x804a008
 80483e6:	68 10 00 00 00       	push   0x10
 80483eb:	e9 c0 ff ff ff       	jmp    80483b0 <printf@plt-0x10>

080483f0 <puts@plt>:
 80483f0:	ff 25 0c a0 04 08    	jmp    DWORD PTR ds:0x804a00c
 80483f6:	68 18 00 00 00       	push   0x18
 80483fb:	e9 b0 ff ff ff       	jmp    80483b0 <printf@plt-0x10>

08048400 <__gmon_start__@plt>:
 8048400:	ff 25 10 a0 04 08    	jmp    DWORD PTR ds:0x804a010
 8048406:	68 20 00 00 00       	push   0x20
 804840b:	e9 a0 ff ff ff       	jmp    80483b0 <printf@plt-0x10>

08048410 <exit@plt>:
 8048410:	ff 25 14 a0 04 08    	jmp    DWORD PTR ds:0x804a014
 8048416:	68 28 00 00 00       	push   0x28
 804841b:	e9 90 ff ff ff       	jmp    80483b0 <printf@plt-0x10>

08048420 <__libc_start_main@plt>:
 8048420:	ff 25 18 a0 04 08    	jmp    DWORD PTR ds:0x804a018
 8048426:	68 30 00 00 00       	push   0x30
 804842b:	e9 80 ff ff ff       	jmp    80483b0 <printf@plt-0x10>

Disassembly of section .text:

08048430 <.text>:
 8048430:	31 ed                	xor    ebp,ebp
 8048432:	5e                   	pop    esi
 8048433:	89 e1                	mov    ecx,esp
 8048435:	83 e4 f0             	and    esp,0xfffffff0
 8048438:	50                   	push   eax
 8048439:	54                   	push   esp
 804843a:	52                   	push   edx
 804843b:	68 70 87 04 08       	push   0x8048770
 8048440:	68 00 87 04 08       	push   0x8048700
 8048445:	51                   	push   ecx
 8048446:	56                   	push   esi
 8048447:	68 e4 84 04 08       	push   0x80484e4
 804844c:	e8 cf ff ff ff       	call   8048420 <__libc_start_main@plt>
 8048451:	f4                   	hlt    
 8048452:	90                   	nop
 8048453:	90                   	nop
 8048454:	90                   	nop
 8048455:	90                   	nop
 8048456:	90                   	nop
 8048457:	90                   	nop
 8048458:	90                   	nop
 8048459:	90                   	nop
 804845a:	90                   	nop
 804845b:	90                   	nop
 804845c:	90                   	nop
 804845d:	90                   	nop
 804845e:	90                   	nop
 804845f:	90                   	nop
 8048460:	55                   	push   ebp
 8048461:	89 e5                	mov    ebp,esp
 8048463:	53                   	push   ebx
 8048464:	83 ec 04             	sub    esp,0x4
 8048467:	80 3d 28 a0 04 08 00 	cmp    BYTE PTR ds:0x804a028,0x0
 804846e:	75 3f                	jne    80484af <__libc_start_main@plt+0x8f>
 8048470:	a1 2c a0 04 08       	mov    eax,ds:0x804a02c
 8048475:	bb 20 9f 04 08       	mov    ebx,0x8049f20
 804847a:	81 eb 1c 9f 04 08    	sub    ebx,0x8049f1c
 8048480:	c1 fb 02             	sar    ebx,0x2
 8048483:	83 eb 01             	sub    ebx,0x1
 8048486:	39 d8                	cmp    eax,ebx
 8048488:	73 1e                	jae    80484a8 <__libc_start_main@plt+0x88>
 804848a:	8d b6 00 00 00 00    	lea    esi,[esi+0x0]
 8048490:	83 c0 01             	add    eax,0x1
 8048493:	a3 2c a0 04 08       	mov    ds:0x804a02c,eax
 8048498:	ff 14 85 1c 9f 04 08 	call   DWORD PTR [eax*4+0x8049f1c]
 804849f:	a1 2c a0 04 08       	mov    eax,ds:0x804a02c
 80484a4:	39 d8                	cmp    eax,ebx
 80484a6:	72 e8                	jb     8048490 <__libc_start_main@plt+0x70>
 80484a8:	c6 05 28 a0 04 08 01 	mov    BYTE PTR ds:0x804a028,0x1
 80484af:	83 c4 04             	add    esp,0x4
 80484b2:	5b                   	pop    ebx
 80484b3:	5d                   	pop    ebp
 80484b4:	c3                   	ret    
 80484b5:	8d 74 26 00          	lea    esi,[esi+eiz*1+0x0]
 80484b9:	8d bc 27 00 00 00 00 	lea    edi,[edi+eiz*1+0x0]
 80484c0:	55                   	push   ebp
 80484c1:	89 e5                	mov    ebp,esp
 80484c3:	83 ec 18             	sub    esp,0x18
 80484c6:	a1 24 9f 04 08       	mov    eax,ds:0x8049f24
 80484cb:	85 c0                	test   eax,eax
 80484cd:	74 12                	je     80484e1 <__libc_start_main@plt+0xc1>
 80484cf:	b8 00 00 00 00       	mov    eax,0x0
 80484d4:	85 c0                	test   eax,eax
 80484d6:	74 09                	je     80484e1 <__libc_start_main@plt+0xc1>
 80484d8:	c7 04 24 24 9f 04 08 	mov    DWORD PTR [esp],0x8049f24
 80484df:	ff d0                	call   eax
 80484e1:	c9                   	leave  
 80484e2:	c3                   	ret    
 80484e3:	90                   	nop
 80484e4:	55                   	push   ebp
 80484e5:	89 e5                	mov    ebp,esp
 80484e7:	57                   	push   edi
 80484e8:	56                   	push   esi
 80484e9:	53                   	push   ebx
 80484ea:	83 e4 f0             	and    esp,0xfffffff0
 80484ed:	81 ec 20 01 00 00    	sub    esp,0x120
 80484f3:	65 a1 14 00 00 00    	mov    eax,gs:0x14
 80484f9:	89 84 24 1c 01 00 00 	mov    DWORD PTR [esp+0x11c],eax
 8048500:	31 c0                	xor    eax,eax
 8048502:	8d 5c 24 1c          	lea    ebx,[esp+0x1c]
 8048506:	b9 40 00 00 00       	mov    ecx,0x40
 804850b:	89 df                	mov    edi,ebx
 804850d:	f3 ab                	rep stos DWORD PTR es:[edi],eax
 804850f:	c7 04 24 d0 87 04 08 	mov    DWORD PTR [esp],0x80487d0
 8048516:	e8 d5 fe ff ff       	call   80483f0 <puts@plt>
 804851b:	c7 04 24 40 88 04 08 	mov    DWORD PTR [esp],0x8048840
 8048522:	e8 c9 fe ff ff       	call   80483f0 <puts@plt>
 8048527:	a1 24 a0 04 08       	mov    eax,ds:0x804a024
 804852c:	89 44 24 08          	mov    DWORD PTR [esp+0x8],eax
 8048530:	c7 44 24 04 50 00 00 	mov    DWORD PTR [esp+0x4],0x50
 8048537:	00 
 8048538:	89 1c 24             	mov    DWORD PTR [esp],ebx
 804853b:	e8 90 fe ff ff       	call   80483d0 <fgets@plt>
 8048540:	ba ff ff ff ff       	mov    edx,0xffffffff
 8048545:	89 df                	mov    edi,ebx
 8048547:	b8 00 00 00 00       	mov    eax,0x0
 804854c:	89 d1                	mov    ecx,edx
 804854e:	f2 ae                	repnz scas al,BYTE PTR es:[edi]
 8048550:	f7 d1                	not    ecx
 8048552:	c6 44 0c 1a 00       	mov    BYTE PTR [esp+ecx*1+0x1a],0x0
 8048557:	89 df                	mov    edi,ebx
 8048559:	89 d1                	mov    ecx,edx
 804855b:	f2 ae                	repnz scas al,BYTE PTR es:[edi]
 804855d:	83 f9 de             	cmp    ecx,0xffffffde
 8048560:	74 20                	je     8048582 <__libc_start_main@plt+0x162>
 8048562:	8d 44 24 1c          	lea    eax,[esp+0x1c]
 8048566:	89 44 24 04          	mov    DWORD PTR [esp+0x4],eax
 804856a:	c7 04 24 f0 87 04 08 	mov    DWORD PTR [esp],0x80487f0
 8048571:	e8 4a fe ff ff       	call   80483c0 <printf@plt>
 8048576:	c7 04 24 00 00 00 00 	mov    DWORD PTR [esp],0x0
 804857d:	e8 8e fe ff ff       	call   8048410 <exit@plt>
 8048582:	8b 54 24 1c          	mov    edx,DWORD PTR [esp+0x1c]
 8048586:	8b 44 24 20          	mov    eax,DWORD PTR [esp+0x20]
 804858a:	8b 7c 24 24          	mov    edi,DWORD PTR [esp+0x24]
 804858e:	8d 1c 07             	lea    ebx,[edi+eax*1]
 8048591:	b9 00 00 00 00       	mov    ecx,0x0
 8048596:	81 fb ce df dc c0    	cmp    ebx,0xc0dcdfce
 804859c:	75 0f                	jne    80485ad <__libc_start_main@plt+0x18d>
 804859e:	8d 0c 10             	lea    ecx,[eax+edx*1]
 80485a1:	81 f9 dc dd d3 d5    	cmp    ecx,0xd5d3dddc
 80485a7:	0f 94 c1             	sete   cl
 80485aa:	0f b6 c9             	movzx  ecx,cl
 80485ad:	8d 34 52             	lea    esi,[edx+edx*2]
 80485b0:	8d 1c 80             	lea    ebx,[eax+eax*4]
 80485b3:	8d 1c 33             	lea    ebx,[ebx+esi*1]
 80485b6:	81 fb 66 76 4a 40    	cmp    ebx,0x404a7666
 80485bc:	bb 00 00 00 00       	mov    ebx,0x0
 80485c1:	0f 45 cb             	cmovne ecx,ebx
 80485c4:	8b 5c 24 28          	mov    ebx,DWORD PTR [esp+0x28]
 80485c8:	31 d3                	xor    ebx,edx
 80485ca:	81 fb 07 06 03 18    	cmp    ebx,0x18030607
 80485d0:	bb 00 00 00 00       	mov    ebx,0x0
 80485d5:	0f 45 cb             	cmovne ecx,ebx
 80485d8:	23 54 24 28          	and    edx,DWORD PTR [esp+0x28]
 80485dc:	81 fa 70 69 6c 66    	cmp    edx,0x666c6970
 80485e2:	ba 00 00 00 00       	mov    edx,0x0
 80485e7:	0f 45 ca             	cmovne ecx,edx
 80485ea:	8b 5c 24 2c          	mov    ebx,DWORD PTR [esp+0x2c]
 80485ee:	0f af c3             	imul   eax,ebx
 80485f1:	3d 2b 90 80 b1       	cmp    eax,0xb180902b
 80485f6:	b8 00 00 00 00       	mov    eax,0x0
 80485fb:	0f 45 c8             	cmovne ecx,eax
 80485fe:	89 d8                	mov    eax,ebx
 8048600:	0f af c7             	imul   eax,edi
 8048603:	3d 5f 6b 43 3e       	cmp    eax,0x3e436b5f
 8048608:	b8 00 00 00 00       	mov    eax,0x0
 804860d:	0f 45 c8             	cmovne ecx,eax
 8048610:	8b 74 24 30          	mov    esi,DWORD PTR [esp+0x30]
 8048614:	8d 04 73             	lea    eax,[ebx+esi*2]
 8048617:	3d 31 38 48 5c       	cmp    eax,0x5c483831
 804861c:	b8 00 00 00 00       	mov    eax,0x0
 8048621:	0f 45 c8             	cmovne ecx,eax
 8048624:	89 f0                	mov    eax,esi
 8048626:	25 00 00 00 70       	and    eax,0x70000000
 804862b:	3d 00 00 00 70       	cmp    eax,0x70000000
 8048630:	b8 00 00 00 00       	mov    eax,0x0
 8048635:	0f 45 c8             	cmovne ecx,eax
 8048638:	89 f0                	mov    eax,esi
 804863a:	ba 00 00 00 00       	mov    edx,0x0
 804863f:	f7 74 24 34          	div    DWORD PTR [esp+0x34]
 8048643:	83 f8 01             	cmp    eax,0x1
 8048646:	b8 00 00 00 00       	mov    eax,0x0
 804864b:	0f 45 c8             	cmovne ecx,eax
 804864e:	89 f0                	mov    eax,esi
 8048650:	ba 00 00 00 00       	mov    edx,0x0
 8048655:	f7 74 24 34          	div    DWORD PTR [esp+0x34]
 8048659:	81 fa ec 0c 00 0e    	cmp    edx,0xe000cec
 804865f:	b8 00 00 00 00       	mov    eax,0x0
 8048664:	0f 45 c8             	cmovne ecx,eax
 8048667:	8b 44 24 38          	mov    eax,DWORD PTR [esp+0x38]
 804866b:	8d 14 5b             	lea    edx,[ebx+ebx*2]
 804866e:	8d 14 42             	lea    edx,[edx+eax*2]
 8048671:	81 fa 17 eb 26 37    	cmp    edx,0x3726eb17
 8048677:	ba 00 00 00 00       	mov    edx,0x0
 804867c:	0f 45 ca             	cmovne ecx,edx
 804867f:	8d 14 c5 00 00 00 00 	lea    edx,[eax*8+0x0]
 8048686:	29 c2                	sub    edx,eax
 8048688:	8d 14 ba             	lea    edx,[edx+edi*4]
 804868b:	81 fa 2d 92 0b 8b    	cmp    edx,0x8b0b922d
 8048691:	ba 00 00 00 00       	mov    edx,0x0
 8048696:	0f 45 ca             	cmovne ecx,edx
 8048699:	8d 04 40             	lea    eax,[eax+eax*2]
 804869c:	03 44 24 28          	add    eax,DWORD PTR [esp+0x28]
 80486a0:	3d 91 9c cf b9       	cmp    eax,0xb9cf9c91
 80486a5:	75 1a                	jne    80486c1 <__libc_start_main@plt+0x2a1>
 80486a7:	85 c9                	test   ecx,ecx
 80486a9:	74 16                	je     80486c1 <__libc_start_main@plt+0x2a1>
 80486ab:	8d 44 24 1c          	lea    eax,[esp+0x1c]
 80486af:	89 44 24 04          	mov    DWORD PTR [esp+0x4],eax
 80486b3:	c7 04 24 14 88 04 08 	mov    DWORD PTR [esp],0x8048814
 80486ba:	e8 01 fd ff ff       	call   80483c0 <printf@plt>
 80486bf:	eb 14                	jmp    80486d5 <__libc_start_main@plt+0x2b5>
 80486c1:	8d 44 24 1c          	lea    eax,[esp+0x1c]
 80486c5:	89 44 24 04          	mov    DWORD PTR [esp+0x4],eax
 80486c9:	c7 04 24 f0 87 04 08 	mov    DWORD PTR [esp],0x80487f0
 80486d0:	e8 eb fc ff ff       	call   80483c0 <printf@plt>
 80486d5:	8b 9c 24 1c 01 00 00 	mov    ebx,DWORD PTR [esp+0x11c]
 80486dc:	65 33 1d 14 00 00 00 	xor    ebx,DWORD PTR gs:0x14
 80486e3:	74 05                	je     80486ea <__libc_start_main@plt+0x2ca>
 80486e5:	e8 f6 fc ff ff       	call   80483e0 <__stack_chk_fail@plt>
 80486ea:	8d 65 f4             	lea    esp,[ebp-0xc]
 80486ed:	5b                   	pop    ebx
 80486ee:	5e                   	pop    esi
 80486ef:	5f                   	pop    edi
 80486f0:	5d                   	pop    ebp
 80486f1:	c3                   	ret    
 80486f2:	90                   	nop
 80486f3:	90                   	nop
 80486f4:	90                   	nop
 80486f5:	90                   	nop
 80486f6:	90                   	nop
 80486f7:	90                   	nop
 80486f8:	90                   	nop
 80486f9:	90                   	nop
 80486fa:	90                   	nop
 80486fb:	90                   	nop
 80486fc:	90                   	nop
 80486fd:	90                   	nop
 80486fe:	90                   	nop
 80486ff:	90                   	nop
 8048700:	55                   	push   ebp
 8048701:	57                   	push   edi
 8048702:	56                   	push   esi
 8048703:	53                   	push   ebx
 8048704:	e8 69 00 00 00       	call   8048772 <__libc_start_main@plt+0x352>
 8048709:	81 c3 eb 18 00 00    	add    ebx,0x18eb
 804870f:	83 ec 1c             	sub    esp,0x1c
 8048712:	8b 6c 24 30          	mov    ebp,DWORD PTR [esp+0x30]
 8048716:	8d bb 20 ff ff ff    	lea    edi,[ebx-0xe0]
 804871c:	e8 5b fc ff ff       	call   804837c <printf@plt-0x44>
 8048721:	8d 83 20 ff ff ff    	lea    eax,[ebx-0xe0]
 8048727:	29 c7                	sub    edi,eax
 8048729:	c1 ff 02             	sar    edi,0x2
 804872c:	85 ff                	test   edi,edi
 804872e:	74 29                	je     8048759 <__libc_start_main@plt+0x339>
 8048730:	31 f6                	xor    esi,esi
 8048732:	8d b6 00 00 00 00    	lea    esi,[esi+0x0]
 8048738:	8b 44 24 38          	mov    eax,DWORD PTR [esp+0x38]
 804873c:	89 2c 24             	mov    DWORD PTR [esp],ebp
 804873f:	89 44 24 08          	mov    DWORD PTR [esp+0x8],eax
 8048743:	8b 44 24 34          	mov    eax,DWORD PTR [esp+0x34]
 8048747:	89 44 24 04          	mov    DWORD PTR [esp+0x4],eax
 804874b:	ff 94 b3 20 ff ff ff 	call   DWORD PTR [ebx+esi*4-0xe0]
 8048752:	83 c6 01             	add    esi,0x1
 8048755:	39 fe                	cmp    esi,edi
 8048757:	75 df                	jne    8048738 <__libc_start_main@plt+0x318>
 8048759:	83 c4 1c             	add    esp,0x1c
 804875c:	5b                   	pop    ebx
 804875d:	5e                   	pop    esi
 804875e:	5f                   	pop    edi
 804875f:	5d                   	pop    ebp
 8048760:	c3                   	ret    
 8048761:	eb 0d                	jmp    8048770 <__libc_start_main@plt+0x350>
 8048763:	90                   	nop
 8048764:	90                   	nop
 8048765:	90                   	nop
 8048766:	90                   	nop
 8048767:	90                   	nop
 8048768:	90                   	nop
 8048769:	90                   	nop
 804876a:	90                   	nop
 804876b:	90                   	nop
 804876c:	90                   	nop
 804876d:	90                   	nop
 804876e:	90                   	nop
 804876f:	90                   	nop
 8048770:	f3 c3                	repz ret 
 8048772:	8b 1c 24             	mov    ebx,DWORD PTR [esp]
 8048775:	c3                   	ret    
 8048776:	90                   	nop
 8048777:	90                   	nop
 8048778:	90                   	nop
 8048779:	90                   	nop
 804877a:	90                   	nop
 804877b:	90                   	nop
 804877c:	90                   	nop
 804877d:	90                   	nop
 804877e:	90                   	nop
 804877f:	90                   	nop
 8048780:	55                   	push   ebp
 8048781:	89 e5                	mov    ebp,esp
 8048783:	53                   	push   ebx
 8048784:	83 ec 04             	sub    esp,0x4
 8048787:	a1 14 9f 04 08       	mov    eax,ds:0x8049f14
 804878c:	83 f8 ff             	cmp    eax,0xffffffff
 804878f:	74 13                	je     80487a4 <__libc_start_main@plt+0x384>
 8048791:	bb 14 9f 04 08       	mov    ebx,0x8049f14
 8048796:	66 90                	xchg   ax,ax
 8048798:	83 eb 04             	sub    ebx,0x4
 804879b:	ff d0                	call   eax
 804879d:	8b 03                	mov    eax,DWORD PTR [ebx]
 804879f:	83 f8 ff             	cmp    eax,0xffffffff
 80487a2:	75 f4                	jne    8048798 <__libc_start_main@plt+0x378>
 80487a4:	83 c4 04             	add    esp,0x4
 80487a7:	5b                   	pop    ebx
 80487a8:	5d                   	pop    ebp
 80487a9:	c3                   	ret    
 80487aa:	90                   	nop
 80487ab:	90                   	nop

Disassembly of section .fini:

080487ac <.fini>:
 80487ac:	53                   	push   ebx
 80487ad:	83 ec 08             	sub    esp,0x8
 80487b0:	e8 00 00 00 00       	call   80487b5 <__libc_start_main@plt+0x395>
 80487b5:	5b                   	pop    ebx
 80487b6:	81 c3 3f 18 00 00    	add    ebx,0x183f
 80487bc:	e8 9f fc ff ff       	call   8048460 <__libc_start_main@plt+0x40>
 80487c1:	83 c4 08             	add    esp,0x8
 80487c4:	5b                   	pop    ebx
 80487c5:	c3                   	ret    
