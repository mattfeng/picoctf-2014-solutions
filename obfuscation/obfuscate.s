
obfuscate:     file format elf32-i386


Disassembly of section .init:

08048380 <.init>:
 8048380:	53                   	push   ebx
 8048381:	83 ec 08             	sub    esp,0x8
 8048384:	e8 00 00 00 00       	call   8048389 <getline@plt-0x37>
 8048389:	5b                   	pop    ebx
 804838a:	81 c3 6b 1c 00 00    	add    ebx,0x1c6b
 8048390:	8b 83 fc ff ff ff    	mov    eax,DWORD PTR [ebx-0x4]
 8048396:	85 c0                	test   eax,eax
 8048398:	74 05                	je     804839f <getline@plt-0x21>
 804839a:	e8 51 00 00 00       	call   80483f0 <__gmon_start__@plt>
 804839f:	e8 ac 01 00 00       	call   8048550 <__printf_chk@plt+0x140>
 80483a4:	e8 97 07 00 00       	call   8048b40 <__printf_chk@plt+0x730>
 80483a9:	83 c4 08             	add    esp,0x8
 80483ac:	5b                   	pop    ebx
 80483ad:	c3                   	ret    

Disassembly of section .plt:

080483b0 <getline@plt-0x10>:
 80483b0:	ff 35 f8 9f 04 08    	push   DWORD PTR ds:0x8049ff8
 80483b6:	ff 25 fc 9f 04 08    	jmp    DWORD PTR ds:0x8049ffc
 80483bc:	00 00                	add    BYTE PTR [eax],al
	...

080483c0 <getline@plt>:
 80483c0:	ff 25 00 a0 04 08    	jmp    DWORD PTR ds:0x804a000
 80483c6:	68 00 00 00 00       	push   0x0
 80483cb:	e9 e0 ff ff ff       	jmp    80483b0 <getline@plt-0x10>

080483d0 <free@plt>:
 80483d0:	ff 25 04 a0 04 08    	jmp    DWORD PTR ds:0x804a004
 80483d6:	68 08 00 00 00       	push   0x8
 80483db:	e9 d0 ff ff ff       	jmp    80483b0 <getline@plt-0x10>

080483e0 <__stack_chk_fail@plt>:
 80483e0:	ff 25 08 a0 04 08    	jmp    DWORD PTR ds:0x804a008
 80483e6:	68 10 00 00 00       	push   0x10
 80483eb:	e9 c0 ff ff ff       	jmp    80483b0 <getline@plt-0x10>

080483f0 <__gmon_start__@plt>:
 80483f0:	ff 25 0c a0 04 08    	jmp    DWORD PTR ds:0x804a00c
 80483f6:	68 18 00 00 00       	push   0x18
 80483fb:	e9 b0 ff ff ff       	jmp    80483b0 <getline@plt-0x10>

08048400 <__libc_start_main@plt>:
 8048400:	ff 25 10 a0 04 08    	jmp    DWORD PTR ds:0x804a010
 8048406:	68 20 00 00 00       	push   0x20
 804840b:	e9 a0 ff ff ff       	jmp    80483b0 <getline@plt-0x10>

08048410 <__printf_chk@plt>:
 8048410:	ff 25 14 a0 04 08    	jmp    DWORD PTR ds:0x804a014
 8048416:	68 28 00 00 00       	push   0x28
 804841b:	e9 90 ff ff ff       	jmp    80483b0 <getline@plt-0x10>

Disassembly of section .text:

08048420 <.text>:
 8048420:	55                   	push   ebp
 8048421:	89 e5                	mov    ebp,esp
 8048423:	53                   	push   ebx
 8048424:	83 e4 f0             	and    esp,0xfffffff0
 8048427:	83 ec 20             	sub    esp,0x20
 804842a:	c7 44 24 18 00 00 00 	mov    DWORD PTR [esp+0x18],0x0
 8048431:	00 
 8048432:	c7 44 24 1c 00 00 00 	mov    DWORD PTR [esp+0x1c],0x0
 8048439:	00 
 804843a:	eb ff                	jmp    804843b <__printf_chk@plt+0x2b>
 804843c:	c0 48 c7 44          	ror    BYTE PTR [eax-0x39],0x44
 8048440:	24 04                	and    al,0x4
 8048442:	54                   	push   esp
 8048443:	8d 04 08             	lea    eax,[eax+ecx*1]
 8048446:	c7 04 24 01 00 00 00 	mov    DWORD PTR [esp],0x1
 804844d:	e8 be ff ff ff       	call   8048410 <__printf_chk@plt>
 8048452:	a1 20 a0 04 08       	mov    eax,ds:0x804a020
 8048457:	89 44 24 08          	mov    DWORD PTR [esp+0x8],eax
 804845b:	8d 44 24 18          	lea    eax,[esp+0x18]
 804845f:	89 44 24 04          	mov    DWORD PTR [esp+0x4],eax
 8048463:	8d 44 24 1c          	lea    eax,[esp+0x1c]
 8048467:	89 04 24             	mov    DWORD PTR [esp],eax
 804846a:	e8 51 ff ff ff       	call   80483c0 <getline@plt>
 804846f:	85 c0                	test   eax,eax
 8048471:	89 c3                	mov    ebx,eax
 8048473:	78 1a                	js     804848f <__printf_chk@plt+0x7f>
 8048475:	8b 44 24 1c          	mov    eax,DWORD PTR [esp+0x1c]
 8048479:	c7 44 24 04 00 00 00 	mov    DWORD PTR [esp+0x4],0x0
 8048480:	00 
 8048481:	89 04 24             	mov    DWORD PTR [esp],eax
 8048484:	e8 f7 00 00 00       	call   8048580 <__printf_chk@plt+0x170>
 8048489:	85 c0                	test   eax,eax
 804848b:	89 c3                	mov    ebx,eax
 804848d:	75 27                	jne    80484b6 <__printf_chk@plt+0xa6>
 804848f:	c7 44 24 04 68 8d 04 	mov    DWORD PTR [esp+0x4],0x8048d68
 8048496:	08 
 8048497:	c7 04 24 01 00 00 00 	mov    DWORD PTR [esp],0x1
 804849e:	e8 6d ff ff ff       	call   8048410 <__printf_chk@plt>
 80484a3:	8b 44 24 1c          	mov    eax,DWORD PTR [esp+0x1c]
 80484a7:	89 04 24             	mov    DWORD PTR [esp],eax
 80484aa:	e8 21 ff ff ff       	call   80483d0 <free@plt>
 80484af:	89 d8                	mov    eax,ebx
 80484b1:	8b 5d fc             	mov    ebx,DWORD PTR [ebp-0x4]
 80484b4:	c9                   	leave  
 80484b5:	c3                   	ret    
 80484b6:	c7 44 24 04 5f 8d 04 	mov    DWORD PTR [esp+0x4],0x8048d5f
 80484bd:	08 
 80484be:	c7 04 24 01 00 00 00 	mov    DWORD PTR [esp],0x1
 80484c5:	e8 46 ff ff ff       	call   8048410 <__printf_chk@plt>
 80484ca:	eb d7                	jmp    80484a3 <__printf_chk@plt+0x93>
 80484cc:	31 ed                	xor    ebp,ebp
 80484ce:	5e                   	pop    esi
 80484cf:	89 e1                	mov    ecx,esp
 80484d1:	83 e4 f0             	and    esp,0xfffffff0
 80484d4:	50                   	push   eax
 80484d5:	54                   	push   esp
 80484d6:	52                   	push   edx
 80484d7:	68 30 8b 04 08       	push   0x8048b30
 80484dc:	68 c0 8a 04 08       	push   0x8048ac0
 80484e1:	51                   	push   ecx
 80484e2:	56                   	push   esi
 80484e3:	68 20 84 04 08       	push   0x8048420
 80484e8:	e8 13 ff ff ff       	call   8048400 <__libc_start_main@plt>
 80484ed:	f4                   	hlt    
 80484ee:	90                   	nop
 80484ef:	90                   	nop
 80484f0:	55                   	push   ebp
 80484f1:	89 e5                	mov    ebp,esp
 80484f3:	53                   	push   ebx
 80484f4:	83 ec 04             	sub    esp,0x4
 80484f7:	80 3d 24 a0 04 08 00 	cmp    BYTE PTR ds:0x804a024,0x0
 80484fe:	75 3f                	jne    804853f <__printf_chk@plt+0x12f>
 8048500:	a1 28 a0 04 08       	mov    eax,ds:0x804a028
 8048505:	bb 20 9f 04 08       	mov    ebx,0x8049f20
 804850a:	81 eb 1c 9f 04 08    	sub    ebx,0x8049f1c
 8048510:	c1 fb 02             	sar    ebx,0x2
 8048513:	83 eb 01             	sub    ebx,0x1
 8048516:	39 d8                	cmp    eax,ebx
 8048518:	73 1e                	jae    8048538 <__printf_chk@plt+0x128>
 804851a:	8d b6 00 00 00 00    	lea    esi,[esi+0x0]
 8048520:	83 c0 01             	add    eax,0x1
 8048523:	a3 28 a0 04 08       	mov    ds:0x804a028,eax
 8048528:	ff 14 85 1c 9f 04 08 	call   DWORD PTR [eax*4+0x8049f1c]
 804852f:	a1 28 a0 04 08       	mov    eax,ds:0x804a028
 8048534:	39 d8                	cmp    eax,ebx
 8048536:	72 e8                	jb     8048520 <__printf_chk@plt+0x110>
 8048538:	c6 05 24 a0 04 08 01 	mov    BYTE PTR ds:0x804a024,0x1
 804853f:	83 c4 04             	add    esp,0x4
 8048542:	5b                   	pop    ebx
 8048543:	5d                   	pop    ebp
 8048544:	c3                   	ret    
 8048545:	8d 74 26 00          	lea    esi,[esi+eiz*1+0x0]
 8048549:	8d bc 27 00 00 00 00 	lea    edi,[edi+eiz*1+0x0]
 8048550:	55                   	push   ebp
 8048551:	89 e5                	mov    ebp,esp
 8048553:	83 ec 18             	sub    esp,0x18
 8048556:	a1 24 9f 04 08       	mov    eax,ds:0x8049f24
 804855b:	85 c0                	test   eax,eax
 804855d:	74 12                	je     8048571 <__printf_chk@plt+0x161>
 804855f:	b8 00 00 00 00       	mov    eax,0x0
 8048564:	85 c0                	test   eax,eax
 8048566:	74 09                	je     8048571 <__printf_chk@plt+0x161>
 8048568:	c7 04 24 24 9f 04 08 	mov    DWORD PTR [esp],0x8049f24
 804856f:	ff d0                	call   eax
 8048571:	c9                   	leave  
 8048572:	c3                   	ret    
 8048573:	90                   	nop
 8048574:	90                   	nop
 8048575:	90                   	nop
 8048576:	90                   	nop
 8048577:	90                   	nop
 8048578:	90                   	nop
 8048579:	90                   	nop
 804857a:	90                   	nop
 804857b:	90                   	nop
 804857c:	90                   	nop
 804857d:	90                   	nop
 804857e:	90                   	nop
 804857f:	90                   	nop
 8048580:	55                   	push   ebp
 8048581:	57                   	push   edi
 8048582:	56                   	push   esi
 8048583:	53                   	push   ebx
 8048584:	81 ec 9c 00 00 00    	sub    esp,0x9c
 804858a:	65 a1 14 00 00 00    	mov    eax,gs:0x14
 8048590:	89 84 24 8c 00 00 00 	mov    DWORD PTR [esp+0x8c],eax
 8048597:	31 c0                	xor    eax,eax
 8048599:	8b 9c 24 b0 00 00 00 	mov    ebx,DWORD PTR [esp+0xb0]
 80485a0:	8d 74 24 0c          	lea    esi,[esp+0xc]
 80485a4:	8b 94 24 b4 00 00 00 	mov    edx,DWORD PTR [esp+0xb4]
 80485ab:	31 c0                	xor    eax,eax
 80485ad:	89 f7                	mov    edi,esi
 80485af:	b9 20 00 00 00       	mov    ecx,0x20
 80485b4:	f3 ab                	rep stos DWORD PTR es:[edi],eax
 80485b6:	0f b6 2c 13          	movzx  ebp,BYTE PTR [ebx+edx*1]
 80485ba:	89 e8                	mov    eax,ebp
 80485bc:	0f be c8             	movsx  ecx,al
 80485bf:	83 c1 40             	add    ecx,0x40
 80485c2:	89 cf                	mov    edi,ecx
 80485c4:	c1 ff 1f             	sar    edi,0x1f
 80485c7:	c1 ef 19             	shr    edi,0x19
 80485ca:	01 f9                	add    ecx,edi
 80485cc:	83 e1 7f             	and    ecx,0x7f
 80485cf:	29 f9                	sub    ecx,edi
 80485d1:	c6 44 0c 0c 01       	mov    BYTE PTR [esp+ecx*1+0xc],0x1
 80485d6:	8d 4d f6             	lea    ecx,[ebp-0xa]
 80485d9:	80 f9 70             	cmp    cl,0x70
 80485dc:	76 22                	jbe    8048600 <__printf_chk@plt+0x1f0>
 80485de:	31 c0                	xor    eax,eax
 80485e0:	8b 94 24 8c 00 00 00 	mov    edx,DWORD PTR [esp+0x8c]
 80485e7:	65 33 15 14 00 00 00 	xor    edx,DWORD PTR gs:0x14
 80485ee:	0f 85 bc 04 00 00    	jne    8048ab0 <__printf_chk@plt+0x6a0>
 80485f4:	81 c4 9c 00 00 00    	add    esp,0x9c
 80485fa:	5b                   	pop    ebx
 80485fb:	5e                   	pop    esi
 80485fc:	5f                   	pop    edi
 80485fd:	5d                   	pop    ebp
 80485fe:	c3                   	ret    
 80485ff:	90                   	nop
 8048600:	0f b6 c9             	movzx  ecx,cl
 8048603:	ff 24 8d 90 8b 04 08 	jmp    DWORD PTR [ecx*4+0x8048b90]
 804860a:	8d b6 00 00 00 00    	lea    esi,[esi+0x0]
 8048610:	83 fa 0d             	cmp    edx,0xd
 8048613:	0f 94 c2             	sete   dl
 8048616:	31 c0                	xor    eax,eax
 8048618:	80 7c 24 56 00       	cmp    BYTE PTR [esp+0x56],0x0
 804861d:	0f 95 c0             	setne  al
 8048620:	21 d0                	and    eax,edx
 8048622:	eb bc                	jmp    80485e0 <__printf_chk@plt+0x1d0>
 8048624:	8d 74 26 00          	lea    esi,[esi+eiz*1+0x0]
 8048628:	85 d2                	test   edx,edx
 804862a:	75 b2                	jne    80485de <__printf_chk@plt+0x1ce>
 804862c:	80 7c 24 7c 00       	cmp    BYTE PTR [esp+0x7c],0x0
 8048631:	74 ab                	je     80485de <__printf_chk@plt+0x1ce>
 8048633:	ba 01 00 00 00       	mov    edx,0x1
 8048638:	e9 6e ff ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 804863d:	8d 76 00             	lea    esi,[esi+0x0]
 8048640:	83 fa 0e             	cmp    edx,0xe
 8048643:	75 99                	jne    80485de <__printf_chk@plt+0x1ce>
 8048645:	80 7c 24 7d 00       	cmp    BYTE PTR [esp+0x7d],0x0
 804864a:	74 92                	je     80485de <__printf_chk@plt+0x1ce>
 804864c:	ba 0f 00 00 00       	mov    edx,0xf
 8048651:	e9 55 ff ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 8048656:	66 90                	xchg   ax,ax
 8048658:	83 fa 14             	cmp    edx,0x14
 804865b:	75 81                	jne    80485de <__printf_chk@plt+0x1ce>
 804865d:	80 7c 24 7e 00       	cmp    BYTE PTR [esp+0x7e],0x0
 8048662:	0f 84 76 ff ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 8048668:	ba 15 00 00 00       	mov    edx,0x15
 804866d:	e9 39 ff ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 8048672:	8d b6 00 00 00 00    	lea    esi,[esi+0x0]
 8048678:	83 fa 59             	cmp    edx,0x59
 804867b:	0f 85 5d ff ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 8048681:	80 7c 24 7f 00       	cmp    BYTE PTR [esp+0x7f],0x0
 8048686:	0f 84 52 ff ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 804868c:	ba 5a 00 00 00       	mov    edx,0x5a
 8048691:	e9 15 ff ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 8048696:	66 90                	xchg   ax,ax
 8048698:	83 fa 0f             	cmp    edx,0xf
 804869b:	0f 85 3d ff ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 80486a1:	80 bc 24 80 00 00 00 	cmp    BYTE PTR [esp+0x80],0x0
 80486a8:	00 
 80486a9:	0f 84 2f ff ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 80486af:	ba 10 00 00 00       	mov    edx,0x10
 80486b4:	e9 f2 fe ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 80486b9:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
 80486c0:	83 fa 0e             	cmp    edx,0xe
 80486c3:	0f 85 15 ff ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 80486c9:	80 bc 24 81 00 00 00 	cmp    BYTE PTR [esp+0x81],0x0
 80486d0:	00 
 80486d1:	0f 85 75 ff ff ff    	jne    804864c <__printf_chk@plt+0x23c>
 80486d7:	e9 02 ff ff ff       	jmp    80485de <__printf_chk@plt+0x1ce>
 80486dc:	8d 74 26 00          	lea    esi,[esi+eiz*1+0x0]
 80486e0:	83 fa 0c             	cmp    edx,0xc
 80486e3:	0f 85 f5 fe ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 80486e9:	80 bc 24 82 00 00 00 	cmp    BYTE PTR [esp+0x82],0x0
 80486f0:	00 
 80486f1:	0f 84 e7 fe ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 80486f7:	ba 0d 00 00 00       	mov    edx,0xd
 80486fc:	e9 aa fe ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 8048701:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
 8048708:	83 fa 05             	cmp    edx,0x5
 804870b:	0f 85 cd fe ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 8048711:	80 bc 24 83 00 00 00 	cmp    BYTE PTR [esp+0x83],0x0
 8048718:	00 
 8048719:	0f 84 bf fe ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 804871f:	ba 06 00 00 00       	mov    edx,0x6
 8048724:	e9 82 fe ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 8048729:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
 8048730:	31 c0                	xor    eax,eax
 8048732:	80 bc 24 85 00 00 00 	cmp    BYTE PTR [esp+0x85],0x0
 8048739:	00 
 804873a:	0f 84 a0 fe ff ff    	je     80485e0 <__printf_chk@plt+0x1d0>
 8048740:	83 fa 02             	cmp    edx,0x2
 8048743:	0f 94 c0             	sete   al
 8048746:	83 fa 21             	cmp    edx,0x21
 8048749:	0f 94 c2             	sete   dl
 804874c:	09 d0                	or     eax,edx
 804874e:	0f b6 c0             	movzx  eax,al
 8048751:	e9 8a fe ff ff       	jmp    80485e0 <__printf_chk@plt+0x1d0>
 8048756:	66 90                	xchg   ax,ax
 8048758:	83 fa 01             	cmp    edx,0x1
 804875b:	0f 85 7d fe ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 8048761:	80 bc 24 85 00 00 00 	cmp    BYTE PTR [esp+0x85],0x0
 8048768:	00 
 8048769:	0f 84 6f fe ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 804876f:	ba 02 00 00 00       	mov    edx,0x2
 8048774:	e9 32 fe ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 8048779:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
 8048780:	83 fa 23             	cmp    edx,0x23
 8048783:	0f 85 55 fe ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 8048789:	80 7c 24 2d 00       	cmp    BYTE PTR [esp+0x2d],0x0
 804878e:	0f 84 4a fe ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 8048794:	ba 24 00 00 00       	mov    edx,0x24
 8048799:	e9 0d fe ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 804879e:	66 90                	xchg   ax,ax
 80487a0:	83 fa 0b             	cmp    edx,0xb
 80487a3:	0f 85 35 fe ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 80487a9:	80 7c 24 2e 00       	cmp    BYTE PTR [esp+0x2e],0x0
 80487ae:	0f 84 2a fe ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 80487b4:	ba 0c 00 00 00       	mov    edx,0xc
 80487b9:	e9 ed fd ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 80487be:	66 90                	xchg   ax,ax
 80487c0:	83 fa 20             	cmp    edx,0x20
 80487c3:	0f 85 15 fe ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 80487c9:	80 7c 24 2d 00       	cmp    BYTE PTR [esp+0x2d],0x0
 80487ce:	0f 84 0a fe ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 80487d4:	ba 21 00 00 00       	mov    edx,0x21
 80487d9:	e9 cd fd ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 80487de:	66 90                	xchg   ax,ax
 80487e0:	83 fa 03             	cmp    edx,0x3
 80487e3:	0f 85 f5 fd ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 80487e9:	80 7c 24 30 00       	cmp    BYTE PTR [esp+0x30],0x0
 80487ee:	0f 84 ea fd ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 80487f4:	ba 04 00 00 00       	mov    edx,0x4
 80487f9:	e9 ad fd ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 80487fe:	66 90                	xchg   ax,ax
 8048800:	83 fa 07             	cmp    edx,0x7
 8048803:	0f 85 d5 fd ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 8048809:	80 7c 24 31 00       	cmp    BYTE PTR [esp+0x31],0x0
 804880e:	0f 84 ca fd ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 8048814:	ba 08 00 00 00       	mov    edx,0x8
 8048819:	e9 8d fd ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 804881e:	66 90                	xchg   ax,ax
 8048820:	80 7c 24 32 00       	cmp    BYTE PTR [esp+0x32],0x0
 8048825:	0f 84 b3 fd ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 804882b:	83 fa 08             	cmp    edx,0x8
 804882e:	0f 85 6b 02 00 00    	jne    8048a9f <__printf_chk@plt+0x68f>
 8048834:	83 c2 01             	add    edx,0x1
 8048837:	e9 6f fd ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 804883c:	8d 74 26 00          	lea    esi,[esi+eiz*1+0x0]
 8048840:	83 fa 0c             	cmp    edx,0xc
 8048843:	0f 94 c2             	sete   dl
 8048846:	31 c0                	xor    eax,eax
 8048848:	80 7c 24 40 00       	cmp    BYTE PTR [esp+0x40],0x0
 804884d:	0f 95 c0             	setne  al
 8048850:	21 d0                	and    eax,edx
 8048852:	e9 89 fd ff ff       	jmp    80485e0 <__printf_chk@plt+0x1d0>
 8048857:	90                   	nop
 8048858:	83 fa 0d             	cmp    edx,0xd
 804885b:	0f 85 7d fd ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 8048861:	80 7c 24 33 00       	cmp    BYTE PTR [esp+0x33],0x0
 8048866:	0f 84 72 fd ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 804886c:	ba 0e 00 00 00       	mov    edx,0xe
 8048871:	e9 35 fd ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 8048876:	66 90                	xchg   ax,ax
 8048878:	83 fa 09             	cmp    edx,0x9
 804887b:	0f 85 5d fd ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 8048881:	80 7c 24 35 00       	cmp    BYTE PTR [esp+0x35],0x0
 8048886:	0f 84 52 fd ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 804888c:	ba 0a 00 00 00       	mov    edx,0xa
 8048891:	e9 15 fd ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 8048896:	66 90                	xchg   ax,ax
 8048898:	83 fa 0a             	cmp    edx,0xa
 804889b:	0f 85 3d fd ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 80488a1:	80 7c 24 36 00       	cmp    BYTE PTR [esp+0x36],0x0
 80488a6:	0f 84 32 fd ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 80488ac:	ba 0b 00 00 00       	mov    edx,0xb
 80488b1:	e9 f5 fc ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 80488b6:	66 90                	xchg   ax,ax
 80488b8:	83 fa 0c             	cmp    edx,0xc
 80488bb:	0f 94 c2             	sete   dl
 80488be:	31 c0                	xor    eax,eax
 80488c0:	80 7c 24 37 00       	cmp    BYTE PTR [esp+0x37],0x0
 80488c5:	0f 95 c0             	setne  al
 80488c8:	21 d0                	and    eax,edx
 80488ca:	e9 11 fd ff ff       	jmp    80485e0 <__printf_chk@plt+0x1d0>
 80488cf:	90                   	nop
 80488d0:	83 fa 13             	cmp    edx,0x13
 80488d3:	0f 85 05 fd ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 80488d9:	80 7c 24 38 00       	cmp    BYTE PTR [esp+0x38],0x0
 80488de:	0f 84 fa fc ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 80488e4:	ba 14 00 00 00       	mov    edx,0x14
 80488e9:	e9 bd fc ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 80488ee:	66 90                	xchg   ax,ax
 80488f0:	83 fa 11             	cmp    edx,0x11
 80488f3:	0f 85 e5 fc ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 80488f9:	80 7c 24 39 00       	cmp    BYTE PTR [esp+0x39],0x0
 80488fe:	0f 84 da fc ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 8048904:	ba 12 00 00 00       	mov    edx,0x12
 8048909:	e9 9d fc ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 804890e:	66 90                	xchg   ax,ax
 8048910:	83 fa 12             	cmp    edx,0x12
 8048913:	0f 94 c2             	sete   dl
 8048916:	31 c0                	xor    eax,eax
 8048918:	80 7c 24 39 00       	cmp    BYTE PTR [esp+0x39],0x0
 804891d:	0f 95 c0             	setne  al
 8048920:	21 d0                	and    eax,edx
 8048922:	e9 b9 fc ff ff       	jmp    80485e0 <__printf_chk@plt+0x1d0>
 8048927:	90                   	nop
 8048928:	80 7c 24 3a 00       	cmp    BYTE PTR [esp+0x3a],0x0
 804892d:	0f 84 ab fc ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 8048933:	83 fa 06             	cmp    edx,0x6
 8048936:	0f 84 f8 fe ff ff    	je     8048834 <__printf_chk@plt+0x424>
 804893c:	83 fa 1c             	cmp    edx,0x1c
 804893f:	0f 84 ef fe ff ff    	je     8048834 <__printf_chk@plt+0x424>
 8048945:	e9 94 fc ff ff       	jmp    80485de <__printf_chk@plt+0x1ce>
 804894a:	8d b6 00 00 00 00    	lea    esi,[esi+0x0]
 8048950:	83 fa 1e             	cmp    edx,0x1e
 8048953:	0f 85 85 fc ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 8048959:	80 7c 24 3c 00       	cmp    BYTE PTR [esp+0x3c],0x0
 804895e:	66 90                	xchg   ax,ax
 8048960:	0f 84 78 fc ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 8048966:	ba 1f 00 00 00       	mov    edx,0x1f
 804896b:	e9 3b fc ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 8048970:	83 fa 1d             	cmp    edx,0x1d
 8048973:	0f 85 65 fc ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 8048979:	80 7c 24 3d 00       	cmp    BYTE PTR [esp+0x3d],0x0
 804897e:	0f 84 5a fc ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 8048984:	ba 1e 00 00 00       	mov    edx,0x1e
 8048989:	e9 1d fc ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 804898e:	66 90                	xchg   ax,ax
 8048990:	83 fa 14             	cmp    edx,0x14
 8048993:	0f 85 45 fc ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 8048999:	80 7c 24 3e 00       	cmp    BYTE PTR [esp+0x3e],0x0
 804899e:	0f 85 c4 fc ff ff    	jne    8048668 <__printf_chk@plt+0x258>
 80489a4:	e9 35 fc ff ff       	jmp    80485de <__printf_chk@plt+0x1ce>
 80489a9:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
 80489b0:	83 fa 19             	cmp    edx,0x19
 80489b3:	0f 85 25 fc ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 80489b9:	80 7c 24 3f 00       	cmp    BYTE PTR [esp+0x3f],0x0
 80489be:	66 90                	xchg   ax,ax
 80489c0:	0f 84 18 fc ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 80489c6:	ba 1a 00 00 00       	mov    edx,0x1a
 80489cb:	e9 db fb ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 80489d0:	83 fa 18             	cmp    edx,0x18
 80489d3:	0f 94 c2             	sete   dl
 80489d6:	31 c0                	xor    eax,eax
 80489d8:	80 7c 24 3e 00       	cmp    BYTE PTR [esp+0x3e],0x0
 80489dd:	0f 95 c0             	setne  al
 80489e0:	21 d0                	and    eax,edx
 80489e2:	e9 f9 fb ff ff       	jmp    80485e0 <__printf_chk@plt+0x1d0>
 80489e7:	90                   	nop
 80489e8:	83 fa 1a             	cmp    edx,0x1a
 80489eb:	0f 85 ed fb ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 80489f1:	80 7c 24 41 00       	cmp    BYTE PTR [esp+0x41],0x0
 80489f6:	0f 84 e2 fb ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 80489fc:	ba 1b 00 00 00       	mov    edx,0x1b
 8048a01:	e9 a5 fb ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 8048a06:	66 90                	xchg   ax,ax
 8048a08:	83 fa 02             	cmp    edx,0x2
 8048a0b:	0f 85 cd fb ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 8048a11:	80 7c 24 42 00       	cmp    BYTE PTR [esp+0x42],0x0
 8048a16:	0f 84 c2 fb ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 8048a1c:	ba 03 00 00 00       	mov    edx,0x3
 8048a21:	e9 85 fb ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 8048a26:	66 90                	xchg   ax,ax
 8048a28:	83 fa 06             	cmp    edx,0x6
 8048a2b:	0f 85 ad fb ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 8048a31:	80 7c 24 43 00       	cmp    BYTE PTR [esp+0x43],0x0
 8048a36:	0f 84 a2 fb ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 8048a3c:	ba 07 00 00 00       	mov    edx,0x7
 8048a41:	e9 65 fb ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 8048a46:	66 90                	xchg   ax,ax
 8048a48:	83 fa 16             	cmp    edx,0x16
 8048a4b:	0f 85 8d fb ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 8048a51:	80 7c 24 44 00       	cmp    BYTE PTR [esp+0x44],0x0
 8048a56:	0f 84 82 fb ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 8048a5c:	ba 17 00 00 00       	mov    edx,0x17
 8048a61:	e9 45 fb ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 8048a66:	66 90                	xchg   ax,ax
 8048a68:	83 fa 17             	cmp    edx,0x17
 8048a6b:	0f 85 6d fb ff ff    	jne    80485de <__printf_chk@plt+0x1ce>
 8048a71:	80 7c 24 45 00       	cmp    BYTE PTR [esp+0x45],0x0
 8048a76:	0f 84 62 fb ff ff    	je     80485de <__printf_chk@plt+0x1ce>
 8048a7c:	ba 18 00 00 00       	mov    edx,0x18
 8048a81:	e9 25 fb ff ff       	jmp    80485ab <__printf_chk@plt+0x19b>
 8048a86:	66 90                	xchg   ax,ax
 8048a88:	83 fa 15             	cmp    edx,0x15
 8048a8b:	0f 94 c2             	sete   dl
 8048a8e:	31 c0                	xor    eax,eax
 8048a90:	80 7c 24 2d 00       	cmp    BYTE PTR [esp+0x2d],0x0
 8048a95:	0f 95 c0             	setne  al
 8048a98:	21 d0                	and    eax,edx
 8048a9a:	e9 41 fb ff ff       	jmp    80485e0 <__printf_chk@plt+0x1d0>
 8048a9f:	83 fa 04             	cmp    edx,0x4
 8048aa2:	0f 84 8c fd ff ff    	je     8048834 <__printf_chk@plt+0x424>
 8048aa8:	e9 31 fb ff ff       	jmp    80485de <__printf_chk@plt+0x1ce>
 8048aad:	8d 76 00             	lea    esi,[esi+0x0]
 8048ab0:	e8 2b f9 ff ff       	call   80483e0 <__stack_chk_fail@plt>
 8048ab5:	90                   	nop
 8048ab6:	90                   	nop
 8048ab7:	90                   	nop
 8048ab8:	90                   	nop
 8048ab9:	90                   	nop
 8048aba:	90                   	nop
 8048abb:	90                   	nop
 8048abc:	90                   	nop
 8048abd:	90                   	nop
 8048abe:	90                   	nop
 8048abf:	90                   	nop
 8048ac0:	55                   	push   ebp
 8048ac1:	57                   	push   edi
 8048ac2:	56                   	push   esi
 8048ac3:	53                   	push   ebx
 8048ac4:	e8 69 00 00 00       	call   8048b32 <__printf_chk@plt+0x722>
 8048ac9:	81 c3 2b 15 00 00    	add    ebx,0x152b
 8048acf:	83 ec 1c             	sub    esp,0x1c
 8048ad2:	8b 6c 24 30          	mov    ebp,DWORD PTR [esp+0x30]
 8048ad6:	8d bb 20 ff ff ff    	lea    edi,[ebx-0xe0]
 8048adc:	e8 9f f8 ff ff       	call   8048380 <getline@plt-0x40>
 8048ae1:	8d 83 20 ff ff ff    	lea    eax,[ebx-0xe0]
 8048ae7:	29 c7                	sub    edi,eax
 8048ae9:	c1 ff 02             	sar    edi,0x2
 8048aec:	85 ff                	test   edi,edi
 8048aee:	74 29                	je     8048b19 <__printf_chk@plt+0x709>
 8048af0:	31 f6                	xor    esi,esi
 8048af2:	8d b6 00 00 00 00    	lea    esi,[esi+0x0]
 8048af8:	8b 44 24 38          	mov    eax,DWORD PTR [esp+0x38]
 8048afc:	89 2c 24             	mov    DWORD PTR [esp],ebp
 8048aff:	89 44 24 08          	mov    DWORD PTR [esp+0x8],eax
 8048b03:	8b 44 24 34          	mov    eax,DWORD PTR [esp+0x34]
 8048b07:	89 44 24 04          	mov    DWORD PTR [esp+0x4],eax
 8048b0b:	ff 94 b3 20 ff ff ff 	call   DWORD PTR [ebx+esi*4-0xe0]
 8048b12:	83 c6 01             	add    esi,0x1
 8048b15:	39 fe                	cmp    esi,edi
 8048b17:	75 df                	jne    8048af8 <__printf_chk@plt+0x6e8>
 8048b19:	83 c4 1c             	add    esp,0x1c
 8048b1c:	5b                   	pop    ebx
 8048b1d:	5e                   	pop    esi
 8048b1e:	5f                   	pop    edi
 8048b1f:	5d                   	pop    ebp
 8048b20:	c3                   	ret    
 8048b21:	eb 0d                	jmp    8048b30 <__printf_chk@plt+0x720>
 8048b23:	90                   	nop
 8048b24:	90                   	nop
 8048b25:	90                   	nop
 8048b26:	90                   	nop
 8048b27:	90                   	nop
 8048b28:	90                   	nop
 8048b29:	90                   	nop
 8048b2a:	90                   	nop
 8048b2b:	90                   	nop
 8048b2c:	90                   	nop
 8048b2d:	90                   	nop
 8048b2e:	90                   	nop
 8048b2f:	90                   	nop
 8048b30:	f3 c3                	repz ret 
 8048b32:	8b 1c 24             	mov    ebx,DWORD PTR [esp]
 8048b35:	c3                   	ret    
 8048b36:	90                   	nop
 8048b37:	90                   	nop
 8048b38:	90                   	nop
 8048b39:	90                   	nop
 8048b3a:	90                   	nop
 8048b3b:	90                   	nop
 8048b3c:	90                   	nop
 8048b3d:	90                   	nop
 8048b3e:	90                   	nop
 8048b3f:	90                   	nop
 8048b40:	55                   	push   ebp
 8048b41:	89 e5                	mov    ebp,esp
 8048b43:	53                   	push   ebx
 8048b44:	83 ec 04             	sub    esp,0x4
 8048b47:	a1 14 9f 04 08       	mov    eax,ds:0x8049f14
 8048b4c:	83 f8 ff             	cmp    eax,0xffffffff
 8048b4f:	74 13                	je     8048b64 <__printf_chk@plt+0x754>
 8048b51:	bb 14 9f 04 08       	mov    ebx,0x8049f14
 8048b56:	66 90                	xchg   ax,ax
 8048b58:	83 eb 04             	sub    ebx,0x4
 8048b5b:	ff d0                	call   eax
 8048b5d:	8b 03                	mov    eax,DWORD PTR [ebx]
 8048b5f:	83 f8 ff             	cmp    eax,0xffffffff
 8048b62:	75 f4                	jne    8048b58 <__printf_chk@plt+0x748>
 8048b64:	83 c4 04             	add    esp,0x4
 8048b67:	5b                   	pop    ebx
 8048b68:	5d                   	pop    ebp
 8048b69:	c3                   	ret    
 8048b6a:	90                   	nop
 8048b6b:	90                   	nop

Disassembly of section .fini:

08048b6c <.fini>:
 8048b6c:	53                   	push   ebx
 8048b6d:	83 ec 08             	sub    esp,0x8
 8048b70:	e8 00 00 00 00       	call   8048b75 <__printf_chk@plt+0x765>
 8048b75:	5b                   	pop    ebx
 8048b76:	81 c3 7f 14 00 00    	add    ebx,0x147f
 8048b7c:	e8 6f f9 ff ff       	call   80484f0 <__printf_chk@plt+0xe0>
 8048b81:	83 c4 08             	add    esp,0x8
 8048b84:	5b                   	pop    ebx
 8048b85:	c3                   	ret    
