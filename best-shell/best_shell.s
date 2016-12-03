
best_shell:     file format elf32-i386


Disassembly of section .init:

08048550 <_init>:
 8048550:	53                   	push   ebx
 8048551:	83 ec 08             	sub    esp,0x8
 8048554:	e8 87 01 00 00       	call   80486e0 <__x86.get_pc_thunk.bx>
 8048559:	81 c3 a7 2a 00 00    	add    ebx,0x2aa7
 804855f:	8b 83 fc ff ff ff    	mov    eax,DWORD PTR [ebx-0x4]
 8048565:	85 c0                	test   eax,eax
 8048567:	74 05                	je     804856e <_init+0x1e>
 8048569:	e8 d2 00 00 00       	call   8048640 <__gmon_start__@plt>
 804856e:	83 c4 08             	add    esp,0x8
 8048571:	5b                   	pop    ebx
 8048572:	c3                   	ret    

Disassembly of section .plt:

08048580 <strcmp@plt-0x10>:
 8048580:	ff 35 04 b0 04 08    	push   DWORD PTR ds:0x804b004
 8048586:	ff 25 08 b0 04 08    	jmp    DWORD PTR ds:0x804b008
 804858c:	00 00                	add    BYTE PTR [eax],al
	...

08048590 <strcmp@plt>:
 8048590:	ff 25 0c b0 04 08    	jmp    DWORD PTR ds:0x804b00c
 8048596:	68 00 00 00 00       	push   0x0
 804859b:	e9 e0 ff ff ff       	jmp    8048580 <_init+0x30>

080485a0 <printf@plt>:
 80485a0:	ff 25 10 b0 04 08    	jmp    DWORD PTR ds:0x804b010
 80485a6:	68 08 00 00 00       	push   0x8
 80485ab:	e9 d0 ff ff ff       	jmp    8048580 <_init+0x30>

080485b0 <strcspn@plt>:
 80485b0:	ff 25 14 b0 04 08    	jmp    DWORD PTR ds:0x804b014
 80485b6:	68 10 00 00 00       	push   0x10
 80485bb:	e9 c0 ff ff ff       	jmp    8048580 <_init+0x30>

080485c0 <fflush@plt>:
 80485c0:	ff 25 18 b0 04 08    	jmp    DWORD PTR ds:0x804b018
 80485c6:	68 18 00 00 00       	push   0x18
 80485cb:	e9 b0 ff ff ff       	jmp    8048580 <_init+0x30>

080485d0 <fgets@plt>:
 80485d0:	ff 25 1c b0 04 08    	jmp    DWORD PTR ds:0x804b01c
 80485d6:	68 20 00 00 00       	push   0x20
 80485db:	e9 a0 ff ff ff       	jmp    8048580 <_init+0x30>

080485e0 <fclose@plt>:
 80485e0:	ff 25 20 b0 04 08    	jmp    DWORD PTR ds:0x804b020
 80485e6:	68 28 00 00 00       	push   0x28
 80485eb:	e9 90 ff ff ff       	jmp    8048580 <_init+0x30>

080485f0 <__stack_chk_fail@plt>:
 80485f0:	ff 25 24 b0 04 08    	jmp    DWORD PTR ds:0x804b024
 80485f6:	68 30 00 00 00       	push   0x30
 80485fb:	e9 80 ff ff ff       	jmp    8048580 <_init+0x30>

08048600 <getegid@plt>:
 8048600:	ff 25 28 b0 04 08    	jmp    DWORD PTR ds:0x804b028
 8048606:	68 38 00 00 00       	push   0x38
 804860b:	e9 70 ff ff ff       	jmp    8048580 <_init+0x30>

08048610 <strcpy@plt>:
 8048610:	ff 25 2c b0 04 08    	jmp    DWORD PTR ds:0x804b02c
 8048616:	68 40 00 00 00       	push   0x40
 804861b:	e9 60 ff ff ff       	jmp    8048580 <_init+0x30>

08048620 <puts@plt>:
 8048620:	ff 25 30 b0 04 08    	jmp    DWORD PTR ds:0x804b030
 8048626:	68 48 00 00 00       	push   0x48
 804862b:	e9 50 ff ff ff       	jmp    8048580 <_init+0x30>

08048630 <system@plt>:
 8048630:	ff 25 34 b0 04 08    	jmp    DWORD PTR ds:0x804b034
 8048636:	68 50 00 00 00       	push   0x50
 804863b:	e9 40 ff ff ff       	jmp    8048580 <_init+0x30>

08048640 <__gmon_start__@plt>:
 8048640:	ff 25 38 b0 04 08    	jmp    DWORD PTR ds:0x804b038
 8048646:	68 58 00 00 00       	push   0x58
 804864b:	e9 30 ff ff ff       	jmp    8048580 <_init+0x30>

08048650 <exit@plt>:
 8048650:	ff 25 3c b0 04 08    	jmp    DWORD PTR ds:0x804b03c
 8048656:	68 60 00 00 00       	push   0x60
 804865b:	e9 20 ff ff ff       	jmp    8048580 <_init+0x30>

08048660 <__libc_start_main@plt>:
 8048660:	ff 25 40 b0 04 08    	jmp    DWORD PTR ds:0x804b040
 8048666:	68 68 00 00 00       	push   0x68
 804866b:	e9 10 ff ff ff       	jmp    8048580 <_init+0x30>

08048670 <__isoc99_sscanf@plt>:
 8048670:	ff 25 44 b0 04 08    	jmp    DWORD PTR ds:0x804b044
 8048676:	68 70 00 00 00       	push   0x70
 804867b:	e9 00 ff ff ff       	jmp    8048580 <_init+0x30>

08048680 <fopen@plt>:
 8048680:	ff 25 48 b0 04 08    	jmp    DWORD PTR ds:0x804b048
 8048686:	68 78 00 00 00       	push   0x78
 804868b:	e9 f0 fe ff ff       	jmp    8048580 <_init+0x30>

08048690 <strtok@plt>:
 8048690:	ff 25 4c b0 04 08    	jmp    DWORD PTR ds:0x804b04c
 8048696:	68 80 00 00 00       	push   0x80
 804869b:	e9 e0 fe ff ff       	jmp    8048580 <_init+0x30>

080486a0 <setresgid@plt>:
 80486a0:	ff 25 50 b0 04 08    	jmp    DWORD PTR ds:0x804b050
 80486a6:	68 88 00 00 00       	push   0x88
 80486ab:	e9 d0 fe ff ff       	jmp    8048580 <_init+0x30>

Disassembly of section .text:

080486b0 <_start>:
 80486b0:	31 ed                	xor    ebp,ebp
 80486b2:	5e                   	pop    esi
 80486b3:	89 e1                	mov    ecx,esp
 80486b5:	83 e4 f0             	and    esp,0xfffffff0
 80486b8:	50                   	push   eax
 80486b9:	54                   	push   esp
 80486ba:	52                   	push   edx
 80486bb:	68 b0 8d 04 08       	push   0x8048db0
 80486c0:	68 40 8d 04 08       	push   0x8048d40
 80486c5:	51                   	push   ecx
 80486c6:	56                   	push   esi
 80486c7:	68 9d 8c 04 08       	push   0x8048c9d
 80486cc:	e8 8f ff ff ff       	call   8048660 <__libc_start_main@plt>
 80486d1:	f4                   	hlt    
 80486d2:	66 90                	xchg   ax,ax
 80486d4:	66 90                	xchg   ax,ax
 80486d6:	66 90                	xchg   ax,ax
 80486d8:	66 90                	xchg   ax,ax
 80486da:	66 90                	xchg   ax,ax
 80486dc:	66 90                	xchg   ax,ax
 80486de:	66 90                	xchg   ax,ax

080486e0 <__x86.get_pc_thunk.bx>:
 80486e0:	8b 1c 24             	mov    ebx,DWORD PTR [esp]
 80486e3:	c3                   	ret    
 80486e4:	66 90                	xchg   ax,ax
 80486e6:	66 90                	xchg   ax,ax
 80486e8:	66 90                	xchg   ax,ax
 80486ea:	66 90                	xchg   ax,ax
 80486ec:	66 90                	xchg   ax,ax
 80486ee:	66 90                	xchg   ax,ax

080486f0 <deregister_tm_clones>:
 80486f0:	b8 5f b0 04 08       	mov    eax,0x804b05f
 80486f5:	2d 5c b0 04 08       	sub    eax,0x804b05c
 80486fa:	83 f8 06             	cmp    eax,0x6
 80486fd:	77 01                	ja     8048700 <deregister_tm_clones+0x10>
 80486ff:	c3                   	ret    
 8048700:	b8 00 00 00 00       	mov    eax,0x0
 8048705:	85 c0                	test   eax,eax
 8048707:	74 f6                	je     80486ff <deregister_tm_clones+0xf>
 8048709:	55                   	push   ebp
 804870a:	89 e5                	mov    ebp,esp
 804870c:	83 ec 18             	sub    esp,0x18
 804870f:	c7 04 24 5c b0 04 08 	mov    DWORD PTR [esp],0x804b05c
 8048716:	ff d0                	call   eax
 8048718:	c9                   	leave  
 8048719:	c3                   	ret    
 804871a:	8d b6 00 00 00 00    	lea    esi,[esi+0x0]

08048720 <register_tm_clones>:
 8048720:	b8 5c b0 04 08       	mov    eax,0x804b05c
 8048725:	2d 5c b0 04 08       	sub    eax,0x804b05c
 804872a:	c1 f8 02             	sar    eax,0x2
 804872d:	89 c2                	mov    edx,eax
 804872f:	c1 ea 1f             	shr    edx,0x1f
 8048732:	01 d0                	add    eax,edx
 8048734:	d1 f8                	sar    eax,1
 8048736:	75 01                	jne    8048739 <register_tm_clones+0x19>
 8048738:	c3                   	ret    
 8048739:	ba 00 00 00 00       	mov    edx,0x0
 804873e:	85 d2                	test   edx,edx
 8048740:	74 f6                	je     8048738 <register_tm_clones+0x18>
 8048742:	55                   	push   ebp
 8048743:	89 e5                	mov    ebp,esp
 8048745:	83 ec 18             	sub    esp,0x18
 8048748:	89 44 24 04          	mov    DWORD PTR [esp+0x4],eax
 804874c:	c7 04 24 5c b0 04 08 	mov    DWORD PTR [esp],0x804b05c
 8048753:	ff d2                	call   edx
 8048755:	c9                   	leave  
 8048756:	c3                   	ret    
 8048757:	89 f6                	mov    esi,esi
 8048759:	8d bc 27 00 00 00 00 	lea    edi,[edi+eiz*1+0x0]

08048760 <__do_global_dtors_aux>:
 8048760:	80 3d 84 b0 04 08 00 	cmp    BYTE PTR ds:0x804b084,0x0
 8048767:	75 13                	jne    804877c <__do_global_dtors_aux+0x1c>
 8048769:	55                   	push   ebp
 804876a:	89 e5                	mov    ebp,esp
 804876c:	83 ec 08             	sub    esp,0x8
 804876f:	e8 7c ff ff ff       	call   80486f0 <deregister_tm_clones>
 8048774:	c6 05 84 b0 04 08 01 	mov    BYTE PTR ds:0x804b084,0x1
 804877b:	c9                   	leave  
 804877c:	f3 c3                	repz ret 
 804877e:	66 90                	xchg   ax,ax

08048780 <frame_dummy>:
 8048780:	a1 10 af 04 08       	mov    eax,ds:0x804af10
 8048785:	85 c0                	test   eax,eax
 8048787:	74 1f                	je     80487a8 <frame_dummy+0x28>
 8048789:	b8 00 00 00 00       	mov    eax,0x0
 804878e:	85 c0                	test   eax,eax
 8048790:	74 16                	je     80487a8 <frame_dummy+0x28>
 8048792:	55                   	push   ebp
 8048793:	89 e5                	mov    ebp,esp
 8048795:	83 ec 18             	sub    esp,0x18
 8048798:	c7 04 24 10 af 04 08 	mov    DWORD PTR [esp],0x804af10
 804879f:	ff d0                	call   eax
 80487a1:	c9                   	leave  
 80487a2:	e9 79 ff ff ff       	jmp    8048720 <register_tm_clones>
 80487a7:	90                   	nop
 80487a8:	e9 73 ff ff ff       	jmp    8048720 <register_tm_clones>

080487ad <find_handler>:
 80487ad:	55                   	push   ebp
 80487ae:	89 e5                	mov    ebp,esp
 80487b0:	83 ec 28             	sub    esp,0x28
 80487b3:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [ebp-0xc],0x0
 80487ba:	eb 3e                	jmp    80487fa <find_handler+0x4d>
 80487bc:	8b 55 f4             	mov    edx,DWORD PTR [ebp-0xc]
 80487bf:	89 d0                	mov    eax,edx
 80487c1:	c1 e0 03             	shl    eax,0x3
 80487c4:	01 d0                	add    eax,edx
 80487c6:	c1 e0 02             	shl    eax,0x2
 80487c9:	8d 90 e0 b0 04 08    	lea    edx,[eax+0x804b0e0]
 80487cf:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 80487d2:	89 44 24 04          	mov    DWORD PTR [esp+0x4],eax
 80487d6:	89 14 24             	mov    DWORD PTR [esp],edx
 80487d9:	e8 b2 fd ff ff       	call   8048590 <strcmp@plt>
 80487de:	85 c0                	test   eax,eax
 80487e0:	75 14                	jne    80487f6 <find_handler+0x49>
 80487e2:	8b 55 f4             	mov    edx,DWORD PTR [ebp-0xc]
 80487e5:	89 d0                	mov    eax,edx
 80487e7:	c1 e0 03             	shl    eax,0x3
 80487ea:	01 d0                	add    eax,edx
 80487ec:	c1 e0 02             	shl    eax,0x2
 80487ef:	05 e0 b0 04 08       	add    eax,0x804b0e0
 80487f4:	eb 0f                	jmp    8048805 <find_handler+0x58>
 80487f6:	83 45 f4 01          	add    DWORD PTR [ebp-0xc],0x1
 80487fa:	83 7d f4 05          	cmp    DWORD PTR [ebp-0xc],0x5
 80487fe:	7e bc                	jle    80487bc <find_handler+0xf>
 8048800:	b8 00 00 00 00       	mov    eax,0x0
 8048805:	c9                   	leave  
 8048806:	c3                   	ret    

08048807 <lol_handler>:
 8048807:	55                   	push   ebp
 8048808:	89 e5                	mov    ebp,esp
 804880a:	83 ec 18             	sub    esp,0x18
 804880d:	83 7d 08 00          	cmp    DWORD PTR [ebp+0x8],0x0
 8048811:	75 0e                	jne    8048821 <lol_handler+0x1a>
 8048813:	c7 04 24 d0 8d 04 08 	mov    DWORD PTR [esp],0x8048dd0
 804881a:	e8 01 fe ff ff       	call   8048620 <puts@plt>
 804881f:	eb 13                	jmp    8048834 <lol_handler+0x2d>
 8048821:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 8048824:	89 44 24 04          	mov    DWORD PTR [esp+0x4],eax
 8048828:	c7 04 24 e4 8d 04 08 	mov    DWORD PTR [esp],0x8048de4
 804882f:	e8 6c fd ff ff       	call   80485a0 <printf@plt>
 8048834:	c9                   	leave  
 8048835:	c3                   	ret    

08048836 <add_handler>:
 8048836:	55                   	push   ebp
 8048837:	89 e5                	mov    ebp,esp
 8048839:	83 ec 28             	sub    esp,0x28
 804883c:	83 7d 08 00          	cmp    DWORD PTR [ebp+0x8],0x0
 8048840:	75 0e                	jne    8048850 <add_handler+0x1a>
 8048842:	c7 04 24 ec 8d 04 08 	mov    DWORD PTR [esp],0x8048dec
 8048849:	e8 d2 fd ff ff       	call   8048620 <puts@plt>
 804884e:	eb 39                	jmp    8048889 <add_handler+0x53>
 8048850:	8d 45 f4             	lea    eax,[ebp-0xc]
 8048853:	89 44 24 0c          	mov    DWORD PTR [esp+0xc],eax
 8048857:	8d 45 f0             	lea    eax,[ebp-0x10]
 804885a:	89 44 24 08          	mov    DWORD PTR [esp+0x8],eax
 804885e:	c7 44 24 04 05 8e 04 	mov    DWORD PTR [esp+0x4],0x8048e05
 8048865:	08 
 8048866:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 8048869:	89 04 24             	mov    DWORD PTR [esp],eax
 804886c:	e8 ff fd ff ff       	call   8048670 <__isoc99_sscanf@plt>
 8048871:	8b 55 f0             	mov    edx,DWORD PTR [ebp-0x10]
 8048874:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 8048877:	01 d0                	add    eax,edx
 8048879:	89 44 24 04          	mov    DWORD PTR [esp+0x4],eax
 804887d:	c7 04 24 0b 8e 04 08 	mov    DWORD PTR [esp],0x8048e0b
 8048884:	e8 17 fd ff ff       	call   80485a0 <printf@plt>
 8048889:	c9                   	leave  
 804888a:	c3                   	ret    

0804888b <mult_handler>:
 804888b:	55                   	push   ebp
 804888c:	89 e5                	mov    ebp,esp
 804888e:	83 ec 28             	sub    esp,0x28
 8048891:	83 7d 08 00          	cmp    DWORD PTR [ebp+0x8],0x0
 8048895:	75 0e                	jne    80488a5 <mult_handler+0x1a>
 8048897:	c7 04 24 11 8e 04 08 	mov    DWORD PTR [esp],0x8048e11
 804889e:	e8 7d fd ff ff       	call   8048620 <puts@plt>
 80488a3:	eb 3a                	jmp    80488df <mult_handler+0x54>
 80488a5:	8d 45 f4             	lea    eax,[ebp-0xc]
 80488a8:	89 44 24 0c          	mov    DWORD PTR [esp+0xc],eax
 80488ac:	8d 45 f0             	lea    eax,[ebp-0x10]
 80488af:	89 44 24 08          	mov    DWORD PTR [esp+0x8],eax
 80488b3:	c7 44 24 04 05 8e 04 	mov    DWORD PTR [esp+0x4],0x8048e05
 80488ba:	08 
 80488bb:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 80488be:	89 04 24             	mov    DWORD PTR [esp],eax
 80488c1:	e8 aa fd ff ff       	call   8048670 <__isoc99_sscanf@plt>
 80488c6:	8b 55 f0             	mov    edx,DWORD PTR [ebp-0x10]
 80488c9:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 80488cc:	0f af c2             	imul   eax,edx
 80488cf:	89 44 24 04          	mov    DWORD PTR [esp+0x4],eax
 80488d3:	c7 04 24 0b 8e 04 08 	mov    DWORD PTR [esp],0x8048e0b
 80488da:	e8 c1 fc ff ff       	call   80485a0 <printf@plt>
 80488df:	c9                   	leave  
 80488e0:	c3                   	ret    

080488e1 <rename_handler>:
 80488e1:	55                   	push   ebp
 80488e2:	89 e5                	mov    ebp,esp
 80488e4:	83 ec 28             	sub    esp,0x28
 80488e7:	83 7d 08 00          	cmp    DWORD PTR [ebp+0x8],0x0
 80488eb:	75 0e                	jne    80488fb <rename_handler+0x1a>
 80488ed:	c7 04 24 2c 8e 04 08 	mov    DWORD PTR [esp],0x8048e2c
 80488f4:	e8 27 fd ff ff       	call   8048620 <puts@plt>
 80488f9:	eb 75                	jmp    8048970 <rename_handler+0x8f>
 80488fb:	c7 44 24 04 50 8e 04 	mov    DWORD PTR [esp+0x4],0x8048e50
 8048902:	08 
 8048903:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 8048906:	89 04 24             	mov    DWORD PTR [esp],eax
 8048909:	e8 82 fd ff ff       	call   8048690 <strtok@plt>
 804890e:	89 45 ec             	mov    DWORD PTR [ebp-0x14],eax
 8048911:	c7 44 24 04 52 8e 04 	mov    DWORD PTR [esp+0x4],0x8048e52
 8048918:	08 
 8048919:	c7 04 24 00 00 00 00 	mov    DWORD PTR [esp],0x0
 8048920:	e8 6b fd ff ff       	call   8048690 <strtok@plt>
 8048925:	89 45 f0             	mov    DWORD PTR [ebp-0x10],eax
 8048928:	83 7d f0 00          	cmp    DWORD PTR [ebp-0x10],0x0
 804892c:	75 0e                	jne    804893c <rename_handler+0x5b>
 804892e:	c7 04 24 2c 8e 04 08 	mov    DWORD PTR [esp],0x8048e2c
 8048935:	e8 e6 fc ff ff       	call   8048620 <puts@plt>
 804893a:	eb 34                	jmp    8048970 <rename_handler+0x8f>
 804893c:	8b 45 ec             	mov    eax,DWORD PTR [ebp-0x14]
 804893f:	89 04 24             	mov    DWORD PTR [esp],eax
 8048942:	e8 66 fe ff ff       	call   80487ad <find_handler>
 8048947:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
 804894a:	83 7d f4 00          	cmp    DWORD PTR [ebp-0xc],0x0
 804894e:	74 14                	je     8048964 <rename_handler+0x83>
 8048950:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 8048953:	8b 55 f0             	mov    edx,DWORD PTR [ebp-0x10]
 8048956:	89 54 24 04          	mov    DWORD PTR [esp+0x4],edx
 804895a:	89 04 24             	mov    DWORD PTR [esp],eax
 804895d:	e8 ae fc ff ff       	call   8048610 <strcpy@plt>
 8048962:	eb 0c                	jmp    8048970 <rename_handler+0x8f>
 8048964:	c7 04 24 53 8e 04 08 	mov    DWORD PTR [esp],0x8048e53
 804896b:	e8 b0 fc ff ff       	call   8048620 <puts@plt>
 8048970:	c9                   	leave  
 8048971:	c3                   	ret    

08048972 <auth_admin_handler>:
 8048972:	55                   	push   ebp
 8048973:	89 e5                	mov    ebp,esp
 8048975:	83 ec 18             	sub    esp,0x18
 8048978:	83 7d 08 00          	cmp    DWORD PTR [ebp+0x8],0x0
 804897c:	75 0e                	jne    804898c <auth_admin_handler+0x1a>
 804897e:	c7 04 24 65 8e 04 08 	mov    DWORD PTR [esp],0x8048e65
 8048985:	e8 96 fc ff ff       	call   8048620 <puts@plt>
 804898a:	eb 38                	jmp    80489c4 <auth_admin_handler+0x52>
 804898c:	c7 44 24 04 a0 b0 04 	mov    DWORD PTR [esp+0x4],0x804b0a0
 8048993:	08 
 8048994:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 8048997:	89 04 24             	mov    DWORD PTR [esp],eax
 804899a:	e8 f1 fb ff ff       	call   8048590 <strcmp@plt>
 804899f:	85 c0                	test   eax,eax
 80489a1:	75 15                	jne    80489b8 <auth_admin_handler+0x46>
 80489a3:	c6 05 85 b0 04 08 01 	mov    BYTE PTR ds:0x804b085,0x1
 80489aa:	c7 04 24 7c 8e 04 08 	mov    DWORD PTR [esp],0x8048e7c
 80489b1:	e8 6a fc ff ff       	call   8048620 <puts@plt>
 80489b6:	eb 0c                	jmp    80489c4 <auth_admin_handler+0x52>
 80489b8:	c7 04 24 8f 8e 04 08 	mov    DWORD PTR [esp],0x8048e8f
 80489bf:	e8 5c fc ff ff       	call   8048620 <puts@plt>
 80489c4:	c9                   	leave  
 80489c5:	c3                   	ret    

080489c6 <shell_handler>:
 80489c6:	55                   	push   ebp
 80489c7:	89 e5                	mov    ebp,esp
 80489c9:	83 ec 28             	sub    esp,0x28
 80489cc:	0f b6 05 85 b0 04 08 	movzx  eax,BYTE PTR ds:0x804b085
 80489d3:	84 c0                	test   al,al
 80489d5:	74 2f                	je     8048a06 <shell_handler+0x40>
 80489d7:	e8 24 fc ff ff       	call   8048600 <getegid@plt>
 80489dc:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
 80489df:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 80489e2:	89 44 24 08          	mov    DWORD PTR [esp+0x8],eax
 80489e6:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 80489e9:	89 44 24 04          	mov    DWORD PTR [esp+0x4],eax
 80489ed:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 80489f0:	89 04 24             	mov    DWORD PTR [esp],eax
 80489f3:	e8 a8 fc ff ff       	call   80486a0 <setresgid@plt>
 80489f8:	c7 04 24 a3 8e 04 08 	mov    DWORD PTR [esp],0x8048ea3
 80489ff:	e8 2c fc ff ff       	call   8048630 <system@plt>
 8048a04:	eb 0c                	jmp    8048a12 <shell_handler+0x4c>
 8048a06:	c7 04 24 ab 8e 04 08 	mov    DWORD PTR [esp],0x8048eab
 8048a0d:	e8 0e fc ff ff       	call   8048620 <puts@plt>
 8048a12:	c9                   	leave  
 8048a13:	c3                   	ret    

08048a14 <setup_handlers>:
 8048a14:	55                   	push   ebp
 8048a15:	89 e5                	mov    ebp,esp
 8048a17:	53                   	push   ebx
 8048a18:	c7 05 e0 b0 04 08 73 	mov    DWORD PTR ds:0x804b0e0,0x6c656873
 8048a1f:	68 65 6c 
 8048a22:	c7 05 e4 b0 04 08 6c 	mov    DWORD PTR ds:0x804b0e4,0x6c
 8048a29:	00 00 00 
 8048a2c:	ba e8 b0 04 08       	mov    edx,0x804b0e8
 8048a31:	b9 00 00 00 00       	mov    ecx,0x0
 8048a36:	b8 18 00 00 00       	mov    eax,0x18
 8048a3b:	83 e0 fc             	and    eax,0xfffffffc
 8048a3e:	89 c3                	mov    ebx,eax
 8048a40:	b8 00 00 00 00       	mov    eax,0x0
 8048a45:	89 0c 02             	mov    DWORD PTR [edx+eax*1],ecx
 8048a48:	83 c0 04             	add    eax,0x4
 8048a4b:	39 d8                	cmp    eax,ebx
 8048a4d:	72 f6                	jb     8048a45 <setup_handlers+0x31>
 8048a4f:	01 c2                	add    edx,eax
 8048a51:	c7 05 00 b1 04 08 c6 	mov    DWORD PTR ds:0x804b100,0x80489c6
 8048a58:	89 04 08 
 8048a5b:	c7 05 04 b1 04 08 61 	mov    DWORD PTR ds:0x804b104,0x68747561
 8048a62:	75 74 68 
 8048a65:	c7 05 08 b1 04 08 00 	mov    DWORD PTR ds:0x804b108,0x0
 8048a6c:	00 00 00 
 8048a6f:	ba 0c b1 04 08       	mov    edx,0x804b10c
 8048a74:	b9 00 00 00 00       	mov    ecx,0x0
 8048a79:	b8 18 00 00 00       	mov    eax,0x18
 8048a7e:	83 e0 fc             	and    eax,0xfffffffc
 8048a81:	89 c3                	mov    ebx,eax
 8048a83:	b8 00 00 00 00       	mov    eax,0x0
 8048a88:	89 0c 02             	mov    DWORD PTR [edx+eax*1],ecx
 8048a8b:	83 c0 04             	add    eax,0x4
 8048a8e:	39 d8                	cmp    eax,ebx
 8048a90:	72 f6                	jb     8048a88 <setup_handlers+0x74>
 8048a92:	01 c2                	add    edx,eax
 8048a94:	c7 05 24 b1 04 08 72 	mov    DWORD PTR ds:0x804b124,0x8048972
 8048a9b:	89 04 08 
 8048a9e:	c7 05 28 b1 04 08 72 	mov    DWORD PTR ds:0x804b128,0x616e6572
 8048aa5:	65 6e 61 
 8048aa8:	c7 05 2c b1 04 08 6d 	mov    DWORD PTR ds:0x804b12c,0x656d
 8048aaf:	65 00 00 
 8048ab2:	ba 30 b1 04 08       	mov    edx,0x804b130
 8048ab7:	b9 00 00 00 00       	mov    ecx,0x0
 8048abc:	b8 18 00 00 00       	mov    eax,0x18
 8048ac1:	83 e0 fc             	and    eax,0xfffffffc
 8048ac4:	89 c3                	mov    ebx,eax
 8048ac6:	b8 00 00 00 00       	mov    eax,0x0
 8048acb:	89 0c 02             	mov    DWORD PTR [edx+eax*1],ecx
 8048ace:	83 c0 04             	add    eax,0x4
 8048ad1:	39 d8                	cmp    eax,ebx
 8048ad3:	72 f6                	jb     8048acb <setup_handlers+0xb7>
 8048ad5:	01 c2                	add    edx,eax
 8048ad7:	c7 05 48 b1 04 08 e1 	mov    DWORD PTR ds:0x804b148,0x80488e1
 8048ade:	88 04 08 
 8048ae1:	c7 05 4c b1 04 08 61 	mov    DWORD PTR ds:0x804b14c,0x646461
 8048ae8:	64 64 00 
 8048aeb:	ba 50 b1 04 08       	mov    edx,0x804b150
 8048af0:	b9 00 00 00 00       	mov    ecx,0x0
 8048af5:	b8 1c 00 00 00       	mov    eax,0x1c
 8048afa:	83 e0 fc             	and    eax,0xfffffffc
 8048afd:	89 c3                	mov    ebx,eax
 8048aff:	b8 00 00 00 00       	mov    eax,0x0
 8048b04:	89 0c 02             	mov    DWORD PTR [edx+eax*1],ecx
 8048b07:	83 c0 04             	add    eax,0x4
 8048b0a:	39 d8                	cmp    eax,ebx
 8048b0c:	72 f6                	jb     8048b04 <setup_handlers+0xf0>
 8048b0e:	01 c2                	add    edx,eax
 8048b10:	c7 05 6c b1 04 08 36 	mov    DWORD PTR ds:0x804b16c,0x8048836
 8048b17:	88 04 08 
 8048b1a:	c7 05 70 b1 04 08 6d 	mov    DWORD PTR ds:0x804b170,0x746c756d
 8048b21:	75 6c 74 
 8048b24:	c7 05 74 b1 04 08 00 	mov    DWORD PTR ds:0x804b174,0x0
 8048b2b:	00 00 00 
 8048b2e:	ba 78 b1 04 08       	mov    edx,0x804b178
 8048b33:	b9 00 00 00 00       	mov    ecx,0x0
 8048b38:	b8 18 00 00 00       	mov    eax,0x18
 8048b3d:	83 e0 fc             	and    eax,0xfffffffc
 8048b40:	89 c3                	mov    ebx,eax
 8048b42:	b8 00 00 00 00       	mov    eax,0x0
 8048b47:	89 0c 02             	mov    DWORD PTR [edx+eax*1],ecx
 8048b4a:	83 c0 04             	add    eax,0x4
 8048b4d:	39 d8                	cmp    eax,ebx
 8048b4f:	72 f6                	jb     8048b47 <setup_handlers+0x133>
 8048b51:	01 c2                	add    edx,eax
 8048b53:	c7 05 90 b1 04 08 8b 	mov    DWORD PTR ds:0x804b190,0x804888b
 8048b5a:	88 04 08 
 8048b5d:	c7 05 94 b1 04 08 6c 	mov    DWORD PTR ds:0x804b194,0x6c6f6c
 8048b64:	6f 6c 00 
 8048b67:	ba 98 b1 04 08       	mov    edx,0x804b198
 8048b6c:	b9 00 00 00 00       	mov    ecx,0x0
 8048b71:	b8 1c 00 00 00       	mov    eax,0x1c
 8048b76:	83 e0 fc             	and    eax,0xfffffffc
 8048b79:	89 c3                	mov    ebx,eax
 8048b7b:	b8 00 00 00 00       	mov    eax,0x0
 8048b80:	89 0c 02             	mov    DWORD PTR [edx+eax*1],ecx
 8048b83:	83 c0 04             	add    eax,0x4
 8048b86:	39 d8                	cmp    eax,ebx
 8048b88:	72 f6                	jb     8048b80 <setup_handlers+0x16c>
 8048b8a:	01 c2                	add    edx,eax
 8048b8c:	c7 05 b4 b1 04 08 07 	mov    DWORD PTR ds:0x804b1b4,0x8048807
 8048b93:	88 04 08 
 8048b96:	5b                   	pop    ebx
 8048b97:	5d                   	pop    ebp
 8048b98:	c3                   	ret    

08048b99 <input_loop>:
 8048b99:	55                   	push   ebp
 8048b9a:	89 e5                	mov    ebp,esp
 8048b9c:	81 ec a8 00 00 00    	sub    esp,0xa8
 8048ba2:	65 a1 14 00 00 00    	mov    eax,gs:0x14
 8048ba8:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
 8048bab:	31 c0                	xor    eax,eax
 8048bad:	c7 04 24 be 8e 04 08 	mov    DWORD PTR [esp],0x8048ebe
 8048bb4:	e8 e7 f9 ff ff       	call   80485a0 <printf@plt>
 8048bb9:	a1 80 b0 04 08       	mov    eax,ds:0x804b080
 8048bbe:	89 04 24             	mov    DWORD PTR [esp],eax
 8048bc1:	e8 fa f9 ff ff       	call   80485c0 <fflush@plt>
 8048bc6:	e9 98 00 00 00       	jmp    8048c63 <input_loop+0xca>
 8048bcb:	c7 44 24 04 c2 8e 04 	mov    DWORD PTR [esp+0x4],0x8048ec2
 8048bd2:	08 
 8048bd3:	8d 85 74 ff ff ff    	lea    eax,[ebp-0x8c]
 8048bd9:	89 04 24             	mov    DWORD PTR [esp],eax
 8048bdc:	e8 af fa ff ff       	call   8048690 <strtok@plt>
 8048be1:	89 85 68 ff ff ff    	mov    DWORD PTR [ebp-0x98],eax
 8048be7:	c7 44 24 04 c5 8e 04 	mov    DWORD PTR [esp+0x4],0x8048ec5
 8048bee:	08 
 8048bef:	c7 04 24 00 00 00 00 	mov    DWORD PTR [esp],0x0
 8048bf6:	e8 95 fa ff ff       	call   8048690 <strtok@plt>
 8048bfb:	89 85 6c ff ff ff    	mov    DWORD PTR [ebp-0x94],eax
 8048c01:	8b 85 68 ff ff ff    	mov    eax,DWORD PTR [ebp-0x98]
 8048c07:	89 04 24             	mov    DWORD PTR [esp],eax
 8048c0a:	e8 9e fb ff ff       	call   80487ad <find_handler>
 8048c0f:	89 85 70 ff ff ff    	mov    DWORD PTR [ebp-0x90],eax
 8048c15:	83 bd 70 ff ff ff 00 	cmp    DWORD PTR [ebp-0x90],0x0
 8048c1c:	74 16                	je     8048c34 <input_loop+0x9b>
 8048c1e:	8b 85 70 ff ff ff    	mov    eax,DWORD PTR [ebp-0x90]
 8048c24:	8b 40 20             	mov    eax,DWORD PTR [eax+0x20]
 8048c27:	8b 95 6c ff ff ff    	mov    edx,DWORD PTR [ebp-0x94]
 8048c2d:	89 14 24             	mov    DWORD PTR [esp],edx
 8048c30:	ff d0                	call   eax
 8048c32:	eb 16                	jmp    8048c4a <input_loop+0xb1>
 8048c34:	8b 85 68 ff ff ff    	mov    eax,DWORD PTR [ebp-0x98]
 8048c3a:	89 44 24 04          	mov    DWORD PTR [esp+0x4],eax
 8048c3e:	c7 04 24 c7 8e 04 08 	mov    DWORD PTR [esp],0x8048ec7
 8048c45:	e8 56 f9 ff ff       	call   80485a0 <printf@plt>
 8048c4a:	c7 04 24 be 8e 04 08 	mov    DWORD PTR [esp],0x8048ebe
 8048c51:	e8 4a f9 ff ff       	call   80485a0 <printf@plt>
 8048c56:	a1 80 b0 04 08       	mov    eax,ds:0x804b080
 8048c5b:	89 04 24             	mov    DWORD PTR [esp],eax
 8048c5e:	e8 5d f9 ff ff       	call   80485c0 <fflush@plt>
 8048c63:	a1 60 b0 04 08       	mov    eax,ds:0x804b060
 8048c68:	89 44 24 08          	mov    DWORD PTR [esp+0x8],eax
 8048c6c:	c7 44 24 04 80 00 00 	mov    DWORD PTR [esp+0x4],0x80
 8048c73:	00 
 8048c74:	8d 85 74 ff ff ff    	lea    eax,[ebp-0x8c]
 8048c7a:	89 04 24             	mov    DWORD PTR [esp],eax
 8048c7d:	e8 4e f9 ff ff       	call   80485d0 <fgets@plt>
 8048c82:	85 c0                	test   eax,eax
 8048c84:	0f 85 41 ff ff ff    	jne    8048bcb <input_loop+0x32>
 8048c8a:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 8048c8d:	65 33 05 14 00 00 00 	xor    eax,DWORD PTR gs:0x14
 8048c94:	74 05                	je     8048c9b <input_loop+0x102>
 8048c96:	e8 55 f9 ff ff       	call   80485f0 <__stack_chk_fail@plt>
 8048c9b:	c9                   	leave  
 8048c9c:	c3                   	ret    

08048c9d <main>:
 8048c9d:	55                   	push   ebp
 8048c9e:	89 e5                	mov    ebp,esp
 8048ca0:	83 e4 f0             	and    esp,0xfffffff0
 8048ca3:	83 ec 20             	sub    esp,0x20
 8048ca6:	c7 44 24 04 e0 8e 04 	mov    DWORD PTR [esp+0x4],0x8048ee0
 8048cad:	08 
 8048cae:	c7 04 24 e2 8e 04 08 	mov    DWORD PTR [esp],0x8048ee2
 8048cb5:	e8 c6 f9 ff ff       	call   8048680 <fopen@plt>
 8048cba:	89 44 24 1c          	mov    DWORD PTR [esp+0x1c],eax
 8048cbe:	83 7c 24 1c 00       	cmp    DWORD PTR [esp+0x1c],0x0
 8048cc3:	75 18                	jne    8048cdd <main+0x40>
 8048cc5:	c7 04 24 00 8f 04 08 	mov    DWORD PTR [esp],0x8048f00
 8048ccc:	e8 cf f8 ff ff       	call   80485a0 <printf@plt>
 8048cd1:	c7 04 24 01 00 00 00 	mov    DWORD PTR [esp],0x1
 8048cd8:	e8 73 f9 ff ff       	call   8048650 <exit@plt>
 8048cdd:	8b 44 24 1c          	mov    eax,DWORD PTR [esp+0x1c]
 8048ce1:	89 44 24 08          	mov    DWORD PTR [esp+0x8],eax
 8048ce5:	c7 44 24 04 40 00 00 	mov    DWORD PTR [esp+0x4],0x40
 8048cec:	00 
 8048ced:	c7 04 24 a0 b0 04 08 	mov    DWORD PTR [esp],0x804b0a0
 8048cf4:	e8 d7 f8 ff ff       	call   80485d0 <fgets@plt>
 8048cf9:	c7 44 24 04 c5 8e 04 	mov    DWORD PTR [esp+0x4],0x8048ec5
 8048d00:	08 
 8048d01:	c7 04 24 a0 b0 04 08 	mov    DWORD PTR [esp],0x804b0a0
 8048d08:	e8 a3 f8 ff ff       	call   80485b0 <strcspn@plt>
 8048d0d:	c6 80 a0 b0 04 08 00 	mov    BYTE PTR [eax+0x804b0a0],0x0
 8048d14:	8b 44 24 1c          	mov    eax,DWORD PTR [esp+0x1c]
 8048d18:	89 04 24             	mov    DWORD PTR [esp],eax
 8048d1b:	e8 c0 f8 ff ff       	call   80485e0 <fclose@plt>
 8048d20:	e8 ef fc ff ff       	call   8048a14 <setup_handlers>
 8048d25:	e8 6f fe ff ff       	call   8048b99 <input_loop>
 8048d2a:	b8 00 00 00 00       	mov    eax,0x0
 8048d2f:	c9                   	leave  
 8048d30:	c3                   	ret    
 8048d31:	66 90                	xchg   ax,ax
 8048d33:	66 90                	xchg   ax,ax
 8048d35:	66 90                	xchg   ax,ax
 8048d37:	66 90                	xchg   ax,ax
 8048d39:	66 90                	xchg   ax,ax
 8048d3b:	66 90                	xchg   ax,ax
 8048d3d:	66 90                	xchg   ax,ax
 8048d3f:	90                   	nop

08048d40 <__libc_csu_init>:
 8048d40:	55                   	push   ebp
 8048d41:	57                   	push   edi
 8048d42:	31 ff                	xor    edi,edi
 8048d44:	56                   	push   esi
 8048d45:	53                   	push   ebx
 8048d46:	e8 95 f9 ff ff       	call   80486e0 <__x86.get_pc_thunk.bx>
 8048d4b:	81 c3 b5 22 00 00    	add    ebx,0x22b5
 8048d51:	83 ec 1c             	sub    esp,0x1c
 8048d54:	8b 6c 24 30          	mov    ebp,DWORD PTR [esp+0x30]
 8048d58:	8d b3 0c ff ff ff    	lea    esi,[ebx-0xf4]
 8048d5e:	e8 ed f7 ff ff       	call   8048550 <_init>
 8048d63:	8d 83 08 ff ff ff    	lea    eax,[ebx-0xf8]
 8048d69:	29 c6                	sub    esi,eax
 8048d6b:	c1 fe 02             	sar    esi,0x2
 8048d6e:	85 f6                	test   esi,esi
 8048d70:	74 27                	je     8048d99 <__libc_csu_init+0x59>
 8048d72:	8d b6 00 00 00 00    	lea    esi,[esi+0x0]
 8048d78:	8b 44 24 38          	mov    eax,DWORD PTR [esp+0x38]
 8048d7c:	89 2c 24             	mov    DWORD PTR [esp],ebp
 8048d7f:	89 44 24 08          	mov    DWORD PTR [esp+0x8],eax
 8048d83:	8b 44 24 34          	mov    eax,DWORD PTR [esp+0x34]
 8048d87:	89 44 24 04          	mov    DWORD PTR [esp+0x4],eax
 8048d8b:	ff 94 bb 08 ff ff ff 	call   DWORD PTR [ebx+edi*4-0xf8]
 8048d92:	83 c7 01             	add    edi,0x1
 8048d95:	39 f7                	cmp    edi,esi
 8048d97:	75 df                	jne    8048d78 <__libc_csu_init+0x38>
 8048d99:	83 c4 1c             	add    esp,0x1c
 8048d9c:	5b                   	pop    ebx
 8048d9d:	5e                   	pop    esi
 8048d9e:	5f                   	pop    edi
 8048d9f:	5d                   	pop    ebp
 8048da0:	c3                   	ret    
 8048da1:	eb 0d                	jmp    8048db0 <__libc_csu_fini>
 8048da3:	90                   	nop
 8048da4:	90                   	nop
 8048da5:	90                   	nop
 8048da6:	90                   	nop
 8048da7:	90                   	nop
 8048da8:	90                   	nop
 8048da9:	90                   	nop
 8048daa:	90                   	nop
 8048dab:	90                   	nop
 8048dac:	90                   	nop
 8048dad:	90                   	nop
 8048dae:	90                   	nop
 8048daf:	90                   	nop

08048db0 <__libc_csu_fini>:
 8048db0:	f3 c3                	repz ret 

Disassembly of section .fini:

08048db4 <_fini>:
 8048db4:	53                   	push   ebx
 8048db5:	83 ec 08             	sub    esp,0x8
 8048db8:	e8 23 f9 ff ff       	call   80486e0 <__x86.get_pc_thunk.bx>
 8048dbd:	81 c3 43 22 00 00    	add    ebx,0x2243
 8048dc3:	83 c4 08             	add    esp,0x8
 8048dc6:	5b                   	pop    ebx
 8048dc7:	c3                   	ret    
