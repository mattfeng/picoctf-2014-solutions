
baleful:     file format elf32-i386


Disassembly of section .interp:

08048154 <.interp>:
 8048154:	2f                   	das    
 8048155:	6c                   	ins    BYTE PTR es:[edi],dx
 8048156:	69 62 2f 6c 64 2d 6c 	imul   esp,DWORD PTR [edx+0x2f],0x6c2d646c
 804815d:	69 6e 75 78 2e 73 6f 	imul   ebp,DWORD PTR [esi+0x75],0x6f732e78
 8048164:	2e 32 00             	xor    al,BYTE PTR cs:[eax]

Disassembly of section .note.ABI-tag:

08048168 <.note.ABI-tag>:
 8048168:	04 00                	add    al,0x0
 804816a:	00 00                	add    BYTE PTR [eax],al
 804816c:	10 00                	adc    BYTE PTR [eax],al
 804816e:	00 00                	add    BYTE PTR [eax],al
 8048170:	01 00                	add    DWORD PTR [eax],eax
 8048172:	00 00                	add    BYTE PTR [eax],al
 8048174:	47                   	inc    edi
 8048175:	4e                   	dec    esi
 8048176:	55                   	push   ebp
 8048177:	00 00                	add    BYTE PTR [eax],al
 8048179:	00 00                	add    BYTE PTR [eax],al
 804817b:	00 02                	add    BYTE PTR [edx],al
 804817d:	00 00                	add    BYTE PTR [eax],al
 804817f:	00 06                	add    BYTE PTR [esi],al
 8048181:	00 00                	add    BYTE PTR [eax],al
 8048183:	00 18                	add    BYTE PTR [eax],bl
 8048185:	00 00                	add    BYTE PTR [eax],al
	...

Disassembly of section .note.gnu.build-id:

08048188 <.note.gnu.build-id>:
 8048188:	04 00                	add    al,0x0
 804818a:	00 00                	add    BYTE PTR [eax],al
 804818c:	14 00                	adc    al,0x0
 804818e:	00 00                	add    BYTE PTR [eax],al
 8048190:	03 00                	add    eax,DWORD PTR [eax]
 8048192:	00 00                	add    BYTE PTR [eax],al
 8048194:	47                   	inc    edi
 8048195:	4e                   	dec    esi
 8048196:	55                   	push   ebp
 8048197:	00 35 d1 a3 73 cb    	add    BYTE PTR ds:0xcb73a3d1,dh
 804819d:	e6 a6                	out    0xa6,al
 804819f:	75 ec                	jne    804818d <raise@plt-0x303>
 80481a1:	bb c9 04 72 2a       	mov    ebx,0x2a7204c9
 80481a6:	86 f8                	xchg   al,bh
 80481a8:	53                   	push   ebx
 80481a9:	f2 0c e3             	repnz or al,0xe3

Disassembly of section .gnu.hash:

080481ac <.gnu.hash>:
 80481ac:	03 00                	add    eax,DWORD PTR [eax]
 80481ae:	00 00                	add    BYTE PTR [eax],al
 80481b0:	0c 00                	or     al,0x0
 80481b2:	00 00                	add    BYTE PTR [eax],al
 80481b4:	01 00                	add    DWORD PTR [eax],eax
 80481b6:	00 00                	add    BYTE PTR [eax],al
 80481b8:	05 00 00 00 80       	add    eax,0x80000000
 80481bd:	28 02                	sub    BYTE PTR [edx],al
 80481bf:	22 00                	and    al,BYTE PTR [eax]
 80481c1:	00 00                	add    BYTE PTR [eax],al
 80481c3:	00 0c 00             	add    BYTE PTR [eax+eax*1],cl
 80481c6:	00 00                	add    BYTE PTR [eax],al
 80481c8:	00 00                	add    BYTE PTR [eax],al
 80481ca:	00 00                	add    BYTE PTR [eax],al
 80481cc:	38 f2                	cmp    dl,dh
 80481ce:	8b 1c ac             	mov    ebx,DWORD PTR [esp+ebp*4]
 80481d1:	4b                   	dec    ebx
 80481d2:	e3 c0                	jecxz  8048194 <raise@plt-0x2fc>
 80481d4:	67 55                	addr16 push ebp
 80481d6:	61                   	popa   
 80481d7:	10                   	.byte 0x10

Disassembly of section .dynsym:

080481d8 <.dynsym>:
	...
 80481e8:	6f                   	outs   dx,DWORD PTR ds:[esi]
	...
 80481f1:	00 00                	add    BYTE PTR [eax],al
 80481f3:	00 12                	add    BYTE PTR [edx],dl
 80481f5:	00 00                	add    BYTE PTR [eax],al
 80481f7:	00 5f 00             	add    BYTE PTR [edi+0x0],bl
	...
 8048202:	00 00                	add    BYTE PTR [eax],al
 8048204:	12 00                	adc    al,BYTE PTR [eax]
 8048206:	00 00                	add    BYTE PTR [eax],al
 8048208:	29 00                	sub    DWORD PTR [eax],eax
	...
 8048212:	00 00                	add    BYTE PTR [eax],al
 8048214:	12 00                	adc    al,BYTE PTR [eax]
 8048216:	00 00                	add    BYTE PTR [eax],al
 8048218:	30 00                	xor    BYTE PTR [eax],al
	...
 8048222:	00 00                	add    BYTE PTR [eax],al
 8048224:	12 00                	adc    al,BYTE PTR [eax]
 8048226:	00 00                	add    BYTE PTR [eax],al
 8048228:	01 00                	add    DWORD PTR [eax],eax
	...
 8048232:	00 00                	add    BYTE PTR [eax],al
 8048234:	20 00                	and    BYTE PTR [eax],al
 8048236:	00 00                	add    BYTE PTR [eax],al
 8048238:	47                   	inc    edi
	...
 8048241:	00 00                	add    BYTE PTR [eax],al
 8048243:	00 12                	add    BYTE PTR [edx],dl
 8048245:	00 00                	add    BYTE PTR [eax],al
 8048247:	00 84 00 00 00 00 00 	add    BYTE PTR [eax+eax*1+0x0],al
 804824e:	00 00                	add    BYTE PTR [eax],al
 8048250:	00 00                	add    BYTE PTR [eax],al
 8048252:	00 00                	add    BYTE PTR [eax],al
 8048254:	12 00                	adc    al,BYTE PTR [eax]
 8048256:	00 00                	add    BYTE PTR [eax],al
 8048258:	7c 00                	jl     804825a <raise@plt-0x236>
	...
 8048262:	00 00                	add    BYTE PTR [eax],al
 8048264:	12 00                	adc    al,BYTE PTR [eax]
 8048266:	00 00                	add    BYTE PTR [eax],al
 8048268:	52                   	push   edx
	...
 8048271:	00 00                	add    BYTE PTR [eax],al
 8048273:	00 12                	add    BYTE PTR [edx],dl
 8048275:	00 00                	add    BYTE PTR [eax],al
 8048277:	00 4c 00 00          	add    BYTE PTR [eax+eax*1+0x0],cl
	...
 8048283:	00 12                	add    BYTE PTR [edx],dl
 8048285:	00 00                	add    BYTE PTR [eax],al
 8048287:	00 59 00             	add    BYTE PTR [ecx+0x0],bl
	...
 8048292:	00 00                	add    BYTE PTR [eax],al
 8048294:	12 00                	adc    al,BYTE PTR [eax]
 8048296:	00 00                	add    BYTE PTR [eax],al
 8048298:	75 00                	jne    804829a <raise@plt-0x1f6>
 804829a:	00 00                	add    BYTE PTR [eax],al
 804829c:	c4                   	(bad)  
 804829d:	c0 06 08             	rol    BYTE PTR [esi],0x8
 80482a0:	04 00                	add    al,0x0
 80482a2:	00 00                	add    BYTE PTR [eax],al
 80482a4:	11 00                	adc    DWORD PTR [eax],eax
 80482a6:	19 00                	sbb    DWORD PTR [eax],eax
 80482a8:	1a 00                	sbb    al,BYTE PTR [eax]
 80482aa:	00 00                	add    BYTE PTR [eax],al
 80482ac:	bc 9d 04 08 04       	mov    esp,0x408049d
 80482b1:	00 00                	add    BYTE PTR [eax],al
 80482b3:	00 11                	add    BYTE PTR [ecx],dl
 80482b5:	00 0f                	add    BYTE PTR [edi],cl
 80482b7:	00 41 00             	add    BYTE PTR [ecx+0x0],al
 80482ba:	00 00                	add    BYTE PTR [eax],al
 80482bc:	c8 c0 06 08          	enter  0x6c0,0x8
 80482c0:	04 00                	add    al,0x0
 80482c2:	00 00                	add    BYTE PTR [eax],al
 80482c4:	11 00                	adc    DWORD PTR [eax],eax
 80482c6:	19 00                	sbb    DWORD PTR [eax],eax

Disassembly of section .dynstr:

080482c8 <.dynstr>:
 80482c8:	00 5f 5f             	add    BYTE PTR [edi+0x5f],bl
 80482cb:	67 6d                	ins    DWORD PTR es:[di],dx
 80482cd:	6f                   	outs   dx,DWORD PTR ds:[esi]
 80482ce:	6e                   	outs   dx,BYTE PTR ds:[esi]
 80482cf:	5f                   	pop    edi
 80482d0:	73 74                	jae    8048346 <raise@plt-0x14a>
 80482d2:	61                   	popa   
 80482d3:	72 74                	jb     8048349 <raise@plt-0x147>
 80482d5:	5f                   	pop    edi
 80482d6:	5f                   	pop    edi
 80482d7:	00 6c 69 62          	add    BYTE PTR [ecx+ebp*2+0x62],ch
 80482db:	63 2e                	arpl   WORD PTR [esi],bp
 80482dd:	73 6f                	jae    804834e <raise@plt-0x142>
 80482df:	2e 36 00 5f 49       	cs add BYTE PTR ss:[edi+0x49],bl
 80482e4:	4f                   	dec    edi
 80482e5:	5f                   	pop    edi
 80482e6:	73 74                	jae    804835c <raise@plt-0x134>
 80482e8:	64 69 6e 5f 75 73 65 	imul   ebp,DWORD PTR fs:[esi+0x5f],0x64657375
 80482ef:	64 
 80482f0:	00 66 66             	add    BYTE PTR [esi+0x66],ah
 80482f3:	6c                   	ins    BYTE PTR es:[edi],dx
 80482f4:	75 73                	jne    8048369 <raise@plt-0x127>
 80482f6:	68 00 5f 5f 73       	push   0x735f5f00
 80482fb:	74 61                	je     804835e <raise@plt-0x132>
 80482fd:	63 6b 5f             	arpl   WORD PTR [ebx+0x5f],bp
 8048300:	63 68 6b             	arpl   WORD PTR [eax+0x6b],bp
 8048303:	5f                   	pop    edi
 8048304:	66 61                	popaw  
 8048306:	69 6c 00 73 74 64 69 	imul   ebp,DWORD PTR [eax+eax*1+0x73],0x6e696474
 804830d:	6e 
 804830e:	00 66 65             	add    BYTE PTR [esi+0x65],ah
 8048311:	6f                   	outs   dx,DWORD PTR ds:[esi]
 8048312:	66 00 66 67          	data16 add BYTE PTR [esi+0x67],ah
 8048316:	65 74 63             	gs je  804837c <raise@plt-0x114>
 8048319:	00 75 6e             	add    BYTE PTR [ebp+0x6e],dh
 804831c:	67 65 74 63          	addr16 gs je 8048383 <raise@plt-0x10d>
 8048320:	00 66 70             	add    BYTE PTR [esi+0x70],ah
 8048323:	75 74                	jne    8048399 <raise@plt-0xf7>
 8048325:	63 00                	arpl   WORD PTR [eax],ax
 8048327:	5f                   	pop    edi
 8048328:	5f                   	pop    edi
 8048329:	69 73 6f 63 39 39 5f 	imul   esi,DWORD PTR [ebx+0x6f],0x5f393963
 8048330:	66 73 63             	data16 jae 8048396 <raise@plt-0xfa>
 8048333:	61                   	popa   
 8048334:	6e                   	outs   dx,BYTE PTR ds:[esi]
 8048335:	66 00 72 61          	data16 add BYTE PTR [edx+0x61],dh
 8048339:	69 73 65 00 73 74 64 	imul   esi,DWORD PTR [ebx+0x65],0x64747300
 8048340:	65 72 72             	gs jb  80483b5 <raise@plt-0xdb>
 8048343:	00 66 70             	add    BYTE PTR [esi+0x70],ah
 8048346:	72 69                	jb     80483b1 <raise@plt-0xdf>
 8048348:	6e                   	outs   dx,BYTE PTR ds:[esi]
 8048349:	74 66                	je     80483b1 <raise@plt-0xdf>
 804834b:	00 5f 5f             	add    BYTE PTR [edi+0x5f],bl
 804834e:	6c                   	ins    BYTE PTR es:[edi],dx
 804834f:	69 62 63 5f 73 74 61 	imul   esp,DWORD PTR [edx+0x63],0x6174735f
 8048356:	72 74                	jb     80483cc <raise@plt-0xc4>
 8048358:	5f                   	pop    edi
 8048359:	6d                   	ins    DWORD PTR es:[edi],dx
 804835a:	61                   	popa   
 804835b:	69 6e 00 47 4c 49 42 	imul   ebp,DWORD PTR [esi+0x0],0x42494c47
 8048362:	43                   	inc    ebx
 8048363:	5f                   	pop    edi
 8048364:	32 2e                	xor    ch,BYTE PTR [esi]
 8048366:	34 00                	xor    al,0x0
 8048368:	47                   	inc    edi
 8048369:	4c                   	dec    esp
 804836a:	49                   	dec    ecx
 804836b:	42                   	inc    edx
 804836c:	43                   	inc    ebx
 804836d:	5f                   	pop    edi
 804836e:	32 2e                	xor    ch,BYTE PTR [esi]
 8048370:	37                   	aaa    
 8048371:	00 47 4c             	add    BYTE PTR [edi+0x4c],al
 8048374:	49                   	dec    ecx
 8048375:	42                   	inc    edx
 8048376:	43                   	inc    ebx
 8048377:	5f                   	pop    edi
 8048378:	32 2e                	xor    ch,BYTE PTR [esi]
 804837a:	30 00                	xor    BYTE PTR [eax],al

Disassembly of section .gnu.version:

0804837c <.gnu.version>:
 804837c:	00 00                	add    BYTE PTR [eax],al
 804837e:	02 00                	add    al,BYTE PTR [eax]
 8048380:	03 00                	add    eax,DWORD PTR [eax]
 8048382:	02 00                	add    al,BYTE PTR [eax]
 8048384:	04 00                	add    al,0x0
 8048386:	00 00                	add    BYTE PTR [eax],al
 8048388:	02 00                	add    al,BYTE PTR [eax]
 804838a:	02 00                	add    al,BYTE PTR [eax]
 804838c:	02 00                	add    al,BYTE PTR [eax]
 804838e:	02 00                	add    al,BYTE PTR [eax]
 8048390:	02 00                	add    al,BYTE PTR [eax]
 8048392:	02 00                	add    al,BYTE PTR [eax]
 8048394:	02 00                	add    al,BYTE PTR [eax]
 8048396:	01 00                	add    DWORD PTR [eax],eax
 8048398:	02 00                	add    al,BYTE PTR [eax]

Disassembly of section .gnu.version_r:

0804839c <.gnu.version_r>:
 804839c:	01 00                	add    DWORD PTR [eax],eax
 804839e:	03 00                	add    eax,DWORD PTR [eax]
 80483a0:	10 00                	adc    BYTE PTR [eax],al
 80483a2:	00 00                	add    BYTE PTR [eax],al
 80483a4:	10 00                	adc    BYTE PTR [eax],al
 80483a6:	00 00                	add    BYTE PTR [eax],al
 80483a8:	00 00                	add    BYTE PTR [eax],al
 80483aa:	00 00                	add    BYTE PTR [eax],al
 80483ac:	14 69                	adc    al,0x69
 80483ae:	69 0d 00 00 04 00 96 	imul   ecx,DWORD PTR ds:0x40000,0x96
 80483b5:	00 00 00 
 80483b8:	10 00                	adc    BYTE PTR [eax],al
 80483ba:	00 00                	add    BYTE PTR [eax],al
 80483bc:	17                   	pop    ss
 80483bd:	69 69 0d 00 00 03 00 	imul   ebp,DWORD PTR [ecx+0xd],0x30000
 80483c4:	a0 00 00 00 10       	mov    al,ds:0x10000000
 80483c9:	00 00                	add    BYTE PTR [eax],al
 80483cb:	00 10                	add    BYTE PTR [eax],dl
 80483cd:	69 69 0d 00 00 02 00 	imul   ebp,DWORD PTR [ecx+0xd],0x20000
 80483d4:	aa                   	stos   BYTE PTR es:[edi],al
 80483d5:	00 00                	add    BYTE PTR [eax],al
 80483d7:	00 00                	add    BYTE PTR [eax],al
 80483d9:	00 00                	add    BYTE PTR [eax],al
	...

Disassembly of section .rel.dyn:

080483dc <.rel.dyn>:
 80483dc:	f0 bf 04 08 06 05    	lock mov edi,0x5060804
 80483e2:	00 00                	add    BYTE PTR [eax],al
 80483e4:	c4                   	(bad)  
 80483e5:	c0 06 08             	rol    BYTE PTR [esi],0x8
 80483e8:	05 0c 00 00 c8       	add    eax,0xc800000c
 80483ed:	c0 06 08             	rol    BYTE PTR [esi],0x8
 80483f0:	05                   	.byte 0x5
 80483f1:	0e                   	push   cs
	...

Disassembly of section .rel.plt:

080483f4 <.rel.plt>:
 80483f4:	00 c0                	add    al,al
 80483f6:	04 08                	add    al,0x8
 80483f8:	07                   	pop    es
 80483f9:	01 00                	add    DWORD PTR [eax],eax
 80483fb:	00 04 c0             	add    BYTE PTR [eax+eax*8],al
 80483fe:	04 08                	add    al,0x8
 8048400:	07                   	pop    es
 8048401:	02 00                	add    al,BYTE PTR [eax]
 8048403:	00 08                	add    BYTE PTR [eax],cl
 8048405:	c0 04 08 07          	rol    BYTE PTR [eax+ecx*1],0x7
 8048409:	03 00                	add    eax,DWORD PTR [eax]
 804840b:	00 0c c0             	add    BYTE PTR [eax+eax*8],cl
 804840e:	04 08                	add    al,0x8
 8048410:	07                   	pop    es
 8048411:	04 00                	add    al,0x0
 8048413:	00 10                	add    BYTE PTR [eax],dl
 8048415:	c0 04 08 07          	rol    BYTE PTR [eax+ecx*1],0x7
 8048419:	05 00 00 14 c0       	add    eax,0xc0140000
 804841e:	04 08                	add    al,0x8
 8048420:	07                   	pop    es
 8048421:	06                   	push   es
 8048422:	00 00                	add    BYTE PTR [eax],al
 8048424:	18 c0                	sbb    al,al
 8048426:	04 08                	add    al,0x8
 8048428:	07                   	pop    es
 8048429:	07                   	pop    es
 804842a:	00 00                	add    BYTE PTR [eax],al
 804842c:	1c c0                	sbb    al,0xc0
 804842e:	04 08                	add    al,0x8
 8048430:	07                   	pop    es
 8048431:	08 00                	or     BYTE PTR [eax],al
 8048433:	00 20                	add    BYTE PTR [eax],ah
 8048435:	c0 04 08 07          	rol    BYTE PTR [eax+ecx*1],0x7
 8048439:	09 00                	or     DWORD PTR [eax],eax
 804843b:	00 24 c0             	add    BYTE PTR [eax+eax*8],ah
 804843e:	04 08                	add    al,0x8
 8048440:	07                   	pop    es
 8048441:	0a 00                	or     al,BYTE PTR [eax]
 8048443:	00 28                	add    BYTE PTR [eax],ch
 8048445:	c0 04 08 07          	rol    BYTE PTR [eax+ecx*1],0x7
 8048449:	0b 00                	or     eax,DWORD PTR [eax]
	...

Disassembly of section .init:

0804844c <.init>:
 804844c:	53                   	push   ebx
 804844d:	83 ec 08             	sub    esp,0x8
 8048450:	e8 00 00 00 00       	call   8048455 <raise@plt-0x3b>
 8048455:	5b                   	pop    ebx
 8048456:	81 c3 9f 3b 00 00    	add    ebx,0x3b9f
 804845c:	8b 83 fc ff ff ff    	mov    eax,DWORD PTR [ebx-0x4]
 8048462:	85 c0                	test   eax,eax
 8048464:	74 05                	je     804846b <raise@plt-0x25>
 8048466:	e8 65 00 00 00       	call   80484d0 <__gmon_start__@plt>
 804846b:	e8 60 01 00 00       	call   80485d0 <fputc@plt+0xa0>
 8048470:	e8 fb 18 00 00       	call   8049d70 <fputc@plt+0x1840>
 8048475:	83 c4 08             	add    esp,0x8
 8048478:	5b                   	pop    ebx
 8048479:	c3                   	ret    

Disassembly of section .plt:

08048480 <raise@plt-0x10>:
 8048480:	ff 35 f8 bf 04 08    	push   DWORD PTR ds:0x804bff8
 8048486:	ff 25 fc bf 04 08    	jmp    DWORD PTR ds:0x804bffc
 804848c:	00 00                	add    BYTE PTR [eax],al
	...

08048490 <raise@plt>:
 8048490:	ff 25 00 c0 04 08    	jmp    DWORD PTR ds:0x804c000
 8048496:	68 00 00 00 00       	push   0x0
 804849b:	e9 e0 ff ff ff       	jmp    8048480 <raise@plt-0x10>

080484a0 <__isoc99_fscanf@plt>:
 80484a0:	ff 25 04 c0 04 08    	jmp    DWORD PTR ds:0x804c004
 80484a6:	68 08 00 00 00       	push   0x8
 80484ab:	e9 d0 ff ff ff       	jmp    8048480 <raise@plt-0x10>

080484b0 <fflush@plt>:
 80484b0:	ff 25 08 c0 04 08    	jmp    DWORD PTR ds:0x804c008
 80484b6:	68 10 00 00 00       	push   0x10
 80484bb:	e9 c0 ff ff ff       	jmp    8048480 <raise@plt-0x10>

080484c0 <__stack_chk_fail@plt>:
 80484c0:	ff 25 0c c0 04 08    	jmp    DWORD PTR ds:0x804c00c
 80484c6:	68 18 00 00 00       	push   0x18
 80484cb:	e9 b0 ff ff ff       	jmp    8048480 <raise@plt-0x10>

080484d0 <__gmon_start__@plt>:
 80484d0:	ff 25 10 c0 04 08    	jmp    DWORD PTR ds:0x804c010
 80484d6:	68 20 00 00 00       	push   0x20
 80484db:	e9 a0 ff ff ff       	jmp    8048480 <raise@plt-0x10>

080484e0 <feof@plt>:
 80484e0:	ff 25 14 c0 04 08    	jmp    DWORD PTR ds:0x804c014
 80484e6:	68 28 00 00 00       	push   0x28
 80484eb:	e9 90 ff ff ff       	jmp    8048480 <raise@plt-0x10>

080484f0 <__libc_start_main@plt>:
 80484f0:	ff 25 18 c0 04 08    	jmp    DWORD PTR ds:0x804c018
 80484f6:	68 30 00 00 00       	push   0x30
 80484fb:	e9 80 ff ff ff       	jmp    8048480 <raise@plt-0x10>

08048500 <fprintf@plt>:
 8048500:	ff 25 1c c0 04 08    	jmp    DWORD PTR ds:0x804c01c
 8048506:	68 38 00 00 00       	push   0x38
 804850b:	e9 70 ff ff ff       	jmp    8048480 <raise@plt-0x10>

08048510 <ungetc@plt>:
 8048510:	ff 25 20 c0 04 08    	jmp    DWORD PTR ds:0x804c020
 8048516:	68 40 00 00 00       	push   0x40
 804851b:	e9 60 ff ff ff       	jmp    8048480 <raise@plt-0x10>

08048520 <fgetc@plt>:
 8048520:	ff 25 24 c0 04 08    	jmp    DWORD PTR ds:0x804c024
 8048526:	68 48 00 00 00       	push   0x48
 804852b:	e9 50 ff ff ff       	jmp    8048480 <raise@plt-0x10>

08048530 <fputc@plt>:
 8048530:	ff 25 28 c0 04 08    	jmp    DWORD PTR ds:0x804c028
 8048536:	68 50 00 00 00       	push   0x50
 804853b:	e9 40 ff ff ff       	jmp    8048480 <raise@plt-0x10>

Disassembly of section .text:

08048540 <.text>:
 8048540:	31 ed                	xor    ebp,ebp
 8048542:	5e                   	pop    esi
 8048543:	89 e1                	mov    ecx,esp
 8048545:	83 e4 f0             	and    esp,0xfffffff0
 8048548:	50                   	push   eax
 8048549:	54                   	push   esp
 804854a:	52                   	push   edx
 804854b:	68 60 9d 04 08       	push   0x8049d60
 8048550:	68 f0 9c 04 08       	push   0x8049cf0
 8048555:	51                   	push   ecx
 8048556:	56                   	push   esi
 8048557:	68 82 9c 04 08       	push   0x8049c82
 804855c:	e8 8f ff ff ff       	call   80484f0 <__libc_start_main@plt>
 8048561:	f4                   	hlt    
 8048562:	90                   	nop
 8048563:	90                   	nop
 8048564:	90                   	nop
 8048565:	90                   	nop
 8048566:	90                   	nop
 8048567:	90                   	nop
 8048568:	90                   	nop
 8048569:	90                   	nop
 804856a:	90                   	nop
 804856b:	90                   	nop
 804856c:	90                   	nop
 804856d:	90                   	nop
 804856e:	90                   	nop
 804856f:	90                   	nop
 8048570:	55                   	push   ebp
 8048571:	89 e5                	mov    ebp,esp
 8048573:	53                   	push   ebx
 8048574:	83 ec 04             	sub    esp,0x4
 8048577:	80 3d cc c0 06 08 00 	cmp    BYTE PTR ds:0x806c0cc,0x0
 804857e:	75 3f                	jne    80485bf <fputc@plt+0x8f>
 8048580:	a1 d0 c0 06 08       	mov    eax,ds:0x806c0d0
 8048585:	bb 20 bf 04 08       	mov    ebx,0x804bf20
 804858a:	81 eb 1c bf 04 08    	sub    ebx,0x804bf1c
 8048590:	c1 fb 02             	sar    ebx,0x2
 8048593:	83 eb 01             	sub    ebx,0x1
 8048596:	39 d8                	cmp    eax,ebx
 8048598:	73 1e                	jae    80485b8 <fputc@plt+0x88>
 804859a:	8d b6 00 00 00 00    	lea    esi,[esi+0x0]
 80485a0:	83 c0 01             	add    eax,0x1
 80485a3:	a3 d0 c0 06 08       	mov    ds:0x806c0d0,eax
 80485a8:	ff 14 85 1c bf 04 08 	call   DWORD PTR [eax*4+0x804bf1c]
 80485af:	a1 d0 c0 06 08       	mov    eax,ds:0x806c0d0
 80485b4:	39 d8                	cmp    eax,ebx
 80485b6:	72 e8                	jb     80485a0 <fputc@plt+0x70>
 80485b8:	c6 05 cc c0 06 08 01 	mov    BYTE PTR ds:0x806c0cc,0x1
 80485bf:	83 c4 04             	add    esp,0x4
 80485c2:	5b                   	pop    ebx
 80485c3:	5d                   	pop    ebp
 80485c4:	c3                   	ret    
 80485c5:	8d 74 26 00          	lea    esi,[esi+eiz*1+0x0]
 80485c9:	8d bc 27 00 00 00 00 	lea    edi,[edi+eiz*1+0x0]
 80485d0:	55                   	push   ebp
 80485d1:	89 e5                	mov    ebp,esp
 80485d3:	83 ec 18             	sub    esp,0x18
 80485d6:	a1 24 bf 04 08       	mov    eax,ds:0x804bf24
 80485db:	85 c0                	test   eax,eax
 80485dd:	74 12                	je     80485f1 <fputc@plt+0xc1>
 80485df:	b8 00 00 00 00       	mov    eax,0x0
 80485e4:	85 c0                	test   eax,eax
 80485e6:	74 09                	je     80485f1 <fputc@plt+0xc1>
 80485e8:	c7 04 24 24 bf 04 08 	mov    DWORD PTR [esp],0x804bf24
 80485ef:	ff d0                	call   eax
 80485f1:	c9                   	leave  
 80485f2:	c3                   	ret    
 80485f3:	90                   	nop
 80485f4:	55                   	push   ebp
 80485f5:	89 e5                	mov    ebp,esp
 80485f7:	83 ec 18             	sub    esp,0x18
 80485fa:	a1 c8 c0 06 08       	mov    eax,ds:0x806c0c8
 80485ff:	89 04 24             	mov    DWORD PTR [esp],eax
 8048602:	e8 d9 fe ff ff       	call   80484e0 <feof@plt>
 8048607:	85 c0                	test   eax,eax
 8048609:	74 0c                	je     8048617 <fputc@plt+0xe7>
 804860b:	c7 04 24 0b 00 00 00 	mov    DWORD PTR [esp],0xb
 8048612:	e8 79 fe ff ff       	call   8048490 <raise@plt>
 8048617:	c9                   	leave  
 8048618:	c3                   	ret    
 8048619:	55                   	push   ebp
 804861a:	89 e5                	mov    ebp,esp
 804861c:	83 ec 28             	sub    esp,0x28
 804861f:	a1 c8 c0 06 08       	mov    eax,ds:0x806c0c8
 8048624:	89 04 24             	mov    DWORD PTR [esp],eax
 8048627:	e8 f4 fe ff ff       	call   8048520 <fgetc@plt>
 804862c:	89 45 f0             	mov    DWORD PTR [ebp-0x10],eax
 804862f:	a1 c8 c0 06 08       	mov    eax,ds:0x806c0c8
 8048634:	89 04 24             	mov    DWORD PTR [esp],eax
 8048637:	e8 a4 fe ff ff       	call   80484e0 <feof@plt>
 804863c:	85 c0                	test   eax,eax
 804863e:	0f 95 c0             	setne  al
 8048641:	0f b6 c0             	movzx  eax,al
 8048644:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
 8048647:	a1 c8 c0 06 08       	mov    eax,ds:0x806c0c8
 804864c:	89 44 24 04          	mov    DWORD PTR [esp+0x4],eax
 8048650:	8b 45 f0             	mov    eax,DWORD PTR [ebp-0x10]
 8048653:	89 04 24             	mov    DWORD PTR [esp],eax
 8048656:	e8 b5 fe ff ff       	call   8048510 <ungetc@plt>
 804865b:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 804865e:	c9                   	leave  
 804865f:	c3                   	ret    
 8048660:	55                   	push   ebp
 8048661:	89 e5                	mov    ebp,esp
 8048663:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 8048666:	8b 00                	mov    eax,DWORD PTR [eax]
 8048668:	5d                   	pop    ebp
 8048669:	c3                   	ret    
 804866a:	55                   	push   ebp
 804866b:	89 e5                	mov    ebp,esp
 804866d:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 8048670:	8b 00                	mov    eax,DWORD PTR [eax]
 8048672:	85 c0                	test   eax,eax
 8048674:	0f 95 c0             	setne  al
 8048677:	0f b6 c0             	movzx  eax,al
 804867a:	5d                   	pop    ebp
 804867b:	c3                   	ret    
 804867c:	55                   	push   ebp
 804867d:	89 e5                	mov    ebp,esp
 804867f:	83 ec 18             	sub    esp,0x18
 8048682:	8b 15 c4 c0 06 08    	mov    edx,DWORD PTR ds:0x806c0c4
 8048688:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 804868b:	8b 00                	mov    eax,DWORD PTR [eax]
 804868d:	89 54 24 04          	mov    DWORD PTR [esp+0x4],edx
 8048691:	89 04 24             	mov    DWORD PTR [esp],eax
 8048694:	e8 97 fe ff ff       	call   8048530 <fputc@plt>
 8048699:	a1 c4 c0 06 08       	mov    eax,ds:0x806c0c4
 804869e:	89 04 24             	mov    DWORD PTR [esp],eax
 80486a1:	e8 0a fe ff ff       	call   80484b0 <fflush@plt>
 80486a6:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 80486a9:	8b 00                	mov    eax,DWORD PTR [eax]
 80486ab:	c9                   	leave  
 80486ac:	c3                   	ret    
 80486ad:	55                   	push   ebp
 80486ae:	89 e5                	mov    ebp,esp
 80486b0:	83 ec 18             	sub    esp,0x18
 80486b3:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 80486b6:	8b 08                	mov    ecx,DWORD PTR [eax]
 80486b8:	ba c0 9d 04 08       	mov    edx,0x8049dc0
 80486bd:	a1 c4 c0 06 08       	mov    eax,ds:0x806c0c4
 80486c2:	89 4c 24 08          	mov    DWORD PTR [esp+0x8],ecx
 80486c6:	89 54 24 04          	mov    DWORD PTR [esp+0x4],edx
 80486ca:	89 04 24             	mov    DWORD PTR [esp],eax
 80486cd:	e8 2e fe ff ff       	call   8048500 <fprintf@plt>
 80486d2:	c9                   	leave  
 80486d3:	c3                   	ret    
 80486d4:	55                   	push   ebp
 80486d5:	89 e5                	mov    ebp,esp
 80486d7:	83 ec 18             	sub    esp,0x18
 80486da:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 80486dd:	8b 08                	mov    ecx,DWORD PTR [eax]
 80486df:	ba c3 9d 04 08       	mov    edx,0x8049dc3
 80486e4:	a1 c4 c0 06 08       	mov    eax,ds:0x806c0c4
 80486e9:	89 4c 24 08          	mov    DWORD PTR [esp+0x8],ecx
 80486ed:	89 54 24 04          	mov    DWORD PTR [esp+0x4],edx
 80486f1:	89 04 24             	mov    DWORD PTR [esp],eax
 80486f4:	e8 07 fe ff ff       	call   8048500 <fprintf@plt>
 80486f9:	c9                   	leave  
 80486fa:	c3                   	ret    
 80486fb:	55                   	push   ebp
 80486fc:	89 e5                	mov    ebp,esp
 80486fe:	83 ec 18             	sub    esp,0x18
 8048701:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 8048704:	89 04 24             	mov    DWORD PTR [esp],eax
 8048707:	e8 e8 fe ff ff       	call   80485f4 <fputc@plt+0xc4>
 804870c:	a1 c8 c0 06 08       	mov    eax,ds:0x806c0c8
 8048711:	89 04 24             	mov    DWORD PTR [esp],eax
 8048714:	e8 07 fe ff ff       	call   8048520 <fgetc@plt>
 8048719:	c9                   	leave  
 804871a:	c3                   	ret    
 804871b:	55                   	push   ebp
 804871c:	89 e5                	mov    ebp,esp
 804871e:	83 ec 28             	sub    esp,0x28
 8048721:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 8048724:	89 04 24             	mov    DWORD PTR [esp],eax
 8048727:	e8 c8 fe ff ff       	call   80485f4 <fputc@plt+0xc4>
 804872c:	ba c0 9d 04 08       	mov    edx,0x8049dc0
 8048731:	a1 c8 c0 06 08       	mov    eax,ds:0x806c0c8
 8048736:	8d 4d f4             	lea    ecx,[ebp-0xc]
 8048739:	89 4c 24 08          	mov    DWORD PTR [esp+0x8],ecx
 804873d:	89 54 24 04          	mov    DWORD PTR [esp+0x4],edx
 8048741:	89 04 24             	mov    DWORD PTR [esp],eax
 8048744:	e8 57 fd ff ff       	call   80484a0 <__isoc99_fscanf@plt>
 8048749:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 804874c:	c9                   	leave  
 804874d:	c3                   	ret    
 804874e:	55                   	push   ebp
 804874f:	89 e5                	mov    ebp,esp
 8048751:	83 ec 28             	sub    esp,0x28
 8048754:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 8048757:	89 04 24             	mov    DWORD PTR [esp],eax
 804875a:	e8 95 fe ff ff       	call   80485f4 <fputc@plt+0xc4>
 804875f:	ba c8 9d 04 08       	mov    edx,0x8049dc8
 8048764:	a1 c8 c0 06 08       	mov    eax,ds:0x806c0c8
 8048769:	8d 4d f4             	lea    ecx,[ebp-0xc]
 804876c:	89 4c 24 08          	mov    DWORD PTR [esp+0x8],ecx
 8048770:	89 54 24 04          	mov    DWORD PTR [esp+0x4],edx
 8048774:	89 04 24             	mov    DWORD PTR [esp],eax
 8048777:	e8 24 fd ff ff       	call   80484a0 <__isoc99_fscanf@plt>
 804877c:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 804877f:	c9                   	leave  
 8048780:	c3                   	ret    
 8048781:	55                   	push   ebp
 8048782:	89 e5                	mov    ebp,esp
 8048784:	83 ec 14             	sub    esp,0x14
 8048787:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 804878a:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
 804878d:	8b 45 fc             	mov    eax,DWORD PTR [ebp-0x4]
 8048790:	89 45 ec             	mov    DWORD PTR [ebp-0x14],eax
 8048793:	d9 45 ec             	fld    DWORD PTR [ebp-0x14]
 8048796:	c9                   	leave  
 8048797:	c3                   	ret    
 8048798:	55                   	push   ebp
 8048799:	89 e5                	mov    ebp,esp
 804879b:	83 ec 10             	sub    esp,0x10
 804879e:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 80487a1:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
 80487a4:	8b 45 fc             	mov    eax,DWORD PTR [ebp-0x4]
 80487a7:	c9                   	leave  
 80487a8:	c3                   	ret    
 80487a9:	55                   	push   ebp
 80487aa:	89 e5                	mov    ebp,esp
 80487ac:	83 ec 18             	sub    esp,0x18
 80487af:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 80487b2:	8b 00                	mov    eax,DWORD PTR [eax]
 80487b4:	89 04 24             	mov    DWORD PTR [esp],eax
 80487b7:	e8 c5 ff ff ff       	call   8048781 <fputc@plt+0x251>
 80487bc:	ba cc 9d 04 08       	mov    edx,0x8049dcc
 80487c1:	a1 c4 c0 06 08       	mov    eax,ds:0x806c0c4
 80487c6:	dd 5c 24 08          	fstp   QWORD PTR [esp+0x8]
 80487ca:	89 54 24 04          	mov    DWORD PTR [esp+0x4],edx
 80487ce:	89 04 24             	mov    DWORD PTR [esp],eax
 80487d1:	e8 2a fd ff ff       	call   8048500 <fprintf@plt>
 80487d6:	c9                   	leave  
 80487d7:	c3                   	ret    
 80487d8:	55                   	push   ebp
 80487d9:	89 e5                	mov    ebp,esp
 80487db:	83 ec 28             	sub    esp,0x28
 80487de:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 80487e1:	89 04 24             	mov    DWORD PTR [esp],eax
 80487e4:	e8 0b fe ff ff       	call   80485f4 <fputc@plt+0xc4>
 80487e9:	ba cf 9d 04 08       	mov    edx,0x8049dcf
 80487ee:	a1 c8 c0 06 08       	mov    eax,ds:0x806c0c8
 80487f3:	8d 4d f4             	lea    ecx,[ebp-0xc]
 80487f6:	89 4c 24 08          	mov    DWORD PTR [esp+0x8],ecx
 80487fa:	89 54 24 04          	mov    DWORD PTR [esp+0x4],edx
 80487fe:	89 04 24             	mov    DWORD PTR [esp],eax
 8048801:	e8 9a fc ff ff       	call   80484a0 <__isoc99_fscanf@plt>
 8048806:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 8048809:	89 04 24             	mov    DWORD PTR [esp],eax
 804880c:	e8 87 ff ff ff       	call   8048798 <fputc@plt+0x268>
 8048811:	c9                   	leave  
 8048812:	c3                   	ret    
 8048813:	55                   	push   ebp
 8048814:	89 e5                	mov    ebp,esp
 8048816:	83 ec 0c             	sub    esp,0xc
 8048819:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 804881c:	8b 00                	mov    eax,DWORD PTR [eax]
 804881e:	89 45 f8             	mov    DWORD PTR [ebp-0x8],eax
 8048821:	db 45 f8             	fild   DWORD PTR [ebp-0x8]
 8048824:	d9 5d fc             	fstp   DWORD PTR [ebp-0x4]
 8048827:	d9 45 fc             	fld    DWORD PTR [ebp-0x4]
 804882a:	d9 1c 24             	fstp   DWORD PTR [esp]
 804882d:	e8 66 ff ff ff       	call   8048798 <fputc@plt+0x268>
 8048832:	c9                   	leave  
 8048833:	c3                   	ret    
 8048834:	55                   	push   ebp
 8048835:	89 e5                	mov    ebp,esp
 8048837:	83 ec 0c             	sub    esp,0xc
 804883a:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 804883d:	d9 00                	fld    DWORD PTR [eax]
 804883f:	d9 7d fe             	fnstcw WORD PTR [ebp-0x2]
 8048842:	0f b7 45 fe          	movzx  eax,WORD PTR [ebp-0x2]
 8048846:	b4 0c                	mov    ah,0xc
 8048848:	66 89 45 fc          	mov    WORD PTR [ebp-0x4],ax
 804884c:	d9 6d fc             	fldcw  WORD PTR [ebp-0x4]
 804884f:	db 5d f8             	fistp  DWORD PTR [ebp-0x8]
 8048852:	d9 6d fe             	fldcw  WORD PTR [ebp-0x2]
 8048855:	8b 45 f8             	mov    eax,DWORD PTR [ebp-0x8]
 8048858:	89 04 24             	mov    DWORD PTR [esp],eax
 804885b:	e8 21 ff ff ff       	call   8048781 <fputc@plt+0x251>
 8048860:	d9 7d fe             	fnstcw WORD PTR [ebp-0x2]
 8048863:	0f b7 45 fe          	movzx  eax,WORD PTR [ebp-0x2]
 8048867:	b4 0c                	mov    ah,0xc
 8048869:	66 89 45 fc          	mov    WORD PTR [ebp-0x4],ax
 804886d:	d9 6d fc             	fldcw  WORD PTR [ebp-0x4]
 8048870:	db 5d f8             	fistp  DWORD PTR [ebp-0x8]
 8048873:	d9 6d fe             	fldcw  WORD PTR [ebp-0x2]
 8048876:	8b 45 f8             	mov    eax,DWORD PTR [ebp-0x8]
 8048879:	c9                   	leave  
 804887a:	c3                   	ret    
 804887b:	55                   	push   ebp
 804887c:	89 e5                	mov    ebp,esp
 804887e:	83 ec 14             	sub    esp,0x14
 8048881:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 8048884:	8b 00                	mov    eax,DWORD PTR [eax]
 8048886:	89 04 24             	mov    DWORD PTR [esp],eax
 8048889:	e8 f3 fe ff ff       	call   8048781 <fputc@plt+0x251>
 804888e:	db 7d f0             	fstp   TBYTE PTR [ebp-0x10]
 8048891:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 8048894:	83 c0 04             	add    eax,0x4
 8048897:	8b 00                	mov    eax,DWORD PTR [eax]
 8048899:	89 04 24             	mov    DWORD PTR [esp],eax
 804889c:	e8 e0 fe ff ff       	call   8048781 <fputc@plt+0x251>
 80488a1:	db 6d f0             	fld    TBYTE PTR [ebp-0x10]
 80488a4:	de c1                	faddp  st(1),st
 80488a6:	d9 5d fc             	fstp   DWORD PTR [ebp-0x4]
 80488a9:	d9 45 fc             	fld    DWORD PTR [ebp-0x4]
 80488ac:	d9 1c 24             	fstp   DWORD PTR [esp]
 80488af:	e8 e4 fe ff ff       	call   8048798 <fputc@plt+0x268>
 80488b4:	c9                   	leave  
 80488b5:	c3                   	ret    
 80488b6:	55                   	push   ebp
 80488b7:	89 e5                	mov    ebp,esp
 80488b9:	83 ec 14             	sub    esp,0x14
 80488bc:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 80488bf:	8b 00                	mov    eax,DWORD PTR [eax]
 80488c1:	89 04 24             	mov    DWORD PTR [esp],eax
 80488c4:	e8 b8 fe ff ff       	call   8048781 <fputc@plt+0x251>
 80488c9:	db 7d f0             	fstp   TBYTE PTR [ebp-0x10]
 80488cc:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 80488cf:	83 c0 04             	add    eax,0x4
 80488d2:	8b 00                	mov    eax,DWORD PTR [eax]
 80488d4:	89 04 24             	mov    DWORD PTR [esp],eax
 80488d7:	e8 a5 fe ff ff       	call   8048781 <fputc@plt+0x251>
 80488dc:	db 6d f0             	fld    TBYTE PTR [ebp-0x10]
 80488df:	de e1                	fsubp  st(1),st
 80488e1:	d9 5d fc             	fstp   DWORD PTR [ebp-0x4]
 80488e4:	d9 45 fc             	fld    DWORD PTR [ebp-0x4]
 80488e7:	d9 1c 24             	fstp   DWORD PTR [esp]
 80488ea:	e8 a9 fe ff ff       	call   8048798 <fputc@plt+0x268>
 80488ef:	c9                   	leave  
 80488f0:	c3                   	ret    
 80488f1:	55                   	push   ebp
 80488f2:	89 e5                	mov    ebp,esp
 80488f4:	83 ec 14             	sub    esp,0x14
 80488f7:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 80488fa:	8b 00                	mov    eax,DWORD PTR [eax]
 80488fc:	89 04 24             	mov    DWORD PTR [esp],eax
 80488ff:	e8 7d fe ff ff       	call   8048781 <fputc@plt+0x251>
 8048904:	db 7d f0             	fstp   TBYTE PTR [ebp-0x10]
 8048907:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 804890a:	83 c0 04             	add    eax,0x4
 804890d:	8b 00                	mov    eax,DWORD PTR [eax]
 804890f:	89 04 24             	mov    DWORD PTR [esp],eax
 8048912:	e8 6a fe ff ff       	call   8048781 <fputc@plt+0x251>
 8048917:	db 6d f0             	fld    TBYTE PTR [ebp-0x10]
 804891a:	de c9                	fmulp  st(1),st
 804891c:	d9 5d fc             	fstp   DWORD PTR [ebp-0x4]
 804891f:	d9 45 fc             	fld    DWORD PTR [ebp-0x4]
 8048922:	d9 1c 24             	fstp   DWORD PTR [esp]
 8048925:	e8 6e fe ff ff       	call   8048798 <fputc@plt+0x268>
 804892a:	c9                   	leave  
 804892b:	c3                   	ret    
 804892c:	55                   	push   ebp
 804892d:	89 e5                	mov    ebp,esp
 804892f:	83 ec 14             	sub    esp,0x14
 8048932:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 8048935:	8b 00                	mov    eax,DWORD PTR [eax]
 8048937:	89 04 24             	mov    DWORD PTR [esp],eax
 804893a:	e8 42 fe ff ff       	call   8048781 <fputc@plt+0x251>
 804893f:	db 7d f0             	fstp   TBYTE PTR [ebp-0x10]
 8048942:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 8048945:	83 c0 04             	add    eax,0x4
 8048948:	8b 00                	mov    eax,DWORD PTR [eax]
 804894a:	89 04 24             	mov    DWORD PTR [esp],eax
 804894d:	e8 2f fe ff ff       	call   8048781 <fputc@plt+0x251>
 8048952:	db 6d f0             	fld    TBYTE PTR [ebp-0x10]
 8048955:	de f1                	fdivp  st(1),st
 8048957:	d9 5d fc             	fstp   DWORD PTR [ebp-0x4]
 804895a:	d9 45 fc             	fld    DWORD PTR [ebp-0x4]
 804895d:	d9 1c 24             	fstp   DWORD PTR [esp]
 8048960:	e8 33 fe ff ff       	call   8048798 <fputc@plt+0x268>
 8048965:	c9                   	leave  
 8048966:	c3                   	ret    
 8048967:	55                   	push   ebp
 8048968:	89 e5                	mov    ebp,esp
 804896a:	83 ec 10             	sub    esp,0x10
 804896d:	a1 c0 c0 06 08       	mov    eax,ds:0x806c0c0
 8048972:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
 8048975:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 8048978:	8b 10                	mov    edx,DWORD PTR [eax]
 804897a:	a1 c0 c0 06 08       	mov    eax,ds:0x806c0c0
 804897f:	01 d0                	add    eax,edx
 8048981:	a3 c0 c0 06 08       	mov    ds:0x806c0c0,eax
 8048986:	8b 45 fc             	mov    eax,DWORD PTR [ebp-0x4]
 8048989:	c9                   	leave  
 804898a:	c3                   	ret    
 804898b:	55                   	push   ebp
 804898c:	89 e5                	mov    ebp,esp
 804898e:	81 ec c8 00 00 00    	sub    esp,0xc8
 8048994:	c7 45 cc 00 10 00 00 	mov    DWORD PTR [ebp-0x34],0x1000
 804899b:	83 7d 08 00          	cmp    DWORD PTR [ebp+0x8],0x0
 804899f:	74 2a                	je     80489cb <fputc@plt+0x49b>
 80489a1:	c7 45 d0 00 00 00 00 	mov    DWORD PTR [ebp-0x30],0x0
 80489a8:	eb 19                	jmp    80489c3 <fputc@plt+0x493>
 80489aa:	8b 45 d0             	mov    eax,DWORD PTR [ebp-0x30]
 80489ad:	c1 e0 02             	shl    eax,0x2
 80489b0:	03 45 08             	add    eax,DWORD PTR [ebp+0x8]
 80489b3:	8b 10                	mov    edx,DWORD PTR [eax]
 80489b5:	8b 45 d0             	mov    eax,DWORD PTR [ebp-0x30]
 80489b8:	89 94 85 4c ff ff ff 	mov    DWORD PTR [ebp+eax*4-0xb4],edx
 80489bf:	83 45 d0 01          	add    DWORD PTR [ebp-0x30],0x1
 80489c3:	83 7d d0 1e          	cmp    DWORD PTR [ebp-0x30],0x1e
 80489c7:	7e e1                	jle    80489aa <fputc@plt+0x47a>
 80489c9:	eb 21                	jmp    80489ec <fputc@plt+0x4bc>
 80489cb:	c7 45 d4 00 00 00 00 	mov    DWORD PTR [ebp-0x2c],0x0
 80489d2:	eb 12                	jmp    80489e6 <fputc@plt+0x4b6>
 80489d4:	8b 45 d4             	mov    eax,DWORD PTR [ebp-0x2c]
 80489d7:	c7 84 85 4c ff ff ff 	mov    DWORD PTR [ebp+eax*4-0xb4],0x0
 80489de:	00 00 00 00 
 80489e2:	83 45 d4 01          	add    DWORD PTR [ebp-0x2c],0x1
 80489e6:	83 7d d4 1e          	cmp    DWORD PTR [ebp-0x2c],0x1e
 80489ea:	7e e8                	jle    80489d4 <fputc@plt+0x4a4>
 80489ec:	c7 45 c8 00 f0 00 00 	mov    DWORD PTR [ebp-0x38],0xf000
 80489f3:	c7 45 d8 00 00 00 00 	mov    DWORD PTR [ebp-0x28],0x0
 80489fa:	c7 45 ec 00 00 00 00 	mov    DWORD PTR [ebp-0x14],0x0
 8048a01:	c7 45 f0 00 00 00 00 	mov    DWORD PTR [ebp-0x10],0x0
 8048a08:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [ebp-0xc],0x0
 8048a0f:	c7 45 e8 00 00 00 00 	mov    DWORD PTR [ebp-0x18],0x0
 8048a16:	8b 45 e8             	mov    eax,DWORD PTR [ebp-0x18]
 8048a19:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8048a1c:	8b 45 e4             	mov    eax,DWORD PTR [ebp-0x1c]
 8048a1f:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8048a22:	8b 45 e0             	mov    eax,DWORD PTR [ebp-0x20]
 8048a25:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
 8048a28:	e9 3a 12 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 8048a2d:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048a30:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8048a35:	0f b6 00             	movzx  eax,BYTE PTR [eax]
 8048a38:	0f be c0             	movsx  eax,al
 8048a3b:	83 f8 20             	cmp    eax,0x20
 8048a3e:	0f 87 1e 12 00 00    	ja     8049c62 <fputc@plt+0x1732>
 8048a44:	8b 04 85 d4 9d 04 08 	mov    eax,DWORD PTR [eax*4+0x8049dd4]
 8048a4b:	ff e0                	jmp    eax
 8048a4d:	83 45 cc 01          	add    DWORD PTR [ebp-0x34],0x1
 8048a51:	e9 11 12 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 8048a56:	8b 45 c8             	mov    eax,DWORD PTR [ebp-0x38]
 8048a59:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8048a5e:	8b 00                	mov    eax,DWORD PTR [eax]
 8048a60:	89 45 ec             	mov    DWORD PTR [ebp-0x14],eax
 8048a63:	83 7d ec 00          	cmp    DWORD PTR [ebp-0x14],0x0
 8048a67:	75 0b                	jne    8048a74 <fputc@plt+0x544>
 8048a69:	8b 85 4c ff ff ff    	mov    eax,DWORD PTR [ebp-0xb4]
 8048a6f:	e9 0c 12 00 00       	jmp    8049c80 <fputc@plt+0x1750>
 8048a74:	8b 45 c8             	mov    eax,DWORD PTR [ebp-0x38]
 8048a77:	83 c0 04             	add    eax,0x4
 8048a7a:	89 45 c8             	mov    DWORD PTR [ebp-0x38],eax
 8048a7d:	8b 45 ec             	mov    eax,DWORD PTR [ebp-0x14]
 8048a80:	89 45 cc             	mov    DWORD PTR [ebp-0x34],eax
 8048a83:	c7 45 d8 00 00 00 00 	mov    DWORD PTR [ebp-0x28],0x0
 8048a8a:	e9 d8 11 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 8048a8f:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048a92:	83 c0 01             	add    eax,0x1
 8048a95:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048a9c:	0f be c0             	movsx  eax,al
 8048a9f:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
 8048aa2:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048aa5:	83 c0 02             	add    eax,0x2
 8048aa8:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048aaf:	0f be c0             	movsx  eax,al
 8048ab2:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
 8048ab5:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 8048ab8:	83 f8 01             	cmp    eax,0x1
 8048abb:	74 5e                	je     8048b1b <fputc@plt+0x5eb>
 8048abd:	83 f8 01             	cmp    eax,0x1
 8048ac0:	7f 09                	jg     8048acb <fputc@plt+0x59b>
 8048ac2:	85 c0                	test   eax,eax
 8048ac4:	74 18                	je     8048ade <fputc@plt+0x5ae>
 8048ac6:	e9 d5 00 00 00       	jmp    8048ba0 <fputc@plt+0x670>
 8048acb:	83 f8 02             	cmp    eax,0x2
 8048ace:	74 7b                	je     8048b4b <fputc@plt+0x61b>
 8048ad0:	83 f8 04             	cmp    eax,0x4
 8048ad3:	0f 84 a2 00 00 00    	je     8048b7b <fputc@plt+0x64b>
 8048ad9:	e9 c2 00 00 00       	jmp    8048ba0 <fputc@plt+0x670>
 8048ade:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048ae1:	83 c0 03             	add    eax,0x3
 8048ae4:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048aeb:	0f be c0             	movsx  eax,al
 8048aee:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8048af5:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8048af8:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048afb:	83 c0 04             	add    eax,0x4
 8048afe:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048b05:	0f be c0             	movsx  eax,al
 8048b08:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8048b0f:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8048b12:	83 45 cc 05          	add    DWORD PTR [ebp-0x34],0x5
 8048b16:	e9 85 00 00 00       	jmp    8048ba0 <fputc@plt+0x670>
 8048b1b:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048b1e:	83 c0 03             	add    eax,0x3
 8048b21:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048b28:	0f be c0             	movsx  eax,al
 8048b2b:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8048b32:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8048b35:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048b38:	83 c0 04             	add    eax,0x4
 8048b3b:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8048b40:	8b 00                	mov    eax,DWORD PTR [eax]
 8048b42:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8048b45:	83 45 cc 08          	add    DWORD PTR [ebp-0x34],0x8
 8048b49:	eb 55                	jmp    8048ba0 <fputc@plt+0x670>
 8048b4b:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048b4e:	83 c0 03             	add    eax,0x3
 8048b51:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8048b56:	8b 00                	mov    eax,DWORD PTR [eax]
 8048b58:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8048b5b:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048b5e:	83 c0 07             	add    eax,0x7
 8048b61:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048b68:	0f be c0             	movsx  eax,al
 8048b6b:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8048b72:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8048b75:	83 45 cc 08          	add    DWORD PTR [ebp-0x34],0x8
 8048b79:	eb 25                	jmp    8048ba0 <fputc@plt+0x670>
 8048b7b:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048b7e:	83 c0 03             	add    eax,0x3
 8048b81:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8048b86:	8b 00                	mov    eax,DWORD PTR [eax]
 8048b88:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8048b8b:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048b8e:	83 c0 07             	add    eax,0x7
 8048b91:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8048b96:	8b 00                	mov    eax,DWORD PTR [eax]
 8048b98:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8048b9b:	83 45 cc 0b          	add    DWORD PTR [ebp-0x34],0xb
 8048b9f:	90                   	nop
 8048ba0:	8b 45 e4             	mov    eax,DWORD PTR [ebp-0x1c]
 8048ba3:	8b 55 e0             	mov    edx,DWORD PTR [ebp-0x20]
 8048ba6:	01 c2                	add    edx,eax
 8048ba8:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8048bab:	89 94 85 4c ff ff ff 	mov    DWORD PTR [ebp+eax*4-0xb4],edx
 8048bb2:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8048bb5:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8048bbc:	89 45 d8             	mov    DWORD PTR [ebp-0x28],eax
 8048bbf:	e9 a3 10 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 8048bc4:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048bc7:	83 c0 01             	add    eax,0x1
 8048bca:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048bd1:	0f be c0             	movsx  eax,al
 8048bd4:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
 8048bd7:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048bda:	83 c0 02             	add    eax,0x2
 8048bdd:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048be4:	0f be c0             	movsx  eax,al
 8048be7:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
 8048bea:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 8048bed:	83 f8 01             	cmp    eax,0x1
 8048bf0:	74 5e                	je     8048c50 <fputc@plt+0x720>
 8048bf2:	83 f8 01             	cmp    eax,0x1
 8048bf5:	7f 09                	jg     8048c00 <fputc@plt+0x6d0>
 8048bf7:	85 c0                	test   eax,eax
 8048bf9:	74 18                	je     8048c13 <fputc@plt+0x6e3>
 8048bfb:	e9 d5 00 00 00       	jmp    8048cd5 <fputc@plt+0x7a5>
 8048c00:	83 f8 02             	cmp    eax,0x2
 8048c03:	74 7b                	je     8048c80 <fputc@plt+0x750>
 8048c05:	83 f8 04             	cmp    eax,0x4
 8048c08:	0f 84 a2 00 00 00    	je     8048cb0 <fputc@plt+0x780>
 8048c0e:	e9 c2 00 00 00       	jmp    8048cd5 <fputc@plt+0x7a5>
 8048c13:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048c16:	83 c0 03             	add    eax,0x3
 8048c19:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048c20:	0f be c0             	movsx  eax,al
 8048c23:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8048c2a:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8048c2d:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048c30:	83 c0 04             	add    eax,0x4
 8048c33:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048c3a:	0f be c0             	movsx  eax,al
 8048c3d:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8048c44:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8048c47:	83 45 cc 05          	add    DWORD PTR [ebp-0x34],0x5
 8048c4b:	e9 85 00 00 00       	jmp    8048cd5 <fputc@plt+0x7a5>
 8048c50:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048c53:	83 c0 03             	add    eax,0x3
 8048c56:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048c5d:	0f be c0             	movsx  eax,al
 8048c60:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8048c67:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8048c6a:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048c6d:	83 c0 04             	add    eax,0x4
 8048c70:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8048c75:	8b 00                	mov    eax,DWORD PTR [eax]
 8048c77:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8048c7a:	83 45 cc 08          	add    DWORD PTR [ebp-0x34],0x8
 8048c7e:	eb 55                	jmp    8048cd5 <fputc@plt+0x7a5>
 8048c80:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048c83:	83 c0 03             	add    eax,0x3
 8048c86:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8048c8b:	8b 00                	mov    eax,DWORD PTR [eax]
 8048c8d:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8048c90:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048c93:	83 c0 07             	add    eax,0x7
 8048c96:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048c9d:	0f be c0             	movsx  eax,al
 8048ca0:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8048ca7:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8048caa:	83 45 cc 08          	add    DWORD PTR [ebp-0x34],0x8
 8048cae:	eb 25                	jmp    8048cd5 <fputc@plt+0x7a5>
 8048cb0:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048cb3:	83 c0 03             	add    eax,0x3
 8048cb6:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8048cbb:	8b 00                	mov    eax,DWORD PTR [eax]
 8048cbd:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8048cc0:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048cc3:	83 c0 07             	add    eax,0x7
 8048cc6:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8048ccb:	8b 00                	mov    eax,DWORD PTR [eax]
 8048ccd:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8048cd0:	83 45 cc 0b          	add    DWORD PTR [ebp-0x34],0xb
 8048cd4:	90                   	nop
 8048cd5:	8b 45 e4             	mov    eax,DWORD PTR [ebp-0x1c]
 8048cd8:	8b 55 e0             	mov    edx,DWORD PTR [ebp-0x20]
 8048cdb:	29 c2                	sub    edx,eax
 8048cdd:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8048ce0:	89 94 85 4c ff ff ff 	mov    DWORD PTR [ebp+eax*4-0xb4],edx
 8048ce7:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8048cea:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8048cf1:	89 45 d8             	mov    DWORD PTR [ebp-0x28],eax
 8048cf4:	e9 6e 0f 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 8048cf9:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048cfc:	83 c0 01             	add    eax,0x1
 8048cff:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048d06:	0f be c0             	movsx  eax,al
 8048d09:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
 8048d0c:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048d0f:	83 c0 02             	add    eax,0x2
 8048d12:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048d19:	0f be c0             	movsx  eax,al
 8048d1c:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
 8048d1f:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 8048d22:	83 f8 01             	cmp    eax,0x1
 8048d25:	74 5e                	je     8048d85 <fputc@plt+0x855>
 8048d27:	83 f8 01             	cmp    eax,0x1
 8048d2a:	7f 09                	jg     8048d35 <fputc@plt+0x805>
 8048d2c:	85 c0                	test   eax,eax
 8048d2e:	74 18                	je     8048d48 <fputc@plt+0x818>
 8048d30:	e9 d5 00 00 00       	jmp    8048e0a <fputc@plt+0x8da>
 8048d35:	83 f8 02             	cmp    eax,0x2
 8048d38:	74 7b                	je     8048db5 <fputc@plt+0x885>
 8048d3a:	83 f8 04             	cmp    eax,0x4
 8048d3d:	0f 84 a2 00 00 00    	je     8048de5 <fputc@plt+0x8b5>
 8048d43:	e9 c2 00 00 00       	jmp    8048e0a <fputc@plt+0x8da>
 8048d48:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048d4b:	83 c0 03             	add    eax,0x3
 8048d4e:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048d55:	0f be c0             	movsx  eax,al
 8048d58:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8048d5f:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8048d62:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048d65:	83 c0 04             	add    eax,0x4
 8048d68:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048d6f:	0f be c0             	movsx  eax,al
 8048d72:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8048d79:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8048d7c:	83 45 cc 05          	add    DWORD PTR [ebp-0x34],0x5
 8048d80:	e9 85 00 00 00       	jmp    8048e0a <fputc@plt+0x8da>
 8048d85:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048d88:	83 c0 03             	add    eax,0x3
 8048d8b:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048d92:	0f be c0             	movsx  eax,al
 8048d95:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8048d9c:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8048d9f:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048da2:	83 c0 04             	add    eax,0x4
 8048da5:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8048daa:	8b 00                	mov    eax,DWORD PTR [eax]
 8048dac:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8048daf:	83 45 cc 08          	add    DWORD PTR [ebp-0x34],0x8
 8048db3:	eb 55                	jmp    8048e0a <fputc@plt+0x8da>
 8048db5:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048db8:	83 c0 03             	add    eax,0x3
 8048dbb:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8048dc0:	8b 00                	mov    eax,DWORD PTR [eax]
 8048dc2:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8048dc5:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048dc8:	83 c0 07             	add    eax,0x7
 8048dcb:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048dd2:	0f be c0             	movsx  eax,al
 8048dd5:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8048ddc:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8048ddf:	83 45 cc 08          	add    DWORD PTR [ebp-0x34],0x8
 8048de3:	eb 25                	jmp    8048e0a <fputc@plt+0x8da>
 8048de5:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048de8:	83 c0 03             	add    eax,0x3
 8048deb:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8048df0:	8b 00                	mov    eax,DWORD PTR [eax]
 8048df2:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8048df5:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048df8:	83 c0 07             	add    eax,0x7
 8048dfb:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8048e00:	8b 00                	mov    eax,DWORD PTR [eax]
 8048e02:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8048e05:	83 45 cc 0b          	add    DWORD PTR [ebp-0x34],0xb
 8048e09:	90                   	nop
 8048e0a:	8b 45 e0             	mov    eax,DWORD PTR [ebp-0x20]
 8048e0d:	89 c2                	mov    edx,eax
 8048e0f:	0f af 55 e4          	imul   edx,DWORD PTR [ebp-0x1c]
 8048e13:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8048e16:	89 94 85 4c ff ff ff 	mov    DWORD PTR [ebp+eax*4-0xb4],edx
 8048e1d:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8048e20:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8048e27:	89 45 d8             	mov    DWORD PTR [ebp-0x28],eax
 8048e2a:	e9 38 0e 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 8048e2f:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048e32:	83 c0 01             	add    eax,0x1
 8048e35:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048e3c:	0f be c0             	movsx  eax,al
 8048e3f:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
 8048e42:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048e45:	83 c0 02             	add    eax,0x2
 8048e48:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048e4f:	0f be c0             	movsx  eax,al
 8048e52:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
 8048e55:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048e58:	83 c0 03             	add    eax,0x3
 8048e5b:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048e62:	0f be c0             	movsx  eax,al
 8048e65:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8048e68:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 8048e6b:	83 f8 01             	cmp    eax,0x1
 8048e6e:	74 5e                	je     8048ece <fputc@plt+0x99e>
 8048e70:	83 f8 01             	cmp    eax,0x1
 8048e73:	7f 09                	jg     8048e7e <fputc@plt+0x94e>
 8048e75:	85 c0                	test   eax,eax
 8048e77:	74 18                	je     8048e91 <fputc@plt+0x961>
 8048e79:	e9 d5 00 00 00       	jmp    8048f53 <fputc@plt+0xa23>
 8048e7e:	83 f8 02             	cmp    eax,0x2
 8048e81:	74 7b                	je     8048efe <fputc@plt+0x9ce>
 8048e83:	83 f8 04             	cmp    eax,0x4
 8048e86:	0f 84 a2 00 00 00    	je     8048f2e <fputc@plt+0x9fe>
 8048e8c:	e9 c2 00 00 00       	jmp    8048f53 <fputc@plt+0xa23>
 8048e91:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048e94:	83 c0 04             	add    eax,0x4
 8048e97:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048e9e:	0f be c0             	movsx  eax,al
 8048ea1:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8048ea8:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8048eab:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048eae:	83 c0 05             	add    eax,0x5
 8048eb1:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048eb8:	0f be c0             	movsx  eax,al
 8048ebb:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8048ec2:	89 45 e8             	mov    DWORD PTR [ebp-0x18],eax
 8048ec5:	83 45 cc 05          	add    DWORD PTR [ebp-0x34],0x5
 8048ec9:	e9 85 00 00 00       	jmp    8048f53 <fputc@plt+0xa23>
 8048ece:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048ed1:	83 c0 04             	add    eax,0x4
 8048ed4:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048edb:	0f be c0             	movsx  eax,al
 8048ede:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8048ee5:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8048ee8:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048eeb:	83 c0 05             	add    eax,0x5
 8048eee:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8048ef3:	8b 00                	mov    eax,DWORD PTR [eax]
 8048ef5:	89 45 e8             	mov    DWORD PTR [ebp-0x18],eax
 8048ef8:	83 45 cc 08          	add    DWORD PTR [ebp-0x34],0x8
 8048efc:	eb 55                	jmp    8048f53 <fputc@plt+0xa23>
 8048efe:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048f01:	83 c0 04             	add    eax,0x4
 8048f04:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8048f09:	8b 00                	mov    eax,DWORD PTR [eax]
 8048f0b:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8048f0e:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048f11:	83 c0 08             	add    eax,0x8
 8048f14:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048f1b:	0f be c0             	movsx  eax,al
 8048f1e:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8048f25:	89 45 e8             	mov    DWORD PTR [ebp-0x18],eax
 8048f28:	83 45 cc 08          	add    DWORD PTR [ebp-0x34],0x8
 8048f2c:	eb 25                	jmp    8048f53 <fputc@plt+0xa23>
 8048f2e:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048f31:	83 c0 04             	add    eax,0x4
 8048f34:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8048f39:	8b 00                	mov    eax,DWORD PTR [eax]
 8048f3b:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8048f3e:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048f41:	83 c0 08             	add    eax,0x8
 8048f44:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8048f49:	8b 00                	mov    eax,DWORD PTR [eax]
 8048f4b:	89 45 e8             	mov    DWORD PTR [ebp-0x18],eax
 8048f4e:	83 45 cc 0b          	add    DWORD PTR [ebp-0x34],0xb
 8048f52:	90                   	nop
 8048f53:	8b 45 e4             	mov    eax,DWORD PTR [ebp-0x1c]
 8048f56:	89 c2                	mov    edx,eax
 8048f58:	c1 fa 1f             	sar    edx,0x1f
 8048f5b:	f7 7d e8             	idiv   DWORD PTR [ebp-0x18]
 8048f5e:	89 c2                	mov    edx,eax
 8048f60:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8048f63:	89 94 85 4c ff ff ff 	mov    DWORD PTR [ebp+eax*4-0xb4],edx
 8048f6a:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8048f6d:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8048f74:	89 45 d8             	mov    DWORD PTR [ebp-0x28],eax
 8048f77:	8b 45 e4             	mov    eax,DWORD PTR [ebp-0x1c]
 8048f7a:	89 c2                	mov    edx,eax
 8048f7c:	c1 fa 1f             	sar    edx,0x1f
 8048f7f:	f7 7d e8             	idiv   DWORD PTR [ebp-0x18]
 8048f82:	8b 45 e0             	mov    eax,DWORD PTR [ebp-0x20]
 8048f85:	89 94 85 4c ff ff ff 	mov    DWORD PTR [ebp+eax*4-0xb4],edx
 8048f8c:	e9 d6 0c 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 8048f91:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048f94:	83 c0 01             	add    eax,0x1
 8048f97:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048f9e:	0f be c0             	movsx  eax,al
 8048fa1:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
 8048fa4:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048fa7:	83 c0 02             	add    eax,0x2
 8048faa:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048fb1:	0f be c0             	movsx  eax,al
 8048fb4:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
 8048fb7:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 8048fba:	83 f8 01             	cmp    eax,0x1
 8048fbd:	74 5e                	je     804901d <fputc@plt+0xaed>
 8048fbf:	83 f8 01             	cmp    eax,0x1
 8048fc2:	7f 09                	jg     8048fcd <fputc@plt+0xa9d>
 8048fc4:	85 c0                	test   eax,eax
 8048fc6:	74 18                	je     8048fe0 <fputc@plt+0xab0>
 8048fc8:	e9 d5 00 00 00       	jmp    80490a2 <fputc@plt+0xb72>
 8048fcd:	83 f8 02             	cmp    eax,0x2
 8048fd0:	74 7b                	je     804904d <fputc@plt+0xb1d>
 8048fd2:	83 f8 04             	cmp    eax,0x4
 8048fd5:	0f 84 a2 00 00 00    	je     804907d <fputc@plt+0xb4d>
 8048fdb:	e9 c2 00 00 00       	jmp    80490a2 <fputc@plt+0xb72>
 8048fe0:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048fe3:	83 c0 03             	add    eax,0x3
 8048fe6:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8048fed:	0f be c0             	movsx  eax,al
 8048ff0:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8048ff7:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8048ffa:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8048ffd:	83 c0 04             	add    eax,0x4
 8049000:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049007:	0f be c0             	movsx  eax,al
 804900a:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8049011:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8049014:	83 45 cc 05          	add    DWORD PTR [ebp-0x34],0x5
 8049018:	e9 85 00 00 00       	jmp    80490a2 <fputc@plt+0xb72>
 804901d:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049020:	83 c0 03             	add    eax,0x3
 8049023:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 804902a:	0f be c0             	movsx  eax,al
 804902d:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8049034:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8049037:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 804903a:	83 c0 04             	add    eax,0x4
 804903d:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8049042:	8b 00                	mov    eax,DWORD PTR [eax]
 8049044:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8049047:	83 45 cc 08          	add    DWORD PTR [ebp-0x34],0x8
 804904b:	eb 55                	jmp    80490a2 <fputc@plt+0xb72>
 804904d:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049050:	83 c0 03             	add    eax,0x3
 8049053:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8049058:	8b 00                	mov    eax,DWORD PTR [eax]
 804905a:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 804905d:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049060:	83 c0 07             	add    eax,0x7
 8049063:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 804906a:	0f be c0             	movsx  eax,al
 804906d:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8049074:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8049077:	83 45 cc 08          	add    DWORD PTR [ebp-0x34],0x8
 804907b:	eb 25                	jmp    80490a2 <fputc@plt+0xb72>
 804907d:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049080:	83 c0 03             	add    eax,0x3
 8049083:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8049088:	8b 00                	mov    eax,DWORD PTR [eax]
 804908a:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 804908d:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049090:	83 c0 07             	add    eax,0x7
 8049093:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8049098:	8b 00                	mov    eax,DWORD PTR [eax]
 804909a:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 804909d:	83 45 cc 0b          	add    DWORD PTR [ebp-0x34],0xb
 80490a1:	90                   	nop
 80490a2:	8b 45 e4             	mov    eax,DWORD PTR [ebp-0x1c]
 80490a5:	8b 55 e0             	mov    edx,DWORD PTR [ebp-0x20]
 80490a8:	31 c2                	xor    edx,eax
 80490aa:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 80490ad:	89 94 85 4c ff ff ff 	mov    DWORD PTR [ebp+eax*4-0xb4],edx
 80490b4:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 80490b7:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 80490be:	89 45 d8             	mov    DWORD PTR [ebp-0x28],eax
 80490c1:	e9 a1 0b 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 80490c6:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80490c9:	83 c0 01             	add    eax,0x1
 80490cc:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 80490d3:	0f be c0             	movsx  eax,al
 80490d6:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
 80490d9:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80490dc:	83 c0 02             	add    eax,0x2
 80490df:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 80490e6:	0f be c0             	movsx  eax,al
 80490e9:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
 80490ec:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 80490ef:	83 f8 01             	cmp    eax,0x1
 80490f2:	74 5e                	je     8049152 <fputc@plt+0xc22>
 80490f4:	83 f8 01             	cmp    eax,0x1
 80490f7:	7f 09                	jg     8049102 <fputc@plt+0xbd2>
 80490f9:	85 c0                	test   eax,eax
 80490fb:	74 18                	je     8049115 <fputc@plt+0xbe5>
 80490fd:	e9 d5 00 00 00       	jmp    80491d7 <fputc@plt+0xca7>
 8049102:	83 f8 02             	cmp    eax,0x2
 8049105:	74 7b                	je     8049182 <fputc@plt+0xc52>
 8049107:	83 f8 04             	cmp    eax,0x4
 804910a:	0f 84 a2 00 00 00    	je     80491b2 <fputc@plt+0xc82>
 8049110:	e9 c2 00 00 00       	jmp    80491d7 <fputc@plt+0xca7>
 8049115:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049118:	83 c0 03             	add    eax,0x3
 804911b:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049122:	0f be c0             	movsx  eax,al
 8049125:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 804912c:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 804912f:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049132:	83 c0 04             	add    eax,0x4
 8049135:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 804913c:	0f be c0             	movsx  eax,al
 804913f:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8049146:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8049149:	83 45 cc 05          	add    DWORD PTR [ebp-0x34],0x5
 804914d:	e9 85 00 00 00       	jmp    80491d7 <fputc@plt+0xca7>
 8049152:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049155:	83 c0 03             	add    eax,0x3
 8049158:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 804915f:	0f be c0             	movsx  eax,al
 8049162:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8049169:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 804916c:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 804916f:	83 c0 04             	add    eax,0x4
 8049172:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8049177:	8b 00                	mov    eax,DWORD PTR [eax]
 8049179:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 804917c:	83 45 cc 08          	add    DWORD PTR [ebp-0x34],0x8
 8049180:	eb 55                	jmp    80491d7 <fputc@plt+0xca7>
 8049182:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049185:	83 c0 03             	add    eax,0x3
 8049188:	05 c0 c0 04 08       	add    eax,0x804c0c0
 804918d:	8b 00                	mov    eax,DWORD PTR [eax]
 804918f:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8049192:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049195:	83 c0 07             	add    eax,0x7
 8049198:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 804919f:	0f be c0             	movsx  eax,al
 80491a2:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 80491a9:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 80491ac:	83 45 cc 08          	add    DWORD PTR [ebp-0x34],0x8
 80491b0:	eb 25                	jmp    80491d7 <fputc@plt+0xca7>
 80491b2:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80491b5:	83 c0 03             	add    eax,0x3
 80491b8:	05 c0 c0 04 08       	add    eax,0x804c0c0
 80491bd:	8b 00                	mov    eax,DWORD PTR [eax]
 80491bf:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 80491c2:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80491c5:	83 c0 07             	add    eax,0x7
 80491c8:	05 c0 c0 04 08       	add    eax,0x804c0c0
 80491cd:	8b 00                	mov    eax,DWORD PTR [eax]
 80491cf:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 80491d2:	83 45 cc 0b          	add    DWORD PTR [ebp-0x34],0xb
 80491d6:	90                   	nop
 80491d7:	8b 45 e4             	mov    eax,DWORD PTR [ebp-0x1c]
 80491da:	8b 55 e0             	mov    edx,DWORD PTR [ebp-0x20]
 80491dd:	21 c2                	and    edx,eax
 80491df:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 80491e2:	89 94 85 4c ff ff ff 	mov    DWORD PTR [ebp+eax*4-0xb4],edx
 80491e9:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 80491ec:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 80491f3:	89 45 d8             	mov    DWORD PTR [ebp-0x28],eax
 80491f6:	e9 6c 0a 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 80491fb:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80491fe:	83 c0 01             	add    eax,0x1
 8049201:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049208:	0f be c0             	movsx  eax,al
 804920b:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
 804920e:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049211:	83 c0 02             	add    eax,0x2
 8049214:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 804921b:	0f be c0             	movsx  eax,al
 804921e:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
 8049221:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 8049224:	83 f8 01             	cmp    eax,0x1
 8049227:	74 5e                	je     8049287 <fputc@plt+0xd57>
 8049229:	83 f8 01             	cmp    eax,0x1
 804922c:	7f 09                	jg     8049237 <fputc@plt+0xd07>
 804922e:	85 c0                	test   eax,eax
 8049230:	74 18                	je     804924a <fputc@plt+0xd1a>
 8049232:	e9 d5 00 00 00       	jmp    804930c <fputc@plt+0xddc>
 8049237:	83 f8 02             	cmp    eax,0x2
 804923a:	74 7b                	je     80492b7 <fputc@plt+0xd87>
 804923c:	83 f8 04             	cmp    eax,0x4
 804923f:	0f 84 a2 00 00 00    	je     80492e7 <fputc@plt+0xdb7>
 8049245:	e9 c2 00 00 00       	jmp    804930c <fputc@plt+0xddc>
 804924a:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 804924d:	83 c0 03             	add    eax,0x3
 8049250:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049257:	0f be c0             	movsx  eax,al
 804925a:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8049261:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8049264:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049267:	83 c0 04             	add    eax,0x4
 804926a:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049271:	0f be c0             	movsx  eax,al
 8049274:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 804927b:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 804927e:	83 45 cc 05          	add    DWORD PTR [ebp-0x34],0x5
 8049282:	e9 85 00 00 00       	jmp    804930c <fputc@plt+0xddc>
 8049287:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 804928a:	83 c0 03             	add    eax,0x3
 804928d:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049294:	0f be c0             	movsx  eax,al
 8049297:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 804929e:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 80492a1:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80492a4:	83 c0 04             	add    eax,0x4
 80492a7:	05 c0 c0 04 08       	add    eax,0x804c0c0
 80492ac:	8b 00                	mov    eax,DWORD PTR [eax]
 80492ae:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 80492b1:	83 45 cc 08          	add    DWORD PTR [ebp-0x34],0x8
 80492b5:	eb 55                	jmp    804930c <fputc@plt+0xddc>
 80492b7:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80492ba:	83 c0 03             	add    eax,0x3
 80492bd:	05 c0 c0 04 08       	add    eax,0x804c0c0
 80492c2:	8b 00                	mov    eax,DWORD PTR [eax]
 80492c4:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 80492c7:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80492ca:	83 c0 07             	add    eax,0x7
 80492cd:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 80492d4:	0f be c0             	movsx  eax,al
 80492d7:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 80492de:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 80492e1:	83 45 cc 08          	add    DWORD PTR [ebp-0x34],0x8
 80492e5:	eb 25                	jmp    804930c <fputc@plt+0xddc>
 80492e7:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80492ea:	83 c0 03             	add    eax,0x3
 80492ed:	05 c0 c0 04 08       	add    eax,0x804c0c0
 80492f2:	8b 00                	mov    eax,DWORD PTR [eax]
 80492f4:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 80492f7:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80492fa:	83 c0 07             	add    eax,0x7
 80492fd:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8049302:	8b 00                	mov    eax,DWORD PTR [eax]
 8049304:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8049307:	83 45 cc 0b          	add    DWORD PTR [ebp-0x34],0xb
 804930b:	90                   	nop
 804930c:	8b 45 e4             	mov    eax,DWORD PTR [ebp-0x1c]
 804930f:	8b 55 e0             	mov    edx,DWORD PTR [ebp-0x20]
 8049312:	09 c2                	or     edx,eax
 8049314:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8049317:	89 94 85 4c ff ff ff 	mov    DWORD PTR [ebp+eax*4-0xb4],edx
 804931e:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8049321:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8049328:	89 45 d8             	mov    DWORD PTR [ebp-0x28],eax
 804932b:	e9 37 09 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 8049330:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049333:	83 c0 01             	add    eax,0x1
 8049336:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 804933d:	0f be c0             	movsx  eax,al
 8049340:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
 8049343:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049346:	83 c0 02             	add    eax,0x2
 8049349:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049350:	0f be c0             	movsx  eax,al
 8049353:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
 8049356:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 8049359:	83 f8 01             	cmp    eax,0x1
 804935c:	74 5e                	je     80493bc <fputc@plt+0xe8c>
 804935e:	83 f8 01             	cmp    eax,0x1
 8049361:	7f 09                	jg     804936c <fputc@plt+0xe3c>
 8049363:	85 c0                	test   eax,eax
 8049365:	74 18                	je     804937f <fputc@plt+0xe4f>
 8049367:	e9 d5 00 00 00       	jmp    8049441 <fputc@plt+0xf11>
 804936c:	83 f8 02             	cmp    eax,0x2
 804936f:	74 7b                	je     80493ec <fputc@plt+0xebc>
 8049371:	83 f8 04             	cmp    eax,0x4
 8049374:	0f 84 a2 00 00 00    	je     804941c <fputc@plt+0xeec>
 804937a:	e9 c2 00 00 00       	jmp    8049441 <fputc@plt+0xf11>
 804937f:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049382:	83 c0 03             	add    eax,0x3
 8049385:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 804938c:	0f be c0             	movsx  eax,al
 804938f:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8049396:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8049399:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 804939c:	83 c0 04             	add    eax,0x4
 804939f:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 80493a6:	0f be c0             	movsx  eax,al
 80493a9:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 80493b0:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 80493b3:	83 45 cc 05          	add    DWORD PTR [ebp-0x34],0x5
 80493b7:	e9 85 00 00 00       	jmp    8049441 <fputc@plt+0xf11>
 80493bc:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80493bf:	83 c0 03             	add    eax,0x3
 80493c2:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 80493c9:	0f be c0             	movsx  eax,al
 80493cc:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 80493d3:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 80493d6:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80493d9:	83 c0 04             	add    eax,0x4
 80493dc:	05 c0 c0 04 08       	add    eax,0x804c0c0
 80493e1:	8b 00                	mov    eax,DWORD PTR [eax]
 80493e3:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 80493e6:	83 45 cc 08          	add    DWORD PTR [ebp-0x34],0x8
 80493ea:	eb 55                	jmp    8049441 <fputc@plt+0xf11>
 80493ec:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80493ef:	83 c0 03             	add    eax,0x3
 80493f2:	05 c0 c0 04 08       	add    eax,0x804c0c0
 80493f7:	8b 00                	mov    eax,DWORD PTR [eax]
 80493f9:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 80493fc:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80493ff:	83 c0 07             	add    eax,0x7
 8049402:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049409:	0f be c0             	movsx  eax,al
 804940c:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8049413:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8049416:	83 45 cc 08          	add    DWORD PTR [ebp-0x34],0x8
 804941a:	eb 25                	jmp    8049441 <fputc@plt+0xf11>
 804941c:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 804941f:	83 c0 03             	add    eax,0x3
 8049422:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8049427:	8b 00                	mov    eax,DWORD PTR [eax]
 8049429:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 804942c:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 804942f:	83 c0 07             	add    eax,0x7
 8049432:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8049437:	8b 00                	mov    eax,DWORD PTR [eax]
 8049439:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 804943c:	83 45 cc 0b          	add    DWORD PTR [ebp-0x34],0xb
 8049440:	90                   	nop
 8049441:	8b 45 e4             	mov    eax,DWORD PTR [ebp-0x1c]
 8049444:	8b 55 e0             	mov    edx,DWORD PTR [ebp-0x20]
 8049447:	89 c1                	mov    ecx,eax
 8049449:	d3 e2                	shl    edx,cl
 804944b:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 804944e:	89 94 85 4c ff ff ff 	mov    DWORD PTR [ebp+eax*4-0xb4],edx
 8049455:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8049458:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 804945f:	89 45 d8             	mov    DWORD PTR [ebp-0x28],eax
 8049462:	e9 00 08 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 8049467:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 804946a:	83 c0 01             	add    eax,0x1
 804946d:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049474:	0f be c0             	movsx  eax,al
 8049477:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
 804947a:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 804947d:	83 c0 02             	add    eax,0x2
 8049480:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049487:	0f be c0             	movsx  eax,al
 804948a:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
 804948d:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 8049490:	83 f8 01             	cmp    eax,0x1
 8049493:	74 5e                	je     80494f3 <fputc@plt+0xfc3>
 8049495:	83 f8 01             	cmp    eax,0x1
 8049498:	7f 09                	jg     80494a3 <fputc@plt+0xf73>
 804949a:	85 c0                	test   eax,eax
 804949c:	74 18                	je     80494b6 <fputc@plt+0xf86>
 804949e:	e9 d5 00 00 00       	jmp    8049578 <fputc@plt+0x1048>
 80494a3:	83 f8 02             	cmp    eax,0x2
 80494a6:	74 7b                	je     8049523 <fputc@plt+0xff3>
 80494a8:	83 f8 04             	cmp    eax,0x4
 80494ab:	0f 84 a2 00 00 00    	je     8049553 <fputc@plt+0x1023>
 80494b1:	e9 c2 00 00 00       	jmp    8049578 <fputc@plt+0x1048>
 80494b6:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80494b9:	83 c0 03             	add    eax,0x3
 80494bc:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 80494c3:	0f be c0             	movsx  eax,al
 80494c6:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 80494cd:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 80494d0:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80494d3:	83 c0 04             	add    eax,0x4
 80494d6:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 80494dd:	0f be c0             	movsx  eax,al
 80494e0:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 80494e7:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 80494ea:	83 45 cc 05          	add    DWORD PTR [ebp-0x34],0x5
 80494ee:	e9 85 00 00 00       	jmp    8049578 <fputc@plt+0x1048>
 80494f3:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80494f6:	83 c0 03             	add    eax,0x3
 80494f9:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049500:	0f be c0             	movsx  eax,al
 8049503:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 804950a:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 804950d:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049510:	83 c0 04             	add    eax,0x4
 8049513:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8049518:	8b 00                	mov    eax,DWORD PTR [eax]
 804951a:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 804951d:	83 45 cc 08          	add    DWORD PTR [ebp-0x34],0x8
 8049521:	eb 55                	jmp    8049578 <fputc@plt+0x1048>
 8049523:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049526:	83 c0 03             	add    eax,0x3
 8049529:	05 c0 c0 04 08       	add    eax,0x804c0c0
 804952e:	8b 00                	mov    eax,DWORD PTR [eax]
 8049530:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8049533:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049536:	83 c0 07             	add    eax,0x7
 8049539:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049540:	0f be c0             	movsx  eax,al
 8049543:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 804954a:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 804954d:	83 45 cc 08          	add    DWORD PTR [ebp-0x34],0x8
 8049551:	eb 25                	jmp    8049578 <fputc@plt+0x1048>
 8049553:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049556:	83 c0 03             	add    eax,0x3
 8049559:	05 c0 c0 04 08       	add    eax,0x804c0c0
 804955e:	8b 00                	mov    eax,DWORD PTR [eax]
 8049560:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8049563:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049566:	83 c0 07             	add    eax,0x7
 8049569:	05 c0 c0 04 08       	add    eax,0x804c0c0
 804956e:	8b 00                	mov    eax,DWORD PTR [eax]
 8049570:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8049573:	83 45 cc 0b          	add    DWORD PTR [ebp-0x34],0xb
 8049577:	90                   	nop
 8049578:	8b 45 e4             	mov    eax,DWORD PTR [ebp-0x1c]
 804957b:	8b 55 e0             	mov    edx,DWORD PTR [ebp-0x20]
 804957e:	89 c1                	mov    ecx,eax
 8049580:	d3 fa                	sar    edx,cl
 8049582:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8049585:	89 94 85 4c ff ff ff 	mov    DWORD PTR [ebp+eax*4-0xb4],edx
 804958c:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 804958f:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8049596:	89 45 d8             	mov    DWORD PTR [ebp-0x28],eax
 8049599:	e9 c9 06 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 804959e:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80495a1:	83 c0 01             	add    eax,0x1
 80495a4:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 80495ab:	0f be c0             	movsx  eax,al
 80495ae:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
 80495b1:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80495b4:	83 c0 02             	add    eax,0x2
 80495b7:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 80495be:	0f be c0             	movsx  eax,al
 80495c1:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 80495c8:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 80495cb:	83 45 cc 03          	add    DWORD PTR [ebp-0x34],0x3
 80495cf:	83 7d e0 00          	cmp    DWORD PTR [ebp-0x20],0x0
 80495d3:	0f 94 c0             	sete   al
 80495d6:	0f b6 d0             	movzx  edx,al
 80495d9:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 80495dc:	89 94 85 4c ff ff ff 	mov    DWORD PTR [ebp+eax*4-0xb4],edx
 80495e3:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 80495e6:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 80495ed:	89 45 d8             	mov    DWORD PTR [ebp-0x28],eax
 80495f0:	e9 72 06 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 80495f5:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80495f8:	83 c0 01             	add    eax,0x1
 80495fb:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049602:	0f be c0             	movsx  eax,al
 8049605:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
 8049608:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 804960b:	83 c0 02             	add    eax,0x2
 804960e:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049615:	0f be c0             	movsx  eax,al
 8049618:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 804961f:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8049622:	83 45 cc 03          	add    DWORD PTR [ebp-0x34],0x3
 8049626:	8b 45 e0             	mov    eax,DWORD PTR [ebp-0x20]
 8049629:	89 c2                	mov    edx,eax
 804962b:	f7 da                	neg    edx
 804962d:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8049630:	89 94 85 4c ff ff ff 	mov    DWORD PTR [ebp+eax*4-0xb4],edx
 8049637:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 804963a:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8049641:	89 45 d8             	mov    DWORD PTR [ebp-0x28],eax
 8049644:	e9 1e 06 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 8049649:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 804964c:	83 c0 01             	add    eax,0x1
 804964f:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049656:	0f be c0             	movsx  eax,al
 8049659:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
 804965c:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 804965f:	83 c0 02             	add    eax,0x2
 8049662:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049669:	0f be c0             	movsx  eax,al
 804966c:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8049673:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8049676:	83 45 cc 03          	add    DWORD PTR [ebp-0x34],0x3
 804967a:	8b 45 e0             	mov    eax,DWORD PTR [ebp-0x20]
 804967d:	89 c2                	mov    edx,eax
 804967f:	f7 d2                	not    edx
 8049681:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8049684:	89 94 85 4c ff ff ff 	mov    DWORD PTR [ebp+eax*4-0xb4],edx
 804968b:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 804968e:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8049695:	89 45 d8             	mov    DWORD PTR [ebp-0x28],eax
 8049698:	e9 ca 05 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 804969d:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80496a0:	83 c0 01             	add    eax,0x1
 80496a3:	05 c0 c0 04 08       	add    eax,0x804c0c0
 80496a8:	8b 00                	mov    eax,DWORD PTR [eax]
 80496aa:	89 45 f0             	mov    DWORD PTR [ebp-0x10],eax
 80496ad:	8b 45 c8             	mov    eax,DWORD PTR [ebp-0x38]
 80496b0:	83 e8 04             	sub    eax,0x4
 80496b3:	89 45 c8             	mov    DWORD PTR [ebp-0x38],eax
 80496b6:	8b 45 c8             	mov    eax,DWORD PTR [ebp-0x38]
 80496b9:	05 c0 c0 04 08       	add    eax,0x804c0c0
 80496be:	8b 55 cc             	mov    edx,DWORD PTR [ebp-0x34]
 80496c1:	83 c2 05             	add    edx,0x5
 80496c4:	89 10                	mov    DWORD PTR [eax],edx
 80496c6:	8b 45 f0             	mov    eax,DWORD PTR [ebp-0x10]
 80496c9:	89 45 cc             	mov    DWORD PTR [ebp-0x34],eax
 80496cc:	e9 96 05 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 80496d1:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80496d4:	83 c0 01             	add    eax,0x1
 80496d7:	05 c0 c0 04 08       	add    eax,0x804c0c0
 80496dc:	8b 00                	mov    eax,DWORD PTR [eax]
 80496de:	89 45 f0             	mov    DWORD PTR [ebp-0x10],eax
 80496e1:	8b 45 f0             	mov    eax,DWORD PTR [ebp-0x10]
 80496e4:	89 45 cc             	mov    DWORD PTR [ebp-0x34],eax
 80496e7:	e9 7b 05 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 80496ec:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80496ef:	83 c0 01             	add    eax,0x1
 80496f2:	05 c0 c0 04 08       	add    eax,0x804c0c0
 80496f7:	8b 00                	mov    eax,DWORD PTR [eax]
 80496f9:	89 45 f0             	mov    DWORD PTR [ebp-0x10],eax
 80496fc:	83 7d d8 00          	cmp    DWORD PTR [ebp-0x28],0x0
 8049700:	74 08                	je     804970a <fputc@plt+0x11da>
 8049702:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049705:	83 c0 05             	add    eax,0x5
 8049708:	eb 03                	jmp    804970d <fputc@plt+0x11dd>
 804970a:	8b 45 f0             	mov    eax,DWORD PTR [ebp-0x10]
 804970d:	89 45 cc             	mov    DWORD PTR [ebp-0x34],eax
 8049710:	e9 52 05 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 8049715:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049718:	83 c0 01             	add    eax,0x1
 804971b:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8049720:	8b 00                	mov    eax,DWORD PTR [eax]
 8049722:	89 45 f0             	mov    DWORD PTR [ebp-0x10],eax
 8049725:	83 7d d8 00          	cmp    DWORD PTR [ebp-0x28],0x0
 8049729:	78 08                	js     8049733 <fputc@plt+0x1203>
 804972b:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 804972e:	83 c0 05             	add    eax,0x5
 8049731:	eb 03                	jmp    8049736 <fputc@plt+0x1206>
 8049733:	8b 45 f0             	mov    eax,DWORD PTR [ebp-0x10]
 8049736:	89 45 cc             	mov    DWORD PTR [ebp-0x34],eax
 8049739:	e9 29 05 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 804973e:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049741:	83 c0 01             	add    eax,0x1
 8049744:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8049749:	8b 00                	mov    eax,DWORD PTR [eax]
 804974b:	89 45 f0             	mov    DWORD PTR [ebp-0x10],eax
 804974e:	83 7d d8 00          	cmp    DWORD PTR [ebp-0x28],0x0
 8049752:	7e 08                	jle    804975c <fputc@plt+0x122c>
 8049754:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049757:	83 c0 05             	add    eax,0x5
 804975a:	eb 03                	jmp    804975f <fputc@plt+0x122f>
 804975c:	8b 45 f0             	mov    eax,DWORD PTR [ebp-0x10]
 804975f:	89 45 cc             	mov    DWORD PTR [ebp-0x34],eax
 8049762:	e9 00 05 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 8049767:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 804976a:	83 c0 01             	add    eax,0x1
 804976d:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8049772:	8b 00                	mov    eax,DWORD PTR [eax]
 8049774:	89 45 f0             	mov    DWORD PTR [ebp-0x10],eax
 8049777:	83 7d d8 00          	cmp    DWORD PTR [ebp-0x28],0x0
 804977b:	7f 08                	jg     8049785 <fputc@plt+0x1255>
 804977d:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049780:	83 c0 05             	add    eax,0x5
 8049783:	eb 03                	jmp    8049788 <fputc@plt+0x1258>
 8049785:	8b 45 f0             	mov    eax,DWORD PTR [ebp-0x10]
 8049788:	89 45 cc             	mov    DWORD PTR [ebp-0x34],eax
 804978b:	e9 d7 04 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 8049790:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049793:	83 c0 01             	add    eax,0x1
 8049796:	05 c0 c0 04 08       	add    eax,0x804c0c0
 804979b:	8b 00                	mov    eax,DWORD PTR [eax]
 804979d:	89 45 f0             	mov    DWORD PTR [ebp-0x10],eax
 80497a0:	83 7d d8 00          	cmp    DWORD PTR [ebp-0x28],0x0
 80497a4:	79 08                	jns    80497ae <fputc@plt+0x127e>
 80497a6:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80497a9:	83 c0 05             	add    eax,0x5
 80497ac:	eb 03                	jmp    80497b1 <fputc@plt+0x1281>
 80497ae:	8b 45 f0             	mov    eax,DWORD PTR [ebp-0x10]
 80497b1:	89 45 cc             	mov    DWORD PTR [ebp-0x34],eax
 80497b4:	e9 ae 04 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 80497b9:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80497bc:	83 c0 01             	add    eax,0x1
 80497bf:	05 c0 c0 04 08       	add    eax,0x804c0c0
 80497c4:	8b 00                	mov    eax,DWORD PTR [eax]
 80497c6:	89 45 f0             	mov    DWORD PTR [ebp-0x10],eax
 80497c9:	83 7d d8 00          	cmp    DWORD PTR [ebp-0x28],0x0
 80497cd:	75 08                	jne    80497d7 <fputc@plt+0x12a7>
 80497cf:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80497d2:	83 c0 05             	add    eax,0x5
 80497d5:	eb 03                	jmp    80497da <fputc@plt+0x12aa>
 80497d7:	8b 45 f0             	mov    eax,DWORD PTR [ebp-0x10]
 80497da:	89 45 cc             	mov    DWORD PTR [ebp-0x34],eax
 80497dd:	e9 85 04 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 80497e2:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80497e5:	83 c0 01             	add    eax,0x1
 80497e8:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 80497ef:	0f be c0             	movsx  eax,al
 80497f2:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
 80497f5:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 80497f8:	83 f8 01             	cmp    eax,0x1
 80497fb:	74 5e                	je     804985b <fputc@plt+0x132b>
 80497fd:	83 f8 01             	cmp    eax,0x1
 8049800:	7f 09                	jg     804980b <fputc@plt+0x12db>
 8049802:	85 c0                	test   eax,eax
 8049804:	74 18                	je     804981e <fputc@plt+0x12ee>
 8049806:	e9 d5 00 00 00       	jmp    80498e0 <fputc@plt+0x13b0>
 804980b:	83 f8 02             	cmp    eax,0x2
 804980e:	74 7b                	je     804988b <fputc@plt+0x135b>
 8049810:	83 f8 04             	cmp    eax,0x4
 8049813:	0f 84 a2 00 00 00    	je     80498bb <fputc@plt+0x138b>
 8049819:	e9 c2 00 00 00       	jmp    80498e0 <fputc@plt+0x13b0>
 804981e:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049821:	83 c0 02             	add    eax,0x2
 8049824:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 804982b:	0f be c0             	movsx  eax,al
 804982e:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8049835:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8049838:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 804983b:	83 c0 03             	add    eax,0x3
 804983e:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049845:	0f be c0             	movsx  eax,al
 8049848:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 804984f:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8049852:	83 45 cc 04          	add    DWORD PTR [ebp-0x34],0x4
 8049856:	e9 85 00 00 00       	jmp    80498e0 <fputc@plt+0x13b0>
 804985b:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 804985e:	83 c0 02             	add    eax,0x2
 8049861:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049868:	0f be c0             	movsx  eax,al
 804986b:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8049872:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8049875:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049878:	83 c0 03             	add    eax,0x3
 804987b:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8049880:	8b 00                	mov    eax,DWORD PTR [eax]
 8049882:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8049885:	83 45 cc 07          	add    DWORD PTR [ebp-0x34],0x7
 8049889:	eb 55                	jmp    80498e0 <fputc@plt+0x13b0>
 804988b:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 804988e:	83 c0 02             	add    eax,0x2
 8049891:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8049896:	8b 00                	mov    eax,DWORD PTR [eax]
 8049898:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 804989b:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 804989e:	83 c0 06             	add    eax,0x6
 80498a1:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 80498a8:	0f be c0             	movsx  eax,al
 80498ab:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 80498b2:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 80498b5:	83 45 cc 07          	add    DWORD PTR [ebp-0x34],0x7
 80498b9:	eb 25                	jmp    80498e0 <fputc@plt+0x13b0>
 80498bb:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80498be:	83 c0 02             	add    eax,0x2
 80498c1:	05 c0 c0 04 08       	add    eax,0x804c0c0
 80498c6:	8b 00                	mov    eax,DWORD PTR [eax]
 80498c8:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 80498cb:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80498ce:	83 c0 06             	add    eax,0x6
 80498d1:	05 c0 c0 04 08       	add    eax,0x804c0c0
 80498d6:	8b 00                	mov    eax,DWORD PTR [eax]
 80498d8:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 80498db:	83 45 cc 0a          	add    DWORD PTR [ebp-0x34],0xa
 80498df:	90                   	nop
 80498e0:	8b 45 e4             	mov    eax,DWORD PTR [ebp-0x1c]
 80498e3:	8b 55 e0             	mov    edx,DWORD PTR [ebp-0x20]
 80498e6:	21 d0                	and    eax,edx
 80498e8:	89 45 d8             	mov    DWORD PTR [ebp-0x28],eax
 80498eb:	e9 77 03 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 80498f0:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80498f3:	83 c0 01             	add    eax,0x1
 80498f6:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 80498fd:	0f be c0             	movsx  eax,al
 8049900:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
 8049903:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 8049906:	83 f8 01             	cmp    eax,0x1
 8049909:	74 5e                	je     8049969 <fputc@plt+0x1439>
 804990b:	83 f8 01             	cmp    eax,0x1
 804990e:	7f 09                	jg     8049919 <fputc@plt+0x13e9>
 8049910:	85 c0                	test   eax,eax
 8049912:	74 18                	je     804992c <fputc@plt+0x13fc>
 8049914:	e9 d5 00 00 00       	jmp    80499ee <fputc@plt+0x14be>
 8049919:	83 f8 02             	cmp    eax,0x2
 804991c:	74 7b                	je     8049999 <fputc@plt+0x1469>
 804991e:	83 f8 04             	cmp    eax,0x4
 8049921:	0f 84 a2 00 00 00    	je     80499c9 <fputc@plt+0x1499>
 8049927:	e9 c2 00 00 00       	jmp    80499ee <fputc@plt+0x14be>
 804992c:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 804992f:	83 c0 02             	add    eax,0x2
 8049932:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049939:	0f be c0             	movsx  eax,al
 804993c:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8049943:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8049946:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049949:	83 c0 03             	add    eax,0x3
 804994c:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049953:	0f be c0             	movsx  eax,al
 8049956:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 804995d:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8049960:	83 45 cc 04          	add    DWORD PTR [ebp-0x34],0x4
 8049964:	e9 85 00 00 00       	jmp    80499ee <fputc@plt+0x14be>
 8049969:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 804996c:	83 c0 02             	add    eax,0x2
 804996f:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049976:	0f be c0             	movsx  eax,al
 8049979:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8049980:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8049983:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049986:	83 c0 03             	add    eax,0x3
 8049989:	05 c0 c0 04 08       	add    eax,0x804c0c0
 804998e:	8b 00                	mov    eax,DWORD PTR [eax]
 8049990:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 8049993:	83 45 cc 07          	add    DWORD PTR [ebp-0x34],0x7
 8049997:	eb 55                	jmp    80499ee <fputc@plt+0x14be>
 8049999:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 804999c:	83 c0 02             	add    eax,0x2
 804999f:	05 c0 c0 04 08       	add    eax,0x804c0c0
 80499a4:	8b 00                	mov    eax,DWORD PTR [eax]
 80499a6:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 80499a9:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80499ac:	83 c0 06             	add    eax,0x6
 80499af:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 80499b6:	0f be c0             	movsx  eax,al
 80499b9:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 80499c0:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 80499c3:	83 45 cc 07          	add    DWORD PTR [ebp-0x34],0x7
 80499c7:	eb 25                	jmp    80499ee <fputc@plt+0x14be>
 80499c9:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80499cc:	83 c0 02             	add    eax,0x2
 80499cf:	05 c0 c0 04 08       	add    eax,0x804c0c0
 80499d4:	8b 00                	mov    eax,DWORD PTR [eax]
 80499d6:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 80499d9:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 80499dc:	83 c0 06             	add    eax,0x6
 80499df:	05 c0 c0 04 08       	add    eax,0x804c0c0
 80499e4:	8b 00                	mov    eax,DWORD PTR [eax]
 80499e6:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
 80499e9:	83 45 cc 0a          	add    DWORD PTR [ebp-0x34],0xa
 80499ed:	90                   	nop
 80499ee:	8b 45 e4             	mov    eax,DWORD PTR [ebp-0x1c]
 80499f1:	8b 55 e0             	mov    edx,DWORD PTR [ebp-0x20]
 80499f4:	89 d1                	mov    ecx,edx
 80499f6:	29 c1                	sub    ecx,eax
 80499f8:	89 c8                	mov    eax,ecx
 80499fa:	89 45 d8             	mov    DWORD PTR [ebp-0x28],eax
 80499fd:	e9 65 02 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 8049a02:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049a05:	83 c0 01             	add    eax,0x1
 8049a08:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049a0f:	0f be c0             	movsx  eax,al
 8049a12:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
 8049a15:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
 8049a18:	85 c0                	test   eax,eax
 8049a1a:	74 07                	je     8049a23 <fputc@plt+0x14f3>
 8049a1c:	83 f8 01             	cmp    eax,0x1
 8049a1f:	74 36                	je     8049a57 <fputc@plt+0x1527>
 8049a21:	eb 5e                	jmp    8049a81 <fputc@plt+0x1551>
 8049a23:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049a26:	83 c0 02             	add    eax,0x2
 8049a29:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049a30:	0f be c0             	movsx  eax,al
 8049a33:	8b 55 cc             	mov    edx,DWORD PTR [ebp-0x34]
 8049a36:	83 c2 03             	add    edx,0x3
 8049a39:	0f b6 92 c0 c0 04 08 	movzx  edx,BYTE PTR [edx+0x804c0c0]
 8049a40:	0f be d2             	movsx  edx,dl
 8049a43:	8b 94 95 4c ff ff ff 	mov    edx,DWORD PTR [ebp+edx*4-0xb4]
 8049a4a:	89 94 85 4c ff ff ff 	mov    DWORD PTR [ebp+eax*4-0xb4],edx
 8049a51:	83 45 cc 04          	add    DWORD PTR [ebp-0x34],0x4
 8049a55:	eb 2a                	jmp    8049a81 <fputc@plt+0x1551>
 8049a57:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049a5a:	83 c0 02             	add    eax,0x2
 8049a5d:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049a64:	0f be c0             	movsx  eax,al
 8049a67:	8b 55 cc             	mov    edx,DWORD PTR [ebp-0x34]
 8049a6a:	83 c2 03             	add    edx,0x3
 8049a6d:	81 c2 c0 c0 04 08    	add    edx,0x804c0c0
 8049a73:	8b 12                	mov    edx,DWORD PTR [edx]
 8049a75:	89 94 85 4c ff ff ff 	mov    DWORD PTR [ebp+eax*4-0xb4],edx
 8049a7c:	83 45 cc 07          	add    DWORD PTR [ebp-0x34],0x7
 8049a80:	90                   	nop
 8049a81:	e9 e1 01 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 8049a86:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049a89:	83 c0 01             	add    eax,0x1
 8049a8c:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049a93:	0f be c0             	movsx  eax,al
 8049a96:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
 8049a99:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8049a9c:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8049aa3:	8d 50 01             	lea    edx,[eax+0x1]
 8049aa6:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8049aa9:	89 94 85 4c ff ff ff 	mov    DWORD PTR [ebp+eax*4-0xb4],edx
 8049ab0:	83 45 cc 02          	add    DWORD PTR [ebp-0x34],0x2
 8049ab4:	e9 ae 01 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 8049ab9:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049abc:	83 c0 01             	add    eax,0x1
 8049abf:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049ac6:	0f be c0             	movsx  eax,al
 8049ac9:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
 8049acc:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8049acf:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8049ad6:	8d 50 ff             	lea    edx,[eax-0x1]
 8049ad9:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8049adc:	89 94 85 4c ff ff ff 	mov    DWORD PTR [ebp+eax*4-0xb4],edx
 8049ae3:	83 45 cc 02          	add    DWORD PTR [ebp-0x34],0x2
 8049ae7:	e9 7b 01 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 8049aec:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049aef:	83 c0 01             	add    eax,0x1
 8049af2:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049af9:	0f be c0             	movsx  eax,al
 8049afc:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
 8049aff:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049b02:	83 c0 02             	add    eax,0x2
 8049b05:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049b0c:	0f be c0             	movsx  eax,al
 8049b0f:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8049b12:	83 45 cc 03          	add    DWORD PTR [ebp-0x34],0x3
 8049b16:	8b 45 e0             	mov    eax,DWORD PTR [ebp-0x20]
 8049b19:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8049b20:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8049b25:	8b 10                	mov    edx,DWORD PTR [eax]
 8049b27:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8049b2a:	89 94 85 4c ff ff ff 	mov    DWORD PTR [ebp+eax*4-0xb4],edx
 8049b31:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8049b34:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8049b3b:	89 45 d8             	mov    DWORD PTR [ebp-0x28],eax
 8049b3e:	e9 24 01 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 8049b43:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049b46:	83 c0 01             	add    eax,0x1
 8049b49:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049b50:	0f be c0             	movsx  eax,al
 8049b53:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
 8049b56:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049b59:	83 c0 02             	add    eax,0x2
 8049b5c:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049b63:	0f be c0             	movsx  eax,al
 8049b66:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
 8049b69:	83 45 cc 03          	add    DWORD PTR [ebp-0x34],0x3
 8049b6d:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8049b70:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8049b77:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8049b7c:	8b 55 e0             	mov    edx,DWORD PTR [ebp-0x20]
 8049b7f:	8b 94 95 4c ff ff ff 	mov    edx,DWORD PTR [ebp+edx*4-0xb4]
 8049b86:	89 10                	mov    DWORD PTR [eax],edx
 8049b88:	8b 00                	mov    eax,DWORD PTR [eax]
 8049b8a:	89 45 d8             	mov    DWORD PTR [ebp-0x28],eax
 8049b8d:	e9 d5 00 00 00       	jmp    8049c67 <fputc@plt+0x1737>
 8049b92:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049b95:	83 c0 01             	add    eax,0x1
 8049b98:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049b9f:	0f be c0             	movsx  eax,al
 8049ba2:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
 8049ba5:	83 7d f4 00          	cmp    DWORD PTR [ebp-0xc],0x0
 8049ba9:	74 16                	je     8049bc1 <fputc@plt+0x1691>
 8049bab:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049bae:	83 c0 02             	add    eax,0x2
 8049bb1:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8049bb6:	8b 00                	mov    eax,DWORD PTR [eax]
 8049bb8:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
 8049bbb:	83 45 cc 06          	add    DWORD PTR [ebp-0x34],0x6
 8049bbf:	eb 1e                	jmp    8049bdf <fputc@plt+0x16af>
 8049bc1:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049bc4:	83 c0 02             	add    eax,0x2
 8049bc7:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049bce:	0f be c0             	movsx  eax,al
 8049bd1:	8b 84 85 4c ff ff ff 	mov    eax,DWORD PTR [ebp+eax*4-0xb4]
 8049bd8:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
 8049bdb:	83 45 cc 03          	add    DWORD PTR [ebp-0x34],0x3
 8049bdf:	8b 45 c8             	mov    eax,DWORD PTR [ebp-0x38]
 8049be2:	83 e8 04             	sub    eax,0x4
 8049be5:	89 45 c8             	mov    DWORD PTR [ebp-0x38],eax
 8049be8:	8b 45 c8             	mov    eax,DWORD PTR [ebp-0x38]
 8049beb:	8d 90 c0 c0 04 08    	lea    edx,[eax+0x804c0c0]
 8049bf1:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8049bf4:	89 02                	mov    DWORD PTR [edx],eax
 8049bf6:	eb 6f                	jmp    8049c67 <fputc@plt+0x1737>
 8049bf8:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049bfb:	83 c0 01             	add    eax,0x1
 8049bfe:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049c05:	0f be c0             	movsx  eax,al
 8049c08:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
 8049c0b:	8b 45 c8             	mov    eax,DWORD PTR [ebp-0x38]
 8049c0e:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8049c13:	8b 10                	mov    edx,DWORD PTR [eax]
 8049c15:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8049c18:	89 94 85 4c ff ff ff 	mov    DWORD PTR [ebp+eax*4-0xb4],edx
 8049c1f:	8b 45 c8             	mov    eax,DWORD PTR [ebp-0x38]
 8049c22:	83 c0 04             	add    eax,0x4
 8049c25:	89 45 c8             	mov    DWORD PTR [ebp-0x38],eax
 8049c28:	83 45 cc 02          	add    DWORD PTR [ebp-0x34],0x2
 8049c2c:	eb 39                	jmp    8049c67 <fputc@plt+0x1737>
 8049c2e:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049c31:	83 c0 01             	add    eax,0x1
 8049c34:	0f b6 80 c0 c0 04 08 	movzx  eax,BYTE PTR [eax+0x804c0c0]
 8049c3b:	0f be c0             	movsx  eax,al
 8049c3e:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
 8049c41:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
 8049c44:	8b 14 85 60 c0 04 08 	mov    edx,DWORD PTR [eax*4+0x804c060]
 8049c4b:	8d 85 4c ff ff ff    	lea    eax,[ebp-0xb4]
 8049c51:	89 04 24             	mov    DWORD PTR [esp],eax
 8049c54:	ff d2                	call   edx
 8049c56:	89 85 4c ff ff ff    	mov    DWORD PTR [ebp-0xb4],eax
 8049c5c:	83 45 cc 02          	add    DWORD PTR [ebp-0x34],0x2
 8049c60:	eb 05                	jmp    8049c67 <fputc@plt+0x1737>
 8049c62:	83 45 cc 01          	add    DWORD PTR [ebp-0x34],0x1
 8049c66:	90                   	nop
 8049c67:	8b 45 cc             	mov    eax,DWORD PTR [ebp-0x34]
 8049c6a:	05 c0 c0 04 08       	add    eax,0x804c0c0
 8049c6f:	0f b6 00             	movzx  eax,BYTE PTR [eax]
 8049c72:	3c 1d                	cmp    al,0x1d
 8049c74:	0f 85 b3 ed ff ff    	jne    8048a2d <fputc@plt+0x4fd>
 8049c7a:	8b 85 4c ff ff ff    	mov    eax,DWORD PTR [ebp-0xb4]
 8049c80:	c9                   	leave  
 8049c81:	c3                   	ret    
 8049c82:	55                   	push   ebp
 8049c83:	89 e5                	mov    ebp,esp
 8049c85:	57                   	push   edi
 8049c86:	53                   	push   ebx
 8049c87:	83 e4 f0             	and    esp,0xfffffff0
 8049c8a:	81 ec 90 00 00 00    	sub    esp,0x90
 8049c90:	65 a1 14 00 00 00    	mov    eax,gs:0x14
 8049c96:	89 84 24 8c 00 00 00 	mov    DWORD PTR [esp+0x8c],eax
 8049c9d:	31 c0                	xor    eax,eax
 8049c9f:	8d 44 24 10          	lea    eax,[esp+0x10]
 8049ca3:	89 c3                	mov    ebx,eax
 8049ca5:	b8 00 00 00 00       	mov    eax,0x0
 8049caa:	ba 1f 00 00 00       	mov    edx,0x1f
 8049caf:	89 df                	mov    edi,ebx
 8049cb1:	89 d1                	mov    ecx,edx
 8049cb3:	f3 ab                	rep stos DWORD PTR es:[edi],eax
 8049cb5:	8d 44 24 10          	lea    eax,[esp+0x10]
 8049cb9:	89 04 24             	mov    DWORD PTR [esp],eax
 8049cbc:	e8 ca ec ff ff       	call   804898b <fputc@plt+0x45b>
 8049cc1:	b8 00 00 00 00       	mov    eax,0x0
 8049cc6:	8b 94 24 8c 00 00 00 	mov    edx,DWORD PTR [esp+0x8c]
 8049ccd:	65 33 15 14 00 00 00 	xor    edx,DWORD PTR gs:0x14
 8049cd4:	74 05                	je     8049cdb <fputc@plt+0x17ab>
 8049cd6:	e8 e5 e7 ff ff       	call   80484c0 <__stack_chk_fail@plt>
 8049cdb:	8d 65 f8             	lea    esp,[ebp-0x8]
 8049cde:	5b                   	pop    ebx
 8049cdf:	5f                   	pop    edi
 8049ce0:	5d                   	pop    ebp
 8049ce1:	c3                   	ret    
 8049ce2:	90                   	nop
 8049ce3:	90                   	nop
 8049ce4:	90                   	nop
 8049ce5:	90                   	nop
 8049ce6:	90                   	nop
 8049ce7:	90                   	nop
 8049ce8:	90                   	nop
 8049ce9:	90                   	nop
 8049cea:	90                   	nop
 8049ceb:	90                   	nop
 8049cec:	90                   	nop
 8049ced:	90                   	nop
 8049cee:	90                   	nop
 8049cef:	90                   	nop
 8049cf0:	55                   	push   ebp
 8049cf1:	57                   	push   edi
 8049cf2:	56                   	push   esi
 8049cf3:	53                   	push   ebx
 8049cf4:	e8 69 00 00 00       	call   8049d62 <fputc@plt+0x1832>
 8049cf9:	81 c3 fb 22 00 00    	add    ebx,0x22fb
 8049cff:	83 ec 1c             	sub    esp,0x1c
 8049d02:	8b 6c 24 30          	mov    ebp,DWORD PTR [esp+0x30]
 8049d06:	8d bb 20 ff ff ff    	lea    edi,[ebx-0xe0]
 8049d0c:	e8 3b e7 ff ff       	call   804844c <raise@plt-0x44>
 8049d11:	8d 83 20 ff ff ff    	lea    eax,[ebx-0xe0]
 8049d17:	29 c7                	sub    edi,eax
 8049d19:	c1 ff 02             	sar    edi,0x2
 8049d1c:	85 ff                	test   edi,edi
 8049d1e:	74 29                	je     8049d49 <fputc@plt+0x1819>
 8049d20:	31 f6                	xor    esi,esi
 8049d22:	8d b6 00 00 00 00    	lea    esi,[esi+0x0]
 8049d28:	8b 44 24 38          	mov    eax,DWORD PTR [esp+0x38]
 8049d2c:	89 2c 24             	mov    DWORD PTR [esp],ebp
 8049d2f:	89 44 24 08          	mov    DWORD PTR [esp+0x8],eax
 8049d33:	8b 44 24 34          	mov    eax,DWORD PTR [esp+0x34]
 8049d37:	89 44 24 04          	mov    DWORD PTR [esp+0x4],eax
 8049d3b:	ff 94 b3 20 ff ff ff 	call   DWORD PTR [ebx+esi*4-0xe0]
 8049d42:	83 c6 01             	add    esi,0x1
 8049d45:	39 fe                	cmp    esi,edi
 8049d47:	75 df                	jne    8049d28 <fputc@plt+0x17f8>
 8049d49:	83 c4 1c             	add    esp,0x1c
 8049d4c:	5b                   	pop    ebx
 8049d4d:	5e                   	pop    esi
 8049d4e:	5f                   	pop    edi
 8049d4f:	5d                   	pop    ebp
 8049d50:	c3                   	ret    
 8049d51:	eb 0d                	jmp    8049d60 <fputc@plt+0x1830>
 8049d53:	90                   	nop
 8049d54:	90                   	nop
 8049d55:	90                   	nop
 8049d56:	90                   	nop
 8049d57:	90                   	nop
 8049d58:	90                   	nop
 8049d59:	90                   	nop
 8049d5a:	90                   	nop
 8049d5b:	90                   	nop
 8049d5c:	90                   	nop
 8049d5d:	90                   	nop
 8049d5e:	90                   	nop
 8049d5f:	90                   	nop
 8049d60:	f3 c3                	repz ret 
 8049d62:	8b 1c 24             	mov    ebx,DWORD PTR [esp]
 8049d65:	c3                   	ret    
 8049d66:	90                   	nop
 8049d67:	90                   	nop
 8049d68:	90                   	nop
 8049d69:	90                   	nop
 8049d6a:	90                   	nop
 8049d6b:	90                   	nop
 8049d6c:	90                   	nop
 8049d6d:	90                   	nop
 8049d6e:	90                   	nop
 8049d6f:	90                   	nop
 8049d70:	55                   	push   ebp
 8049d71:	89 e5                	mov    ebp,esp
 8049d73:	53                   	push   ebx
 8049d74:	83 ec 04             	sub    esp,0x4
 8049d77:	a1 14 bf 04 08       	mov    eax,ds:0x804bf14
 8049d7c:	83 f8 ff             	cmp    eax,0xffffffff
 8049d7f:	74 13                	je     8049d94 <fputc@plt+0x1864>
 8049d81:	bb 14 bf 04 08       	mov    ebx,0x804bf14
 8049d86:	66 90                	xchg   ax,ax
 8049d88:	83 eb 04             	sub    ebx,0x4
 8049d8b:	ff d0                	call   eax
 8049d8d:	8b 03                	mov    eax,DWORD PTR [ebx]
 8049d8f:	83 f8 ff             	cmp    eax,0xffffffff
 8049d92:	75 f4                	jne    8049d88 <fputc@plt+0x1858>
 8049d94:	83 c4 04             	add    esp,0x4
 8049d97:	5b                   	pop    ebx
 8049d98:	5d                   	pop    ebp
 8049d99:	c3                   	ret    
 8049d9a:	90                   	nop
 8049d9b:	90                   	nop

Disassembly of section .fini:

08049d9c <.fini>:
 8049d9c:	53                   	push   ebx
 8049d9d:	83 ec 08             	sub    esp,0x8
 8049da0:	e8 00 00 00 00       	call   8049da5 <fputc@plt+0x1875>
 8049da5:	5b                   	pop    ebx
 8049da6:	81 c3 4f 22 00 00    	add    ebx,0x224f
 8049dac:	e8 bf e7 ff ff       	call   8048570 <fputc@plt+0x40>
 8049db1:	83 c4 08             	add    esp,0x8
 8049db4:	5b                   	pop    ebx
 8049db5:	c3                   	ret    

Disassembly of section .rodata:

08049db8 <_IO_stdin_used@@Base-0x4>:
 8049db8:	03 00                	add    eax,DWORD PTR [eax]
	...

08049dbc <_IO_stdin_used@@Base>:
 8049dbc:	01 00                	add    DWORD PTR [eax],eax
 8049dbe:	02 00                	add    al,BYTE PTR [eax]
 8049dc0:	25 64 00 30 78       	and    eax,0x78300064
 8049dc5:	25 58 00 25 78       	and    eax,0x78250058
 8049dca:	20 00                	and    BYTE PTR [eax],al
 8049dcc:	25 66 00 25 66       	and    eax,0x66250066
 8049dd1:	20 00                	and    BYTE PTR [eax],al
 8049dd3:	00 4d 8a             	add    BYTE PTR [ebp-0x76],cl
 8049dd6:	04 08                	add    al,0x8
 8049dd8:	56                   	push   esi
 8049dd9:	8a 04 08             	mov    al,BYTE PTR [eax+ecx*1]
 8049ddc:	8f 8a                	(bad)  
 8049dde:	04 08                	add    al,0x8
 8049de0:	c4 8b 04 08 f9 8c    	les    ecx,FWORD PTR [ebx-0x7306f7fc]
 8049de6:	04 08                	add    al,0x8
 8049de8:	2f                   	das    
 8049de9:	8e 04 08             	mov    es,WORD PTR [eax+ecx*1]
 8049dec:	91                   	xchg   ecx,eax
 8049ded:	8f 04 08             	pop    DWORD PTR [eax+ecx*1]
 8049df0:	f5                   	cmc    
 8049df1:	95                   	xchg   ebp,eax
 8049df2:	04 08                	add    al,0x8
 8049df4:	49                   	dec    ecx
 8049df5:	96                   	xchg   esi,eax
 8049df6:	04 08                	add    al,0x8
 8049df8:	c6                   	(bad)  
 8049df9:	90                   	nop
 8049dfa:	04 08                	add    al,0x8
 8049dfc:	fb                   	sti    
 8049dfd:	91                   	xchg   ecx,eax
 8049dfe:	04 08                	add    al,0x8
 8049e00:	9e                   	sahf   
 8049e01:	95                   	xchg   ebp,eax
 8049e02:	04 08                	add    al,0x8
 8049e04:	30 93 04 08 67 94    	xor    BYTE PTR [ebx-0x6b98f7fc],dl
 8049e0a:	04 08                	add    al,0x8
 8049e0c:	d1 96 04 08 9d 96    	rcl    DWORD PTR [esi-0x6962f7fc],1
 8049e12:	04 08                	add    al,0x8
 8049e14:	ec                   	in     al,dx
 8049e15:	96                   	xchg   esi,eax
 8049e16:	04 08                	add    al,0x8
 8049e18:	15 97 04 08 3e       	adc    eax,0x3e080497
 8049e1d:	97                   	xchg   edi,eax
 8049e1e:	04 08                	add    al,0x8
 8049e20:	67 97                	addr16 xchg edi,eax
 8049e22:	04 08                	add    al,0x8
 8049e24:	90                   	nop
 8049e25:	97                   	xchg   edi,eax
 8049e26:	04 08                	add    al,0x8
 8049e28:	b9 97 04 08 e2       	mov    ecx,0xe2080497
 8049e2d:	97                   	xchg   edi,eax
 8049e2e:	04 08                	add    al,0x8
 8049e30:	f0 98                	lock cwde 
 8049e32:	04 08                	add    al,0x8
 8049e34:	02 9a 04 08 86 9a    	add    bl,BYTE PTR [edx-0x6579f7fc]
 8049e3a:	04 08                	add    al,0x8
 8049e3c:	b9 9a 04 08 ec       	mov    ecx,0xec08049a
 8049e41:	9a 04 08 43 9b 04 08 	call   0x804:0x9b430804
 8049e48:	62 9c 04 08 92 9b 04 	bound  ebx,QWORD PTR [esp+eax*1+0x49b9208]
 8049e4f:	08 f8                	or     al,bh
 8049e51:	9b                   	fwait
 8049e52:	04 08                	add    al,0x8
 8049e54:	2e 9c                	cs pushf 
 8049e56:	04 08                	add    al,0x8

Disassembly of section .eh_frame_hdr:

08049e58 <.eh_frame_hdr>:
 8049e58:	01 1b                	add    DWORD PTR [ebx],ebx
 8049e5a:	03 3b                	add    edi,DWORD PTR [ebx]
 8049e5c:	e0 00                	loopne 8049e5e <_IO_stdin_used@@Base+0xa2>
 8049e5e:	00 00                	add    BYTE PTR [eax],al
 8049e60:	1b 00                	sbb    eax,DWORD PTR [eax]
 8049e62:	00 00                	add    BYTE PTR [eax],al
 8049e64:	28 e6                	sub    dh,ah
 8049e66:	ff                   	(bad)  
 8049e67:	ff                   	(bad)  
 8049e68:	fc                   	cld    
 8049e69:	00 00                	add    BYTE PTR [eax],al
 8049e6b:	00 9c e7 ff ff 20 01 	add    BYTE PTR [edi+eiz*8+0x120ffff],bl
 8049e72:	00 00                	add    BYTE PTR [eax],al
 8049e74:	c1 e7 ff             	shl    edi,0xff
 8049e77:	ff 40 01             	inc    DWORD PTR [eax+0x1]
 8049e7a:	00 00                	add    BYTE PTR [eax],al
 8049e7c:	08 e8                	or     al,ch
 8049e7e:	ff                   	(bad)  
 8049e7f:	ff 60 01             	jmp    DWORD PTR [eax+0x1]
 8049e82:	00 00                	add    BYTE PTR [eax],al
 8049e84:	12 e8                	adc    ch,al
 8049e86:	ff                   	(bad)  
 8049e87:	ff 80 01 00 00 24    	inc    DWORD PTR [eax+0x24000001]
 8049e8d:	e8 ff ff a0 01       	call   9a59e91 <stdin@@GLIBC_2.0+0x19eddc9>
 8049e92:	00 00                	add    BYTE PTR [eax],al
 8049e94:	55                   	push   ebp
 8049e95:	e8 ff ff c0 01       	call   9c59e99 <stdin@@GLIBC_2.0+0x1beddd1>
 8049e9a:	00 00                	add    BYTE PTR [eax],al
 8049e9c:	7c e8                	jl     8049e86 <_IO_stdin_used@@Base+0xca>
 8049e9e:	ff                   	(bad)  
 8049e9f:	ff e0                	jmp    eax
 8049ea1:	01 00                	add    DWORD PTR [eax],eax
 8049ea3:	00 a3 e8 ff ff 00    	add    BYTE PTR [ebx+0xffffe8],ah
 8049ea9:	02 00                	add    al,BYTE PTR [eax]
 8049eab:	00 c3                	add    bl,al
 8049ead:	e8 ff ff 20 02       	call   a259eb1 <stdin@@GLIBC_2.0+0x21edde9>
 8049eb2:	00 00                	add    BYTE PTR [eax],al
 8049eb4:	f6 e8                	imul   al
 8049eb6:	ff                   	(bad)  
 8049eb7:	ff 40 02             	inc    DWORD PTR [eax+0x2]
 8049eba:	00 00                	add    BYTE PTR [eax],al
 8049ebc:	29 e9                	sub    ecx,ebp
 8049ebe:	ff                   	(bad)  
 8049ebf:	ff 60 02             	jmp    DWORD PTR [eax+0x2]
 8049ec2:	00 00                	add    BYTE PTR [eax],al
 8049ec4:	40                   	inc    eax
 8049ec5:	e9 ff ff 80 02       	jmp    a859ec9 <stdin@@GLIBC_2.0+0x27ede01>
 8049eca:	00 00                	add    BYTE PTR [eax],al
 8049ecc:	51                   	push   ecx
 8049ecd:	e9 ff ff a0 02       	jmp    aa59ed1 <stdin@@GLIBC_2.0+0x29ede09>
 8049ed2:	00 00                	add    BYTE PTR [eax],al
 8049ed4:	80 e9 ff             	sub    cl,0xff
 8049ed7:	ff c0                	inc    eax
 8049ed9:	02 00                	add    al,BYTE PTR [eax]
 8049edb:	00 bb e9 ff ff e0    	add    BYTE PTR [ebx-0x1f000017],bh
 8049ee1:	02 00                	add    al,BYTE PTR [eax]
 8049ee3:	00 dc                	add    ah,bl
 8049ee5:	e9 ff ff 00 03       	jmp    b059ee9 <stdin@@GLIBC_2.0+0x2fede21>
 8049eea:	00 00                	add    BYTE PTR [eax],al
 8049eec:	23 ea                	and    ebp,edx
 8049eee:	ff                   	(bad)  
 8049eef:	ff 20                	jmp    DWORD PTR [eax]
 8049ef1:	03 00                	add    eax,DWORD PTR [eax]
 8049ef3:	00 5e ea             	add    BYTE PTR [esi-0x16],bl
 8049ef6:	ff                   	(bad)  
 8049ef7:	ff 40 03             	inc    DWORD PTR [eax+0x3]
 8049efa:	00 00                	add    BYTE PTR [eax],al
 8049efc:	99                   	cdq    
 8049efd:	ea ff ff 60 03 00 00 	jmp    0x0:0x360ffff
 8049f04:	d4 ea                	aam    0xea
 8049f06:	ff                   	(bad)  
 8049f07:	ff 80 03 00 00 0f    	inc    DWORD PTR [eax+0xf000003]
 8049f0d:	eb ff                	jmp    8049f0e <_IO_stdin_used@@Base+0x152>
 8049f0f:	ff a0 03 00 00 33    	jmp    DWORD PTR [eax+0x33000003]
 8049f15:	eb ff                	jmp    8049f16 <_IO_stdin_used@@Base+0x15a>
 8049f17:	ff c0                	inc    eax
 8049f19:	03 00                	add    eax,DWORD PTR [eax]
 8049f1b:	00 2a                	add    BYTE PTR [edx],ch
 8049f1d:	fe                   	(bad)  
 8049f1e:	ff                   	(bad)  
 8049f1f:	ff e0                	jmp    eax
 8049f21:	03 00                	add    eax,DWORD PTR [eax]
 8049f23:	00 98 fe ff ff 08    	add    BYTE PTR [eax+0x8fffffe],bl
 8049f29:	04 00                	add    al,0x0
 8049f2b:	00 08                	add    BYTE PTR [eax],cl
 8049f2d:	ff                   	(bad)  
 8049f2e:	ff                   	(bad)  
 8049f2f:	ff 44 04 00          	inc    DWORD PTR [esp+eax*1+0x0]
 8049f33:	00 0a                	add    BYTE PTR [edx],cl
 8049f35:	ff                   	(bad)  
 8049f36:	ff                   	(bad)  
 8049f37:	ff 58 04             	call   FWORD PTR [eax+0x4]
	...

Disassembly of section .eh_frame:

08049f3c <.eh_frame>:
 8049f3c:	14 00                	adc    al,0x0
 8049f3e:	00 00                	add    BYTE PTR [eax],al
 8049f40:	00 00                	add    BYTE PTR [eax],al
 8049f42:	00 00                	add    BYTE PTR [eax],al
 8049f44:	01 7a 52             	add    DWORD PTR [edx+0x52],edi
 8049f47:	00 01                	add    BYTE PTR [ecx],al
 8049f49:	7c 08                	jl     8049f53 <_IO_stdin_used@@Base+0x197>
 8049f4b:	01 1b                	add    DWORD PTR [ebx],ebx
 8049f4d:	0c 04                	or     al,0x4
 8049f4f:	04 88                	add    al,0x88
 8049f51:	01 00                	add    DWORD PTR [eax],eax
 8049f53:	00 20                	add    BYTE PTR [eax],ah
 8049f55:	00 00                	add    BYTE PTR [eax],al
 8049f57:	00 1c 00             	add    BYTE PTR [eax+eax*1],bl
 8049f5a:	00 00                	add    BYTE PTR [eax],al
 8049f5c:	24 e5                	and    al,0xe5
 8049f5e:	ff                   	(bad)  
 8049f5f:	ff c0                	inc    eax
 8049f61:	00 00                	add    BYTE PTR [eax],al
 8049f63:	00 00                	add    BYTE PTR [eax],al
 8049f65:	0e                   	push   cs
 8049f66:	08 46 0e             	or     BYTE PTR [esi+0xe],al
 8049f69:	0c 4a                	or     al,0x4a
 8049f6b:	0f 0b                	ud2    
 8049f6d:	74 04                	je     8049f73 <_IO_stdin_used@@Base+0x1b7>
 8049f6f:	78 00                	js     8049f71 <_IO_stdin_used@@Base+0x1b5>
 8049f71:	3f                   	aas    
 8049f72:	1a 3b                	sbb    bh,BYTE PTR [ebx]
 8049f74:	2a 32                	sub    dh,BYTE PTR [edx]
 8049f76:	24 22                	and    al,0x22
 8049f78:	1c 00                	sbb    al,0x0
 8049f7a:	00 00                	add    BYTE PTR [eax],al
 8049f7c:	40                   	inc    eax
 8049f7d:	00 00                	add    BYTE PTR [eax],al
 8049f7f:	00 74 e6 ff          	add    BYTE PTR [esi+eiz*8-0x1],dh
 8049f83:	ff 25 00 00 00 00    	jmp    DWORD PTR ds:0x0
 8049f89:	41                   	inc    ecx
 8049f8a:	0e                   	push   cs
 8049f8b:	08 85 02 42 0d 05    	or     BYTE PTR [ebp+0x50d4202],al
 8049f91:	61                   	popa   
 8049f92:	c5 0c 04             	lds    ecx,FWORD PTR [esp+eax*1]
 8049f95:	04 00                	add    al,0x0
 8049f97:	00 1c 00             	add    BYTE PTR [eax+eax*1],bl
 8049f9a:	00 00                	add    BYTE PTR [eax],al
 8049f9c:	60                   	pusha  
 8049f9d:	00 00                	add    BYTE PTR [eax],al
 8049f9f:	00 79 e6             	add    BYTE PTR [ecx-0x1a],bh
 8049fa2:	ff                   	(bad)  
 8049fa3:	ff 47 00             	inc    DWORD PTR [edi+0x0]
 8049fa6:	00 00                	add    BYTE PTR [eax],al
 8049fa8:	00 41 0e             	add    BYTE PTR [ecx+0xe],al
 8049fab:	08 85 02 42 0d 05    	or     BYTE PTR [ebp+0x50d4202],al
 8049fb1:	02 43 c5             	add    al,BYTE PTR [ebx-0x3b]
 8049fb4:	0c 04                	or     al,0x4
 8049fb6:	04 00                	add    al,0x0
 8049fb8:	1c 00                	sbb    al,0x0
 8049fba:	00 00                	add    BYTE PTR [eax],al
 8049fbc:	80 00 00             	add    BYTE PTR [eax],0x0
 8049fbf:	00 a0 e6 ff ff 0a    	add    BYTE PTR [eax+0xaffffe6],ah
 8049fc5:	00 00                	add    BYTE PTR [eax],al
 8049fc7:	00 00                	add    BYTE PTR [eax],al
 8049fc9:	41                   	inc    ecx
 8049fca:	0e                   	push   cs
 8049fcb:	08 85 02 42 0d 05    	or     BYTE PTR [ebp+0x50d4202],al
 8049fd1:	46                   	inc    esi
 8049fd2:	0c 04                	or     al,0x4
 8049fd4:	04 c5                	add    al,0xc5
 8049fd6:	00 00                	add    BYTE PTR [eax],al
 8049fd8:	1c 00                	sbb    al,0x0
 8049fda:	00 00                	add    BYTE PTR [eax],al
 8049fdc:	a0 00 00 00 8a       	mov    al,ds:0x8a000000
 8049fe1:	e6 ff                	out    0xff,al
 8049fe3:	ff 12                	call   DWORD PTR [edx]
 8049fe5:	00 00                	add    BYTE PTR [eax],al
 8049fe7:	00 00                	add    BYTE PTR [eax],al
 8049fe9:	41                   	inc    ecx
 8049fea:	0e                   	push   cs
 8049feb:	08 85 02 42 0d 05    	or     BYTE PTR [ebp+0x50d4202],al
 8049ff1:	4e                   	dec    esi
 8049ff2:	0c 04                	or     al,0x4
 8049ff4:	04 c5                	add    al,0xc5
 8049ff6:	00 00                	add    BYTE PTR [eax],al
 8049ff8:	1c 00                	sbb    al,0x0
 8049ffa:	00 00                	add    BYTE PTR [eax],al
 8049ffc:	c0 00 00             	rol    BYTE PTR [eax],0x0
 8049fff:	00 7c e6 ff          	add    BYTE PTR [esi+eiz*8-0x1],bh
 804a003:	ff 31                	push   DWORD PTR [ecx]
 804a005:	00 00                	add    BYTE PTR [eax],al
 804a007:	00 00                	add    BYTE PTR [eax],al
 804a009:	41                   	inc    ecx
 804a00a:	0e                   	push   cs
 804a00b:	08 85 02 42 0d 05    	or     BYTE PTR [ebp+0x50d4202],al
 804a011:	6d                   	ins    DWORD PTR es:[edi],dx
 804a012:	c5 0c 04             	lds    ecx,FWORD PTR [esp+eax*1]
 804a015:	04 00                	add    al,0x0
 804a017:	00 1c 00             	add    BYTE PTR [eax+eax*1],bl
 804a01a:	00 00                	add    BYTE PTR [eax],al
 804a01c:	e0 00                	loopne 804a01e <_IO_stdin_used@@Base+0x262>
 804a01e:	00 00                	add    BYTE PTR [eax],al
 804a020:	8d                   	(bad)  
 804a021:	e6 ff                	out    0xff,al
 804a023:	ff 27                	jmp    DWORD PTR [edi]
 804a025:	00 00                	add    BYTE PTR [eax],al
 804a027:	00 00                	add    BYTE PTR [eax],al
 804a029:	41                   	inc    ecx
 804a02a:	0e                   	push   cs
 804a02b:	08 85 02 42 0d 05    	or     BYTE PTR [ebp+0x50d4202],al
 804a031:	63 c5                	arpl   bp,ax
 804a033:	0c 04                	or     al,0x4
 804a035:	04 00                	add    al,0x0
 804a037:	00 1c 00             	add    BYTE PTR [eax+eax*1],bl
 804a03a:	00 00                	add    BYTE PTR [eax],al
 804a03c:	00 01                	add    BYTE PTR [ecx],al
 804a03e:	00 00                	add    BYTE PTR [eax],al
 804a040:	94                   	xchg   esp,eax
 804a041:	e6 ff                	out    0xff,al
 804a043:	ff 27                	jmp    DWORD PTR [edi]
 804a045:	00 00                	add    BYTE PTR [eax],al
 804a047:	00 00                	add    BYTE PTR [eax],al
 804a049:	41                   	inc    ecx
 804a04a:	0e                   	push   cs
 804a04b:	08 85 02 42 0d 05    	or     BYTE PTR [ebp+0x50d4202],al
 804a051:	63 c5                	arpl   bp,ax
 804a053:	0c 04                	or     al,0x4
 804a055:	04 00                	add    al,0x0
 804a057:	00 1c 00             	add    BYTE PTR [eax+eax*1],bl
 804a05a:	00 00                	add    BYTE PTR [eax],al
 804a05c:	20 01                	and    BYTE PTR [ecx],al
 804a05e:	00 00                	add    BYTE PTR [eax],al
 804a060:	9b                   	fwait
 804a061:	e6 ff                	out    0xff,al
 804a063:	ff 20                	jmp    DWORD PTR [eax]
 804a065:	00 00                	add    BYTE PTR [eax],al
 804a067:	00 00                	add    BYTE PTR [eax],al
 804a069:	41                   	inc    ecx
 804a06a:	0e                   	push   cs
 804a06b:	08 85 02 42 0d 05    	or     BYTE PTR [ebp+0x50d4202],al
 804a071:	5c                   	pop    esp
 804a072:	c5 0c 04             	lds    ecx,FWORD PTR [esp+eax*1]
 804a075:	04 00                	add    al,0x0
 804a077:	00 1c 00             	add    BYTE PTR [eax+eax*1],bl
 804a07a:	00 00                	add    BYTE PTR [eax],al
 804a07c:	40                   	inc    eax
 804a07d:	01 00                	add    DWORD PTR [eax],eax
 804a07f:	00 9b e6 ff ff 33    	add    BYTE PTR [ebx+0x33ffffe6],bl
 804a085:	00 00                	add    BYTE PTR [eax],al
 804a087:	00 00                	add    BYTE PTR [eax],al
 804a089:	41                   	inc    ecx
 804a08a:	0e                   	push   cs
 804a08b:	08 85 02 42 0d 05    	or     BYTE PTR [ebp+0x50d4202],al
 804a091:	6f                   	outs   dx,DWORD PTR ds:[esi]
 804a092:	c5 0c 04             	lds    ecx,FWORD PTR [esp+eax*1]
 804a095:	04 00                	add    al,0x0
 804a097:	00 1c 00             	add    BYTE PTR [eax+eax*1],bl
 804a09a:	00 00                	add    BYTE PTR [eax],al
 804a09c:	60                   	pusha  
 804a09d:	01 00                	add    DWORD PTR [eax],eax
 804a09f:	00 ae e6 ff ff 33    	add    BYTE PTR [esi+0x33ffffe6],ch
 804a0a5:	00 00                	add    BYTE PTR [eax],al
 804a0a7:	00 00                	add    BYTE PTR [eax],al
 804a0a9:	41                   	inc    ecx
 804a0aa:	0e                   	push   cs
 804a0ab:	08 85 02 42 0d 05    	or     BYTE PTR [ebp+0x50d4202],al
 804a0b1:	6f                   	outs   dx,DWORD PTR ds:[esi]
 804a0b2:	c5 0c 04             	lds    ecx,FWORD PTR [esp+eax*1]
 804a0b5:	04 00                	add    al,0x0
 804a0b7:	00 1c 00             	add    BYTE PTR [eax+eax*1],bl
 804a0ba:	00 00                	add    BYTE PTR [eax],al
 804a0bc:	80 01 00             	add    BYTE PTR [ecx],0x0
 804a0bf:	00 c1                	add    cl,al
 804a0c1:	e6 ff                	out    0xff,al
 804a0c3:	ff 17                	call   DWORD PTR [edi]
 804a0c5:	00 00                	add    BYTE PTR [eax],al
 804a0c7:	00 00                	add    BYTE PTR [eax],al
 804a0c9:	41                   	inc    ecx
 804a0ca:	0e                   	push   cs
 804a0cb:	08 85 02 42 0d 05    	or     BYTE PTR [ebp+0x50d4202],al
 804a0d1:	53                   	push   ebx
 804a0d2:	c5 0c 04             	lds    ecx,FWORD PTR [esp+eax*1]
 804a0d5:	04 00                	add    al,0x0
 804a0d7:	00 1c 00             	add    BYTE PTR [eax+eax*1],bl
 804a0da:	00 00                	add    BYTE PTR [eax],al
 804a0dc:	a0 01 00 00 b8       	mov    al,ds:0xb8000001
 804a0e1:	e6 ff                	out    0xff,al
 804a0e3:	ff 11                	call   DWORD PTR [ecx]
 804a0e5:	00 00                	add    BYTE PTR [eax],al
 804a0e7:	00 00                	add    BYTE PTR [eax],al
 804a0e9:	41                   	inc    ecx
 804a0ea:	0e                   	push   cs
 804a0eb:	08 85 02 42 0d 05    	or     BYTE PTR [ebp+0x50d4202],al
 804a0f1:	4d                   	dec    ebp
 804a0f2:	c5 0c 04             	lds    ecx,FWORD PTR [esp+eax*1]
 804a0f5:	04 00                	add    al,0x0
 804a0f7:	00 1c 00             	add    BYTE PTR [eax+eax*1],bl
 804a0fa:	00 00                	add    BYTE PTR [eax],al
 804a0fc:	c0 01 00             	rol    BYTE PTR [ecx],0x0
 804a0ff:	00 a9 e6 ff ff 2f    	add    BYTE PTR [ecx+0x2fffffe6],ch
 804a105:	00 00                	add    BYTE PTR [eax],al
 804a107:	00 00                	add    BYTE PTR [eax],al
 804a109:	41                   	inc    ecx
 804a10a:	0e                   	push   cs
 804a10b:	08 85 02 42 0d 05    	or     BYTE PTR [ebp+0x50d4202],al
 804a111:	6b c5 0c             	imul   eax,ebp,0xc
 804a114:	04 04                	add    al,0x4
 804a116:	00 00                	add    BYTE PTR [eax],al
 804a118:	1c 00                	sbb    al,0x0
 804a11a:	00 00                	add    BYTE PTR [eax],al
 804a11c:	e0 01                	loopne 804a11f <_IO_stdin_used@@Base+0x363>
 804a11e:	00 00                	add    BYTE PTR [eax],al
 804a120:	b8 e6 ff ff 3b       	mov    eax,0x3bffffe6
 804a125:	00 00                	add    BYTE PTR [eax],al
 804a127:	00 00                	add    BYTE PTR [eax],al
 804a129:	41                   	inc    ecx
 804a12a:	0e                   	push   cs
 804a12b:	08 85 02 42 0d 05    	or     BYTE PTR [ebp+0x50d4202],al
 804a131:	77 c5                	ja     804a0f8 <_IO_stdin_used@@Base+0x33c>
 804a133:	0c 04                	or     al,0x4
 804a135:	04 00                	add    al,0x0
 804a137:	00 1c 00             	add    BYTE PTR [eax+eax*1],bl
 804a13a:	00 00                	add    BYTE PTR [eax],al
 804a13c:	00 02                	add    BYTE PTR [edx],al
 804a13e:	00 00                	add    BYTE PTR [eax],al
 804a140:	d3 e6                	shl    esi,cl
 804a142:	ff                   	(bad)  
 804a143:	ff 21                	jmp    DWORD PTR [ecx]
 804a145:	00 00                	add    BYTE PTR [eax],al
 804a147:	00 00                	add    BYTE PTR [eax],al
 804a149:	41                   	inc    ecx
 804a14a:	0e                   	push   cs
 804a14b:	08 85 02 42 0d 05    	or     BYTE PTR [ebp+0x50d4202],al
 804a151:	5d                   	pop    ebp
 804a152:	c5 0c 04             	lds    ecx,FWORD PTR [esp+eax*1]
 804a155:	04 00                	add    al,0x0
 804a157:	00 1c 00             	add    BYTE PTR [eax+eax*1],bl
 804a15a:	00 00                	add    BYTE PTR [eax],al
 804a15c:	20 02                	and    BYTE PTR [edx],al
 804a15e:	00 00                	add    BYTE PTR [eax],al
 804a160:	d4 e6                	aam    0xe6
 804a162:	ff                   	(bad)  
 804a163:	ff 47 00             	inc    DWORD PTR [edi+0x0]
 804a166:	00 00                	add    BYTE PTR [eax],al
 804a168:	00 41 0e             	add    BYTE PTR [ecx+0xe],al
 804a16b:	08 85 02 42 0d 05    	or     BYTE PTR [ebp+0x50d4202],al
 804a171:	02 43 c5             	add    al,BYTE PTR [ebx-0x3b]
 804a174:	0c 04                	or     al,0x4
 804a176:	04 00                	add    al,0x0
 804a178:	1c 00                	sbb    al,0x0
 804a17a:	00 00                	add    BYTE PTR [eax],al
 804a17c:	40                   	inc    eax
 804a17d:	02 00                	add    al,BYTE PTR [eax]
 804a17f:	00 fb                	add    bl,bh
 804a181:	e6 ff                	out    0xff,al
 804a183:	ff                   	(bad)  
 804a184:	3b 00                	cmp    eax,DWORD PTR [eax]
 804a186:	00 00                	add    BYTE PTR [eax],al
 804a188:	00 41 0e             	add    BYTE PTR [ecx+0xe],al
 804a18b:	08 85 02 42 0d 05    	or     BYTE PTR [ebp+0x50d4202],al
 804a191:	77 c5                	ja     804a158 <_IO_stdin_used@@Base+0x39c>
 804a193:	0c 04                	or     al,0x4
 804a195:	04 00                	add    al,0x0
 804a197:	00 1c 00             	add    BYTE PTR [eax+eax*1],bl
 804a19a:	00 00                	add    BYTE PTR [eax],al
 804a19c:	60                   	pusha  
 804a19d:	02 00                	add    al,BYTE PTR [eax]
 804a19f:	00 16                	add    BYTE PTR [esi],dl
 804a1a1:	e7 ff                	out    0xff,eax
 804a1a3:	ff                   	(bad)  
 804a1a4:	3b 00                	cmp    eax,DWORD PTR [eax]
 804a1a6:	00 00                	add    BYTE PTR [eax],al
 804a1a8:	00 41 0e             	add    BYTE PTR [ecx+0xe],al
 804a1ab:	08 85 02 42 0d 05    	or     BYTE PTR [ebp+0x50d4202],al
 804a1b1:	77 c5                	ja     804a178 <_IO_stdin_used@@Base+0x3bc>
 804a1b3:	0c 04                	or     al,0x4
 804a1b5:	04 00                	add    al,0x0
 804a1b7:	00 1c 00             	add    BYTE PTR [eax+eax*1],bl
 804a1ba:	00 00                	add    BYTE PTR [eax],al
 804a1bc:	80 02 00             	add    BYTE PTR [edx],0x0
 804a1bf:	00 31                	add    BYTE PTR [ecx],dh
 804a1c1:	e7 ff                	out    0xff,eax
 804a1c3:	ff                   	(bad)  
 804a1c4:	3b 00                	cmp    eax,DWORD PTR [eax]
 804a1c6:	00 00                	add    BYTE PTR [eax],al
 804a1c8:	00 41 0e             	add    BYTE PTR [ecx+0xe],al
 804a1cb:	08 85 02 42 0d 05    	or     BYTE PTR [ebp+0x50d4202],al
 804a1d1:	77 c5                	ja     804a198 <_IO_stdin_used@@Base+0x3dc>
 804a1d3:	0c 04                	or     al,0x4
 804a1d5:	04 00                	add    al,0x0
 804a1d7:	00 1c 00             	add    BYTE PTR [eax+eax*1],bl
 804a1da:	00 00                	add    BYTE PTR [eax],al
 804a1dc:	a0 02 00 00 4c       	mov    al,ds:0x4c000002
 804a1e1:	e7 ff                	out    0xff,eax
 804a1e3:	ff                   	(bad)  
 804a1e4:	3b 00                	cmp    eax,DWORD PTR [eax]
 804a1e6:	00 00                	add    BYTE PTR [eax],al
 804a1e8:	00 41 0e             	add    BYTE PTR [ecx+0xe],al
 804a1eb:	08 85 02 42 0d 05    	or     BYTE PTR [ebp+0x50d4202],al
 804a1f1:	77 c5                	ja     804a1b8 <_IO_stdin_used@@Base+0x3fc>
 804a1f3:	0c 04                	or     al,0x4
 804a1f5:	04 00                	add    al,0x0
 804a1f7:	00 1c 00             	add    BYTE PTR [eax+eax*1],bl
 804a1fa:	00 00                	add    BYTE PTR [eax],al
 804a1fc:	c0 02 00             	rol    BYTE PTR [edx],0x0
 804a1ff:	00 67 e7             	add    BYTE PTR [edi-0x19],ah
 804a202:	ff                   	(bad)  
 804a203:	ff 24 00             	jmp    DWORD PTR [eax+eax*1]
 804a206:	00 00                	add    BYTE PTR [eax],al
 804a208:	00 41 0e             	add    BYTE PTR [ecx+0xe],al
 804a20b:	08 85 02 42 0d 05    	or     BYTE PTR [ebp+0x50d4202],al
 804a211:	60                   	pusha  
 804a212:	c5 0c 04             	lds    ecx,FWORD PTR [esp+eax*1]
 804a215:	04 00                	add    al,0x0
 804a217:	00 1c 00             	add    BYTE PTR [eax+eax*1],bl
 804a21a:	00 00                	add    BYTE PTR [eax],al
 804a21c:	e0 02                	loopne 804a220 <_IO_stdin_used@@Base+0x464>
 804a21e:	00 00                	add    BYTE PTR [eax],al
 804a220:	6b e7 ff             	imul   esp,edi,0xffffffff
 804a223:	ff f7                	push   edi
 804a225:	12 00                	adc    al,BYTE PTR [eax]
 804a227:	00 00                	add    BYTE PTR [eax],al
 804a229:	41                   	inc    ecx
 804a22a:	0e                   	push   cs
 804a22b:	08 85 02 42 0d 05    	or     BYTE PTR [ebp+0x50d4202],al
 804a231:	03 f3                	add    esi,ebx
 804a233:	12 c5                	adc    al,ch
 804a235:	0c 04                	or     al,0x4
 804a237:	04 24                	add    al,0x24
 804a239:	00 00                	add    BYTE PTR [eax],al
 804a23b:	00 00                	add    BYTE PTR [eax],al
 804a23d:	03 00                	add    eax,DWORD PTR [eax]
 804a23f:	00 42 fa             	add    BYTE PTR [edx-0x6],al
 804a242:	ff                   	(bad)  
 804a243:	ff 60 00             	jmp    DWORD PTR [eax+0x0]
 804a246:	00 00                	add    BYTE PTR [eax],al
 804a248:	00 41 0e             	add    BYTE PTR [ecx+0xe],al
 804a24b:	08 85 02 42 0d 05    	or     BYTE PTR [ebp+0x50d4202],al
 804a251:	60                   	pusha  
 804a252:	83 04 87 03          	add    DWORD PTR [edi+eax*4],0x3
 804a256:	7a c3                	jp     804a21b <_IO_stdin_used@@Base+0x45f>
 804a258:	41                   	inc    ecx
 804a259:	c7 41 0c 04 04 c5 00 	mov    DWORD PTR [ecx+0xc],0xc50404
 804a260:	38 00                	cmp    BYTE PTR [eax],al
 804a262:	00 00                	add    BYTE PTR [eax],al
 804a264:	28 03                	sub    BYTE PTR [ebx],al
 804a266:	00 00                	add    BYTE PTR [eax],al
 804a268:	88 fa                	mov    dl,bh
 804a26a:	ff                   	(bad)  
 804a26b:	ff 61 00             	jmp    DWORD PTR [ecx+0x0]
 804a26e:	00 00                	add    BYTE PTR [eax],al
 804a270:	00 41 0e             	add    BYTE PTR [ecx+0xe],al
 804a273:	08 85 02 41 0e 0c    	or     BYTE PTR [ebp+0xc0e4102],al
 804a279:	87 03                	xchg   DWORD PTR [ebx],eax
 804a27b:	41                   	inc    ecx
 804a27c:	0e                   	push   cs
 804a27d:	10 86 04 41 0e 14    	adc    BYTE PTR [esi+0x140e4104],al
 804a283:	83 05 4e 0e 30 02 4a 	add    DWORD PTR ds:0x2300e4e,0x4a
 804a28a:	0e                   	push   cs
 804a28b:	14 41                	adc    al,0x41
 804a28d:	0e                   	push   cs
 804a28e:	10 c3                	adc    bl,al
 804a290:	41                   	inc    ecx
 804a291:	0e                   	push   cs
 804a292:	0c c6                	or     al,0xc6
 804a294:	41                   	inc    ecx
 804a295:	0e                   	push   cs
 804a296:	08 c7                	or     bh,al
 804a298:	41                   	inc    ecx
 804a299:	0e                   	push   cs
 804a29a:	04 c5                	add    al,0xc5
 804a29c:	10 00                	adc    BYTE PTR [eax],al
 804a29e:	00 00                	add    BYTE PTR [eax],al
 804a2a0:	64 03 00             	add    eax,DWORD PTR fs:[eax]
 804a2a3:	00 bc fa ff ff 02 00 	add    BYTE PTR [edx+edi*8+0x2ffff],bh
 804a2aa:	00 00                	add    BYTE PTR [eax],al
 804a2ac:	00 00                	add    BYTE PTR [eax],al
 804a2ae:	00 00                	add    BYTE PTR [eax],al
 804a2b0:	10 00                	adc    BYTE PTR [eax],al
 804a2b2:	00 00                	add    BYTE PTR [eax],al
 804a2b4:	78 03                	js     804a2b9 <_IO_stdin_used@@Base+0x4fd>
 804a2b6:	00 00                	add    BYTE PTR [eax],al
 804a2b8:	aa                   	stos   BYTE PTR es:[edi],al
 804a2b9:	fa                   	cli    
 804a2ba:	ff                   	(bad)  
 804a2bb:	ff 04 00             	inc    DWORD PTR [eax+eax*1]
	...

Disassembly of section .ctors:

0804bf14 <.ctors>:
 804bf14:	ff                   	(bad)  
 804bf15:	ff                   	(bad)  
 804bf16:	ff                   	(bad)  
 804bf17:	ff 00                	inc    DWORD PTR [eax]
 804bf19:	00 00                	add    BYTE PTR [eax],al
	...

Disassembly of section .dtors:

0804bf1c <.dtors>:
 804bf1c:	ff                   	(bad)  
 804bf1d:	ff                   	(bad)  
 804bf1e:	ff                   	(bad)  
 804bf1f:	ff 00                	inc    DWORD PTR [eax]
 804bf21:	00 00                	add    BYTE PTR [eax],al
	...

Disassembly of section .jcr:

0804bf24 <.jcr>:
 804bf24:	00 00                	add    BYTE PTR [eax],al
	...

Disassembly of section .dynamic:

0804bf28 <.dynamic>:
 804bf28:	01 00                	add    DWORD PTR [eax],eax
 804bf2a:	00 00                	add    BYTE PTR [eax],al
 804bf2c:	10 00                	adc    BYTE PTR [eax],al
 804bf2e:	00 00                	add    BYTE PTR [eax],al
 804bf30:	0c 00                	or     al,0x0
 804bf32:	00 00                	add    BYTE PTR [eax],al
 804bf34:	4c                   	dec    esp
 804bf35:	84 04 08             	test   BYTE PTR [eax+ecx*1],al
 804bf38:	0d 00 00 00 9c       	or     eax,0x9c000000
 804bf3d:	9d                   	popf   
 804bf3e:	04 08                	add    al,0x8
 804bf40:	f5                   	cmc    
 804bf41:	fe                   	(bad)  
 804bf42:	ff 6f ac             	jmp    FWORD PTR [edi-0x54]
 804bf45:	81 04 08 05 00 00 00 	add    DWORD PTR [eax+ecx*1],0x5
 804bf4c:	c8 82 04 08          	enter  0x482,0x8
 804bf50:	06                   	push   es
 804bf51:	00 00                	add    BYTE PTR [eax],al
 804bf53:	00 d8                	add    al,bl
 804bf55:	81 04 08 0a 00 00 00 	add    DWORD PTR [eax+ecx*1],0xa
 804bf5c:	b4 00                	mov    ah,0x0
 804bf5e:	00 00                	add    BYTE PTR [eax],al
 804bf60:	0b 00                	or     eax,DWORD PTR [eax]
 804bf62:	00 00                	add    BYTE PTR [eax],al
 804bf64:	10 00                	adc    BYTE PTR [eax],al
 804bf66:	00 00                	add    BYTE PTR [eax],al
 804bf68:	15 00 00 00 00       	adc    eax,0x0
 804bf6d:	00 00                	add    BYTE PTR [eax],al
 804bf6f:	00 03                	add    BYTE PTR [ebx],al
 804bf71:	00 00                	add    BYTE PTR [eax],al
 804bf73:	00 f4                	add    ah,dh
 804bf75:	bf 04 08 02 00       	mov    edi,0x20804
 804bf7a:	00 00                	add    BYTE PTR [eax],al
 804bf7c:	58                   	pop    eax
 804bf7d:	00 00                	add    BYTE PTR [eax],al
 804bf7f:	00 14 00             	add    BYTE PTR [eax+eax*1],dl
 804bf82:	00 00                	add    BYTE PTR [eax],al
 804bf84:	11 00                	adc    DWORD PTR [eax],eax
 804bf86:	00 00                	add    BYTE PTR [eax],al
 804bf88:	17                   	pop    ss
 804bf89:	00 00                	add    BYTE PTR [eax],al
 804bf8b:	00 f4                	add    ah,dh
 804bf8d:	83 04 08 11          	add    DWORD PTR [eax+ecx*1],0x11
 804bf91:	00 00                	add    BYTE PTR [eax],al
 804bf93:	00 dc                	add    ah,bl
 804bf95:	83 04 08 12          	add    DWORD PTR [eax+ecx*1],0x12
 804bf99:	00 00                	add    BYTE PTR [eax],al
 804bf9b:	00 18                	add    BYTE PTR [eax],bl
 804bf9d:	00 00                	add    BYTE PTR [eax],al
 804bf9f:	00 13                	add    BYTE PTR [ebx],dl
 804bfa1:	00 00                	add    BYTE PTR [eax],al
 804bfa3:	00 08                	add    BYTE PTR [eax],cl
 804bfa5:	00 00                	add    BYTE PTR [eax],al
 804bfa7:	00 fe                	add    dh,bh
 804bfa9:	ff                   	(bad)  
 804bfaa:	ff 6f 9c             	jmp    FWORD PTR [edi-0x64]
 804bfad:	83 04 08 ff          	add    DWORD PTR [eax+ecx*1],0xffffffff
 804bfb1:	ff                   	(bad)  
 804bfb2:	ff 6f 01             	jmp    FWORD PTR [edi+0x1]
 804bfb5:	00 00                	add    BYTE PTR [eax],al
 804bfb7:	00 f0                	add    al,dh
 804bfb9:	ff                   	(bad)  
 804bfba:	ff 6f 7c             	jmp    FWORD PTR [edi+0x7c]
 804bfbd:	83 04 08 00          	add    DWORD PTR [eax+ecx*1],0x0
	...

Disassembly of section .got:

0804bff0 <.got>:
 804bff0:	00 00                	add    BYTE PTR [eax],al
	...

Disassembly of section .got.plt:

0804bff4 <.got.plt>:
 804bff4:	28 bf 04 08 00 00    	sub    BYTE PTR [edi+0x804],bh
 804bffa:	00 00                	add    BYTE PTR [eax],al
 804bffc:	00 00                	add    BYTE PTR [eax],al
 804bffe:	00 00                	add    BYTE PTR [eax],al
 804c000:	96                   	xchg   esi,eax
 804c001:	84 04 08             	test   BYTE PTR [eax+ecx*1],al
 804c004:	a6                   	cmps   BYTE PTR ds:[esi],BYTE PTR es:[edi]
 804c005:	84 04 08             	test   BYTE PTR [eax+ecx*1],al
 804c008:	b6 84                	mov    dh,0x84
 804c00a:	04 08                	add    al,0x8
 804c00c:	c6 84 04 08 d6 84 04 	mov    BYTE PTR [esp+eax*1+0x484d608],0x8
 804c013:	08 
 804c014:	e6 84                	out    0x84,al
 804c016:	04 08                	add    al,0x8
 804c018:	f6 84 04 08 06 85 04 	test   BYTE PTR [esp+eax*1+0x4850608],0x8
 804c01f:	08 
 804c020:	16                   	push   ss
 804c021:	85 04 08             	test   DWORD PTR [eax+ecx*1],eax
 804c024:	26 85 04 08          	test   DWORD PTR es:[eax+ecx*1],eax
 804c028:	36 85 04 08          	test   DWORD PTR ss:[eax+ecx*1],eax

Disassembly of section .data:

0804c040 <.data>:
	...
 804c060:	7c 86                	jl     804bfe8 <_IO_stdin_used@@Base+0x222c>
 804c062:	04 08                	add    al,0x8
 804c064:	ad                   	lods   eax,DWORD PTR ds:[esi]
 804c065:	86 04 08             	xchg   BYTE PTR [eax+ecx*1],al
 804c068:	d4 86                	aam    0x86
 804c06a:	04 08                	add    al,0x8
 804c06c:	a9 87 04 08 fb       	test   eax,0xfb080487
 804c071:	86 04 08             	xchg   BYTE PTR [eax+ecx*1],al
 804c074:	1b 87 04 08 4e 87    	sbb    eax,DWORD PTR [edi-0x78b1f7fc]
 804c07a:	04 08                	add    al,0x8
 804c07c:	d8 87 04 08 19 86    	fadd   DWORD PTR [edi-0x79e6f7fc]
 804c082:	04 08                	add    al,0x8
 804c084:	13 88 04 08 34 88    	adc    ecx,DWORD PTR [eax-0x77cbf7fc]
 804c08a:	04 08                	add    al,0x8
 804c08c:	7b 88                	jnp    804c016 <_IO_stdin_used@@Base+0x225a>
 804c08e:	04 08                	add    al,0x8
 804c090:	b6 88                	mov    dh,0x88
 804c092:	04 08                	add    al,0x8
 804c094:	f1                   	icebp  
 804c095:	88 04 08             	mov    BYTE PTR [eax+ecx*1],al
 804c098:	2c 89                	sub    al,0x89
 804c09a:	04 08                	add    al,0x8
 804c09c:	60                   	pusha  
 804c09d:	86 04 08             	xchg   BYTE PTR [eax+ecx*1],al
 804c0a0:	6a 86                	push   0xffffff86
 804c0a2:	04 08                	add    al,0x8
 804c0a4:	67 89 04             	mov    DWORD PTR [si],eax
 804c0a7:	08 00                	or     BYTE PTR [eax],al
	...
 804d0bd:	00 00                	add    BYTE PTR [eax],al
 804d0bf:	00 18                	add    BYTE PTR [eax],bl
 804d0c1:	01 00                	add    DWORD PTR [eax],eax
 804d0c3:	3a 10                	cmp    dl,BYTE PTR [eax]
 804d0c5:	00 00                	add    BYTE PTR [eax],al
 804d0c7:	18 01                	sbb    BYTE PTR [ecx],al
 804d0c9:	01 db                	add    ebx,ebx
 804d0cb:	1e                   	push   ds
 804d0cc:	00 00                	add    BYTE PTR [eax],al
 804d0ce:	18 00                	sbb    BYTE PTR [eax],al
 804d0d0:	03 00                	add    eax,DWORD PTR [eax]
 804d0d2:	18 01                	sbb    BYTE PTR [ecx],al
 804d0d4:	05 42 cf 74 01       	add    eax,0x174cf42
 804d0d9:	1b 04 03             	sbb    eax,DWORD PTR [ebx+eax*1]
 804d0dc:	06                   	push   es
 804d0dd:	00 04 04             	add    BYTE PTR [esp+eax*1],al
 804d0e0:	05 1c 03 04 02       	add    eax,0x204031c
 804d0e5:	01 03                	add    DWORD PTR [ebx],eax
 804d0e7:	03 04 00             	add    eax,DWORD PTR [eax+eax*1]
 804d0ea:	00 00                	add    BYTE PTR [eax],al
 804d0ec:	17                   	pop    ss
 804d0ed:	00 01                	add    BYTE PTR [ecx],al
 804d0ef:	03 14 19             	add    edx,DWORD PTR [ecx+ebx*1]
 804d0f2:	10 00                	adc    BYTE PTR [eax],al
 804d0f4:	00 0e                	add    BYTE PTR [esi],cl
 804d0f6:	3a 10                	cmp    dl,BYTE PTR [eax]
 804d0f8:	00 00                	add    BYTE PTR [eax],al
 804d0fa:	4c                   	dec    esp
 804d0fb:	0f 6f 01             	movq   mm0,QWORD PTR [ecx]
 804d0fe:	42                   	inc    edx
 804d0ff:	ef                   	out    dx,eax
 804d100:	74 00                	je     804d102 <_IO_stdin_used@@Base+0x3346>
 804d102:	62                   	(bad)  
 804d103:	ce                   	into   
 804d104:	75 21                	jne    804d127 <_IO_stdin_used@@Base+0x336b>
 804d106:	40                   	inc    eax
 804d107:	ce                   	into   
 804d108:	54                   	push   esp
 804d109:	02 43 ef             	add    al,BYTE PTR [ebx-0x11]
 804d10c:	70 00                	jo     804d10e <_IO_stdin_used@@Base+0x3352>
 804d10e:	62                   	(bad)  
 804d10f:	ca 75 21             	retf   0x2175
 804d112:	44                   	inc    esp
 804d113:	ce                   	into   
 804d114:	54                   	push   esp
 804d115:	06                   	push   es
 804d116:	43                   	inc    ebx
 804d117:	ef                   	out    dx,eax
 804d118:	7c 00                	jl     804d11a <_IO_stdin_used@@Base+0x335e>
 804d11a:	62                   	(bad)  
 804d11b:	c6                   	(bad)  
 804d11c:	75 21                	jne    804d13f <_IO_stdin_used@@Base+0x3383>
 804d11e:	48                   	dec    eax
 804d11f:	ce                   	into   
 804d120:	54                   	push   esp
 804d121:	0a 43 ef             	or     al,BYTE PTR [ebx-0x11]
 804d124:	78 00                	js     804d126 <_IO_stdin_used@@Base+0x336a>
 804d126:	62 c2 75 21 4c ce    	vrcp14ps ymm1{k1},ymm6
 804d12c:	54                   	push   esp
 804d12d:	0e                   	push   cs
 804d12e:	43                   	inc    ebx
 804d12f:	ef                   	out    dx,eax
 804d130:	64 00 55 cf          	add    BYTE PTR fs:[ebp-0x31],dl
 804d134:	74 01                	je     804d137 <_IO_stdin_used@@Base+0x337b>
 804d136:	52                   	push   edx
 804d137:	b3 64                	mov    bl,0x64
 804d139:	01 42 ce             	add    DWORD PTR [edx-0x32],eax
 804d13c:	69 21 53 ce 6a 01    	imul   esp,DWORD PTR [ecx],0x16ace53
 804d142:	5c                   	pop    esp
 804d143:	d1                   	(bad)  
 804d144:	74 1c                	je     804d162 <_IO_stdin_used@@Base+0x33a6>
 804d146:	5a                   	pop    edx
 804d147:	cf                   	iret   
 804d148:	6a 00                	push   0x0
 804d14a:	46                   	inc    esi
 804d14b:	cf                   	iret   
 804d14c:	74 1f                	je     804d16d <_IO_stdin_used@@Base+0x33b1>
 804d14e:	42                   	inc    edx
 804d14f:	cd 75                	int    0x75
 804d151:	01 42 c7             	add    DWORD PTR [edx-0x39],eax
 804d154:	74 01                	je     804d157 <_IO_stdin_used@@Base+0x339b>
 804d156:	42                   	inc    edx
 804d157:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d158:	74 1c                	je     804d176 <_IO_stdin_used@@Base+0x33ba>
 804d15a:	42                   	inc    edx
 804d15b:	ef                   	out    dx,eax
 804d15c:	65 17                	gs pop ss
 804d15e:	42                   	inc    edx
 804d15f:	cf                   	iret   
 804d160:	74 11                	je     804d173 <_IO_stdin_used@@Base+0x33b7>
 804d162:	80 df 74             	sbb    bh,0x74
 804d165:	01 5a cf             	add    DWORD PTR [edx-0x31],ebx
 804d168:	70 1c                	jo     804d186 <_IO_stdin_used@@Base+0x33ca>
 804d16a:	4f                   	dec    edi
 804d16b:	ce                   	into   
 804d16c:	70 05                	jo     804d173 <_IO_stdin_used@@Base+0x33b7>
 804d16e:	41                   	inc    ecx
 804d16f:	cf                   	iret   
 804d170:	74 01                	je     804d173 <_IO_stdin_used@@Base+0x33b7>
 804d172:	5e                   	pop    esi
 804d173:	cf                   	iret   
 804d174:	70 03                	jo     804d179 <_IO_stdin_used@@Base+0x33bd>
 804d176:	43                   	inc    ebx
 804d177:	cf                   	iret   
 804d178:	74 09                	je     804d183 <_IO_stdin_used@@Base+0x33c7>
 804d17a:	42                   	inc    edx
 804d17b:	cf                   	iret   
 804d17c:	74 1e                	je     804d19c <_IO_stdin_used@@Base+0x33e0>
 804d17e:	5f                   	pop    edi
 804d17f:	d0 6a 00             	shr    BYTE PTR [edx+0x0],1
 804d182:	5f                   	pop    edi
 804d183:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d184:	75 01                	jne    804d187 <_IO_stdin_used@@Base+0x33cb>
 804d186:	01 cf                	add    edi,ecx
 804d188:	74 01                	je     804d18b <_IO_stdin_used@@Base+0x33cf>
 804d18a:	4d                   	dec    ebp
 804d18b:	f0 64 01 42 d7       	lock add DWORD PTR fs:[edx-0x29],eax
 804d190:	75 01                	jne    804d193 <_IO_stdin_used@@Base+0x33d7>
 804d192:	2d cf 74 01 4d       	sub    eax,0x4d0174cf
 804d197:	f0 64 01 42 d7       	lock add DWORD PTR fs:[edx-0x29],eax
 804d19c:	75 01                	jne    804d19f <_IO_stdin_used@@Base+0x33e3>
 804d19e:	2c cf                	sub    al,0xcf
 804d1a0:	74 01                	je     804d1a3 <_IO_stdin_used@@Base+0x33e7>
 804d1a2:	4d                   	dec    ebp
 804d1a3:	f0 64 01 42 d7       	lock add DWORD PTR fs:[edx-0x29],eax
 804d1a8:	75 01                	jne    804d1ab <_IO_stdin_used@@Base+0x33ef>
 804d1aa:	25 cf 74 01 4d       	and    eax,0x4d0174cf
 804d1af:	f0 64 01 42 d7       	lock add DWORD PTR fs:[edx-0x29],eax
 804d1b4:	75 01                	jne    804d1b7 <_IO_stdin_used@@Base+0x33fb>
 804d1b6:	30 cf                	xor    bh,cl
 804d1b8:	74 01                	je     804d1bb <_IO_stdin_used@@Base+0x33ff>
 804d1ba:	4d                   	dec    ebp
 804d1bb:	f0 64 01 42 d7       	lock add DWORD PTR fs:[edx-0x29],eax
 804d1c0:	75 01                	jne    804d1c3 <_IO_stdin_used@@Base+0x3407>
 804d1c2:	23 cf                	and    ecx,edi
 804d1c4:	74 01                	je     804d1c7 <_IO_stdin_used@@Base+0x340b>
 804d1c6:	4d                   	dec    ebp
 804d1c7:	f0 64 01 42 d7       	lock add DWORD PTR fs:[edx-0x29],eax
 804d1cc:	75 01                	jne    804d1cf <_IO_stdin_used@@Base+0x3413>
 804d1ce:	36 cf                	ss iret 
 804d1d0:	74 01                	je     804d1d3 <_IO_stdin_used@@Base+0x3417>
 804d1d2:	4d                   	dec    ebp
 804d1d3:	f0 64 01 42 d7       	lock add DWORD PTR fs:[edx-0x29],eax
 804d1d8:	75 01                	jne    804d1db <_IO_stdin_used@@Base+0x341f>
 804d1da:	37                   	aaa    
 804d1db:	cf                   	iret   
 804d1dc:	74 01                	je     804d1df <_IO_stdin_used@@Base+0x3423>
 804d1de:	4d                   	dec    ebp
 804d1df:	f0 64 01 42 d7       	lock add DWORD PTR fs:[edx-0x29],eax
 804d1e4:	75 01                	jne    804d1e7 <_IO_stdin_used@@Base+0x342b>
 804d1e6:	2e cf                	cs iret 
 804d1e8:	74 01                	je     804d1eb <_IO_stdin_used@@Base+0x342f>
 804d1ea:	4d                   	dec    ebp
 804d1eb:	f0 64 01 42 d7       	lock add DWORD PTR fs:[edx-0x29],eax
 804d1f0:	75 01                	jne    804d1f3 <_IO_stdin_used@@Base+0x3437>
 804d1f2:	23 cf                	and    ecx,edi
 804d1f4:	74 01                	je     804d1f7 <_IO_stdin_used@@Base+0x343b>
 804d1f6:	4d                   	dec    ebp
 804d1f7:	f0 64 01 42 d7       	lock add DWORD PTR fs:[edx-0x29],eax
 804d1fc:	75 01                	jne    804d1ff <_IO_stdin_used@@Base+0x3443>
 804d1fe:	36 cf                	ss iret 
 804d200:	74 01                	je     804d203 <_IO_stdin_used@@Base+0x3447>
 804d202:	4d                   	dec    ebp
 804d203:	f0 64 01 42 d7       	lock add DWORD PTR fs:[edx-0x29],eax
 804d208:	75 01                	jne    804d20b <_IO_stdin_used@@Base+0x344f>
 804d20a:	2b cf                	sub    ecx,edi
 804d20c:	74 01                	je     804d20f <_IO_stdin_used@@Base+0x3453>
 804d20e:	4d                   	dec    ebp
 804d20f:	f0 64 01 42 d7       	lock add DWORD PTR fs:[edx-0x29],eax
 804d214:	75 01                	jne    804d217 <_IO_stdin_used@@Base+0x345b>
 804d216:	2d cf 74 01 4d       	sub    eax,0x4d0174cf
 804d21b:	f0 64 01 42 d7       	lock add DWORD PTR fs:[edx-0x29],eax
 804d220:	75 01                	jne    804d223 <_IO_stdin_used@@Base+0x3467>
 804d222:	2c cf                	sub    al,0xcf
 804d224:	74 01                	je     804d227 <_IO_stdin_used@@Base+0x346b>
 804d226:	4d                   	dec    ebp
 804d227:	f0 64 01 42 d7       	lock add DWORD PTR fs:[edx-0x29],eax
 804d22c:	75 01                	jne    804d22f <_IO_stdin_used@@Base+0x3473>
 804d22e:	31 cf                	xor    edi,ecx
 804d230:	74 01                	je     804d233 <_IO_stdin_used@@Base+0x3477>
 804d232:	4d                   	dec    ebp
 804d233:	f0 64 01 42 d7       	lock add DWORD PTR fs:[edx-0x29],eax
 804d238:	75 01                	jne    804d23b <_IO_stdin_used@@Base+0x347f>
 804d23a:	63 cf                	arpl   di,cx
 804d23c:	74 01                	je     804d23f <_IO_stdin_used@@Base+0x3483>
 804d23e:	4d                   	dec    ebp
 804d23f:	f0 64 01 42 d7       	lock add DWORD PTR fs:[edx-0x29],eax
 804d244:	75 01                	jne    804d247 <_IO_stdin_used@@Base+0x348b>
 804d246:	48                   	dec    eax
 804d247:	cf                   	iret   
 804d248:	74 01                	je     804d24b <_IO_stdin_used@@Base+0x348f>
 804d24a:	4d                   	dec    ebp
 804d24b:	f0 64 01 42 ce       	lock add DWORD PTR fs:[edx-0x32],eax
 804d250:	69 1c 5a ce 74 52 42 	imul   ebx,DWORD PTR [edx+ebx*2],0x425274ce
 804d257:	cf                   	iret   
 804d258:	74 0e                	je     804d268 <_IO_stdin_used@@Base+0x34ac>
 804d25a:	7d df                	jge    804d23b <_IO_stdin_used@@Base+0x347f>
 804d25c:	74 01                	je     804d25f <_IO_stdin_used@@Base+0x34a3>
 804d25e:	5a                   	pop    edx
 804d25f:	ce                   	into   
 804d260:	74 6e                	je     804d2d0 <_IO_stdin_used@@Base+0x3514>
 804d262:	42                   	inc    edx
 804d263:	cf                   	iret   
 804d264:	74 0e                	je     804d274 <_IO_stdin_used@@Base+0x34b8>
 804d266:	7d df                	jge    804d247 <_IO_stdin_used@@Base+0x348b>
 804d268:	74 01                	je     804d26b <_IO_stdin_used@@Base+0x34af>
 804d26a:	5a                   	pop    edx
 804d26b:	ce                   	into   
 804d26c:	74 73                	je     804d2e1 <_IO_stdin_used@@Base+0x3525>
 804d26e:	42                   	inc    edx
 804d26f:	cf                   	iret   
 804d270:	74 0e                	je     804d280 <_IO_stdin_used@@Base+0x34c4>
 804d272:	7d df                	jge    804d253 <_IO_stdin_used@@Base+0x3497>
 804d274:	74 01                	je     804d277 <_IO_stdin_used@@Base+0x34bb>
 804d276:	5a                   	pop    edx
 804d277:	ce                   	into   
 804d278:	74 73                	je     804d2ed <_IO_stdin_used@@Base+0x3531>
 804d27a:	42                   	inc    edx
 804d27b:	cf                   	iret   
 804d27c:	74 0e                	je     804d28c <_IO_stdin_used@@Base+0x34d0>
 804d27e:	7d df                	jge    804d25f <_IO_stdin_used@@Base+0x34a3>
 804d280:	74 01                	je     804d283 <_IO_stdin_used@@Base+0x34c7>
 804d282:	5a                   	pop    edx
 804d283:	ce                   	into   
 804d284:	74 78                	je     804d2fe <_IO_stdin_used@@Base+0x3542>
 804d286:	42                   	inc    edx
 804d287:	cf                   	iret   
 804d288:	74 0e                	je     804d298 <_IO_stdin_used@@Base+0x34dc>
 804d28a:	7d df                	jge    804d26b <_IO_stdin_used@@Base+0x34af>
 804d28c:	74 01                	je     804d28f <_IO_stdin_used@@Base+0x34d3>
 804d28e:	5a                   	pop    edx
 804d28f:	ce                   	into   
 804d290:	74 2d                	je     804d2bf <_IO_stdin_used@@Base+0x3503>
 804d292:	42                   	inc    edx
 804d293:	cf                   	iret   
 804d294:	74 0e                	je     804d2a4 <_IO_stdin_used@@Base+0x34e8>
 804d296:	7d df                	jge    804d277 <_IO_stdin_used@@Base+0x34bb>
 804d298:	74 01                	je     804d29b <_IO_stdin_used@@Base+0x34df>
 804d29a:	5a                   	pop    edx
 804d29b:	ce                   	into   
 804d29c:	74 21                	je     804d2bf <_IO_stdin_used@@Base+0x3503>
 804d29e:	42                   	inc    edx
 804d29f:	cf                   	iret   
 804d2a0:	74 0e                	je     804d2b0 <_IO_stdin_used@@Base+0x34f4>
 804d2a2:	7d df                	jge    804d283 <_IO_stdin_used@@Base+0x34c7>
 804d2a4:	74 01                	je     804d2a7 <_IO_stdin_used@@Base+0x34eb>
 804d2a6:	5a                   	pop    edx
 804d2a7:	ce                   	into   
 804d2a8:	74 76                	je     804d320 <_IO_stdin_used@@Base+0x3564>
 804d2aa:	42                   	inc    edx
 804d2ab:	cf                   	iret   
 804d2ac:	74 0e                	je     804d2bc <_IO_stdin_used@@Base+0x3500>
 804d2ae:	7d df                	jge    804d28f <_IO_stdin_used@@Base+0x34d3>
 804d2b0:	74 01                	je     804d2b3 <_IO_stdin_used@@Base+0x34f7>
 804d2b2:	5a                   	pop    edx
 804d2b3:	ce                   	into   
 804d2b4:	74 73                	je     804d329 <_IO_stdin_used@@Base+0x356d>
 804d2b6:	42                   	inc    edx
 804d2b7:	cf                   	iret   
 804d2b8:	74 0e                	je     804d2c8 <_IO_stdin_used@@Base+0x350c>
 804d2ba:	7d df                	jge    804d29b <_IO_stdin_used@@Base+0x34df>
 804d2bc:	74 01                	je     804d2bf <_IO_stdin_used@@Base+0x3503>
 804d2be:	5a                   	pop    edx
 804d2bf:	ce                   	into   
 804d2c0:	74 6e                	je     804d330 <_IO_stdin_used@@Base+0x3574>
 804d2c2:	42                   	inc    edx
 804d2c3:	cf                   	iret   
 804d2c4:	74 0e                	je     804d2d4 <_IO_stdin_used@@Base+0x3518>
 804d2c6:	7d df                	jge    804d2a7 <_IO_stdin_used@@Base+0x34eb>
 804d2c8:	74 01                	je     804d2cb <_IO_stdin_used@@Base+0x350f>
 804d2ca:	5a                   	pop    edx
 804d2cb:	ce                   	into   
 804d2cc:	74 6f                	je     804d33d <_IO_stdin_used@@Base+0x3581>
 804d2ce:	42                   	inc    edx
 804d2cf:	cf                   	iret   
 804d2d0:	74 0e                	je     804d2e0 <_IO_stdin_used@@Base+0x3524>
 804d2d2:	7d df                	jge    804d2b3 <_IO_stdin_used@@Base+0x34f7>
 804d2d4:	74 01                	je     804d2d7 <_IO_stdin_used@@Base+0x351b>
 804d2d6:	5a                   	pop    edx
 804d2d7:	ce                   	into   
 804d2d8:	74 66                	je     804d340 <_IO_stdin_used@@Base+0x3584>
 804d2da:	42                   	inc    edx
 804d2db:	cf                   	iret   
 804d2dc:	74 0e                	je     804d2ec <_IO_stdin_used@@Base+0x3530>
 804d2de:	7d df                	jge    804d2bf <_IO_stdin_used@@Base+0x3503>
 804d2e0:	74 01                	je     804d2e3 <_IO_stdin_used@@Base+0x3527>
 804d2e2:	5a                   	pop    edx
 804d2e3:	ce                   	into   
 804d2e4:	74 21                	je     804d307 <_IO_stdin_used@@Base+0x354b>
 804d2e6:	42                   	inc    edx
 804d2e7:	cf                   	iret   
 804d2e8:	74 0e                	je     804d2f8 <_IO_stdin_used@@Base+0x353c>
 804d2ea:	7d df                	jge    804d2cb <_IO_stdin_used@@Base+0x350f>
 804d2ec:	74 01                	je     804d2ef <_IO_stdin_used@@Base+0x3533>
 804d2ee:	5a                   	pop    edx
 804d2ef:	ce                   	into   
 804d2f0:	74 71                	je     804d363 <_IO_stdin_used@@Base+0x35a7>
 804d2f2:	42                   	inc    edx
 804d2f3:	cf                   	iret   
 804d2f4:	74 0e                	je     804d304 <_IO_stdin_used@@Base+0x3548>
 804d2f6:	7d df                	jge    804d2d7 <_IO_stdin_used@@Base+0x351b>
 804d2f8:	74 01                	je     804d2fb <_IO_stdin_used@@Base+0x353f>
 804d2fa:	5a                   	pop    edx
 804d2fb:	ce                   	into   
 804d2fc:	74 60                	je     804d35e <_IO_stdin_used@@Base+0x35a2>
 804d2fe:	42                   	inc    edx
 804d2ff:	cf                   	iret   
 804d300:	74 0e                	je     804d310 <_IO_stdin_used@@Base+0x3554>
 804d302:	7d df                	jge    804d2e3 <_IO_stdin_used@@Base+0x3527>
 804d304:	74 01                	je     804d307 <_IO_stdin_used@@Base+0x354b>
 804d306:	5a                   	pop    edx
 804d307:	ce                   	into   
 804d308:	74 72                	je     804d37c <_IO_stdin_used@@Base+0x35c0>
 804d30a:	42                   	inc    edx
 804d30b:	cf                   	iret   
 804d30c:	74 0e                	je     804d31c <_IO_stdin_used@@Base+0x3560>
 804d30e:	7d df                	jge    804d2ef <_IO_stdin_used@@Base+0x3533>
 804d310:	74 01                	je     804d313 <_IO_stdin_used@@Base+0x3557>
 804d312:	5a                   	pop    edx
 804d313:	ce                   	into   
 804d314:	74 72                	je     804d388 <_IO_stdin_used@@Base+0x35cc>
 804d316:	42                   	inc    edx
 804d317:	cf                   	iret   
 804d318:	74 0e                	je     804d328 <_IO_stdin_used@@Base+0x356c>
 804d31a:	7d df                	jge    804d2fb <_IO_stdin_used@@Base+0x353f>
 804d31c:	74 01                	je     804d31f <_IO_stdin_used@@Base+0x3563>
 804d31e:	5a                   	pop    edx
 804d31f:	ce                   	into   
 804d320:	74 76                	je     804d398 <_IO_stdin_used@@Base+0x35dc>
 804d322:	42                   	inc    edx
 804d323:	cf                   	iret   
 804d324:	74 0e                	je     804d334 <_IO_stdin_used@@Base+0x3578>
 804d326:	7d df                	jge    804d307 <_IO_stdin_used@@Base+0x354b>
 804d328:	74 01                	je     804d32b <_IO_stdin_used@@Base+0x356f>
 804d32a:	5a                   	pop    edx
 804d32b:	ce                   	into   
 804d32c:	74 6e                	je     804d39c <_IO_stdin_used@@Base+0x35e0>
 804d32e:	42                   	inc    edx
 804d32f:	cf                   	iret   
 804d330:	74 0e                	je     804d340 <_IO_stdin_used@@Base+0x3584>
 804d332:	7d df                	jge    804d313 <_IO_stdin_used@@Base+0x3557>
 804d334:	74 01                	je     804d337 <_IO_stdin_used@@Base+0x357b>
 804d336:	5a                   	pop    edx
 804d337:	ce                   	into   
 804d338:	74 73                	je     804d3ad <_IO_stdin_used@@Base+0x35f1>
 804d33a:	42                   	inc    edx
 804d33b:	cf                   	iret   
 804d33c:	74 0e                	je     804d34c <_IO_stdin_used@@Base+0x3590>
 804d33e:	7d df                	jge    804d31f <_IO_stdin_used@@Base+0x3563>
 804d340:	74 01                	je     804d343 <_IO_stdin_used@@Base+0x3587>
 804d342:	5a                   	pop    edx
 804d343:	ce                   	into   
 804d344:	74 65                	je     804d3ab <_IO_stdin_used@@Base+0x35ef>
 804d346:	42                   	inc    edx
 804d347:	cf                   	iret   
 804d348:	74 0e                	je     804d358 <_IO_stdin_used@@Base+0x359c>
 804d34a:	7d df                	jge    804d32b <_IO_stdin_used@@Base+0x356f>
 804d34c:	74 01                	je     804d34f <_IO_stdin_used@@Base+0x3593>
 804d34e:	5a                   	pop    edx
 804d34f:	ce                   	into   
 804d350:	74 20                	je     804d372 <_IO_stdin_used@@Base+0x35b6>
 804d352:	42                   	inc    edx
 804d353:	cf                   	iret   
 804d354:	74 0e                	je     804d364 <_IO_stdin_used@@Base+0x35a8>
 804d356:	7d df                	jge    804d337 <_IO_stdin_used@@Base+0x357b>
 804d358:	74 01                	je     804d35b <_IO_stdin_used@@Base+0x359f>
 804d35a:	5a                   	pop    edx
 804d35b:	ce                   	into   
 804d35c:	74 0b                	je     804d369 <_IO_stdin_used@@Base+0x35ad>
 804d35e:	42                   	inc    edx
 804d35f:	cf                   	iret   
 804d360:	74 0e                	je     804d370 <_IO_stdin_used@@Base+0x35b4>
 804d362:	7d df                	jge    804d343 <_IO_stdin_used@@Base+0x3587>
 804d364:	74 01                	je     804d367 <_IO_stdin_used@@Base+0x35ab>
 804d366:	43                   	inc    ebx
 804d367:	d2 69 1f             	shr    BYTE PTR [ecx+0x1f],cl
 804d36a:	42                   	inc    edx
 804d36b:	c6                   	(bad)  
 804d36c:	6a 01                	push   0x1
 804d36e:	48                   	dec    eax
 804d36f:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d370:	74 0b                	je     804d37d <_IO_stdin_used@@Base+0x35c1>
 804d372:	42                   	inc    edx
 804d373:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d374:	75 00                	jne    804d376 <_IO_stdin_used@@Base+0x35ba>
 804d376:	5c                   	pop    esp
 804d377:	cf                   	iret   
 804d378:	74 01                	je     804d37b <_IO_stdin_used@@Base+0x35bf>
 804d37a:	5a                   	pop    edx
 804d37b:	ce                   	into   
 804d37c:	74 05                	je     804d383 <_IO_stdin_used@@Base+0x35c7>
 804d37e:	42                   	inc    edx
 804d37f:	cf                   	iret   
 804d380:	74 0e                	je     804d390 <_IO_stdin_used@@Base+0x35d4>
 804d382:	c2 df 74             	ret    0x74df
 804d385:	01 5a cf             	add    DWORD PTR [edx-0x31],ebx
 804d388:	7d 01                	jge    804d38b <_IO_stdin_used@@Base+0x35cf>
 804d38a:	5a                   	pop    edx
 804d38b:	ce                   	into   
 804d38c:	75 05                	jne    804d393 <_IO_stdin_used@@Base+0x35d7>
 804d38e:	42                   	inc    edx
 804d38f:	cf                   	iret   
 804d390:	74 19                	je     804d3ab <_IO_stdin_used@@Base+0x35ef>
 804d392:	43                   	inc    ebx
 804d393:	cf                   	iret   
 804d394:	70 01                	jo     804d397 <_IO_stdin_used@@Base+0x35db>
 804d396:	42                   	inc    edx
 804d397:	cf                   	iret   
 804d398:	7b 81                	jnp    804d31b <_IO_stdin_used@@Base+0x355f>
 804d39a:	52                   	push   edx
 804d39b:	cf                   	iret   
 804d39c:	74 19                	je     804d3b7 <_IO_stdin_used@@Base+0x35fb>
 804d39e:	42                   	inc    edx
 804d39f:	ca 74 19             	retf   0x1974
 804d3a2:	43                   	inc    ebx
 804d3a3:	d1 89 01 42 cf 68    	ror    DWORD PTR [ecx+0x68cf4201],1
 804d3a9:	04 5c                	add    al,0x5c
 804d3ab:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d3ac:	75 1f                	jne    804d3cd <_IO_stdin_used@@Base+0x3611>
 804d3ae:	43                   	inc    ebx
 804d3af:	cf                   	iret   
 804d3b0:	74 01                	je     804d3b3 <_IO_stdin_used@@Base+0x35f7>
 804d3b2:	46                   	inc    esi
 804d3b3:	ce                   	into   
 804d3b4:	6a 1f                	push   0x1f
 804d3b6:	46                   	inc    esi
 804d3b7:	cf                   	iret   
 804d3b8:	74 01                	je     804d3bb <_IO_stdin_used@@Base+0x35ff>
 804d3ba:	5a                   	pop    edx
 804d3bb:	cf                   	iret   
 804d3bc:	74 04                	je     804d3c2 <_IO_stdin_used@@Base+0x3606>
 804d3be:	40                   	inc    eax
 804d3bf:	cf                   	iret   
 804d3c0:	6a 1f                	push   0x1f
 804d3c2:	42                   	inc    edx
 804d3c3:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d3c4:	74 00                	je     804d3c6 <_IO_stdin_used@@Base+0x360a>
 804d3c6:	5c                   	pop    esp
 804d3c7:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d3c8:	75 1f                	jne    804d3e9 <_IO_stdin_used@@Base+0x362d>
 804d3ca:	4c                   	dec    esp
 804d3cb:	cf                   	iret   
 804d3cc:	74 01                	je     804d3cf <_IO_stdin_used@@Base+0x3613>
 804d3ce:	5e                   	pop    esi
 804d3cf:	ce                   	into   
 804d3d0:	6a 19                	push   0x19
 804d3d2:	43                   	inc    ebx
 804d3d3:	d1                   	(bad)  
 804d3d4:	75 01                	jne    804d3d7 <_IO_stdin_used@@Base+0x361b>
 804d3d6:	42                   	inc    edx
 804d3d7:	cf                   	iret   
 804d3d8:	70 00                	jo     804d3da <_IO_stdin_used@@Base+0x361e>
 804d3da:	5c                   	pop    esp
 804d3db:	d1 7c 01 42          	sar    DWORD PTR [ecx+eax*1+0x42],1
 804d3df:	cf                   	iret   
 804d3e0:	6c                   	ins    BYTE PTR es:[edi],dx
 804d3e1:	01 42 ca             	add    DWORD PTR [edx-0x36],eax
 804d3e4:	76 01                	jbe    804d3e7 <_IO_stdin_used@@Base+0x362b>
 804d3e6:	5c                   	pop    esp
 804d3e7:	d1                   	(bad)  
 804d3e8:	74 19                	je     804d403 <_IO_stdin_used@@Base+0x3647>
 804d3ea:	42                   	inc    edx
 804d3eb:	ce                   	into   
 804d3ec:	6a 19                	push   0x19
 804d3ee:	43                   	inc    ebx
 804d3ef:	d1 17                	rcl    DWORD PTR [edi],1
 804d3f1:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804d3f4:	68 00 5c d7 75       	push   0x75d75c00
 804d3f9:	1f                   	pop    ds
 804d3fa:	43                   	inc    ebx
 804d3fb:	cf                   	iret   
 804d3fc:	74 01                	je     804d3ff <_IO_stdin_used@@Base+0x3643>
 804d3fe:	46                   	inc    esi
 804d3ff:	ce                   	into   
 804d400:	6a 1f                	push   0x1f
 804d402:	4e                   	dec    esi
 804d403:	cf                   	iret   
 804d404:	74 01                	je     804d407 <_IO_stdin_used@@Base+0x364b>
 804d406:	5a                   	pop    edx
 804d407:	cf                   	iret   
 804d408:	74 04                	je     804d40e <_IO_stdin_used@@Base+0x3652>
 804d40a:	40                   	inc    eax
 804d40b:	cf                   	iret   
 804d40c:	6a 1f                	push   0x1f
 804d40e:	42                   	inc    edx
 804d40f:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d410:	74 00                	je     804d412 <_IO_stdin_used@@Base+0x3656>
 804d412:	5c                   	pop    esp
 804d413:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d414:	75 1f                	jne    804d435 <_IO_stdin_used@@Base+0x3679>
 804d416:	0d cf 74 01 5e       	or     eax,0x5e0174cf
 804d41b:	ce                   	into   
 804d41c:	6a 19                	push   0x19
 804d41e:	43                   	inc    ebx
 804d41f:	d1 f9                	sar    ecx,1
 804d421:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804d424:	68 08 5c d7 75       	push   0x75d75c08
 804d429:	1f                   	pop    ds
 804d42a:	43                   	inc    ebx
 804d42b:	cf                   	iret   
 804d42c:	74 01                	je     804d42f <_IO_stdin_used@@Base+0x3673>
 804d42e:	46                   	inc    esi
 804d42f:	ce                   	into   
 804d430:	6a 1f                	push   0x1f
 804d432:	46                   	inc    esi
 804d433:	cf                   	iret   
 804d434:	74 01                	je     804d437 <_IO_stdin_used@@Base+0x367b>
 804d436:	5a                   	pop    edx
 804d437:	cf                   	iret   
 804d438:	74 08                	je     804d442 <_IO_stdin_used@@Base+0x3686>
 804d43a:	40                   	inc    eax
 804d43b:	cf                   	iret   
 804d43c:	6a 1f                	push   0x1f
 804d43e:	42                   	inc    edx
 804d43f:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d440:	74 00                	je     804d442 <_IO_stdin_used@@Base+0x3686>
 804d442:	5c                   	pop    esp
 804d443:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d444:	75 1f                	jne    804d465 <_IO_stdin_used@@Base+0x36a9>
 804d446:	2d cf 74 01 5e       	sub    eax,0x5e0174cf
 804d44b:	ce                   	into   
 804d44c:	6a 19                	push   0x19
 804d44e:	43                   	inc    ebx
 804d44f:	d1                   	(bad)  
 804d450:	75 01                	jne    804d453 <_IO_stdin_used@@Base+0x3697>
 804d452:	42                   	inc    edx
 804d453:	cf                   	iret   
 804d454:	70 00                	jo     804d456 <_IO_stdin_used@@Base+0x369a>
 804d456:	5c                   	pop    esp
 804d457:	d1 7c 01 42          	sar    DWORD PTR [ecx+eax*1+0x42],1
 804d45b:	cf                   	iret   
 804d45c:	6c                   	ins    BYTE PTR es:[edi],dx
 804d45d:	01 42 c6             	add    DWORD PTR [edx-0x3a],eax
 804d460:	76 01                	jbe    804d463 <_IO_stdin_used@@Base+0x36a7>
 804d462:	5c                   	pop    esp
 804d463:	d1                   	(bad)  
 804d464:	74 19                	je     804d47f <_IO_stdin_used@@Base+0x36c3>
 804d466:	42                   	inc    edx
 804d467:	ce                   	into   
 804d468:	6a 19                	push   0x19
 804d46a:	43                   	inc    ebx
 804d46b:	d1                   	(bad)  
 804d46c:	74 01                	je     804d46f <_IO_stdin_used@@Base+0x36b3>
 804d46e:	42                   	inc    edx
 804d46f:	cf                   	iret   
 804d470:	68 00 5c d7 75       	push   0x75d75c00
 804d475:	1f                   	pop    ds
 804d476:	43                   	inc    ebx
 804d477:	cf                   	iret   
 804d478:	74 01                	je     804d47b <_IO_stdin_used@@Base+0x36bf>
 804d47a:	46                   	inc    esi
 804d47b:	ce                   	into   
 804d47c:	6a 1f                	push   0x1f
 804d47e:	4e                   	dec    esi
 804d47f:	cf                   	iret   
 804d480:	74 01                	je     804d483 <_IO_stdin_used@@Base+0x36c7>
 804d482:	5a                   	pop    edx
 804d483:	cf                   	iret   
 804d484:	74 08                	je     804d48e <_IO_stdin_used@@Base+0x36d2>
 804d486:	40                   	inc    eax
 804d487:	cf                   	iret   
 804d488:	6a 1f                	push   0x1f
 804d48a:	42                   	inc    edx
 804d48b:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d48c:	74 00                	je     804d48e <_IO_stdin_used@@Base+0x36d2>
 804d48e:	5c                   	pop    esp
 804d48f:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d490:	75 1f                	jne    804d4b1 <_IO_stdin_used@@Base+0x36f5>
 804d492:	66 cf                	iretw  
 804d494:	74 01                	je     804d497 <_IO_stdin_used@@Base+0x36db>
 804d496:	5e                   	pop    esi
 804d497:	ce                   	into   
 804d498:	6a 19                	push   0x19
 804d49a:	43                   	inc    ebx
 804d49b:	d1                   	(bad)  
 804d49c:	75 01                	jne    804d49f <_IO_stdin_used@@Base+0x36e3>
 804d49e:	42                   	inc    edx
 804d49f:	cf                   	iret   
 804d4a0:	70 00                	jo     804d4a2 <_IO_stdin_used@@Base+0x36e6>
 804d4a2:	5c                   	pop    esp
 804d4a3:	d1 64 01 42          	shl    DWORD PTR [ecx+eax*1+0x42],1
 804d4a7:	cf                   	iret   
 804d4a8:	6c                   	ins    BYTE PTR es:[edi],dx
 804d4a9:	01 42 c6             	add    DWORD PTR [edx-0x3a],eax
 804d4ac:	76 01                	jbe    804d4af <_IO_stdin_used@@Base+0x36f3>
 804d4ae:	5c                   	pop    esp
 804d4af:	d1                   	(bad)  
 804d4b0:	74 19                	je     804d4cb <_IO_stdin_used@@Base+0x370f>
 804d4b2:	42                   	inc    edx
 804d4b3:	ce                   	into   
 804d4b4:	6a 19                	push   0x19
 804d4b6:	43                   	inc    ebx
 804d4b7:	d1 ec                	shr    esp,1
 804d4b9:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804d4bc:	68 00 5c d7 75       	push   0x75d75c00
 804d4c1:	1f                   	pop    ds
 804d4c2:	43                   	inc    ebx
 804d4c3:	cf                   	iret   
 804d4c4:	74 01                	je     804d4c7 <_IO_stdin_used@@Base+0x370b>
 804d4c6:	46                   	inc    esi
 804d4c7:	ce                   	into   
 804d4c8:	6a 1f                	push   0x1f
 804d4ca:	56                   	push   esi
 804d4cb:	cf                   	iret   
 804d4cc:	74 01                	je     804d4cf <_IO_stdin_used@@Base+0x3713>
 804d4ce:	5a                   	pop    edx
 804d4cf:	cf                   	iret   
 804d4d0:	74 08                	je     804d4da <_IO_stdin_used@@Base+0x371e>
 804d4d2:	40                   	inc    eax
 804d4d3:	cf                   	iret   
 804d4d4:	6a 1f                	push   0x1f
 804d4d6:	42                   	inc    edx
 804d4d7:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d4d8:	74 00                	je     804d4da <_IO_stdin_used@@Base+0x371e>
 804d4da:	5c                   	pop    esp
 804d4db:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d4dc:	75 1f                	jne    804d4fd <_IO_stdin_used@@Base+0x3741>
 804d4de:	3e cf                	ds iret 
 804d4e0:	74 01                	je     804d4e3 <_IO_stdin_used@@Base+0x3727>
 804d4e2:	5e                   	pop    esi
 804d4e3:	ce                   	into   
 804d4e4:	6a 19                	push   0x19
 804d4e6:	43                   	inc    ebx
 804d4e7:	d1                   	(bad)  
 804d4e8:	75 01                	jne    804d4eb <_IO_stdin_used@@Base+0x372f>
 804d4ea:	42                   	inc    edx
 804d4eb:	cf                   	iret   
 804d4ec:	70 00                	jo     804d4ee <_IO_stdin_used@@Base+0x3732>
 804d4ee:	5c                   	pop    esp
 804d4ef:	d1 6c 01 42          	shr    DWORD PTR [ecx+eax*1+0x42],1
 804d4f3:	cf                   	iret   
 804d4f4:	6c                   	ins    BYTE PTR es:[edi],dx
 804d4f5:	01 42 c6             	add    DWORD PTR [edx-0x3a],eax
 804d4f8:	76 01                	jbe    804d4fb <_IO_stdin_used@@Base+0x373f>
 804d4fa:	5c                   	pop    esp
 804d4fb:	d1                   	(bad)  
 804d4fc:	74 19                	je     804d517 <_IO_stdin_used@@Base+0x375b>
 804d4fe:	42                   	inc    edx
 804d4ff:	ce                   	into   
 804d500:	6a 19                	push   0x19
 804d502:	43                   	inc    ebx
 804d503:	d1 64 01 42          	shl    DWORD PTR [ecx+eax*1+0x42],1
 804d507:	cf                   	iret   
 804d508:	68 00 5c d7 75       	push   0x75d75c00
 804d50d:	1f                   	pop    ds
 804d50e:	43                   	inc    ebx
 804d50f:	cf                   	iret   
 804d510:	74 01                	je     804d513 <_IO_stdin_used@@Base+0x3757>
 804d512:	46                   	inc    esi
 804d513:	ce                   	into   
 804d514:	6a 1f                	push   0x1f
 804d516:	5e                   	pop    esi
 804d517:	cf                   	iret   
 804d518:	74 01                	je     804d51b <_IO_stdin_used@@Base+0x375f>
 804d51a:	5a                   	pop    edx
 804d51b:	cf                   	iret   
 804d51c:	74 08                	je     804d526 <_IO_stdin_used@@Base+0x376a>
 804d51e:	40                   	inc    eax
 804d51f:	cf                   	iret   
 804d520:	6a 1f                	push   0x1f
 804d522:	42                   	inc    edx
 804d523:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d524:	74 00                	je     804d526 <_IO_stdin_used@@Base+0x376a>
 804d526:	5c                   	pop    esp
 804d527:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d528:	75 1f                	jne    804d549 <_IO_stdin_used@@Base+0x378d>
 804d52a:	52                   	push   edx
 804d52b:	cf                   	iret   
 804d52c:	74 01                	je     804d52f <_IO_stdin_used@@Base+0x3773>
 804d52e:	5e                   	pop    esi
 804d52f:	ce                   	into   
 804d530:	6a 19                	push   0x19
 804d532:	43                   	inc    ebx
 804d533:	d1                   	(bad)  
 804d534:	75 01                	jne    804d537 <_IO_stdin_used@@Base+0x377b>
 804d536:	42                   	inc    edx
 804d537:	cf                   	iret   
 804d538:	70 00                	jo     804d53a <_IO_stdin_used@@Base+0x377e>
 804d53a:	5c                   	pop    esp
 804d53b:	d1 54 01 42          	rcl    DWORD PTR [ecx+eax*1+0x42],1
 804d53f:	cf                   	iret   
 804d540:	6c                   	ins    BYTE PTR es:[edi],dx
 804d541:	01 42 c6             	add    DWORD PTR [edx-0x3a],eax
 804d544:	76 01                	jbe    804d547 <_IO_stdin_used@@Base+0x378b>
 804d546:	5c                   	pop    esp
 804d547:	d1                   	(bad)  
 804d548:	74 19                	je     804d563 <_IO_stdin_used@@Base+0x37a7>
 804d54a:	42                   	inc    edx
 804d54b:	ce                   	into   
 804d54c:	6a 19                	push   0x19
 804d54e:	43                   	inc    ebx
 804d54f:	d1 e8                	shr    eax,1
 804d551:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804d554:	68 00 5c d7 75       	push   0x75d75c00
 804d559:	1f                   	pop    ds
 804d55a:	43                   	inc    ebx
 804d55b:	cf                   	iret   
 804d55c:	74 01                	je     804d55f <_IO_stdin_used@@Base+0x37a3>
 804d55e:	46                   	inc    esi
 804d55f:	ce                   	into   
 804d560:	6a 1f                	push   0x1f
 804d562:	66 cf                	iretw  
 804d564:	74 01                	je     804d567 <_IO_stdin_used@@Base+0x37ab>
 804d566:	5a                   	pop    edx
 804d567:	cf                   	iret   
 804d568:	74 08                	je     804d572 <_IO_stdin_used@@Base+0x37b6>
 804d56a:	40                   	inc    eax
 804d56b:	cf                   	iret   
 804d56c:	6a 1f                	push   0x1f
 804d56e:	42                   	inc    edx
 804d56f:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d570:	74 00                	je     804d572 <_IO_stdin_used@@Base+0x37b6>
 804d572:	5c                   	pop    esp
 804d573:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d574:	75 1f                	jne    804d595 <_IO_stdin_used@@Base+0x37d9>
 804d576:	22 cf                	and    cl,bh
 804d578:	74 01                	je     804d57b <_IO_stdin_used@@Base+0x37bf>
 804d57a:	5e                   	pop    esi
 804d57b:	ce                   	into   
 804d57c:	6a 19                	push   0x19
 804d57e:	43                   	inc    ebx
 804d57f:	d1                   	(bad)  
 804d580:	75 01                	jne    804d583 <_IO_stdin_used@@Base+0x37c7>
 804d582:	42                   	inc    edx
 804d583:	cf                   	iret   
 804d584:	70 00                	jo     804d586 <_IO_stdin_used@@Base+0x37ca>
 804d586:	5c                   	pop    esp
 804d587:	d1 5c 01 42          	rcr    DWORD PTR [ecx+eax*1+0x42],1
 804d58b:	cf                   	iret   
 804d58c:	6c                   	ins    BYTE PTR es:[edi],dx
 804d58d:	01 42 c6             	add    DWORD PTR [edx-0x3a],eax
 804d590:	76 01                	jbe    804d593 <_IO_stdin_used@@Base+0x37d7>
 804d592:	5c                   	pop    esp
 804d593:	d1                   	(bad)  
 804d594:	74 19                	je     804d5af <_IO_stdin_used@@Base+0x37f3>
 804d596:	42                   	inc    edx
 804d597:	ce                   	into   
 804d598:	6a 19                	push   0x19
 804d59a:	43                   	inc    ebx
 804d59b:	d1                   	(bad)  
 804d59c:	73 01                	jae    804d59f <_IO_stdin_used@@Base+0x37e3>
 804d59e:	42                   	inc    edx
 804d59f:	cf                   	iret   
 804d5a0:	68 00 5c d7 75       	push   0x75d75c00
 804d5a5:	1f                   	pop    ds
 804d5a6:	43                   	inc    ebx
 804d5a7:	cf                   	iret   
 804d5a8:	74 01                	je     804d5ab <_IO_stdin_used@@Base+0x37ef>
 804d5aa:	46                   	inc    esi
 804d5ab:	ce                   	into   
 804d5ac:	6a 1f                	push   0x1f
 804d5ae:	6e                   	outs   dx,BYTE PTR ds:[esi]
 804d5af:	cf                   	iret   
 804d5b0:	74 01                	je     804d5b3 <_IO_stdin_used@@Base+0x37f7>
 804d5b2:	5a                   	pop    edx
 804d5b3:	cf                   	iret   
 804d5b4:	74 08                	je     804d5be <_IO_stdin_used@@Base+0x3802>
 804d5b6:	40                   	inc    eax
 804d5b7:	cf                   	iret   
 804d5b8:	6a 1f                	push   0x1f
 804d5ba:	42                   	inc    edx
 804d5bb:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d5bc:	74 00                	je     804d5be <_IO_stdin_used@@Base+0x3802>
 804d5be:	5c                   	pop    esp
 804d5bf:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d5c0:	75 1f                	jne    804d5e1 <_IO_stdin_used@@Base+0x3825>
 804d5c2:	52                   	push   edx
 804d5c3:	cf                   	iret   
 804d5c4:	74 01                	je     804d5c7 <_IO_stdin_used@@Base+0x380b>
 804d5c6:	5e                   	pop    esi
 804d5c7:	ce                   	into   
 804d5c8:	6a 19                	push   0x19
 804d5ca:	43                   	inc    ebx
 804d5cb:	d1                   	(bad)  
 804d5cc:	75 01                	jne    804d5cf <_IO_stdin_used@@Base+0x3813>
 804d5ce:	42                   	inc    edx
 804d5cf:	cf                   	iret   
 804d5d0:	70 00                	jo     804d5d2 <_IO_stdin_used@@Base+0x3816>
 804d5d2:	5c                   	pop    esp
 804d5d3:	d1 44 01 42          	rol    DWORD PTR [ecx+eax*1+0x42],1
 804d5d7:	cf                   	iret   
 804d5d8:	6c                   	ins    BYTE PTR es:[edi],dx
 804d5d9:	01 42 c6             	add    DWORD PTR [edx-0x3a],eax
 804d5dc:	76 01                	jbe    804d5df <_IO_stdin_used@@Base+0x3823>
 804d5de:	5c                   	pop    esp
 804d5df:	d1                   	(bad)  
 804d5e0:	74 19                	je     804d5fb <_IO_stdin_used@@Base+0x383f>
 804d5e2:	42                   	inc    edx
 804d5e3:	ce                   	into   
 804d5e4:	6a 19                	push   0x19
 804d5e6:	43                   	inc    ebx
 804d5e7:	d1 ff                	sar    edi,1
 804d5e9:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804d5ec:	68 00 5c d7 75       	push   0x75d75c00
 804d5f1:	1f                   	pop    ds
 804d5f2:	43                   	inc    ebx
 804d5f3:	cf                   	iret   
 804d5f4:	74 01                	je     804d5f7 <_IO_stdin_used@@Base+0x383b>
 804d5f6:	46                   	inc    esi
 804d5f7:	ce                   	into   
 804d5f8:	6a 1f                	push   0x1f
 804d5fa:	76 cf                	jbe    804d5cb <_IO_stdin_used@@Base+0x380f>
 804d5fc:	74 01                	je     804d5ff <_IO_stdin_used@@Base+0x3843>
 804d5fe:	5a                   	pop    edx
 804d5ff:	cf                   	iret   
 804d600:	74 08                	je     804d60a <_IO_stdin_used@@Base+0x384e>
 804d602:	40                   	inc    eax
 804d603:	cf                   	iret   
 804d604:	6a 1f                	push   0x1f
 804d606:	42                   	inc    edx
 804d607:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d608:	74 00                	je     804d60a <_IO_stdin_used@@Base+0x384e>
 804d60a:	5c                   	pop    esp
 804d60b:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d60c:	75 1f                	jne    804d62d <_IO_stdin_used@@Base+0x3871>
 804d60e:	21 cf                	and    edi,ecx
 804d610:	74 01                	je     804d613 <_IO_stdin_used@@Base+0x3857>
 804d612:	5e                   	pop    esi
 804d613:	ce                   	into   
 804d614:	6a 19                	push   0x19
 804d616:	43                   	inc    ebx
 804d617:	d1                   	(bad)  
 804d618:	75 01                	jne    804d61b <_IO_stdin_used@@Base+0x385f>
 804d61a:	42                   	inc    edx
 804d61b:	cf                   	iret   
 804d61c:	70 00                	jo     804d61e <_IO_stdin_used@@Base+0x3862>
 804d61e:	5c                   	pop    esp
 804d61f:	d1 4c 01 42          	ror    DWORD PTR [ecx+eax*1+0x42],1
 804d623:	cf                   	iret   
 804d624:	6c                   	ins    BYTE PTR es:[edi],dx
 804d625:	01 42 c6             	add    DWORD PTR [edx-0x3a],eax
 804d628:	76 01                	jbe    804d62b <_IO_stdin_used@@Base+0x386f>
 804d62a:	5c                   	pop    esp
 804d62b:	d1                   	(bad)  
 804d62c:	74 19                	je     804d647 <_IO_stdin_used@@Base+0x388b>
 804d62e:	42                   	inc    edx
 804d62f:	ce                   	into   
 804d630:	6a 19                	push   0x19
 804d632:	43                   	inc    ebx
 804d633:	d1 64 01 42          	shl    DWORD PTR [ecx+eax*1+0x42],1
 804d637:	cf                   	iret   
 804d638:	68 00 5c d7 75       	push   0x75d75c00
 804d63d:	1f                   	pop    ds
 804d63e:	43                   	inc    ebx
 804d63f:	cf                   	iret   
 804d640:	74 01                	je     804d643 <_IO_stdin_used@@Base+0x3887>
 804d642:	46                   	inc    esi
 804d643:	ce                   	into   
 804d644:	6a 1f                	push   0x1f
 804d646:	7e cf                	jle    804d617 <_IO_stdin_used@@Base+0x385b>
 804d648:	74 01                	je     804d64b <_IO_stdin_used@@Base+0x388f>
 804d64a:	5a                   	pop    edx
 804d64b:	cf                   	iret   
 804d64c:	74 08                	je     804d656 <_IO_stdin_used@@Base+0x389a>
 804d64e:	40                   	inc    eax
 804d64f:	cf                   	iret   
 804d650:	6a 1f                	push   0x1f
 804d652:	42                   	inc    edx
 804d653:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d654:	74 00                	je     804d656 <_IO_stdin_used@@Base+0x389a>
 804d656:	5c                   	pop    esp
 804d657:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d658:	75 1f                	jne    804d679 <_IO_stdin_used@@Base+0x38bd>
 804d65a:	52                   	push   edx
 804d65b:	cf                   	iret   
 804d65c:	74 01                	je     804d65f <_IO_stdin_used@@Base+0x38a3>
 804d65e:	5e                   	pop    esi
 804d65f:	ce                   	into   
 804d660:	6a 19                	push   0x19
 804d662:	43                   	inc    ebx
 804d663:	d1                   	(bad)  
 804d664:	75 01                	jne    804d667 <_IO_stdin_used@@Base+0x38ab>
 804d666:	42                   	inc    edx
 804d667:	cf                   	iret   
 804d668:	70 00                	jo     804d66a <_IO_stdin_used@@Base+0x38ae>
 804d66a:	5c                   	pop    esp
 804d66b:	d1                   	(bad)  
 804d66c:	34 01                	xor    al,0x1
 804d66e:	42                   	inc    edx
 804d66f:	cf                   	iret   
 804d670:	6c                   	ins    BYTE PTR es:[edi],dx
 804d671:	01 42 c6             	add    DWORD PTR [edx-0x3a],eax
 804d674:	76 01                	jbe    804d677 <_IO_stdin_used@@Base+0x38bb>
 804d676:	5c                   	pop    esp
 804d677:	d1                   	(bad)  
 804d678:	74 19                	je     804d693 <_IO_stdin_used@@Base+0x38d7>
 804d67a:	42                   	inc    edx
 804d67b:	ce                   	into   
 804d67c:	6a 19                	push   0x19
 804d67e:	43                   	inc    ebx
 804d67f:	d1 e8                	shr    eax,1
 804d681:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804d684:	68 00 5c d7 75       	push   0x75d75c00
 804d689:	1f                   	pop    ds
 804d68a:	43                   	inc    ebx
 804d68b:	cf                   	iret   
 804d68c:	74 01                	je     804d68f <_IO_stdin_used@@Base+0x38d3>
 804d68e:	46                   	inc    esi
 804d68f:	ce                   	into   
 804d690:	6a 1f                	push   0x1f
 804d692:	06                   	push   es
 804d693:	cf                   	iret   
 804d694:	74 01                	je     804d697 <_IO_stdin_used@@Base+0x38db>
 804d696:	5a                   	pop    edx
 804d697:	cf                   	iret   
 804d698:	74 08                	je     804d6a2 <_IO_stdin_used@@Base+0x38e6>
 804d69a:	40                   	inc    eax
 804d69b:	cf                   	iret   
 804d69c:	6a 1f                	push   0x1f
 804d69e:	42                   	inc    edx
 804d69f:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d6a0:	74 00                	je     804d6a2 <_IO_stdin_used@@Base+0x38e6>
 804d6a2:	5c                   	pop    esp
 804d6a3:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d6a4:	75 1f                	jne    804d6c5 <_IO_stdin_used@@Base+0x3909>
 804d6a6:	22 cf                	and    cl,bh
 804d6a8:	74 01                	je     804d6ab <_IO_stdin_used@@Base+0x38ef>
 804d6aa:	5e                   	pop    esi
 804d6ab:	ce                   	into   
 804d6ac:	6a 19                	push   0x19
 804d6ae:	43                   	inc    ebx
 804d6af:	d1                   	(bad)  
 804d6b0:	75 01                	jne    804d6b3 <_IO_stdin_used@@Base+0x38f7>
 804d6b2:	42                   	inc    edx
 804d6b3:	cf                   	iret   
 804d6b4:	70 00                	jo     804d6b6 <_IO_stdin_used@@Base+0x38fa>
 804d6b6:	5c                   	pop    esp
 804d6b7:	d1 3c 01             	sar    DWORD PTR [ecx+eax*1],1
 804d6ba:	42                   	inc    edx
 804d6bb:	cf                   	iret   
 804d6bc:	6c                   	ins    BYTE PTR es:[edi],dx
 804d6bd:	01 42 c6             	add    DWORD PTR [edx-0x3a],eax
 804d6c0:	76 01                	jbe    804d6c3 <_IO_stdin_used@@Base+0x3907>
 804d6c2:	5c                   	pop    esp
 804d6c3:	d1                   	(bad)  
 804d6c4:	74 19                	je     804d6df <_IO_stdin_used@@Base+0x3923>
 804d6c6:	42                   	inc    edx
 804d6c7:	ce                   	into   
 804d6c8:	6a 19                	push   0x19
 804d6ca:	43                   	inc    ebx
 804d6cb:	d1                   	(bad)  
 804d6cc:	73 01                	jae    804d6cf <_IO_stdin_used@@Base+0x3913>
 804d6ce:	42                   	inc    edx
 804d6cf:	cf                   	iret   
 804d6d0:	68 00 5c d7 75       	push   0x75d75c00
 804d6d5:	1f                   	pop    ds
 804d6d6:	43                   	inc    ebx
 804d6d7:	cf                   	iret   
 804d6d8:	74 01                	je     804d6db <_IO_stdin_used@@Base+0x391f>
 804d6da:	46                   	inc    esi
 804d6db:	ce                   	into   
 804d6dc:	6a 1f                	push   0x1f
 804d6de:	0e                   	push   cs
 804d6df:	cf                   	iret   
 804d6e0:	74 01                	je     804d6e3 <_IO_stdin_used@@Base+0x3927>
 804d6e2:	5a                   	pop    edx
 804d6e3:	cf                   	iret   
 804d6e4:	74 08                	je     804d6ee <_IO_stdin_used@@Base+0x3932>
 804d6e6:	40                   	inc    eax
 804d6e7:	cf                   	iret   
 804d6e8:	6a 1f                	push   0x1f
 804d6ea:	42                   	inc    edx
 804d6eb:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d6ec:	74 00                	je     804d6ee <_IO_stdin_used@@Base+0x3932>
 804d6ee:	5c                   	pop    esp
 804d6ef:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d6f0:	75 1f                	jne    804d711 <_IO_stdin_used@@Base+0x3955>
 804d6f2:	52                   	push   edx
 804d6f3:	cf                   	iret   
 804d6f4:	74 01                	je     804d6f7 <_IO_stdin_used@@Base+0x393b>
 804d6f6:	5e                   	pop    esi
 804d6f7:	ce                   	into   
 804d6f8:	6a 19                	push   0x19
 804d6fa:	43                   	inc    ebx
 804d6fb:	d1                   	(bad)  
 804d6fc:	75 01                	jne    804d6ff <_IO_stdin_used@@Base+0x3943>
 804d6fe:	42                   	inc    edx
 804d6ff:	cf                   	iret   
 804d700:	70 00                	jo     804d702 <_IO_stdin_used@@Base+0x3946>
 804d702:	5c                   	pop    esp
 804d703:	d1 24 01             	shl    DWORD PTR [ecx+eax*1],1
 804d706:	42                   	inc    edx
 804d707:	cf                   	iret   
 804d708:	6c                   	ins    BYTE PTR es:[edi],dx
 804d709:	01 42 c6             	add    DWORD PTR [edx-0x3a],eax
 804d70c:	76 01                	jbe    804d70f <_IO_stdin_used@@Base+0x3953>
 804d70e:	5c                   	pop    esp
 804d70f:	d1                   	(bad)  
 804d710:	74 19                	je     804d72b <_IO_stdin_used@@Base+0x396f>
 804d712:	42                   	inc    edx
 804d713:	ce                   	into   
 804d714:	6a 19                	push   0x19
 804d716:	43                   	inc    ebx
 804d717:	d1                   	(bad)  
 804d718:	f1                   	icebp  
 804d719:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804d71c:	68 00 5c d7 75       	push   0x75d75c00
 804d721:	1f                   	pop    ds
 804d722:	43                   	inc    ebx
 804d723:	cf                   	iret   
 804d724:	74 01                	je     804d727 <_IO_stdin_used@@Base+0x396b>
 804d726:	46                   	inc    esi
 804d727:	ce                   	into   
 804d728:	6a 1f                	push   0x1f
 804d72a:	16                   	push   ss
 804d72b:	cf                   	iret   
 804d72c:	74 01                	je     804d72f <_IO_stdin_used@@Base+0x3973>
 804d72e:	5a                   	pop    edx
 804d72f:	cf                   	iret   
 804d730:	74 08                	je     804d73a <_IO_stdin_used@@Base+0x397e>
 804d732:	40                   	inc    eax
 804d733:	cf                   	iret   
 804d734:	6a 1f                	push   0x1f
 804d736:	42                   	inc    edx
 804d737:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d738:	74 00                	je     804d73a <_IO_stdin_used@@Base+0x397e>
 804d73a:	5c                   	pop    esp
 804d73b:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d73c:	75 1f                	jne    804d75d <_IO_stdin_used@@Base+0x39a1>
 804d73e:	23 cf                	and    ecx,edi
 804d740:	74 01                	je     804d743 <_IO_stdin_used@@Base+0x3987>
 804d742:	5e                   	pop    esi
 804d743:	ce                   	into   
 804d744:	6a 19                	push   0x19
 804d746:	43                   	inc    ebx
 804d747:	d1                   	(bad)  
 804d748:	75 01                	jne    804d74b <_IO_stdin_used@@Base+0x398f>
 804d74a:	42                   	inc    edx
 804d74b:	cf                   	iret   
 804d74c:	70 00                	jo     804d74e <_IO_stdin_used@@Base+0x3992>
 804d74e:	5c                   	pop    esp
 804d74f:	d1 2c 01             	shr    DWORD PTR [ecx+eax*1],1
 804d752:	42                   	inc    edx
 804d753:	cf                   	iret   
 804d754:	6c                   	ins    BYTE PTR es:[edi],dx
 804d755:	01 42 c6             	add    DWORD PTR [edx-0x3a],eax
 804d758:	76 01                	jbe    804d75b <_IO_stdin_used@@Base+0x399f>
 804d75a:	5c                   	pop    esp
 804d75b:	d1                   	(bad)  
 804d75c:	74 19                	je     804d777 <_IO_stdin_used@@Base+0x39bb>
 804d75e:	42                   	inc    edx
 804d75f:	ce                   	into   
 804d760:	6a 19                	push   0x19
 804d762:	43                   	inc    ebx
 804d763:	d1 65 01             	shl    DWORD PTR [ebp+0x1],1
 804d766:	42                   	inc    edx
 804d767:	cf                   	iret   
 804d768:	68 00 5c d7 75       	push   0x75d75c00
 804d76d:	1f                   	pop    ds
 804d76e:	43                   	inc    ebx
 804d76f:	cf                   	iret   
 804d770:	74 01                	je     804d773 <_IO_stdin_used@@Base+0x39b7>
 804d772:	46                   	inc    esi
 804d773:	ce                   	into   
 804d774:	6a 1f                	push   0x1f
 804d776:	1e                   	push   ds
 804d777:	cf                   	iret   
 804d778:	74 01                	je     804d77b <_IO_stdin_used@@Base+0x39bf>
 804d77a:	5a                   	pop    edx
 804d77b:	cf                   	iret   
 804d77c:	74 08                	je     804d786 <_IO_stdin_used@@Base+0x39ca>
 804d77e:	40                   	inc    eax
 804d77f:	cf                   	iret   
 804d780:	6a 1f                	push   0x1f
 804d782:	42                   	inc    edx
 804d783:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d784:	74 00                	je     804d786 <_IO_stdin_used@@Base+0x39ca>
 804d786:	5c                   	pop    esp
 804d787:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d788:	75 1f                	jne    804d7a9 <_IO_stdin_used@@Base+0x39ed>
 804d78a:	7e cf                	jle    804d75b <_IO_stdin_used@@Base+0x399f>
 804d78c:	74 01                	je     804d78f <_IO_stdin_used@@Base+0x39d3>
 804d78e:	5e                   	pop    esi
 804d78f:	ce                   	into   
 804d790:	6a 19                	push   0x19
 804d792:	43                   	inc    ebx
 804d793:	d1                   	(bad)  
 804d794:	75 01                	jne    804d797 <_IO_stdin_used@@Base+0x39db>
 804d796:	42                   	inc    edx
 804d797:	cf                   	iret   
 804d798:	70 00                	jo     804d79a <_IO_stdin_used@@Base+0x39de>
 804d79a:	5c                   	pop    esp
 804d79b:	d1 14 01             	rcl    DWORD PTR [ecx+eax*1],1
 804d79e:	42                   	inc    edx
 804d79f:	cf                   	iret   
 804d7a0:	6c                   	ins    BYTE PTR es:[edi],dx
 804d7a1:	01 42 c6             	add    DWORD PTR [edx-0x3a],eax
 804d7a4:	76 01                	jbe    804d7a7 <_IO_stdin_used@@Base+0x39eb>
 804d7a6:	5c                   	pop    esp
 804d7a7:	d1                   	(bad)  
 804d7a8:	74 19                	je     804d7c3 <_IO_stdin_used@@Base+0x3a07>
 804d7aa:	42                   	inc    edx
 804d7ab:	ce                   	into   
 804d7ac:	6a 19                	push   0x19
 804d7ae:	43                   	inc    ebx
 804d7af:	d1 d6                	rcl    esi,1
 804d7b1:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804d7b4:	68 00 5c d7 75       	push   0x75d75c00
 804d7b9:	1f                   	pop    ds
 804d7ba:	43                   	inc    ebx
 804d7bb:	cf                   	iret   
 804d7bc:	74 01                	je     804d7bf <_IO_stdin_used@@Base+0x3a03>
 804d7be:	46                   	inc    esi
 804d7bf:	ce                   	into   
 804d7c0:	6a 1f                	push   0x1f
 804d7c2:	26 cf                	es iret 
 804d7c4:	74 01                	je     804d7c7 <_IO_stdin_used@@Base+0x3a0b>
 804d7c6:	5a                   	pop    edx
 804d7c7:	cf                   	iret   
 804d7c8:	74 08                	je     804d7d2 <_IO_stdin_used@@Base+0x3a16>
 804d7ca:	40                   	inc    eax
 804d7cb:	cf                   	iret   
 804d7cc:	6a 1f                	push   0x1f
 804d7ce:	42                   	inc    edx
 804d7cf:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d7d0:	74 00                	je     804d7d2 <_IO_stdin_used@@Base+0x3a16>
 804d7d2:	5c                   	pop    esp
 804d7d3:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d7d4:	75 1f                	jne    804d7f5 <_IO_stdin_used@@Base+0x3a39>
 804d7d6:	23 cf                	and    ecx,edi
 804d7d8:	74 01                	je     804d7db <_IO_stdin_used@@Base+0x3a1f>
 804d7da:	5e                   	pop    esi
 804d7db:	ce                   	into   
 804d7dc:	6a 19                	push   0x19
 804d7de:	43                   	inc    ebx
 804d7df:	d1                   	(bad)  
 804d7e0:	75 01                	jne    804d7e3 <_IO_stdin_used@@Base+0x3a27>
 804d7e2:	42                   	inc    edx
 804d7e3:	cf                   	iret   
 804d7e4:	70 00                	jo     804d7e6 <_IO_stdin_used@@Base+0x3a2a>
 804d7e6:	5c                   	pop    esp
 804d7e7:	d1 1c 01             	rcr    DWORD PTR [ecx+eax*1],1
 804d7ea:	42                   	inc    edx
 804d7eb:	cf                   	iret   
 804d7ec:	6c                   	ins    BYTE PTR es:[edi],dx
 804d7ed:	01 42 c6             	add    DWORD PTR [edx-0x3a],eax
 804d7f0:	76 01                	jbe    804d7f3 <_IO_stdin_used@@Base+0x3a37>
 804d7f2:	5c                   	pop    esp
 804d7f3:	d1                   	(bad)  
 804d7f4:	74 19                	je     804d80f <_IO_stdin_used@@Base+0x3a53>
 804d7f6:	42                   	inc    edx
 804d7f7:	ce                   	into   
 804d7f8:	6a 19                	push   0x19
 804d7fa:	43                   	inc    ebx
 804d7fb:	d1 7f 01             	sar    DWORD PTR [edi+0x1],1
 804d7fe:	42                   	inc    edx
 804d7ff:	cf                   	iret   
 804d800:	68 00 5c d7 75       	push   0x75d75c00
 804d805:	1f                   	pop    ds
 804d806:	43                   	inc    ebx
 804d807:	cf                   	iret   
 804d808:	74 01                	je     804d80b <_IO_stdin_used@@Base+0x3a4f>
 804d80a:	46                   	inc    esi
 804d80b:	ce                   	into   
 804d80c:	6a 1f                	push   0x1f
 804d80e:	2e cf                	cs iret 
 804d810:	74 01                	je     804d813 <_IO_stdin_used@@Base+0x3a57>
 804d812:	5a                   	pop    edx
 804d813:	cf                   	iret   
 804d814:	74 08                	je     804d81e <_IO_stdin_used@@Base+0x3a62>
 804d816:	40                   	inc    eax
 804d817:	cf                   	iret   
 804d818:	6a 1f                	push   0x1f
 804d81a:	42                   	inc    edx
 804d81b:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d81c:	74 00                	je     804d81e <_IO_stdin_used@@Base+0x3a62>
 804d81e:	5c                   	pop    esp
 804d81f:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d820:	75 1f                	jne    804d841 <_IO_stdin_used@@Base+0x3a85>
 804d822:	52                   	push   edx
 804d823:	cf                   	iret   
 804d824:	74 01                	je     804d827 <_IO_stdin_used@@Base+0x3a6b>
 804d826:	5e                   	pop    esi
 804d827:	ce                   	into   
 804d828:	6a 19                	push   0x19
 804d82a:	43                   	inc    ebx
 804d82b:	d1                   	(bad)  
 804d82c:	75 01                	jne    804d82f <_IO_stdin_used@@Base+0x3a73>
 804d82e:	42                   	inc    edx
 804d82f:	cf                   	iret   
 804d830:	70 00                	jo     804d832 <_IO_stdin_used@@Base+0x3a76>
 804d832:	5c                   	pop    esp
 804d833:	d1 04 01             	rol    DWORD PTR [ecx+eax*1],1
 804d836:	42                   	inc    edx
 804d837:	cf                   	iret   
 804d838:	6c                   	ins    BYTE PTR es:[edi],dx
 804d839:	01 42 c6             	add    DWORD PTR [edx-0x3a],eax
 804d83c:	76 01                	jbe    804d83f <_IO_stdin_used@@Base+0x3a83>
 804d83e:	5c                   	pop    esp
 804d83f:	d1                   	(bad)  
 804d840:	74 19                	je     804d85b <_IO_stdin_used@@Base+0x3a9f>
 804d842:	42                   	inc    edx
 804d843:	ce                   	into   
 804d844:	6a 19                	push   0x19
 804d846:	43                   	inc    ebx
 804d847:	d1 e4                	shl    esp,1
 804d849:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804d84c:	68 00 5c d7 75       	push   0x75d75c00
 804d851:	1f                   	pop    ds
 804d852:	43                   	inc    ebx
 804d853:	cf                   	iret   
 804d854:	74 01                	je     804d857 <_IO_stdin_used@@Base+0x3a9b>
 804d856:	46                   	inc    esi
 804d857:	ce                   	into   
 804d858:	6a 1f                	push   0x1f
 804d85a:	36 cf                	ss iret 
 804d85c:	74 01                	je     804d85f <_IO_stdin_used@@Base+0x3aa3>
 804d85e:	5a                   	pop    edx
 804d85f:	cf                   	iret   
 804d860:	74 08                	je     804d86a <_IO_stdin_used@@Base+0x3aae>
 804d862:	40                   	inc    eax
 804d863:	cf                   	iret   
 804d864:	6a 1f                	push   0x1f
 804d866:	42                   	inc    edx
 804d867:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d868:	74 00                	je     804d86a <_IO_stdin_used@@Base+0x3aae>
 804d86a:	5c                   	pop    esp
 804d86b:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d86c:	75 1f                	jne    804d88d <_IO_stdin_used@@Base+0x3ad1>
 804d86e:	35 cf 74 01 5e       	xor    eax,0x5e0174cf
 804d873:	ce                   	into   
 804d874:	6a 19                	push   0x19
 804d876:	43                   	inc    ebx
 804d877:	cc                   	int3   
 804d878:	74 01                	je     804d87b <_IO_stdin_used@@Base+0x3abf>
 804d87a:	42                   	inc    edx
 804d87b:	cf                   	iret   
 804d87c:	7a c7                	jp     804d845 <_IO_stdin_used@@Base+0x3a89>
 804d87e:	55                   	push   ebp
 804d87f:	cf                   	iret   
 804d880:	74 0f                	je     804d891 <_IO_stdin_used@@Base+0x3ad5>
 804d882:	3a d7                	cmp    dl,bh
 804d884:	74 01                	je     804d887 <_IO_stdin_used@@Base+0x3acb>
 804d886:	5a                   	pop    edx
 804d887:	ce                   	into   
 804d888:	75 01                	jne    804d88b <_IO_stdin_used@@Base+0x3acf>
 804d88a:	42                   	inc    edx
 804d88b:	cf                   	iret   
 804d88c:	74 19                	je     804d8a7 <_IO_stdin_used@@Base+0x3aeb>
 804d88e:	43                   	inc    ebx
 804d88f:	cd 74                	int    0x74
 804d891:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804d894:	7a 61                	jp     804d8f7 <_IO_stdin_used@@Base+0x3b3b>
 804d896:	5a                   	pop    edx
 804d897:	cf                   	iret   
 804d898:	74 19                	je     804d8b3 <_IO_stdin_used@@Base+0x3af7>
 804d89a:	42                   	inc    edx
 804d89b:	d1                   	(bad)  
 804d89c:	76 05                	jbe    804d8a3 <_IO_stdin_used@@Base+0x3ae7>
 804d89e:	43                   	inc    ebx
 804d89f:	d1 6a 05             	shr    DWORD PTR [edx+0x5],1
 804d8a2:	42                   	inc    edx
 804d8a3:	cf                   	iret   
 804d8a4:	74 19                	je     804d8bf <_IO_stdin_used@@Base+0x3b03>
 804d8a6:	42                   	inc    edx
 804d8a7:	cf                   	iret   
 804d8a8:	7e 03                	jle    804d8ad <_IO_stdin_used@@Base+0x3af1>
 804d8aa:	42                   	inc    edx
 804d8ab:	d1 6a 01             	shr    DWORD PTR [edx+0x1],1
 804d8ae:	5a                   	pop    edx
 804d8af:	cf                   	iret   
 804d8b0:	77 1f                	ja     804d8d1 <_IO_stdin_used@@Base+0x3b15>
 804d8b2:	59                   	pop    ecx
 804d8b3:	cb                   	retf   
 804d8b4:	77 04                	ja     804d8ba <_IO_stdin_used@@Base+0x3afe>
 804d8b6:	43                   	inc    ebx
 804d8b7:	cf                   	iret   
 804d8b8:	77 03                	ja     804d8bd <_IO_stdin_used@@Base+0x3b01>
 804d8ba:	46                   	inc    esi
 804d8bb:	cf                   	iret   
 804d8bc:	74 01                	je     804d8bf <_IO_stdin_used@@Base+0x3b03>
 804d8be:	5a                   	pop    edx
 804d8bf:	cf                   	iret   
 804d8c0:	6a 02                	push   0x2
 804d8c2:	46                   	inc    esi
 804d8c3:	ce                   	into   
 804d8c4:	6a 1f                	push   0x1f
 804d8c6:	46                   	inc    esi
 804d8c7:	cf                   	iret   
 804d8c8:	74 01                	je     804d8cb <_IO_stdin_used@@Base+0x3b0f>
 804d8ca:	5a                   	pop    edx
 804d8cb:	cf                   	iret   
 804d8cc:	74 04                	je     804d8d2 <_IO_stdin_used@@Base+0x3b16>
 804d8ce:	40                   	inc    eax
 804d8cf:	cf                   	iret   
 804d8d0:	6a 1f                	push   0x1f
 804d8d2:	42                   	inc    edx
 804d8d3:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d8d4:	74 02                	je     804d8d8 <_IO_stdin_used@@Base+0x3b1c>
 804d8d6:	5c                   	pop    esp
 804d8d7:	d4 77                	aam    0x77
 804d8d9:	02 44 cf 70          	add    al,BYTE PTR [edi+ecx*8+0x70]
 804d8dd:	05 41 d7 74 1f       	add    eax,0x1f74d741
 804d8e2:	40                   	inc    eax
 804d8e3:	cb                   	retf   
 804d8e4:	75 1f                	jne    804d905 <_IO_stdin_used@@Base+0x3b49>
 804d8e6:	5c                   	pop    esp
 804d8e7:	cb                   	retf   
 804d8e8:	74 01                	je     804d8eb <_IO_stdin_used@@Base+0x3b2f>
 804d8ea:	42                   	inc    edx
 804d8eb:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d8ec:	74 01                	je     804d8ef <_IO_stdin_used@@Base+0x3b33>
 804d8ee:	4b                   	dec    ebx
 804d8ef:	cd 74                	int    0x74
 804d8f1:	1f                   	pop    ds
 804d8f2:	5c                   	pop    esp
 804d8f3:	cf                   	iret   
 804d8f4:	6c                   	ins    BYTE PTR es:[edi],dx
 804d8f5:	01 41 d1             	add    DWORD PTR [ecx-0x2f],eax
 804d8f8:	6f                   	outs   dx,DWORD PTR ds:[esi]
 804d8f9:	02 41 d7             	add    al,BYTE PTR [ecx-0x29]
 804d8fc:	74 1f                	je     804d91d <_IO_stdin_used@@Base+0x3b61>
 804d8fe:	46                   	inc    esi
 804d8ff:	d7                   	xlat   BYTE PTR ds:[ebx]
 804d900:	74 01                	je     804d903 <_IO_stdin_used@@Base+0x3b47>
 804d902:	41                   	inc    ecx
 804d903:	d8 74 1f 42          	fdiv   DWORD PTR [edi+ebx*1+0x42]
 804d907:	da 25 19 42 cf 7a    	fisub  DWORD PTR ds:0x7acf4219
 804d90d:	59                   	pop    ecx
 804d90e:	5a                   	pop    edx
 804d90f:	cf                   	iret   
 804d910:	74 19                	je     804d92b <_IO_stdin_used@@Base+0x3b6f>
 804d912:	43                   	inc    ebx
 804d913:	ce                   	into   
 804d914:	75 01                	jne    804d917 <_IO_stdin_used@@Base+0x3b5b>
 804d916:	42                   	inc    edx
 804d917:	cf                   	iret   
 804d918:	76 00                	jbe    804d91a <_IO_stdin_used@@Base+0x3b5e>
 804d91a:	40                   	inc    eax
 804d91b:	cd 75                	int    0x75
 804d91d:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804d920:	6c                   	ins    BYTE PTR es:[edi],dx
 804d921:	01 41 ce             	add    DWORD PTR [ecx-0x32],eax
 804d924:	6c                   	ins    BYTE PTR es:[edi],dx
 804d925:	01 5c cd 6c          	add    DWORD PTR [ebp+ecx*8+0x6c],ebx
 804d929:	00 42 d1             	add    BYTE PTR [edx-0x2f],al
 804d92c:	74 01                	je     804d92f <_IO_stdin_used@@Base+0x3b73>
 804d92e:	42                   	inc    edx
 804d92f:	d8 74 1f 42          	fdiv   DWORD PTR [edi+ebx*1+0x42]
 804d933:	de ad 16 42 cf 62    	fisubr WORD PTR [ebp+0x62cf4216]
 804d939:	01 41 cc             	add    DWORD PTR [ecx-0x34],eax
 804d93c:	61                   	popa   
 804d93d:	53                   	push   ebx
 804d93e:	5b                   	pop    ebx
 804d93f:	cf                   	iret   
 804d940:	74 19                	je     804d95b <_IO_stdin_used@@Base+0x3b9f>
 804d942:	43                   	inc    ebx
 804d943:	cf                   	iret   
 804d944:	37                   	aaa    
 804d945:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804d948:	7b 3e                	jnp    804d988 <_IO_stdin_used@@Base+0x3bcc>
 804d94a:	52                   	push   edx
 804d94b:	cf                   	iret   
 804d94c:	74 19                	je     804d967 <_IO_stdin_used@@Base+0x3bab>
 804d94e:	43                   	inc    ebx
 804d94f:	cf                   	iret   
 804d950:	1b 01                	sbb    eax,DWORD PTR [ecx]
 804d952:	42                   	inc    edx
 804d953:	cf                   	iret   
 804d954:	7b 3e                	jnp    804d994 <_IO_stdin_used@@Base+0x3bd8>
 804d956:	52                   	push   edx
 804d957:	cf                   	iret   
 804d958:	74 19                	je     804d973 <_IO_stdin_used@@Base+0x3bb7>
 804d95a:	43                   	inc    ebx
 804d95b:	cf                   	iret   
 804d95c:	1a 01                	sbb    al,BYTE PTR [ecx]
 804d95e:	42                   	inc    edx
 804d95f:	cf                   	iret   
 804d960:	7b 3e                	jnp    804d9a0 <_IO_stdin_used@@Base+0x3be4>
 804d962:	52                   	push   edx
 804d963:	cf                   	iret   
 804d964:	74 19                	je     804d97f <_IO_stdin_used@@Base+0x3bc3>
 804d966:	43                   	inc    ebx
 804d967:	cf                   	iret   
 804d968:	13 01                	adc    eax,DWORD PTR [ecx]
 804d96a:	42                   	inc    edx
 804d96b:	cf                   	iret   
 804d96c:	7b 3e                	jnp    804d9ac <_IO_stdin_used@@Base+0x3bf0>
 804d96e:	52                   	push   edx
 804d96f:	cf                   	iret   
 804d970:	74 19                	je     804d98b <_IO_stdin_used@@Base+0x3bcf>
 804d972:	43                   	inc    ebx
 804d973:	cf                   	iret   
 804d974:	06                   	push   es
 804d975:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804d978:	7b 3e                	jnp    804d9b8 <_IO_stdin_used@@Base+0x3bfc>
 804d97a:	52                   	push   edx
 804d97b:	cf                   	iret   
 804d97c:	74 19                	je     804d997 <_IO_stdin_used@@Base+0x3bdb>
 804d97e:	43                   	inc    ebx
 804d97f:	cf                   	iret   
 804d980:	15 01 42 cf 7b       	adc    eax,0x7bcf4201
 804d985:	3e 52                	ds push edx
 804d987:	cf                   	iret   
 804d988:	74 19                	je     804d9a3 <_IO_stdin_used@@Base+0x3be7>
 804d98a:	43                   	inc    ebx
 804d98b:	cf                   	iret   
 804d98c:	00 01                	add    BYTE PTR [ecx],al
 804d98e:	42                   	inc    edx
 804d98f:	cf                   	iret   
 804d990:	7b 3e                	jnp    804d9d0 <_IO_stdin_used@@Base+0x3c14>
 804d992:	52                   	push   edx
 804d993:	cf                   	iret   
 804d994:	74 19                	je     804d9af <_IO_stdin_used@@Base+0x3bf3>
 804d996:	43                   	inc    ebx
 804d997:	cf                   	iret   
 804d998:	01 01                	add    DWORD PTR [ecx],eax
 804d99a:	42                   	inc    edx
 804d99b:	cf                   	iret   
 804d99c:	7b 3e                	jnp    804d9dc <_IO_stdin_used@@Base+0x3c20>
 804d99e:	52                   	push   edx
 804d99f:	cf                   	iret   
 804d9a0:	74 19                	je     804d9bb <_IO_stdin_used@@Base+0x3bff>
 804d9a2:	43                   	inc    ebx
 804d9a3:	cf                   	iret   
 804d9a4:	18 01                	sbb    BYTE PTR [ecx],al
 804d9a6:	42                   	inc    edx
 804d9a7:	cf                   	iret   
 804d9a8:	7b 3e                	jnp    804d9e8 <_IO_stdin_used@@Base+0x3c2c>
 804d9aa:	52                   	push   edx
 804d9ab:	cf                   	iret   
 804d9ac:	74 19                	je     804d9c7 <_IO_stdin_used@@Base+0x3c0b>
 804d9ae:	43                   	inc    ebx
 804d9af:	cf                   	iret   
 804d9b0:	15 01 42 cf 7b       	adc    eax,0x7bcf4201
 804d9b5:	3e 52                	ds push edx
 804d9b7:	cf                   	iret   
 804d9b8:	74 19                	je     804d9d3 <_IO_stdin_used@@Base+0x3c17>
 804d9ba:	43                   	inc    ebx
 804d9bb:	cf                   	iret   
 804d9bc:	00 01                	add    BYTE PTR [ecx],al
 804d9be:	42                   	inc    edx
 804d9bf:	cf                   	iret   
 804d9c0:	7b 3e                	jnp    804da00 <_IO_stdin_used@@Base+0x3c44>
 804d9c2:	52                   	push   edx
 804d9c3:	cf                   	iret   
 804d9c4:	74 19                	je     804d9df <_IO_stdin_used@@Base+0x3c23>
 804d9c6:	43                   	inc    ebx
 804d9c7:	cf                   	iret   
 804d9c8:	1d 01 42 cf 7b       	sbb    eax,0x7bcf4201
 804d9cd:	3e 52                	ds push edx
 804d9cf:	cf                   	iret   
 804d9d0:	74 19                	je     804d9eb <_IO_stdin_used@@Base+0x3c2f>
 804d9d2:	43                   	inc    ebx
 804d9d3:	cf                   	iret   
 804d9d4:	1b 01                	sbb    eax,DWORD PTR [ecx]
 804d9d6:	42                   	inc    edx
 804d9d7:	cf                   	iret   
 804d9d8:	7b 3e                	jnp    804da18 <_IO_stdin_used@@Base+0x3c5c>
 804d9da:	52                   	push   edx
 804d9db:	cf                   	iret   
 804d9dc:	74 19                	je     804d9f7 <_IO_stdin_used@@Base+0x3c3b>
 804d9de:	43                   	inc    ebx
 804d9df:	cf                   	iret   
 804d9e0:	1a 01                	sbb    al,BYTE PTR [ecx]
 804d9e2:	42                   	inc    edx
 804d9e3:	cf                   	iret   
 804d9e4:	7b 3e                	jnp    804da24 <_IO_stdin_used@@Base+0x3c68>
 804d9e6:	52                   	push   edx
 804d9e7:	cf                   	iret   
 804d9e8:	74 19                	je     804da03 <_IO_stdin_used@@Base+0x3c47>
 804d9ea:	43                   	inc    ebx
 804d9eb:	cf                   	iret   
 804d9ec:	07                   	pop    es
 804d9ed:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804d9f0:	7b 3e                	jnp    804da30 <_IO_stdin_used@@Base+0x3c74>
 804d9f2:	52                   	push   edx
 804d9f3:	cf                   	iret   
 804d9f4:	74 19                	je     804da0f <_IO_stdin_used@@Base+0x3c53>
 804d9f6:	43                   	inc    ebx
 804d9f7:	cf                   	iret   
 804d9f8:	55                   	push   ebp
 804d9f9:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804d9fc:	7b 3e                	jnp    804da3c <_IO_stdin_used@@Base+0x3c80>
 804d9fe:	52                   	push   edx
 804d9ff:	cf                   	iret   
 804da00:	74 19                	je     804da1b <_IO_stdin_used@@Base+0x3c5f>
 804da02:	43                   	inc    ebx
 804da03:	cf                   	iret   
 804da04:	7e 01                	jle    804da07 <_IO_stdin_used@@Base+0x3c4b>
 804da06:	42                   	inc    edx
 804da07:	cf                   	iret   
 804da08:	7b 3e                	jnp    804da48 <_IO_stdin_used@@Base+0x3c8c>
 804da0a:	52                   	push   edx
 804da0b:	cf                   	iret   
 804da0c:	74 0f                	je     804da1d <_IO_stdin_used@@Base+0x3c61>
 804da0e:	24 d5                	and    al,0xd5
 804da10:	74 01                	je     804da13 <_IO_stdin_used@@Base+0x3c57>
 804da12:	5a                   	pop    edx
 804da13:	ce                   	into   
 804da14:	74 52                	je     804da68 <_IO_stdin_used@@Base+0x3cac>
 804da16:	42                   	inc    edx
 804da17:	cf                   	iret   
 804da18:	74 0e                	je     804da28 <_IO_stdin_used@@Base+0x3c6c>
 804da1a:	7d df                	jge    804d9fb <_IO_stdin_used@@Base+0x3c3f>
 804da1c:	74 01                	je     804da1f <_IO_stdin_used@@Base+0x3c63>
 804da1e:	5a                   	pop    edx
 804da1f:	ce                   	into   
 804da20:	74 6e                	je     804da90 <_IO_stdin_used@@Base+0x3cd4>
 804da22:	42                   	inc    edx
 804da23:	cf                   	iret   
 804da24:	74 0e                	je     804da34 <_IO_stdin_used@@Base+0x3c78>
 804da26:	7d df                	jge    804da07 <_IO_stdin_used@@Base+0x3c4b>
 804da28:	74 01                	je     804da2b <_IO_stdin_used@@Base+0x3c6f>
 804da2a:	5a                   	pop    edx
 804da2b:	ce                   	into   
 804da2c:	74 73                	je     804daa1 <_IO_stdin_used@@Base+0x3ce5>
 804da2e:	42                   	inc    edx
 804da2f:	cf                   	iret   
 804da30:	74 0e                	je     804da40 <_IO_stdin_used@@Base+0x3c84>
 804da32:	7d df                	jge    804da13 <_IO_stdin_used@@Base+0x3c57>
 804da34:	74 01                	je     804da37 <_IO_stdin_used@@Base+0x3c7b>
 804da36:	5a                   	pop    edx
 804da37:	ce                   	into   
 804da38:	74 73                	je     804daad <_IO_stdin_used@@Base+0x3cf1>
 804da3a:	42                   	inc    edx
 804da3b:	cf                   	iret   
 804da3c:	74 0e                	je     804da4c <_IO_stdin_used@@Base+0x3c90>
 804da3e:	7d df                	jge    804da1f <_IO_stdin_used@@Base+0x3c63>
 804da40:	74 01                	je     804da43 <_IO_stdin_used@@Base+0x3c87>
 804da42:	5a                   	pop    edx
 804da43:	ce                   	into   
 804da44:	74 78                	je     804dabe <_IO_stdin_used@@Base+0x3d02>
 804da46:	42                   	inc    edx
 804da47:	cf                   	iret   
 804da48:	74 0e                	je     804da58 <_IO_stdin_used@@Base+0x3c9c>
 804da4a:	7d df                	jge    804da2b <_IO_stdin_used@@Base+0x3c6f>
 804da4c:	74 01                	je     804da4f <_IO_stdin_used@@Base+0x3c93>
 804da4e:	5a                   	pop    edx
 804da4f:	ce                   	into   
 804da50:	74 2d                	je     804da7f <_IO_stdin_used@@Base+0x3cc3>
 804da52:	42                   	inc    edx
 804da53:	cf                   	iret   
 804da54:	74 0e                	je     804da64 <_IO_stdin_used@@Base+0x3ca8>
 804da56:	7d df                	jge    804da37 <_IO_stdin_used@@Base+0x3c7b>
 804da58:	74 01                	je     804da5b <_IO_stdin_used@@Base+0x3c9f>
 804da5a:	5a                   	pop    edx
 804da5b:	ce                   	into   
 804da5c:	74 21                	je     804da7f <_IO_stdin_used@@Base+0x3cc3>
 804da5e:	42                   	inc    edx
 804da5f:	cf                   	iret   
 804da60:	74 0e                	je     804da70 <_IO_stdin_used@@Base+0x3cb4>
 804da62:	7d df                	jge    804da43 <_IO_stdin_used@@Base+0x3c87>
 804da64:	74 01                	je     804da67 <_IO_stdin_used@@Base+0x3cab>
 804da66:	5a                   	pop    edx
 804da67:	ce                   	into   
 804da68:	74 76                	je     804dae0 <_IO_stdin_used@@Base+0x3d24>
 804da6a:	42                   	inc    edx
 804da6b:	cf                   	iret   
 804da6c:	74 0e                	je     804da7c <_IO_stdin_used@@Base+0x3cc0>
 804da6e:	7d df                	jge    804da4f <_IO_stdin_used@@Base+0x3c93>
 804da70:	74 01                	je     804da73 <_IO_stdin_used@@Base+0x3cb7>
 804da72:	5a                   	pop    edx
 804da73:	ce                   	into   
 804da74:	74 73                	je     804dae9 <_IO_stdin_used@@Base+0x3d2d>
 804da76:	42                   	inc    edx
 804da77:	cf                   	iret   
 804da78:	74 0e                	je     804da88 <_IO_stdin_used@@Base+0x3ccc>
 804da7a:	7d df                	jge    804da5b <_IO_stdin_used@@Base+0x3c9f>
 804da7c:	74 01                	je     804da7f <_IO_stdin_used@@Base+0x3cc3>
 804da7e:	5a                   	pop    edx
 804da7f:	ce                   	into   
 804da80:	74 6e                	je     804daf0 <_IO_stdin_used@@Base+0x3d34>
 804da82:	42                   	inc    edx
 804da83:	cf                   	iret   
 804da84:	74 0e                	je     804da94 <_IO_stdin_used@@Base+0x3cd8>
 804da86:	7d df                	jge    804da67 <_IO_stdin_used@@Base+0x3cab>
 804da88:	74 01                	je     804da8b <_IO_stdin_used@@Base+0x3ccf>
 804da8a:	5a                   	pop    edx
 804da8b:	ce                   	into   
 804da8c:	74 6f                	je     804dafd <_IO_stdin_used@@Base+0x3d41>
 804da8e:	42                   	inc    edx
 804da8f:	cf                   	iret   
 804da90:	74 0e                	je     804daa0 <_IO_stdin_used@@Base+0x3ce4>
 804da92:	7d df                	jge    804da73 <_IO_stdin_used@@Base+0x3cb7>
 804da94:	74 01                	je     804da97 <_IO_stdin_used@@Base+0x3cdb>
 804da96:	5a                   	pop    edx
 804da97:	ce                   	into   
 804da98:	74 66                	je     804db00 <_IO_stdin_used@@Base+0x3d44>
 804da9a:	42                   	inc    edx
 804da9b:	cf                   	iret   
 804da9c:	74 0e                	je     804daac <_IO_stdin_used@@Base+0x3cf0>
 804da9e:	7d df                	jge    804da7f <_IO_stdin_used@@Base+0x3cc3>
 804daa0:	74 01                	je     804daa3 <_IO_stdin_used@@Base+0x3ce7>
 804daa2:	5a                   	pop    edx
 804daa3:	ce                   	into   
 804daa4:	74 21                	je     804dac7 <_IO_stdin_used@@Base+0x3d0b>
 804daa6:	42                   	inc    edx
 804daa7:	cf                   	iret   
 804daa8:	74 0e                	je     804dab8 <_IO_stdin_used@@Base+0x3cfc>
 804daaa:	7d df                	jge    804da8b <_IO_stdin_used@@Base+0x3ccf>
 804daac:	74 01                	je     804daaf <_IO_stdin_used@@Base+0x3cf3>
 804daae:	5a                   	pop    edx
 804daaf:	ce                   	into   
 804dab0:	74 71                	je     804db23 <_IO_stdin_used@@Base+0x3d67>
 804dab2:	42                   	inc    edx
 804dab3:	cf                   	iret   
 804dab4:	74 0e                	je     804dac4 <_IO_stdin_used@@Base+0x3d08>
 804dab6:	7d df                	jge    804da97 <_IO_stdin_used@@Base+0x3cdb>
 804dab8:	74 01                	je     804dabb <_IO_stdin_used@@Base+0x3cff>
 804daba:	5a                   	pop    edx
 804dabb:	ce                   	into   
 804dabc:	74 60                	je     804db1e <_IO_stdin_used@@Base+0x3d62>
 804dabe:	42                   	inc    edx
 804dabf:	cf                   	iret   
 804dac0:	74 0e                	je     804dad0 <_IO_stdin_used@@Base+0x3d14>
 804dac2:	7d df                	jge    804daa3 <_IO_stdin_used@@Base+0x3ce7>
 804dac4:	74 01                	je     804dac7 <_IO_stdin_used@@Base+0x3d0b>
 804dac6:	5a                   	pop    edx
 804dac7:	ce                   	into   
 804dac8:	74 72                	je     804db3c <_IO_stdin_used@@Base+0x3d80>
 804daca:	42                   	inc    edx
 804dacb:	cf                   	iret   
 804dacc:	74 0e                	je     804dadc <_IO_stdin_used@@Base+0x3d20>
 804dace:	7d df                	jge    804daaf <_IO_stdin_used@@Base+0x3cf3>
 804dad0:	74 01                	je     804dad3 <_IO_stdin_used@@Base+0x3d17>
 804dad2:	5a                   	pop    edx
 804dad3:	ce                   	into   
 804dad4:	74 72                	je     804db48 <_IO_stdin_used@@Base+0x3d8c>
 804dad6:	42                   	inc    edx
 804dad7:	cf                   	iret   
 804dad8:	74 0e                	je     804dae8 <_IO_stdin_used@@Base+0x3d2c>
 804dada:	7d df                	jge    804dabb <_IO_stdin_used@@Base+0x3cff>
 804dadc:	74 01                	je     804dadf <_IO_stdin_used@@Base+0x3d23>
 804dade:	5a                   	pop    edx
 804dadf:	ce                   	into   
 804dae0:	74 76                	je     804db58 <_IO_stdin_used@@Base+0x3d9c>
 804dae2:	42                   	inc    edx
 804dae3:	cf                   	iret   
 804dae4:	74 0e                	je     804daf4 <_IO_stdin_used@@Base+0x3d38>
 804dae6:	7d df                	jge    804dac7 <_IO_stdin_used@@Base+0x3d0b>
 804dae8:	74 01                	je     804daeb <_IO_stdin_used@@Base+0x3d2f>
 804daea:	5a                   	pop    edx
 804daeb:	ce                   	into   
 804daec:	74 6e                	je     804db5c <_IO_stdin_used@@Base+0x3da0>
 804daee:	42                   	inc    edx
 804daef:	cf                   	iret   
 804daf0:	74 0e                	je     804db00 <_IO_stdin_used@@Base+0x3d44>
 804daf2:	7d df                	jge    804dad3 <_IO_stdin_used@@Base+0x3d17>
 804daf4:	74 01                	je     804daf7 <_IO_stdin_used@@Base+0x3d3b>
 804daf6:	5a                   	pop    edx
 804daf7:	ce                   	into   
 804daf8:	74 73                	je     804db6d <_IO_stdin_used@@Base+0x3db1>
 804dafa:	42                   	inc    edx
 804dafb:	cf                   	iret   
 804dafc:	74 0e                	je     804db0c <_IO_stdin_used@@Base+0x3d50>
 804dafe:	7d df                	jge    804dadf <_IO_stdin_used@@Base+0x3d23>
 804db00:	74 01                	je     804db03 <_IO_stdin_used@@Base+0x3d47>
 804db02:	5a                   	pop    edx
 804db03:	ce                   	into   
 804db04:	74 65                	je     804db6b <_IO_stdin_used@@Base+0x3daf>
 804db06:	42                   	inc    edx
 804db07:	cf                   	iret   
 804db08:	74 0e                	je     804db18 <_IO_stdin_used@@Base+0x3d5c>
 804db0a:	7d df                	jge    804daeb <_IO_stdin_used@@Base+0x3d2f>
 804db0c:	74 01                	je     804db0f <_IO_stdin_used@@Base+0x3d53>
 804db0e:	5a                   	pop    edx
 804db0f:	ce                   	into   
 804db10:	74 20                	je     804db32 <_IO_stdin_used@@Base+0x3d76>
 804db12:	42                   	inc    edx
 804db13:	cf                   	iret   
 804db14:	74 0e                	je     804db24 <_IO_stdin_used@@Base+0x3d68>
 804db16:	7d df                	jge    804daf7 <_IO_stdin_used@@Base+0x3d3b>
 804db18:	74 01                	je     804db1b <_IO_stdin_used@@Base+0x3d5f>
 804db1a:	5a                   	pop    edx
 804db1b:	ce                   	into   
 804db1c:	74 0b                	je     804db29 <_IO_stdin_used@@Base+0x3d6d>
 804db1e:	42                   	inc    edx
 804db1f:	cf                   	iret   
 804db20:	74 0e                	je     804db30 <_IO_stdin_used@@Base+0x3d74>
 804db22:	7d df                	jge    804db03 <_IO_stdin_used@@Base+0x3d47>
 804db24:	74 01                	je     804db27 <_IO_stdin_used@@Base+0x3d6b>
 804db26:	5d                   	pop    ebp
 804db27:	c5 6b 08             	lds    ebp,FWORD PTR [ebx+0x8]
 804db2a:	43                   	inc    ebx
 804db2b:	d2 69 19             	shr    BYTE PTR [ecx+0x19],cl
 804db2e:	43                   	inc    ebx
 804db2f:	cf                   	iret   
 804db30:	24 01                	and    al,0x1
 804db32:	42                   	inc    edx
 804db33:	cf                   	iret   
 804db34:	7b 3e                	jnp    804db74 <_IO_stdin_used@@Base+0x3db8>
 804db36:	52                   	push   edx
 804db37:	cf                   	iret   
 804db38:	74 19                	je     804db53 <_IO_stdin_used@@Base+0x3d97>
 804db3a:	43                   	inc    ebx
 804db3b:	cf                   	iret   
 804db3c:	18 01                	sbb    BYTE PTR [ecx],al
 804db3e:	42                   	inc    edx
 804db3f:	cf                   	iret   
 804db40:	7b 3e                	jnp    804db80 <_IO_stdin_used@@Base+0x3dc4>
 804db42:	52                   	push   edx
 804db43:	cf                   	iret   
 804db44:	74 19                	je     804db5f <_IO_stdin_used@@Base+0x3da3>
 804db46:	43                   	inc    ebx
 804db47:	cf                   	iret   
 804db48:	11 01                	adc    DWORD PTR [ecx],eax
 804db4a:	42                   	inc    edx
 804db4b:	cf                   	iret   
 804db4c:	7b 3e                	jnp    804db8c <_IO_stdin_used@@Base+0x3dd0>
 804db4e:	52                   	push   edx
 804db4f:	cf                   	iret   
 804db50:	74 19                	je     804db6b <_IO_stdin_used@@Base+0x3daf>
 804db52:	43                   	inc    ebx
 804db53:	cf                   	iret   
 804db54:	15 01 42 cf 7b       	adc    eax,0x7bcf4201
 804db59:	3e 52                	ds push edx
 804db5b:	cf                   	iret   
 804db5c:	74 19                	je     804db77 <_IO_stdin_used@@Base+0x3dbb>
 804db5e:	43                   	inc    ebx
 804db5f:	cf                   	iret   
 804db60:	07                   	pop    es
 804db61:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804db64:	7b 3e                	jnp    804dba4 <_IO_stdin_used@@Base+0x3de8>
 804db66:	52                   	push   edx
 804db67:	cf                   	iret   
 804db68:	74 19                	je     804db83 <_IO_stdin_used@@Base+0x3dc7>
 804db6a:	43                   	inc    ebx
 804db6b:	cf                   	iret   
 804db6c:	11 01                	adc    DWORD PTR [ecx],eax
 804db6e:	42                   	inc    edx
 804db6f:	cf                   	iret   
 804db70:	7b 3e                	jnp    804dbb0 <_IO_stdin_used@@Base+0x3df4>
 804db72:	52                   	push   edx
 804db73:	cf                   	iret   
 804db74:	74 19                	je     804db8f <_IO_stdin_used@@Base+0x3dd3>
 804db76:	43                   	inc    ebx
 804db77:	cf                   	iret   
 804db78:	54                   	push   esp
 804db79:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804db7c:	7b 3e                	jnp    804dbbc <_IO_stdin_used@@Base+0x3e00>
 804db7e:	52                   	push   edx
 804db7f:	cf                   	iret   
 804db80:	74 19                	je     804db9b <_IO_stdin_used@@Base+0x3ddf>
 804db82:	43                   	inc    ebx
 804db83:	cf                   	iret   
 804db84:	11 01                	adc    DWORD PTR [ecx],eax
 804db86:	42                   	inc    edx
 804db87:	cf                   	iret   
 804db88:	7b 3e                	jnp    804dbc8 <_IO_stdin_used@@Base+0x3e0c>
 804db8a:	52                   	push   edx
 804db8b:	cf                   	iret   
 804db8c:	74 19                	je     804dba7 <_IO_stdin_used@@Base+0x3deb>
 804db8e:	43                   	inc    ebx
 804db8f:	cf                   	iret   
 804db90:	1a 01                	sbb    al,BYTE PTR [ecx]
 804db92:	42                   	inc    edx
 804db93:	cf                   	iret   
 804db94:	7b 3e                	jnp    804dbd4 <_IO_stdin_used@@Base+0x3e18>
 804db96:	52                   	push   edx
 804db97:	cf                   	iret   
 804db98:	74 19                	je     804dbb3 <_IO_stdin_used@@Base+0x3df7>
 804db9a:	43                   	inc    ebx
 804db9b:	cf                   	iret   
 804db9c:	00 01                	add    BYTE PTR [ecx],al
 804db9e:	42                   	inc    edx
 804db9f:	cf                   	iret   
 804dba0:	7b 3e                	jnp    804dbe0 <_IO_stdin_used@@Base+0x3e24>
 804dba2:	52                   	push   edx
 804dba3:	cf                   	iret   
 804dba4:	74 19                	je     804dbbf <_IO_stdin_used@@Base+0x3e03>
 804dba6:	43                   	inc    ebx
 804dba7:	cf                   	iret   
 804dba8:	11 01                	adc    DWORD PTR [ecx],eax
 804dbaa:	42                   	inc    edx
 804dbab:	cf                   	iret   
 804dbac:	7b 3e                	jnp    804dbec <_IO_stdin_used@@Base+0x3e30>
 804dbae:	52                   	push   edx
 804dbaf:	cf                   	iret   
 804dbb0:	74 19                	je     804dbcb <_IO_stdin_used@@Base+0x3e0f>
 804dbb2:	43                   	inc    ebx
 804dbb3:	cf                   	iret   
 804dbb4:	06                   	push   es
 804dbb5:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804dbb8:	7b 3e                	jnp    804dbf8 <_IO_stdin_used@@Base+0x3e3c>
 804dbba:	52                   	push   edx
 804dbbb:	cf                   	iret   
 804dbbc:	74 19                	je     804dbd7 <_IO_stdin_used@@Base+0x3e1b>
 804dbbe:	43                   	inc    ebx
 804dbbf:	cf                   	iret   
 804dbc0:	54                   	push   esp
 804dbc1:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804dbc4:	7b 3e                	jnp    804dc04 <_IO_stdin_used@@Base+0x3e48>
 804dbc6:	52                   	push   edx
 804dbc7:	cf                   	iret   
 804dbc8:	74 19                	je     804dbe3 <_IO_stdin_used@@Base+0x3e27>
 804dbca:	43                   	inc    ebx
 804dbcb:	cf                   	iret   
 804dbcc:	0d 01 42 cf 7b       	or     eax,0x7bcf4201
 804dbd1:	3e 52                	ds push edx
 804dbd3:	cf                   	iret   
 804dbd4:	74 19                	je     804dbef <_IO_stdin_used@@Base+0x3e33>
 804dbd6:	43                   	inc    ebx
 804dbd7:	cf                   	iret   
 804dbd8:	1b 01                	sbb    eax,DWORD PTR [ecx]
 804dbda:	42                   	inc    edx
 804dbdb:	cf                   	iret   
 804dbdc:	7b 3e                	jnp    804dc1c <_IO_stdin_used@@Base+0x3e60>
 804dbde:	52                   	push   edx
 804dbdf:	cf                   	iret   
 804dbe0:	74 19                	je     804dbfb <_IO_stdin_used@@Base+0x3e3f>
 804dbe2:	43                   	inc    ebx
 804dbe3:	cf                   	iret   
 804dbe4:	01 01                	add    DWORD PTR [ecx],eax
 804dbe6:	42                   	inc    edx
 804dbe7:	cf                   	iret   
 804dbe8:	7b 3e                	jnp    804dc28 <_IO_stdin_used@@Base+0x3e6c>
 804dbea:	52                   	push   edx
 804dbeb:	cf                   	iret   
 804dbec:	74 19                	je     804dc07 <_IO_stdin_used@@Base+0x3e4b>
 804dbee:	43                   	inc    ebx
 804dbef:	cf                   	iret   
 804dbf0:	06                   	push   es
 804dbf1:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804dbf4:	7b 3e                	jnp    804dc34 <_IO_stdin_used@@Base+0x3e78>
 804dbf6:	52                   	push   edx
 804dbf7:	cf                   	iret   
 804dbf8:	74 19                	je     804dc13 <_IO_stdin_used@@Base+0x3e57>
 804dbfa:	43                   	inc    ebx
 804dbfb:	cf                   	iret   
 804dbfc:	54                   	push   esp
 804dbfd:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804dc00:	7b 3e                	jnp    804dc40 <_IO_stdin_used@@Base+0x3e84>
 804dc02:	52                   	push   edx
 804dc03:	cf                   	iret   
 804dc04:	74 19                	je     804dc1f <_IO_stdin_used@@Base+0x3e63>
 804dc06:	43                   	inc    ebx
 804dc07:	cf                   	iret   
 804dc08:	04 01                	add    al,0x1
 804dc0a:	42                   	inc    edx
 804dc0b:	cf                   	iret   
 804dc0c:	7b 3e                	jnp    804dc4c <_IO_stdin_used@@Base+0x3e90>
 804dc0e:	52                   	push   edx
 804dc0f:	cf                   	iret   
 804dc10:	74 19                	je     804dc2b <_IO_stdin_used@@Base+0x3e6f>
 804dc12:	43                   	inc    ebx
 804dc13:	cf                   	iret   
 804dc14:	15 01 42 cf 7b       	adc    eax,0x7bcf4201
 804dc19:	3e 52                	ds push edx
 804dc1b:	cf                   	iret   
 804dc1c:	74 19                	je     804dc37 <_IO_stdin_used@@Base+0x3e7b>
 804dc1e:	43                   	inc    ebx
 804dc1f:	cf                   	iret   
 804dc20:	07                   	pop    es
 804dc21:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804dc24:	7b 3e                	jnp    804dc64 <_IO_stdin_used@@Base+0x3ea8>
 804dc26:	52                   	push   edx
 804dc27:	cf                   	iret   
 804dc28:	74 19                	je     804dc43 <_IO_stdin_used@@Base+0x3e87>
 804dc2a:	43                   	inc    ebx
 804dc2b:	cf                   	iret   
 804dc2c:	07                   	pop    es
 804dc2d:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804dc30:	7b 3e                	jnp    804dc70 <_IO_stdin_used@@Base+0x3eb4>
 804dc32:	52                   	push   edx
 804dc33:	cf                   	iret   
 804dc34:	74 19                	je     804dc4f <_IO_stdin_used@@Base+0x3e93>
 804dc36:	43                   	inc    ebx
 804dc37:	cf                   	iret   
 804dc38:	03 01                	add    eax,DWORD PTR [ecx]
 804dc3a:	42                   	inc    edx
 804dc3b:	cf                   	iret   
 804dc3c:	7b 3e                	jnp    804dc7c <_IO_stdin_used@@Base+0x3ec0>
 804dc3e:	52                   	push   edx
 804dc3f:	cf                   	iret   
 804dc40:	74 19                	je     804dc5b <_IO_stdin_used@@Base+0x3e9f>
 804dc42:	43                   	inc    ebx
 804dc43:	cf                   	iret   
 804dc44:	1b 01                	sbb    eax,DWORD PTR [ecx]
 804dc46:	42                   	inc    edx
 804dc47:	cf                   	iret   
 804dc48:	7b 3e                	jnp    804dc88 <_IO_stdin_used@@Base+0x3ecc>
 804dc4a:	52                   	push   edx
 804dc4b:	cf                   	iret   
 804dc4c:	74 19                	je     804dc67 <_IO_stdin_used@@Base+0x3eab>
 804dc4e:	43                   	inc    ebx
 804dc4f:	cf                   	iret   
 804dc50:	06                   	push   es
 804dc51:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804dc54:	7b 3e                	jnp    804dc94 <_IO_stdin_used@@Base+0x3ed8>
 804dc56:	52                   	push   edx
 804dc57:	cf                   	iret   
 804dc58:	74 19                	je     804dc73 <_IO_stdin_used@@Base+0x3eb7>
 804dc5a:	43                   	inc    ebx
 804dc5b:	cf                   	iret   
 804dc5c:	10 01                	adc    BYTE PTR [ecx],al
 804dc5e:	42                   	inc    edx
 804dc5f:	cf                   	iret   
 804dc60:	7b 3e                	jnp    804dca0 <_IO_stdin_used@@Base+0x3ee4>
 804dc62:	52                   	push   edx
 804dc63:	cf                   	iret   
 804dc64:	74 19                	je     804dc7f <_IO_stdin_used@@Base+0x3ec3>
 804dc66:	43                   	inc    ebx
 804dc67:	cf                   	iret   
 804dc68:	4e                   	dec    esi
 804dc69:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804dc6c:	7b 3e                	jnp    804dcac <_IO_stdin_used@@Base+0x3ef0>
 804dc6e:	52                   	push   edx
 804dc6f:	cf                   	iret   
 804dc70:	74 19                	je     804dc8b <_IO_stdin_used@@Base+0x3ecf>
 804dc72:	43                   	inc    ebx
 804dc73:	cf                   	iret   
 804dc74:	54                   	push   esp
 804dc75:	01 42 cf             	add    DWORD PTR [edx-0x31],eax
 804dc78:	7b 3e                	jnp    804dcb8 <_IO_stdin_used@@Base+0x3efc>
 804dc7a:	52                   	push   edx
 804dc7b:	cf                   	iret   
 804dc7c:	74 00                	je     804dc7e <_IO_stdin_used@@Base+0x3ec2>
 804dc7e:	5f                   	pop    edi
 804dc7f:	d2 6a 01             	shr    BYTE PTR [edx+0x1],cl
 804dc82:	4b                   	dec    ebx
 804dc83:	d1                   	(bad)  
 804dc84:	74 0b                	je     804dc91 <_IO_stdin_used@@Base+0x3ed5>
 804dc86:	5c                   	pop    esp
 804dc87:	cf                   	iret   
 804dc88:	7f 0e                	jg     804dc98 <_IO_stdin_used@@Base+0x3edc>
 804dc8a:	2f                   	das    
 804dc8b:	d5 74                	aad    0x74
 804dc8d:	01 5a ce             	add    DWORD PTR [edx-0x32],ebx
 804dc90:	75 1f                	jne    804dcb1 <_IO_stdin_used@@Base+0x3ef5>
 804dc92:	42                   	inc    edx
 804dc93:	cf                   	iret   
 804dc94:	74 19                	je     804dcaf <_IO_stdin_used@@Base+0x3ef3>
 804dc96:	43                   	inc    ebx
 804dc97:	cf                   	iret   
 804dc98:	70 01                	jo     804dc9b <_IO_stdin_used@@Base+0x3edf>
 804dc9a:	42                   	inc    edx
 804dc9b:	cf                   	iret   
 804dc9c:	7b 81                	jnp    804dc1f <_IO_stdin_used@@Base+0x3e63>
 804dc9e:	52                   	push   edx
 804dc9f:	cf                   	iret   
 804dca0:	74 19                	je     804dcbb <_IO_stdin_used@@Base+0x3eff>
 804dca2:	42                   	inc    edx
 804dca3:	c4 74 0f ad          	les    esi,FWORD PTR [edi+ecx*1-0x53]
 804dca7:	d4 74                	aam    0x74
 804dca9:	01 4c b5 69          	add    DWORD PTR [ebp+esi*4+0x69],ecx
 804dcad:	01 42 d7             	add    DWORD PTR [edx-0x29],eax
 804dcb0:	75 08                	jne    804dcba <_IO_stdin_used@@Base+0x3efe>
 804dcb2:	42                   	inc    edx
 804dcb3:	cf                   	iret   
 804dcb4:	74 01                	je     804dcb7 <_IO_stdin_used@@Base+0x3efb>
 804dcb6:	4c                   	dec    esp
 804dcb7:	a9 69 01 42 d7       	test   eax,0xd7420169
 804dcbc:	74 1f                	je     804dcdd <_IO_stdin_used@@Base+0x3f21>
 804dcbe:	4b                   	dec    ebx
 804dcbf:	cb                   	retf   
 804dcc0:	75 1f                	jne    804dce1 <_IO_stdin_used@@Base+0x3f25>
 804dcc2:	5c                   	pop    esp
 804dcc3:	cb                   	retf   
 804dcc4:	74 01                	je     804dcc7 <_IO_stdin_used@@Base+0x3f0b>
 804dcc6:	42                   	inc    edx
 804dcc7:	d7                   	xlat   BYTE PTR ds:[ebx]
 804dcc8:	74 01                	je     804dccb <_IO_stdin_used@@Base+0x3f0f>
 804dcca:	49                   	dec    ecx
 804dccb:	cd 74                	int    0x74
 804dccd:	1f                   	pop    ds
 804dcce:	5c                   	pop    esp
 804dccf:	cf                   	iret   
 804dcd0:	6c                   	ins    BYTE PTR es:[edi],dx
 804dcd1:	01 48 d1             	add    DWORD PTR [eax-0x2f],ecx
 804dcd4:	7b 4a                	jnp    804dd20 <_IO_stdin_used@@Base+0x3f64>
 804dcd6:	52                   	push   edx
 804dcd7:	cf                   	iret   
 804dcd8:	74 19                	je     804dcf3 <_IO_stdin_used@@Base+0x3f37>
 804dcda:	42                   	inc    edx
 804dcdb:	ce                   	into   
 804dcdc:	74 1d                	je     804dcfb <_IO_stdin_used@@Base+0x3f3f>
 804dcde:	48                   	dec    eax
 804dcdf:	ce                   	into   
 804dce0:	6f                   	outs   dx,DWORD PTR ds:[esi]
 804dce1:	00 48 d7             	add    BYTE PTR [eax-0x29],cl
 804dce4:	74 1f                	je     804dd05 <_IO_stdin_used@@Base+0x3f49>
 804dce6:	43                   	inc    ebx
 804dce7:	d7                   	xlat   BYTE PTR ds:[ebx]
 804dce8:	75 01                	jne    804dceb <_IO_stdin_used@@Base+0x3f2f>
 804dcea:	48                   	dec    eax
 804dceb:	cf                   	iret   
 804dcec:	74 01                	je     804dcef <_IO_stdin_used@@Base+0x3f33>
 804dcee:	55                   	push   ebp
 804dcef:	cf                   	iret   
 804dcf0:	6a 01                	push   0x1
 804dcf2:	52                   	push   edx
 804dcf3:	f3 68 01 42 c1 2a    	repz push 0x2ac14201
 804dcf9:	1c 42                	sbb    al,0x42
 804dcfb:	cf                   	iret   
 804dcfc:	6c                   	ins    BYTE PTR es:[edi],dx
 804dcfd:	00 42 9c             	add    BYTE PTR [edx-0x64],al
 804dd00:	74 01                	je     804dd03 <_IO_stdin_used@@Base+0x3f47>
 804dd02:	42                   	inc    edx
 804dd03:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804dd07:	cf                   	iret   
 804dd08:	6c                   	ins    BYTE PTR es:[edi],dx
 804dd09:	00 42 a0             	add    BYTE PTR [edx-0x60],al
 804dd0c:	74 01                	je     804dd0f <_IO_stdin_used@@Base+0x3f53>
 804dd0e:	42                   	inc    edx
 804dd0f:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804dd13:	cf                   	iret   
 804dd14:	6c                   	ins    BYTE PTR es:[edi],dx
 804dd15:	00 42 bd             	add    BYTE PTR [edx-0x43],al
 804dd18:	74 01                	je     804dd1b <_IO_stdin_used@@Base+0x3f5f>
 804dd1a:	42                   	inc    edx
 804dd1b:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804dd1f:	cf                   	iret   
 804dd20:	6c                   	ins    BYTE PTR es:[edi],dx
 804dd21:	00 42 bd             	add    BYTE PTR [edx-0x43],al
 804dd24:	74 01                	je     804dd27 <_IO_stdin_used@@Base+0x3f6b>
 804dd26:	42                   	inc    edx
 804dd27:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804dd2b:	cf                   	iret   
 804dd2c:	6c                   	ins    BYTE PTR es:[edi],dx
 804dd2d:	00 42 b6             	add    BYTE PTR [edx-0x4a],al
 804dd30:	74 01                	je     804dd33 <_IO_stdin_used@@Base+0x3f77>
 804dd32:	42                   	inc    edx
 804dd33:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804dd37:	cf                   	iret   
 804dd38:	6c                   	ins    BYTE PTR es:[edi],dx
 804dd39:	00 42 e3             	add    BYTE PTR [edx-0x1d],al
 804dd3c:	74 01                	je     804dd3f <_IO_stdin_used@@Base+0x3f83>
 804dd3e:	42                   	inc    edx
 804dd3f:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804dd43:	cf                   	iret   
 804dd44:	6c                   	ins    BYTE PTR es:[edi],dx
 804dd45:	00 42 ef             	add    BYTE PTR [edx-0x11],al
 804dd48:	74 01                	je     804dd4b <_IO_stdin_used@@Base+0x3f8f>
 804dd4a:	42                   	inc    edx
 804dd4b:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804dd4f:	cf                   	iret   
 804dd50:	6c                   	ins    BYTE PTR es:[edi],dx
 804dd51:	00 42 b8             	add    BYTE PTR [edx-0x48],al
 804dd54:	74 01                	je     804dd57 <_IO_stdin_used@@Base+0x3f9b>
 804dd56:	42                   	inc    edx
 804dd57:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804dd5b:	cf                   	iret   
 804dd5c:	6c                   	ins    BYTE PTR es:[edi],dx
 804dd5d:	00 42 bd             	add    BYTE PTR [edx-0x43],al
 804dd60:	74 01                	je     804dd63 <_IO_stdin_used@@Base+0x3fa7>
 804dd62:	42                   	inc    edx
 804dd63:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804dd67:	cf                   	iret   
 804dd68:	6c                   	ins    BYTE PTR es:[edi],dx
 804dd69:	00 42 a0             	add    BYTE PTR [edx-0x60],al
 804dd6c:	74 01                	je     804dd6f <_IO_stdin_used@@Base+0x3fb3>
 804dd6e:	42                   	inc    edx
 804dd6f:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804dd73:	cf                   	iret   
 804dd74:	6c                   	ins    BYTE PTR es:[edi],dx
 804dd75:	00 42 a1             	add    BYTE PTR [edx-0x5f],al
 804dd78:	74 01                	je     804dd7b <_IO_stdin_used@@Base+0x3fbf>
 804dd7a:	42                   	inc    edx
 804dd7b:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804dd7f:	cf                   	iret   
 804dd80:	6c                   	ins    BYTE PTR es:[edi],dx
 804dd81:	00 42 a8             	add    BYTE PTR [edx-0x58],al
 804dd84:	74 01                	je     804dd87 <_IO_stdin_used@@Base+0x3fcb>
 804dd86:	42                   	inc    edx
 804dd87:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804dd8b:	cf                   	iret   
 804dd8c:	6c                   	ins    BYTE PTR es:[edi],dx
 804dd8d:	00 42 ef             	add    BYTE PTR [edx-0x11],al
 804dd90:	74 01                	je     804dd93 <_IO_stdin_used@@Base+0x3fd7>
 804dd92:	42                   	inc    edx
 804dd93:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804dd97:	cf                   	iret   
 804dd98:	6c                   	ins    BYTE PTR es:[edi],dx
 804dd99:	00 42 bf             	add    BYTE PTR [edx-0x41],al
 804dd9c:	74 01                	je     804dd9f <_IO_stdin_used@@Base+0x3fe3>
 804dd9e:	42                   	inc    edx
 804dd9f:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804dda3:	cf                   	iret   
 804dda4:	6c                   	ins    BYTE PTR es:[edi],dx
 804dda5:	00 42 ae             	add    BYTE PTR [edx-0x52],al
 804dda8:	74 01                	je     804ddab <_IO_stdin_used@@Base+0x3fef>
 804ddaa:	42                   	inc    edx
 804ddab:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804ddaf:	cf                   	iret   
 804ddb0:	6c                   	ins    BYTE PTR es:[edi],dx
 804ddb1:	00 42 bc             	add    BYTE PTR [edx-0x44],al
 804ddb4:	74 01                	je     804ddb7 <_IO_stdin_used@@Base+0x3ffb>
 804ddb6:	42                   	inc    edx
 804ddb7:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804ddbb:	cf                   	iret   
 804ddbc:	6c                   	ins    BYTE PTR es:[edi],dx
 804ddbd:	00 42 bc             	add    BYTE PTR [edx-0x44],al
 804ddc0:	74 01                	je     804ddc3 <_IO_stdin_used@@Base+0x4007>
 804ddc2:	42                   	inc    edx
 804ddc3:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804ddc7:	cf                   	iret   
 804ddc8:	6c                   	ins    BYTE PTR es:[edi],dx
 804ddc9:	00 42 b8             	add    BYTE PTR [edx-0x48],al
 804ddcc:	74 01                	je     804ddcf <_IO_stdin_used@@Base+0x4013>
 804ddce:	42                   	inc    edx
 804ddcf:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804ddd3:	cf                   	iret   
 804ddd4:	6c                   	ins    BYTE PTR es:[edi],dx
 804ddd5:	00 42 a0             	add    BYTE PTR [edx-0x60],al
 804ddd8:	74 01                	je     804dddb <_IO_stdin_used@@Base+0x401f>
 804ddda:	42                   	inc    edx
 804dddb:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804dddf:	cf                   	iret   
 804dde0:	6c                   	ins    BYTE PTR es:[edi],dx
 804dde1:	00 42 bd             	add    BYTE PTR [edx-0x43],al
 804dde4:	74 01                	je     804dde7 <_IO_stdin_used@@Base+0x402b>
 804dde6:	42                   	inc    edx
 804dde7:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804ddeb:	cf                   	iret   
 804ddec:	6c                   	ins    BYTE PTR es:[edi],dx
 804dded:	00 42 ab             	add    BYTE PTR [edx-0x55],al
 804ddf0:	74 01                	je     804ddf3 <_IO_stdin_used@@Base+0x4037>
 804ddf2:	42                   	inc    edx
 804ddf3:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804ddf7:	cf                   	iret   
 804ddf8:	6c                   	ins    BYTE PTR es:[edi],dx
 804ddf9:	00 42 ee             	add    BYTE PTR [edx-0x12],al
 804ddfc:	74 01                	je     804ddff <_IO_stdin_used@@Base+0x4043>
 804ddfe:	42                   	inc    edx
 804ddff:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804de03:	cf                   	iret   
 804de04:	6c                   	ins    BYTE PTR es:[edi],dx
 804de05:	00 42 c5             	add    BYTE PTR [edx-0x3b],al
 804de08:	74 01                	je     804de0b <_IO_stdin_used@@Base+0x404f>
 804de0a:	42                   	inc    edx
 804de0b:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804de0f:	cf                   	iret   
 804de10:	6c                   	ins    BYTE PTR es:[edi],dx
 804de11:	00 42 cf             	add    BYTE PTR [edx-0x31],al
 804de14:	74 01                	je     804de17 <_IO_stdin_used@@Base+0x405b>
 804de16:	42                   	inc    edx
 804de17:	d0 7f 1e             	sar    BYTE PTR [edi+0x1e],1
 804de1a:	48                   	dec    eax
 804de1b:	d0 7d 00             	sar    BYTE PTR [ebp+0x0],1
 804de1e:	40                   	inc    eax
 804de1f:	ce                   	into   
 804de20:	7d 08                	jge    804de2a <_IO_stdin_used@@Base+0x406e>
 804de22:	43                   	inc    ebx
 804de23:	cf                   	iret   
 804de24:	74 01                	je     804de27 <_IO_stdin_used@@Base+0x406b>
 804de26:	5a                   	pop    edx
 804de27:	cf                   	iret   
 804de28:	6a 08                	push   0x8
 804de2a:	5a                   	pop    edx
 804de2b:	ce                   	into   
 804de2c:	74 1f                	je     804de4d <_IO_stdin_used@@Base+0x4091>
 804de2e:	42                   	inc    edx
 804de2f:	cf                   	iret   
 804de30:	74 16                	je     804de48 <_IO_stdin_used@@Base+0x408c>
 804de32:	42                   	inc    edx
 804de33:	d1                   	(bad)  
 804de34:	74 10                	je     804de46 <_IO_stdin_used@@Base+0x408a>
 804de36:	b9 d4 74 01 4d       	mov    ecx,0x4d0174d4
 804de3b:	84 64 01 42          	test   BYTE PTR [ecx+eax*1+0x42],ah
 804de3f:	d7                   	xlat   BYTE PTR ds:[ebx]
 804de40:	74 00                	je     804de42 <_IO_stdin_used@@Base+0x4086>
 804de42:	42                   	inc    edx
 804de43:	d7                   	xlat   BYTE PTR ds:[ebx]
 804de44:	74 1f                	je     804de65 <_IO_stdin_used@@Base+0x40a9>
 804de46:	43                   	inc    ebx
 804de47:	d7                   	xlat   BYTE PTR ds:[ebx]
 804de48:	75 01                	jne    804de4b <_IO_stdin_used@@Base+0x408f>
 804de4a:	48                   	dec    eax
 804de4b:	cf                   	iret   
 804de4c:	74 01                	je     804de4f <_IO_stdin_used@@Base+0x4093>
 804de4e:	55                   	push   ebp
 804de4f:	cf                   	iret   
 804de50:	6a 01                	push   0x1
 804de52:	57                   	push   edi
 804de53:	53                   	push   ebx
 804de54:	69 01 42 c1 ca 1f    	imul   eax,DWORD PTR [ecx],0x1fcac142
 804de5a:	42                   	inc    edx
 804de5b:	cf                   	iret   
 804de5c:	6c                   	ins    BYTE PTR es:[edi],dx
 804de5d:	00 42 9c             	add    BYTE PTR [edx-0x64],al
 804de60:	74 01                	je     804de63 <_IO_stdin_used@@Base+0x40a7>
 804de62:	42                   	inc    edx
 804de63:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804de67:	cf                   	iret   
 804de68:	6c                   	ins    BYTE PTR es:[edi],dx
 804de69:	00 42 a0             	add    BYTE PTR [edx-0x60],al
 804de6c:	74 01                	je     804de6f <_IO_stdin_used@@Base+0x40b3>
 804de6e:	42                   	inc    edx
 804de6f:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804de73:	cf                   	iret   
 804de74:	6c                   	ins    BYTE PTR es:[edi],dx
 804de75:	00 42 bd             	add    BYTE PTR [edx-0x43],al
 804de78:	74 01                	je     804de7b <_IO_stdin_used@@Base+0x40bf>
 804de7a:	42                   	inc    edx
 804de7b:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804de7f:	cf                   	iret   
 804de80:	6c                   	ins    BYTE PTR es:[edi],dx
 804de81:	00 42 bd             	add    BYTE PTR [edx-0x43],al
 804de84:	74 01                	je     804de87 <_IO_stdin_used@@Base+0x40cb>
 804de86:	42                   	inc    edx
 804de87:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804de8b:	cf                   	iret   
 804de8c:	6c                   	ins    BYTE PTR es:[edi],dx
 804de8d:	00 42 b6             	add    BYTE PTR [edx-0x4a],al
 804de90:	74 01                	je     804de93 <_IO_stdin_used@@Base+0x40d7>
 804de92:	42                   	inc    edx
 804de93:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804de97:	cf                   	iret   
 804de98:	6c                   	ins    BYTE PTR es:[edi],dx
 804de99:	00 42 e3             	add    BYTE PTR [edx-0x1d],al
 804de9c:	74 01                	je     804de9f <_IO_stdin_used@@Base+0x40e3>
 804de9e:	42                   	inc    edx
 804de9f:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804dea3:	cf                   	iret   
 804dea4:	6c                   	ins    BYTE PTR es:[edi],dx
 804dea5:	00 42 ef             	add    BYTE PTR [edx-0x11],al
 804dea8:	74 01                	je     804deab <_IO_stdin_used@@Base+0x40ef>
 804deaa:	42                   	inc    edx
 804deab:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804deaf:	cf                   	iret   
 804deb0:	6c                   	ins    BYTE PTR es:[edi],dx
 804deb1:	00 42 b8             	add    BYTE PTR [edx-0x48],al
 804deb4:	74 01                	je     804deb7 <_IO_stdin_used@@Base+0x40fb>
 804deb6:	42                   	inc    edx
 804deb7:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804debb:	cf                   	iret   
 804debc:	6c                   	ins    BYTE PTR es:[edi],dx
 804debd:	00 42 bd             	add    BYTE PTR [edx-0x43],al
 804dec0:	74 01                	je     804dec3 <_IO_stdin_used@@Base+0x4107>
 804dec2:	42                   	inc    edx
 804dec3:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804dec7:	cf                   	iret   
 804dec8:	6c                   	ins    BYTE PTR es:[edi],dx
 804dec9:	00 42 a0             	add    BYTE PTR [edx-0x60],al
 804decc:	74 01                	je     804decf <_IO_stdin_used@@Base+0x4113>
 804dece:	42                   	inc    edx
 804decf:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804ded3:	cf                   	iret   
 804ded4:	6c                   	ins    BYTE PTR es:[edi],dx
 804ded5:	00 42 a1             	add    BYTE PTR [edx-0x5f],al
 804ded8:	74 01                	je     804dedb <_IO_stdin_used@@Base+0x411f>
 804deda:	42                   	inc    edx
 804dedb:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804dedf:	cf                   	iret   
 804dee0:	6c                   	ins    BYTE PTR es:[edi],dx
 804dee1:	00 42 a8             	add    BYTE PTR [edx-0x58],al
 804dee4:	74 01                	je     804dee7 <_IO_stdin_used@@Base+0x412b>
 804dee6:	42                   	inc    edx
 804dee7:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804deeb:	cf                   	iret   
 804deec:	6c                   	ins    BYTE PTR es:[edi],dx
 804deed:	00 42 ef             	add    BYTE PTR [edx-0x11],al
 804def0:	74 01                	je     804def3 <_IO_stdin_used@@Base+0x4137>
 804def2:	42                   	inc    edx
 804def3:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804def7:	cf                   	iret   
 804def8:	6c                   	ins    BYTE PTR es:[edi],dx
 804def9:	00 42 bf             	add    BYTE PTR [edx-0x41],al
 804defc:	74 01                	je     804deff <_IO_stdin_used@@Base+0x4143>
 804defe:	42                   	inc    edx
 804deff:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804df03:	cf                   	iret   
 804df04:	6c                   	ins    BYTE PTR es:[edi],dx
 804df05:	00 42 ae             	add    BYTE PTR [edx-0x52],al
 804df08:	74 01                	je     804df0b <_IO_stdin_used@@Base+0x414f>
 804df0a:	42                   	inc    edx
 804df0b:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804df0f:	cf                   	iret   
 804df10:	6c                   	ins    BYTE PTR es:[edi],dx
 804df11:	00 42 bc             	add    BYTE PTR [edx-0x44],al
 804df14:	74 01                	je     804df17 <_IO_stdin_used@@Base+0x415b>
 804df16:	42                   	inc    edx
 804df17:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804df1b:	cf                   	iret   
 804df1c:	6c                   	ins    BYTE PTR es:[edi],dx
 804df1d:	00 42 bc             	add    BYTE PTR [edx-0x44],al
 804df20:	74 01                	je     804df23 <_IO_stdin_used@@Base+0x4167>
 804df22:	42                   	inc    edx
 804df23:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804df27:	cf                   	iret   
 804df28:	6c                   	ins    BYTE PTR es:[edi],dx
 804df29:	00 42 b8             	add    BYTE PTR [edx-0x48],al
 804df2c:	74 01                	je     804df2f <_IO_stdin_used@@Base+0x4173>
 804df2e:	42                   	inc    edx
 804df2f:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804df33:	cf                   	iret   
 804df34:	6c                   	ins    BYTE PTR es:[edi],dx
 804df35:	00 42 a0             	add    BYTE PTR [edx-0x60],al
 804df38:	74 01                	je     804df3b <_IO_stdin_used@@Base+0x417f>
 804df3a:	42                   	inc    edx
 804df3b:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804df3f:	cf                   	iret   
 804df40:	6c                   	ins    BYTE PTR es:[edi],dx
 804df41:	00 42 bd             	add    BYTE PTR [edx-0x43],al
 804df44:	74 01                	je     804df47 <_IO_stdin_used@@Base+0x418b>
 804df46:	42                   	inc    edx
 804df47:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804df4b:	cf                   	iret   
 804df4c:	6c                   	ins    BYTE PTR es:[edi],dx
 804df4d:	00 42 ab             	add    BYTE PTR [edx-0x55],al
 804df50:	74 01                	je     804df53 <_IO_stdin_used@@Base+0x4197>
 804df52:	42                   	inc    edx
 804df53:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804df57:	cf                   	iret   
 804df58:	6c                   	ins    BYTE PTR es:[edi],dx
 804df59:	00 42 ee             	add    BYTE PTR [edx-0x12],al
 804df5c:	74 01                	je     804df5f <_IO_stdin_used@@Base+0x41a3>
 804df5e:	42                   	inc    edx
 804df5f:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804df63:	cf                   	iret   
 804df64:	6c                   	ins    BYTE PTR es:[edi],dx
 804df65:	00 42 c5             	add    BYTE PTR [edx-0x3b],al
 804df68:	74 01                	je     804df6b <_IO_stdin_used@@Base+0x41af>
 804df6a:	42                   	inc    edx
 804df6b:	c0 4b 11 42          	ror    BYTE PTR [ebx+0x11],0x42
 804df6f:	cf                   	iret   
 804df70:	6c                   	ins    BYTE PTR es:[edi],dx
 804df71:	00 42 cf             	add    BYTE PTR [edx-0x31],al
 804df74:	74 01                	je     804df77 <_IO_stdin_used@@Base+0x41bb>
 804df76:	42                   	inc    edx
 804df77:	d0 7f 1e             	sar    BYTE PTR [edi+0x1e],1
 804df7a:	48                   	dec    eax
 804df7b:	d0 7d 00             	sar    BYTE PTR [ebp+0x0],1
 804df7e:	5a                   	pop    edx
 804df7f:	cf                   	iret   
 804df80:	74 0a                	je     804df8c <_IO_stdin_used@@Base+0x41d0>
 804df82:	4d                   	dec    ebp
 804df83:	66 66 01 42 d7       	data16 add WORD PTR [edx-0x29],ax
 804df88:	75 01                	jne    804df8b <_IO_stdin_used@@Base+0x41cf>
 804df8a:	42                   	inc    edx
 804df8b:	cf                   	iret   
 804df8c:	74 01                	je     804df8f <_IO_stdin_used@@Base+0x41d3>
 804df8e:	5d                   	pop    ebp
 804df8f:	c4 6b 0b             	les    ebp,FWORD PTR [ebx+0xb]
 804df92:	5d                   	pop    ebp
 804df93:	c6                   	(bad)  
 804df94:	75 1c                	jne    804dfb2 <_IO_stdin_used@@Base+0x41f6>
 804df96:	5f                   	pop    edi
 804df97:	d7                   	xlat   BYTE PTR ds:[ebx]
 804df98:	6c                   	ins    BYTE PTR es:[edi],dx
 804df99:	19 00                	sbb    DWORD PTR [eax],eax
	...
 806c0bf:	00 00                	add    BYTE PTR [eax],al
 806c0c1:	00 01                	add    BYTE PTR [ecx],al
	...

Disassembly of section .bss:

0806c0c4 <stderr@@GLIBC_2.0>:
 806c0c4:	00 00                	add    BYTE PTR [eax],al
	...

0806c0c8 <stdin@@GLIBC_2.0>:
	...

Disassembly of section .comment:

00000000 <.comment>:
   0:	47                   	inc    edi
   1:	43                   	inc    ebx
   2:	43                   	inc    ebx
   3:	3a 20                	cmp    ah,BYTE PTR [eax]
   5:	28 55 62             	sub    BYTE PTR [ebp+0x62],dl
   8:	75 6e                	jne    78 <raise@plt-0x8048418>
   a:	74 75                	je     81 <raise@plt-0x804840f>
   c:	2f                   	das    
   d:	4c                   	dec    esp
   e:	69 6e 61 72 6f 20 34 	imul   ebp,DWORD PTR [esi+0x61],0x34206f72
  15:	2e 36 2e 33 2d 31 75 	cs ss xor ebp,DWORD PTR cs:0x75627531
  1c:	62 75 
  1e:	6e                   	outs   dx,BYTE PTR ds:[esi]
  1f:	74 75                	je     96 <raise@plt-0x80483fa>
  21:	35 29 20 34 2e       	xor    eax,0x2e342029
  26:	36 2e 33 00          	ss xor eax,DWORD PTR cs:[eax]
