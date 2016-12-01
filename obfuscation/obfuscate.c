int __cdecl sub_8048580(int a1, signed int a2)
{
  signed int v2; // edx@1
  char v3; // al@2
  unsigned int v4; // edi@2
  int result; // eax@3
  int v6; // edx@4
  char v7[33]; // [sp+Ch] [bp-A0h]@2
  char v8; // [sp+2Dh] [bp-7Fh]@37
  char v9; // [sp+2Eh] [bp-7Eh]@40
  char v10; // [sp+30h] [bp-7Ch]@46
  char v11; // [sp+31h] [bp-7Bh]@49
  char v12; // [sp+32h] [bp-7Ah]@51
  char v13; // [sp+33h] [bp-79h]@56
  char v14; // [sp+35h] [bp-77h]@59
  char v15; // [sp+36h] [bp-76h]@62
  char v16; // [sp+37h] [bp-75h]@64
  char v17; // [sp+38h] [bp-74h]@66
  char v18; // [sp+39h] [bp-73h]@69
  char v19; // [sp+3Ah] [bp-72h]@72
  char v20; // [sp+3Ch] [bp-70h]@77
  char v21; // [sp+3Dh] [bp-6Fh]@80
  char v22; // [sp+3Eh] [bp-6Eh]@83
  char v23; // [sp+3Fh] [bp-6Dh]@86
  char v24; // [sp+40h] [bp-6Ch]@54
  char v25; // [sp+41h] [bp-6Bh]@90
  char v26; // [sp+42h] [bp-6Ah]@93
  char v27; // [sp+43h] [bp-69h]@96
  char v28; // [sp+44h] [bp-68h]@99
  char v29; // [sp+45h] [bp-67h]@102
  char v30; // [sp+56h] [bp-56h]@6
  char v31; // [sp+7Ch] [bp-30h]@8
  char v32; // [sp+7Dh] [bp-2Fh]@11
  char v33; // [sp+7Eh] [bp-2Eh]@14
  char v34; // [sp+7Fh] [bp-2Dh]@17
  char v35; // [sp+80h] [bp-2Ch]@20
  char v36; // [sp+81h] [bp-2Bh]@23
  char v37; // [sp+82h] [bp-2Ah]@26
  char v38; // [sp+83h] [bp-29h]@29
  char v39; // [sp+85h] [bp-27h]@31
  int v40; // [sp+8Ch] [bp-20h]@1

  v40 = *MK_FP(__GS__, 20);
  v2 = a2;
  while ( 2 )
  {
    memset(v7, 0, 0x80u);
    v3 = *(_BYTE *)(a1 + v2);
    v4 = (unsigned int)((*(_BYTE *)(a1 + v2) + 64) >> 31) >> 25;
    v7[(((_BYTE)v4 + *(_BYTE *)(a1 + v2) + 64) & 0x7F) - v4] = 1;
    if ( (unsigned __int8)(v3 - 10) <= 'p' )
    {
      switch ( v3 )
      {
        default:
          goto LABEL_3;
        case '\n':
          result = v2 == 13 && v30 != 0;
          break;
        case '0':
          if ( v2 || !v31 )
            goto LABEL_3;
          v2 = 1;
          continue;
        case '1':
          if ( v2 == 14 && v32 )
            goto LABEL_12;
          goto LABEL_3;
        case '2':
          if ( v2 == 20 && v33 )
            goto LABEL_15;
          goto LABEL_3;
        case '3':
          if ( v2 != 89 || !v34 )
            goto LABEL_3;
          v2 = 90;
          continue;
        case '4':
          if ( v2 != 15 || !v35 )
            goto LABEL_3;
          v2 = 16;
          continue;
        case '5':
          if ( v2 != 14 || !v36 )
            goto LABEL_3;
LABEL_12:
          v2 = 15;
          continue;
        case '6':
          if ( v2 != 12 || !v37 )
            goto LABEL_3;
          v2 = 13;
          continue;
        case '7':
          if ( v2 != 5 || !v38 )
            goto LABEL_3;
          v2 = 6;
          continue;
        case '8':
          result = 0;
          if ( v39 )
            result = v2 == 33 || v2 == 2;
          goto LABEL_4;
        case '9':
          if ( v2 != 1 || !v39 )
            goto LABEL_3;
          v2 = 2;
          continue;
        case 'a':
          if ( v2 != 35 || !v8 )
            goto LABEL_3;
          v2 = 36;
          continue;
        case 'b':
          if ( v2 != 11 || !v9 )
            goto LABEL_3;
          v2 = 12;
          continue;
        case 'c':
          if ( v2 != 32 || !v8 )
            goto LABEL_3;
          v2 = 33;
          continue;
        case 'd':
          if ( v2 != 3 || !v10 )
            goto LABEL_3;
          v2 = 4;
          continue;
        case 'e':
          if ( v2 != 7 || !v11 )
            goto LABEL_3;
          v2 = 8;
          continue;
        case 'f':
          if ( !v12 || v2 != 8 && v2 != 4 )
            goto LABEL_3;
          goto LABEL_53;
        case 'g':
          result = v2 == 12 && v24 != 0;
          goto LABEL_4;
        case 'h':
          if ( v2 != 13 || !v13 )
            goto LABEL_3;
          v2 = 14;
          continue;
        case 'i':
          if ( v2 != 9 || !v14 )
            goto LABEL_3;
          v2 = 10;
          continue;
        case 'j':
          if ( v2 != 10 || !v15 )
            goto LABEL_3;
          v2 = 11;
          continue;
        case 'k':
          result = v2 == 12 && v16 != 0;
          goto LABEL_4;
        case 'l':
          if ( v2 != 19 || !v17 )
            goto LABEL_3;
          v2 = 20;
          continue;
        case 'm':
          if ( v2 != 17 || !v18 )
            goto LABEL_3;
          v2 = 18;
          continue;
        case 'n':
          result = v2 == 18 && v18 != 0;
          goto LABEL_4;
        case 'o':
          if ( !v19 || v2 != 6 && v2 != 28 )
            goto LABEL_3;
LABEL_53:
          ++v2;
          continue;
        case 'p':
          if ( v2 != 30 || !v20 )
            goto LABEL_3;
          v2 = 31;
          continue;
        case 'q':
          if ( v2 != 29 || !v21 )
            goto LABEL_3;
          v2 = 30;
          continue;
        case 'r':
          if ( v2 != 20 || !v22 )
            goto LABEL_3;
LABEL_15:
          v2 = 21;
          continue;
        case 's':
          if ( v2 != 25 || !v23 )
            goto LABEL_3;
          v2 = 26;
          continue;
        case 't':
          result = v2 == 24 && v22 != 0;
          goto LABEL_4;
        case 'u':
          if ( v2 != 26 || !v25 )
            goto LABEL_3;
          v2 = 27;
          continue;
        case 'v':
          if ( v2 != 2 || !v26 )
            goto LABEL_3;
          v2 = 3;
          continue;
        case 'w':
          if ( v2 != 6 || !v27 )
            goto LABEL_3;
          v2 = 7;
          continue;
        case 'x':
          if ( v2 != 22 || !v28 )
            goto LABEL_3;
          v2 = 23;
          continue;
        case 'y':
          if ( v2 != 23 || !v29 )
            goto LABEL_3;
          v2 = 24;
          continue;
        case 'z':
          result = v2 == 21 && v8 != 0;
          break;
      }
    }
    else
    {
LABEL_3:
      result = 0;
    }
    break;
  }
LABEL_4:
  v6 = *MK_FP(__GS__, 20) ^ v40;
  return result;
}