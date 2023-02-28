.data

lpEncryptionKey dq 0
lpGetTicks dq 0

.code

InitializeGetTicks PROC
	mov lpGetTicks, rcx
	ret
InitializeGetTicks ENDP

InitializeEncryptionKey PROC
	mov rcx,[rcx]
	mov lpEncryptionKey, rcx
	ret
InitializeEncryptionKey ENDP


SetEncryptionKey PROC
	mov rcx,[rcx]
	mov lpEncryptionKey, rcx
	ret
SetEncryptionKey ENDP

_GetPacketTimestamp PROC

	sub rsp, 128h
	call lpGetTicks ; MSVCP140.Xtime_get_ticks
	add rsp, 128h

	mov rcx,rax
	mov rax, 0D6BF94D5E57A42BDh
	imul rcx
	add rdx,rcx
	sar rdx, 17h
	mov rax,rdx
	shr rax,3Fh
	add rdx,rax

	mov ecx,1
    imul rax,rdx,0013313Bh
	add rax,rcx
						;is now moved into packet+7
	ret
_GetPacketTimestamp ENDP

; RCX = +0x10 from rdx
; RDX =  buffer?
_XorEncryptPacket PROC  ;2nd layer of encryption, is called in a loop inside EncryptPacket

	sub rdx,rcx
	mov r8d,10h
	nop dword ptr[rax+0]
loop1:
	movzx eax, byte ptr[rdx+rcx]
	xor [rcx], al
	lea rcx,[rcx+01]
	sub r8, 1
	jne loop1
	ret
_XorEncryptPacket ENDP

;RCX = Buffer
;RDX = pointer to some string which changes each patch
_EncryptPacket  PROC

	mov [rsp+18h],rbx
	mov [rsp+20h],rbp
	mov [rsp+10h],rdx
	push rsi
	push rdi
	push r12
	push r13
	push r14
	push r15
	mov r15,rdx
	mov rsi,rcx
	sub r15,rcx
	mov r9d,00000004h
	mov [rsp+38h],r15
	nop dword ptr [rax]
l2:
	mov r8d,00000004h
	nop word ptr [rax+rax+00000000h]
l1:
	movzx eax,byte ptr [r15+rcx]
	xor [rcx],al
	inc rcx
	sub r8,01h
	jne l1
	sub r9,01h
	jne l2
	mov r15,[rsp+40h]
	mov r12b,01
setKey:
	lea r10,[lpEncryptionKey]
	mov r8,rsi
	mov r9d,00000004h
	nop
	nop
l4:
	mov rcx,r8
	mov edx,00000004h
	nop dword ptr [rax+rax+00000000h]
l3:
	movzx eax,byte ptr [rcx]
	lea rcx,[rcx+04h]
	movzx eax,byte ptr [rax+r10]
	mov [rcx-04h],al
	sub rdx,01h
	jne l3
	inc r8
	sub r9,01h
	jne l4
	movzx eax,byte ptr [rsi+05h]
	movzx ecx,byte ptr [rsi+01h]
	mov [rsi+01h],al
	movzx eax,byte ptr [rsi+09h]
	mov [rsi+05h],al
	movzx eax,byte ptr [rsi+0Dh]
	mov [rsi+09h],al
	movzx eax,byte ptr [rsi+0Ah]
	mov [rsi+0Dh],cl
	movzx ecx,byte ptr [rsi+02h]
	mov [rsi+02h],al
	movzx eax,byte ptr [rsi+0Eh]
	mov [rsi+0Ah],cl
	movzx ecx,byte ptr [rsi+06h]
	mov [rsi+06h],al
	movzx eax,byte ptr [rsi+0Fh]
	mov [rsi+0Eh],cl
	movzx ecx,byte ptr [rsi+03h]
	mov [rsi+03h],al
	movzx eax,byte ptr [rsi+0Bh]
	mov [rsi+0Fh],al
	movzx eax,byte ptr [rsi+07h]
	mov [rsi+0Bh],al
	mov [rsi+07h],cl
	cmp r12b,0Ah
	je l5
	lea r14,[rsi+02h]
	lea ebp,[rdx+04h]
	nop dword ptr [rax+00h]
	nop word ptr [rax+rax+00000000h]
l8:
	movzx edi,byte ptr [r14-02h]
	movzx r8d,byte ptr [r14-01h]
	movzx edx,dil
	movzx ebx,byte ptr [r14+01h]
	xor dl,r8b
	movzx r10d,byte ptr [r14]
	lea r14,[r14+04h]
	movzx eax,dl
	movzx r9d,bl
	shr al,07h
	add dl,dl
	movzx eax,al
	xor r9b,r10b
	imul ecx,eax,1Bh
	movzx r11,r9b   ; 
	xor r11b,dil
	xor r11b,r8b
	xor cl,dl
	movzx edx,r8b
	xor cl,dil
	xor dl,r10b
	xor cl,r11b
	movzx eax,dl
	mov [r14-06h],cl
	xor dil,bl
	shr al,07h
	add dl,dl
	movzx eax,al
	imul ecx,eax,1Bh
	movzx eax,r9b
	shr al,07h
	add r9b,r9b
	movzx eax,al
	xor cl,dl
	xor cl,r8b
	xor cl,r11b
	mov [r14-05h],cl
	imul ecx,eax,1Bh
	movzx eax,dil
	shr al,07h
	add dil,dil
	movzx eax,al
	xor cl,r9b
	xor cl,r10b
	xor cl,r11b
	mov [r14-04h],cl
	imul ecx,eax,1Bh
	xor cl,dil
	xor cl,bl
	xor cl,r11b
	mov [r14-03h],cl
	sub rbp,01h
	jne l8
	movzx r8d,r12b
	lea r9d,[rbp+04h]
	shl r8,04h
	mov rax,rsi
	sub r8,rsi
	add r8,r15
	nop word ptr [rax+rax+00000000h]
l6:
	mov edx,00000004h
	nop word ptr [rax+rax+00000000h]
l7:
	movzx ecx,byte ptr [r8+rax]
	xor [rax],cl
	inc rax
	sub rdx,01h
	jne l7
	sub r9,01h
	jne l6
	inc r12b
	jmp setKey
l5:
	mov r15,[rsp+38h]
	mov edx,00000004h
	nop dword ptr [rax+rax+00000000h]
l10:
	mov ecx,00000004h
	nop word ptr [rax+rax+00000000h]
l9:
	movzx eax,byte ptr [r15+rsi+000000A0h]
	xor [rsi],al
	inc rsi
	sub rcx,01h
	jne l9
	sub rdx,01h
	jne l10
	mov rbx,[rsp+48h]
	mov rbp,[rsp+50h]
	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	ret 
_EncryptPacket ENDP


END