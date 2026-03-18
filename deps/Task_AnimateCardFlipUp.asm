push {r4, r5, r6, r7, lr}
mov r7, sl
mov r6, sb
mov r5, r8
push {r5, r6, r7}
sub sp, #4
mov r8, r0
ldr r0, [pc, #0x18]  @ loc_0808B568 = #0x020397A4
ldr r0, [r0]
movs r2, #0
strb r2, [r0, #9]
mov r0, r8
ldrh r1, [r0, #0xa]
movs r3, #0xa
ldrsh r0, [r0, r3]
cmp r0, #5
bgt loc_0808B56C
mov r4, r8
strh r2, [r4, #0xa]
b loc_0808B572

loc_0808B568:
.word 0x020397A4

loc_0808B56C:
sub r0, r1, #5
mov r1, r8
strh r0, [r1, #0xa]

loc_0808B572:
ldr r0, [pc, #0xe8]  @ loc_0808B65C = #0x020397A4
ldr r0, [r0]
mov r2, r8
ldrh r1, [r2, #0xa]
ldr r3, [pc, #0xe4]  @ loc_0808B660 = #0x00007BCC
add r0, r0, r3
strh r1, [r0]
ldrh r0, [r2, #0xa]
bl loc_08089BD8
mov r4, r8
movs r0, #0xa
ldrsh r7, [r4, r0]
movs r0, #0xa0
sub r0, r0, r7
mov sb, r0
sub r4, r0, r7
rsbs r0, r7, #0
lsl r6, r0, #0x10
movs r0, #0xa0
lsl r0, r0, #0x10
add r1, r4, #0
bl loc_081E460C
add r5, r0, #0
ldr r1, [pc, #0xbc]  @ loc_0808B664 = #0xFFFF0000
add r5, r5, r1
add r0, r5, #0
mul r0, r4, r0
add r0, r6, r0
str r0, [sp]
add r0, r5, #0
add r1, r4, #0
bl loc_081E460C
mov sl, r0
lsr r5, r5, #1
movs r2, #0
cmp r2, r7
bhs loc_0808B5DC
ldr r3, [pc, #0xa4]  @ loc_0808B668 = #0x02038700

loc_0808B5C4:
lsl r0, r2, #0x10
asr r0, r0, #0x10
lsl r1, r0, #1
add r1, r1, r3
rsbs r2, r0, #0
strh r2, [r1]
add r0, #1
lsl r0, r0, #0x10
lsr r2, r0, #0x10
asr r0, r0, #0x10
cmp r0, r7
blo loc_0808B5C4

loc_0808B5DC:
lsl r1, r2, #0x10
mov r3, sb
lsl r0, r3, #0x10
asr r3, r0, #0x10
ldr r4, [pc, #0x74]  @ loc_0808B65C = #0x020397A4
mov sb, r4
ldr r4, [sp]
lsr r7, r4, #0x10
cmp r1, r0
bge loc_0808B612
ldr r0, [pc, #0x74]  @ loc_0808B668 = #0x02038700
mov ip, r0
add r4, r3, #0

loc_0808B5F6:
lsr r3, r6, #0x10
add r6, r6, r5
add r5, sl
asr r0, r1, #0x10
lsl r1, r0, #1
add r1, ip
strh r3, [r1]
add r0, #1
lsl r0, r0, #0x10
lsr r2, r0, #0x10
lsl r1, r2, #0x10
asr r0, r1, #0x10
cmp r0, r4
blt loc_0808B5F6

loc_0808B612:
add r3, r7, #0
lsl r1, r2, #0x10
asr r0, r1, #0x10
cmp r0, #0x9f
bgt loc_0808B630
ldr r2, [pc, #0x48]  @ loc_0808B668 = #0x02038700

loc_0808B61E:
asr r0, r1, #0x10
lsl r1, r0, #1
add r1, r1, r2
strh r3, [r1]
add r0, #1
lsl r1, r0, #0x10
asr r0, r1, #0x10
cmp r0, #0x9f
ble loc_0808B61E

loc_0808B630:
mov r1, sb
ldr r0, [r1]
movs r1, #1
strb r1, [r0, #9]
mov r2, r8
movs r3, #0xa
ldrsh r0, [r2, r3]
cmp r0, #0
bgt loc_0808B648
ldrh r0, [r2, #8]
add r0, #1
strh r0, [r2, #8]

loc_0808B648:
movs r0, #0
add sp, #4
pop {r3, r4, r5}
mov r8, r3
mov sb, r4
mov sl, r5
pop {r4, r5, r6, r7}
pop {r1}
bx r1
movs r0, r0

loc_0808B65C:
.word 0x020397A4

loc_0808B660:
.word 0x00007BCC

loc_0808B664:
.word 0xFFFF0000

loc_0808B668:
.word 0x02038700