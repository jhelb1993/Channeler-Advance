# ARM7TDMI Assembly for the Game Boy Advance

A guide covering the essentials of programming the ARM7TDMI processor, tailored for the Game Boy Advance. Organized from fundamental concepts through practical usage to advanced internals.

This document is aligned with [gbadev.net’s CPU overview](https://gbadev.net/gbadoc/cpu.html), the Patater [GBA ASM tutorial](https://www.patater.com/gbaguy/gbaasm.htm) (chapters 1–8), the [Touched “Assembler for the GBA” notes](https://github.com/Touched/asm-tutorial/blob/master/doc.md) (memory, CPU, control flow), and [GBATEK](https://problemkaputt.de/gbatek.htm) (especially the THUMB instruction summary and opcode chapters). The ARM7TDMI Technical Reference Manual (*DDI0029G*) is cited for architecture-level details.

---

## Table of Contents

- [Part I: Foundations](#part-i-foundations)
  - [1. What Is the ARM7TDMI?](#1-what-is-the-arm7tdmi)
  - [2. Number Systems and Data Types](#2-number-systems-and-data-types)
  - [3. Registers](#3-registers)
  - [4. ARM State vs. Thumb State](#4-arm-state-vs-thumb-state)
- [Part II: Core Instructions](#part-ii-core-instructions)
  - [5. Moving Data: MOV and LDR/STR](#5-moving-data-mov-and-ldrstr)
  - [6. Arithmetic: ADD, SUB, and Friends](#6-arithmetic-add-sub-and-friends)
  - [7. Branching and Control Flow](#7-branching-and-control-flow)
  - [7.1 GBATEK: Thumb branches, BL encoding, and long-range calls](#71-gbatek-thumb-branches-bl-encoding-and-long-range-calls)
  - [8. The CPSR and Condition Codes](#8-the-cpsr-and-condition-codes)
  - [9. Logical and Bitwise Operations](#9-logical-and-bitwise-operations)
  - [10. Shifts and Rotates](#10-shifts-and-rotates)
  - [11. Multiplication](#11-multiplication)
  - [12. The Stack: PUSH, POP, and Block Transfers](#12-the-stack-push-pop-and-block-transfers)
  - [Subroutines and Calling Conventions (APCS-style)](#subroutines-and-calling-conventions-apcs-style)
- [Part III: GBA-Specific Usage](#part-iii-gba-specific-usage)
  - [13. GBA Memory Map](#13-gba-memory-map)
  - [14. Display Control and Graphics Modes](#14-display-control-and-graphics-modes)
  - [15. VBlank and the Rendering Cycle](#15-vblank-and-the-rendering-cycle)
  - [16. The BIOS and SWI](#16-the-bios-and-swi)
  - [17. Assembler Directives and Program Structure](#17-assembler-directives-and-program-structure)
- [Part IV: Instruction References](#part-iv-instruction-references)
  - [18. Thumb Instruction Reference](#18-thumb-instruction-reference)
  - [19. ARM Instruction Reference](#19-arm-instruction-reference)
- [Part V: Advanced Topics](#part-v-advanced-topics)
  - [20. The Instruction Pipeline](#20-the-instruction-pipeline)
  - [21. Processor Modes and Exceptions](#21-processor-modes-and-exceptions)
  - [22. Memory Alignment and Endianness](#22-memory-alignment-and-endianness)
  - [23. Instruction Cycle Timings](#23-instruction-cycle-timings)
  - [24. ARM/Thumb Interworking](#24-armthumb-interworking)
  - [25. Performance Considerations](#25-performance-considerations)
- [Glossary](#glossary)

---

# Part I: Foundations

## 1. What Is the ARM7TDMI?

The Game Boy Advance runs on a 16.78 MHz ARM7TDMI processor. Each letter in that name means something:

| Letter | Meaning |
|--------|---------|
| ARM7 | Seventh generation of the ARM architecture |
| T | Supports the **Thumb** 16-bit instruction set |
| D | Supports on-chip **Debug** |
| M | Has an enhanced **Multiplier** |
| I | Has **EmbeddedICE** hardware for breakpoints |

It is a 32-bit RISC (Reduced Instruction Set Computer) processor, which means:

- It operates on 32-bit data natively.
- Instructions are simple and uniform rather than complex and variable.
- Most work happens between registers, not directly in memory.
- Only dedicated load/store instructions access memory.

The ARM7TDMI is not manufactured by Nintendo. ARM (the company) licenses the design, and Nintendo's custom chip incorporates the ARM7TDMI core alongside the GBA's graphics and sound hardware.

The processor has two instruction sets — **ARM** (32-bit instructions) and **Thumb** (16-bit instructions) — which can be switched between at runtime. Both operate on the same 32-bit registers and 32-bit address space.

## 2. Number Systems and Data Types

### Hexadecimal

Assembly programming relies heavily on hexadecimal (base 16). A quick reminder:

| Decimal | Hex | Binary |
|---------|-----|--------|
| 0 | 0x0 | 0000 |
| 1 | 0x1 | 0001 |
| 10 | 0xA | 1010 |
| 15 | 0xF | 1111 |
| 255 | 0xFF | 11111111 |
| 256 | 0x100 | 100000000 |

Each hex digit represents exactly 4 bits, making it a compact way to express binary values. Two hex digits = one byte, four hex digits = one halfword, eight hex digits = one word.

### Data Sizes

The ARM7TDMI works with three data sizes:

| Name | Size | Hex range | Example |
|------|------|-----------|---------|
| **Byte** | 8 bits | `0x00` – `0xFF` | A single pixel in Mode 4 |
| **Halfword** | 16 bits | `0x0000` – `0xFFFF` | A color value in Mode 3, a Thumb instruction |
| **Word** | 32 bits | `0x00000000` – `0xFFFFFFFF` | An ARM instruction, a memory address |

### Signed vs. Unsigned

The same bit pattern can represent different values depending on interpretation:

- **Unsigned:** `0xFF` = 255
- **Signed (two's complement):** `0xFF` as a byte = -1

Whether a value is "signed" or "unsigned" depends on which instructions you use. For branching, `BGT`/`BLT` treat values as signed, while `BHI`/`BCC` treat them as unsigned.

## 3. Registers

Registers are small, fast storage locations inside the CPU. The ARM7TDMI has 16 registers visible at any time, each 32 bits wide.

### General-Purpose Registers

| Register | Alias | Purpose |
|----------|-------|---------|
| `r0`–`r7` | — | General purpose (the "Lo registers"). Freely usable by all instructions in both ARM and Thumb state. |
| `r8`–`r12` | — | General purpose (the "Hi registers"). Freely usable in ARM state. In Thumb state, only a few instructions (`MOV`, `ADD`, `CMP`) can access them. |
| `r13` | `SP` | **Stack Pointer.** By convention, points to the top of the stack. Technically a general-purpose register, but treating it otherwise will break function calls. |
| `r14` | `LR` | **Link Register.** When you call a subroutine with `BL`, the return address is saved here. |
| `r15` | `PC` | **Program Counter.** Holds the address of the instruction being fetched. Due to the pipeline, reading it during execution gives an address 8 bytes ahead (ARM) or 4 bytes ahead (Thumb) of the current instruction. |

### The CPSR

Beyond the 16 general registers, there is the **Current Program Status Register (CPSR)**. It holds:

- **Condition flags** (N, Z, C, V) — set by arithmetic/logic instructions.
- **Control bits** — the current processor mode, the Thumb state bit, and interrupt disable flags.

The CPSR is not a normal register you can `MOV` into. It is read/written through special instructions (`MRS`/`MSR` in ARM state) and is implicitly affected by instructions that set flags.

### Default Stack Pointers on GBA

The BIOS initializes stack pointers for different processor modes:

| Mode | SP default |
|------|-----------|
| User/System | `0x03007F00` |
| IRQ | `0x03007FA0` |
| Supervisor | `0x03007FE0` |

## 4. ARM State vs. Thumb State

The processor can execute one of two instruction sets at any time.

### ARM State

- Instructions are **32 bits** (4 bytes) each, word-aligned.
- All 16 registers are directly accessible.
- Instructions are highly flexible: most can incorporate a barrel shift and be made conditional.
- You can choose whether or not an instruction updates the condition flags (the `S` suffix).

### Thumb State

- Instructions are **16 bits** (2 bytes) each, halfword-aligned.
- Most instructions can only use `r0`–`r7` (the Lo registers).
- Instructions are simpler — generally one operation per instruction, no inline shifting.
- Only branches can be conditional.
- Arithmetic instructions always update the condition flags (no choice).
- `BL` (Branch with Link) takes 4 bytes instead of 2 (it's encoded as two 16-bit instructions).

### Why Two Instruction Sets?

The GBA's cartridge ROM is connected via a **16-bit data bus**. This means:

- Fetching a 32-bit ARM instruction from ROM requires **two bus reads**.
- Fetching a 16-bit Thumb instruction from ROM requires **one bus read**.

Thumb code from ROM is therefore roughly **twice as fast** to fetch as ARM code. Thumb code is also **smaller** (about 65% the size of equivalent ARM code).

ARM code is faster when running from **IWRAM** (Internal Work RAM), which has a 32-bit bus, and is more powerful due to conditional execution, inline shifts, and flexible operand formatting.

A well-optimized GBA program uses both: Thumb for the bulk of the code (running from ROM or EWRAM), and ARM for performance-critical routines copied into IWRAM.

### Switching Between States

Use the `BX` (Branch and Exchange) instruction:

```arm
bx r0    @ Jump to the address in r0 and switch state based on bit 0
```

- If bit 0 of the address is **1**, the processor enters Thumb state.
- If bit 0 of the address is **0**, the processor enters ARM state.

This is why calling a Thumb routine requires adding `+1` to its address — the actual code is halfword-aligned (even address), but the `+1` signals the state switch.

Entering any exception (interrupt, SWI, etc.) automatically switches to ARM state.

---

# Part II: Core Instructions

This part covers the instructions you need to start writing functional code. Examples are given in Thumb syntax where possible for simplicity; ARM syntax differences are noted.

## 5. Moving Data: MOV and LDR/STR

### MOV — Move

Copies a value into a register.

```arm
mov r0, r1          @ r0 = r1
mov r3, #0x42       @ r3 = 0x42
```

In Thumb, `MOV` with an immediate can only load an 8-bit value (`0x00`–`0xFF`). In ARM, the immediate must be expressible as an 8-bit value rotated right by an even number of bits (more on this in the ARM instruction reference).

`MOV` is also the only way to transfer data into a Hi register in Thumb state:

```arm
mov r8, r0          @ Copy r0 into r8 (Thumb allows this)
```

### LDR — Load Register

Reads a value from memory into a register.

```arm
ldr r0, [r1]            @ r0 = word at address in r1
ldr r0, [r1, #0x8]      @ r0 = word at address (r1 + 8)
ldr r0, =0x04000000     @ r0 = 0x04000000 (pseudo-instruction: loads from literal pool)
```

The `=` form is a **pseudo-instruction**. The assembler places the constant in a nearby literal pool and generates a PC-relative load. Use `.ltorg` or `.pool` to tell the assembler where it can place the pool.

Variants for different data sizes:

| Instruction | Loads | Upper bits |
|-------------|-------|------------|
| `ldr r0, [r1]` | Word (32 bits) | All 32 bits filled |
| `ldrh r0, [r1]` | Halfword (16 bits) | Zero-extended to 32 bits |
| `ldrb r0, [r1]` | Byte (8 bits) | Zero-extended to 32 bits |
| `ldrsh r0, [r1]` | Signed halfword | Sign-extended to 32 bits |
| `ldrsb r0, [r1]` | Signed byte | Sign-extended to 32 bits |

**Sign extension** preserves the sign of a value when widening it. If you load the byte `0xFE` (-2 as signed):
- `ldrb` gives `0x000000FE` (254 unsigned)
- `ldrsb` gives `0xFFFFFFFE` (-2 signed)

### STR — Store Register

Writes a value from a register to memory.

```arm
str r0, [r1]            @ Store word in r0 to address in r1
strh r0, [r1]           @ Store halfword (lower 16 bits of r0) to address in r1
strb r0, [r1]           @ Store byte (lower 8 bits of r0) to address in r1
```

There are no signed variants of STR — sign doesn't matter when writing, only when reading.

**Important:** You cannot write 8-bit values to VRAM on the GBA. VRAM only supports 16-bit and 32-bit writes. An `strb` to VRAM will write the byte to *both* halves of the halfword, corrupting the adjacent pixel.

### Addressing Modes (ARM State)

ARM state provides much richer addressing:

```arm
ldr r0, [r1, r2]          @ r0 = word at (r1 + r2)           — register offset
ldr r0, [r1, #4]!         @ r0 = word at (r1 + 4), then r1 += 4  — pre-indexed with write-back
ldr r0, [r1], #4          @ r0 = word at r1, then r1 += 4    — post-indexed
ldr r0, [r1, r2, LSL #2]  @ r0 = word at (r1 + r2*4)         — scaled register offset
```

The `!` means **write-back**: the computed address is written back into the base register. Post-indexed addressing automatically writes back.

## 6. Arithmetic: ADD, SUB, and Friends

### ADD — Add

```arm
add r2, r0, r1        @ r2 = r0 + r1
add r0, r0, #5        @ r0 = r0 + 5
add r0, #5            @ Shorthand when destination = first source (Thumb)
```

Thumb restricts immediate values to 8 bits (0–255) when the destination equals the source, or 3 bits (0–7) in the three-register form.

### SUB — Subtract

```arm
sub r2, r0, r1        @ r2 = r0 - r1
sub r0, #3            @ r0 = r0 - 3
```

### ADC / SBC — Add / Subtract with Carry

These use the carry flag from a previous operation, enabling multi-word arithmetic (adding numbers larger than 32 bits):

```arm
adds r0, r2, r4      @ Low 32 bits: r0 = r2 + r4, sets carry
adcs r1, r3, r5      @ High 32 bits: r1 = r3 + r5 + carry
```

### NEG — Negate (Thumb only)

```arm
neg r1, r0            @ r1 = 0 - r0  (two's complement negation)
```

After this, `0x00000001` becomes `0xFFFFFFFF` (-1).

### RSB — Reverse Subtract (ARM only)

```arm
rsb r0, r1, r2        @ r0 = r2 - r1  (operands reversed compared to SUB)
rsb r0, r0, #0        @ r0 = -r0      (ARM equivalent of NEG)
```

### CMP — Compare

```arm
cmp r0, r1            @ Compute r0 - r1, set flags, discard result
cmp r0, #0x10         @ Compare r0 to 16
```

`CMP` is effectively a `SUB` that throws away the result but updates the CPSR flags. It is always followed by a conditional branch or conditional instruction.

### CMN — Compare Negative

```arm
cmn r0, r1            @ Compute r0 + r1, set flags, discard result
```

Useful for comparing against negative values without loading them.

## 7. Branching and Control Flow

### B — Unconditional Branch

```arm
b label               @ Jump to label
```

In Thumb, the range is ±2048 bytes. In ARM, the range is ±32 MB.

### BL — Branch with Link

```arm
bl my_function        @ Save return address in LR, then jump to my_function
```

This is how you call subroutines. The address of the instruction after the `BL` is saved in `r14` (LR), so the called function can return by branching back to LR.

### BX — Branch and Exchange

```arm
bx r0                 @ Jump to address in r0, switch ARM/Thumb based on bit 0
bx lr                 @ Return from subroutine (common pattern)
```

### Conditional Branches

After a `CMP` (or any flag-setting instruction), use a conditional branch:

```arm
cmp r0, #10
beq label_equal       @ Branch if r0 == 10
bne label_not_equal   @ Branch if r0 != 10
bgt label_greater     @ Branch if r0 > 10  (signed)
blt label_less        @ Branch if r0 < 10  (signed)
bge label_ge          @ Branch if r0 >= 10 (signed)
ble label_le          @ Branch if r0 <= 10 (signed)
bhi label_higher      @ Branch if r0 > 10  (unsigned)
bcc label_lower       @ Branch if r0 < 10  (unsigned)
bcs label_higher_same @ Branch if r0 >= 10 (unsigned)
bls label_lower_same  @ Branch if r0 <= 10 (unsigned)
```

The full set of condition codes:

| Suffix | Meaning | Flags tested |
|--------|---------|-------------|
| `EQ` | Equal | Z set |
| `NE` | Not equal | Z clear |
| `CS` / `HS` | Carry set / Unsigned higher or same | C set |
| `CC` / `LO` | Carry clear / Unsigned lower | C clear |
| `MI` | Minus (negative) | N set |
| `PL` | Plus (positive or zero) | N clear |
| `VS` | Overflow | V set |
| `VC` | No overflow | V clear |
| `HI` | Unsigned higher | C set and Z clear |
| `LS` | Unsigned lower or same | C clear or Z set |
| `GE` | Signed greater or equal | N == V |
| `LT` | Signed less than | N != V |
| `GT` | Signed greater than | Z clear and N == V |
| `LE` | Signed less than or equal | Z set or N != V |
| `AL` | Always (default) | — |

In Thumb, **conditional** branches (`B{cond}`) use an 8-bit signed offset (in **halfwords**, i.e. 16-bit units): roughly **−128 to +127 instructions** from the branch, which corresponds to about **−256 to +254 bytes** relative to the branch opcode’s PC (see [GBATEK — THUMB.16](https://problemkaputt.de/gbatek.htm#thumbopcodesjumpsandcalls)). If the condition is **false**, the branch is skipped in **1S** cycle; if **true**, it costs **2S+1N** (taken branch, pipeline refill).

**Unconditional** `B` (Thumb format 18) uses an 11-bit signed halfword offset: about **±2048 bytes** from the branch (`PC+4−2048` … `PC+4+2046`, halfword-aligned targets) — matching the “2048 back / 2046 forward” wording used in many references.

### 7.1 GBATEK: Thumb branches, BL encoding, and long-range calls

This subsection summarizes [GBATEK’s “THUMB Instruction Summary” and “THUMB Opcodes: Jumps and Calls”](https://problemkaputt.de/gbatek.htm#thumbinstructionsummary) (through conditional branches, unconditional `B`, long `BL`, `BX`, and `SWI`).

| Instruction | Typical cycles (Thumb) | Notes |
|---------------|------------------------|--------|
| `B` (uncond.) | 2S+1N | PC = current PC ± offset (see above). |
| `B{cond}` | 1S if not taken; 2S+1N if taken | Condition uses bits 11–8; offset bits 7–0, signed halfwords. |
| `BL` | 3S+1N total | **Two** 16-bit words: first sets up `LR`, second completes jump; see below. |
| `BX Rs` | 2S+1N | PC = Rs; ARM/Thumb selected by **bit 0** of Rs. |
| `SWI #imm8` | 2S+1N | Enters Supervisor (ARM); `R14_svc = PC+2` when called from Thumb (see GBATEK SWI notes). |

**Long branch with link (`BL`) — two halfwords ([THUMB.19](https://problemkaputt.de/gbatek.htm#thumbopcodesjumpsandcalls)):**  
Unlike every other Thumb instruction, `BL` is **32 bits** (two opcodes). The pair builds a 22-bit offset; the **reachable range is ±4 MiB** from the address derived at the **first** halfword (`(PC+4) ± 0x400000` in the usual encoding). After `BL`, `LR` holds the **return address** (the instruction after the `BL` pair); on the GBA, bit 0 of `LR` is set so a later `BX lr` returns **still in Thumb**.  

**No `BLX` on ARMv4:** ARMv5+ has `BLX` (call with link and optional state change). The **ARM7TDMI is ARMv4T**, so you **cannot** use `BLX`. Common pattern (also in [Touched’s doc](https://github.com/Touched/asm-tutorial/blob/master/doc.md)) for a far call with link:

```arm
    ldr r0, =target_func    @ or +1 for Thumb entry
    bl   trampoline         @ LR = address after BL
trampoline:
    bx   r0                 @ unlimited-range jump; return still uses LR from caller
```

**Conditional opcode `0xE`:** In the 4-bit condition field of Thumb `B{cond}`, code **0xE** is **undefined** — do not use. **0xF** is reserved and used together with other patterns for `SWI` (see GBATEK).

### A Simple Loop

```arm
    mov r0, #10           @ counter = 10
loop:
    sub r0, #1            @ counter--
    cmp r0, #0
    bne loop              @ if counter != 0, keep going
```

Or more efficiently in ARM:

```arm
    mov r0, #10
loop:
    subs r0, r0, #1       @ counter-- and set flags
    bne loop              @ if not zero, loop
```

The `S` suffix on `SUBS` means "set flags." Without it, the branch would never know when to stop.

## 8. The CPSR and Condition Codes

The **Current Program Status Register** is a 32-bit register with this layout:

```
Bit:  31 30 29 28 ... 7 6 5 4 3 2 1 0
       N  Z  C  V      I F T M M M M M
```

### Condition Flags (bits 31–28)

| Flag | Name | Set when... |
|------|------|-------------|
| **N** | Negative | Result is negative (bit 31 of result is 1) |
| **Z** | Zero | Result is zero |
| **C** | Carry | Unsigned overflow occurred (addition), or no borrow (subtraction), or shift carry-out |
| **V** | Overflow | Signed overflow occurred (result doesn't fit in 32 bits as signed) |

### How `CMP` (and `CMN`) actually work

`CMP Rn, Rm` performs **`Rn − Rm`**, discards the 32-bit result, and sets **N, Z, C, V** from that subtraction (same as `SUBS` with the result thrown away). `CMN Rn, Rm` does **`Rn + Rm`** for flag purposes only.

- **Z:** Set if the result is zero → **`Rn == Rm`** (for `CMP`).
- **N:** Set if the result is negative (bit 31 = 1).
- **C (for `CMP` as unsigned compare):** For subtract, **C = NOT borrow**. So **`CMP Rn, Rm`** sets **C** when **`Rn ≥ Rm`** as unsigned 32-bit values (no borrow when subtracting `Rm` from `Rn`). That is why **`BHS`/`BCS`** (unsigned ≥) and **`BLO`/`BCC`** (unsigned <) behave as they do.
- **V:** Signed overflow of the subtraction — needed for **`BGT`**, **`BLT`**, **`BGE`**, **`BLE`**.

Signed vs. unsigned comparisons use **different** branch mnemonics because they read **different flag combinations** (e.g. `BHI` uses **C and Z**, not the same as `BGT` which uses **Z, N, and V`). For a deeper treatment of **carry vs. overflow**, see [Ian! Allen’s overflow notes](http://teaching.idallen.com/dat2343/10f/notes/040_overflow.txt) (cited in the [Touched tutorial](https://github.com/Touched/asm-tutorial/blob/master/doc.md)).

### Control Bits

| Bits | Name | Purpose |
|------|------|---------|
| 7 (I) | IRQ disable | When set, IRQ interrupts are disabled |
| 6 (F) | FIQ disable | When set, FIQ interrupts are disabled |
| 5 (T) | Thumb bit | 1 = Thumb state, 0 = ARM state. Never modify this directly. |
| 4–0 (M) | Mode | Encodes the current processor mode (User, IRQ, etc.) |

### Setting Flags: The S Suffix (ARM State)

In ARM state, most data processing instructions *do not* update the flags by default. You must add the `S` suffix:

```arm
add r0, r1, r2        @ r0 = r1 + r2, flags UNCHANGED
adds r0, r1, r2       @ r0 = r1 + r2, flags UPDATED
```

This is a critical feature. It lets you perform arithmetic without disturbing the flags from a previous comparison:

```arm
cmp r0, #5            @ Set flags
add r1, r1, #1        @ This does NOT touch the flags
beq somewhere         @ This still checks the result of the CMP
```

### Conditional Execution (ARM State Only)

In ARM state, *any* instruction can be made conditional by appending a condition code suffix:

```arm
cmp r0, #5
addgt r1, r1, #1      @ Only executes if r0 > 5 (signed)
movle r1, #0           @ Only executes if r0 <= 5 (signed)
```

This avoids branches, which flush the pipeline and cost cycles. A skipped conditional instruction takes 1 cycle (just the fetch, no execute), while a taken branch costs multiple cycles.

In Thumb state, only branch instructions can be conditional.

## 9. Logical and Bitwise Operations

### AND — Bitwise AND

```arm
and r0, r1            @ r0 = r0 & r1
```

Each bit in the result is 1 only if *both* corresponding bits are 1. Used to **mask** bits — to isolate specific bits of a value:

```arm
@ Extract the low byte of r0
mov r1, #0xFF
and r0, r1            @ r0 = r0 & 0xFF (clears everything above bit 7)
```

### ORR — Bitwise OR

```arm
orr r0, r1            @ r0 = r0 | r1
```

Each bit in the result is 1 if *either* corresponding bit is 1. Used to **set** specific bits:

```arm
@ Set bit 3 of r0
mov r1, #0x8           @ 0x8 = 0b1000
orr r0, r1             @ Bit 3 of r0 is now 1, all other bits unchanged
```

### EOR — Exclusive OR

```arm
eor r0, r1            @ r0 = r0 ^ r1
```

Each bit in the result is 1 if the corresponding bits are *different*. Used to **toggle** bits:

```arm
@ Toggle bit 0 of r0
mov r1, #1
eor r0, r1            @ If bit 0 was 0, it's now 1 (and vice versa)
```

A register XORed with itself is always zero:

```arm
eor r0, r0, r0        @ r0 = 0 (ARM syntax)
```

### BIC — Bit Clear

```arm
bic r0, r1            @ r0 = r0 & ~r1
```

Clears the bits in `r0` that are set in `r1`. This is equivalent to `AND` with the inverse of `r1`, but doesn't require inverting it first:

```arm
@ Clear bit 3 of r0
mov r1, #0x8
bic r0, r1            @ Bit 3 of r0 is now 0, all other bits unchanged
```

### TST — Test Bits (ARM, and Thumb)

```arm
tst r0, r1            @ Compute r0 & r1, set flags, discard result
```

Like a `CMP` but for `AND`. After `TST`, the Zero flag tells you whether any of the tested bits were set.

### TEQ — Test Equivalence (ARM only)

```arm
teq r0, r1            @ Compute r0 ^ r1, set flags, discard result
```

Sets the Zero flag if `r0` and `r1` are identical.

### MVN — Move NOT (bitwise invert)

```arm
mvn r0, r1            @ r0 = ~r1 (every bit flipped)
mvn r0, #0            @ r0 = 0xFFFFFFFF
```

## 10. Shifts and Rotates

Shifting moves all bits in a value left or right by a specified amount.

### LSL — Logical Shift Left

```arm
lsl r0, r1, #3        @ r0 = r1 << 3 (multiply by 8)
```

Zeroes fill in from the right. `LSL` by N is equivalent to multiplying by 2^N. Shifting by a multiple of 8 moves whole bytes:

```
0x0000AABB << 16 = 0xAABB0000
```

### LSR — Logical Shift Right

```arm
lsr r0, r1, #4        @ r0 = r1 >> 4 (unsigned divide by 16)
```

Zeroes fill in from the left. `LSR` by N is equivalent to unsigned division by 2^N (discarding remainder).

### ASR — Arithmetic Shift Right

```arm
asr r0, r1, #1        @ r0 = r1 >> 1 (signed divide by 2)
```

The leftmost bit (sign bit) is *preserved* — it fills in from the left. This correctly divides negative numbers:

```
0xFFFFFF00 ASR 4 = 0xFFFFFFF0   (sign bit stays 1)
0x0000FF00 ASR 4 = 0x00000FF0   (sign bit stays 0)
```

### ROR — Rotate Right (ARM state, and Thumb via register)

```arm
mov r0, r0, ROR #8    @ Rotate r0 right by 8 bits (ARM)
ror r0, r1            @ Rotate r0 right by r1 bits (Thumb)
```

Bits that fall off the right end wrap around to the left.

### RRX — Rotate Right Extended (ARM only)

Rotates right by exactly 1 bit, using the carry flag as bit 32. This enables multi-word rotations.

### The Barrel Shifter (ARM State)

One of ARM's most powerful features: **any data processing instruction** can incorporate a shift on its second operand at no extra cost:

```arm
add r0, r1, r2, LSL #2    @ r0 = r1 + (r2 * 4)     — one instruction, one cycle
sub r0, r0, r1, LSR #3    @ r0 = r0 - (r1 / 8)
mov r3, r0, ROR #16        @ r3 = r0 rotated right 16
cmp r0, r1, ASR #1         @ Compare r0 to r1/2
```

There are no standalone shift instructions in the ARM instruction set — shifts always happen through `MOV` or as part of another instruction.

## 11. Multiplication

The ARM7TDMI has hardware multiply support. There are no division instructions.

### MUL — Multiply

```arm
mul r2, r0, r1        @ r2 = r0 * r1 (lower 32 bits of result)
```

Only registers can be operands — no immediates, no shifter. If you need to multiply by a constant power of 2, use `LSL` instead (it's faster).

### MLA — Multiply Accumulate (ARM only)

```arm
mla r3, r0, r1, r2    @ r3 = (r0 * r1) + r2
```

Multiplies and adds in one instruction.

### UMULL / SMULL — Long Multiply (ARM only)

Produces a full 64-bit result from two 32-bit operands:

```arm
umull r0, r1, r2, r3  @ (r1:r0) = r2 * r3 (unsigned 64-bit result)
smull r0, r1, r2, r3  @ (r1:r0) = r2 * r3 (signed 64-bit result)
```

`r1` gets the upper 32 bits, `r0` gets the lower 32 bits.

### UMLAL / SMLAL — Long Multiply Accumulate (ARM only)

Like the long multiplies, but the 64-bit result is *added* to the existing value in the destination register pair:

```arm
umlal r0, r1, r2, r3  @ (r1:r0) = (r1:r0) + (r2 * r3)
```

### Division

There is **no hardware divide instruction** on the ARM7TDMI. Your options:

1. **BIOS SWI 0x06** — Software interrupt for division (see [The BIOS and SWI](#16-the-bios-and-swi)).
2. **Shift right** for powers of 2 (`LSR` for unsigned, `ASR` for signed).
3. **Lookup tables** or software division routines.

## 12. The Stack: PUSH, POP, and Block Transfers

### The Stack

The stack is a region of memory used for temporary storage. On the GBA, it grows **downward** (from higher addresses to lower addresses). The stack pointer (`SP` / `r13`) points at the **last stored word** (the “top” of the stack). **`SP` should stay word-aligned (multiple of 4)** so each `PUSH`/`POP` of a 32-bit register stays aligned.

Following [Touched’s “Assembler for the GBA”](https://github.com/Touched/asm-tutorial/blob/master/doc.md): the stack is **LIFO** (last in, first out). The hardware does **not** remember *which register* a value came from — it only stores **32-bit values** at addresses. **`PUSH {r0}`** means “copy the **bits** currently in `r0` to memory and move `SP`.” **`POP {r1}`** loads **those bits** into `r1`, whatever they are. Order of push/pop must mirror exactly if you want to restore saved registers.

**Rough expansions** (Thumb `PUSH`/`POP` are more efficient than this, but the idea matches [GBATEK — PUSH/POP](https://problemkaputt.de/gbatek.htm#thumbopcodesmemoryloadstoreldrstr)):

```arm
@ push {r0}  ≈  sub sp, #4  then  str r0, [sp]
@ pop  {r0}  ≈  ldr r0, [sp]  then  add sp, #4
```

Smaller **`SP`** = **deeper** stack (more items pushed). Running out of stack space causes **stack overflow** (often from **too much recursion**).

**Swap two registers using only the stack** (from Touched):

```arm
    mov r0, #3
    mov r1, #1
    push {r0}       @ save original r0 on stack
    mov r0, r1      @ r0 gets r1’s value
    pop {r1}        @ original r0 value goes into r1 — swap complete
```

### PUSH and POP (Thumb)

```arm
push {r0, r1, r4-r7, lr}   @ Save registers and return address onto the stack
@ ... function body ...
pop {r0, r1, r4-r7, pc}    @ Restore registers and return (by popping into PC)
```

- `PUSH` decrements SP and writes registers to the stack.
- `POP` reads registers from the stack and increments SP.
- Pushing `LR` and popping into `PC` is the standard way to begin and end a subroutine in Thumb.
- **Always POP the same registers you PUSH.** Mismatched push/pop corrupts the stack and crashes.

**Returns and interworking** (same sources as Touched): if you did **not** overwrite `LR`, **`bx lr`** returns. If you saved `LR` on the stack (nested calls), a common pattern is **`pop {r0}` / `bx r0`** (or use **`r1`** if **`r0`** holds a return value). When **ARM/Thumb interworking** is **not** needed, **`mov pc, lr`** or **`pop {pc}`** return **without** examining bit 0 — they keep the current instruction set state (see [§24](#24-armthumb-interworking)).

### STMIA / LDMIA — Block Transfers (ARM and Thumb)

These instructions store or load *multiple* registers in a single instruction, which is much faster than individual loads/stores:

```arm
stmia r0!, {r3-r10}   @ Store r3 through r10 at address r0, incrementing after each.
                       @ r0 is updated to point past the last written word.
ldmia r1!, {r3-r10}   @ Load r3 through r10 from address r1, incrementing after each.
```

The `!` means write-back (the base register is updated). `IA` means "Increment After" — the address increases after each transfer.

ARM state also supports `IB` (Increment Before), `DA` (Decrement After), `DB` (Decrement Before), and alternate stack-oriented mnemonics (`FD`, `ED`, `FA`, `EA`).

These instructions are used for fast block memory copies:

```arm
@ Copy 32 bytes per iteration (8 registers * 4 bytes each)
loop:
    ldmia r1!, {r3-r10}
    stmia r0!, {r3-r10}
    subs r2, r2, #1
    bne loop
```

## Subroutines and Calling Conventions (APCS-style)

A **subroutine** is a sequence of instructions with a single entry; in C terms it is a **function**. Most commercial GBA code is compiled from C and follows a fixed **calling convention** so routines can call each other without source code. The [Touched tutorial](https://github.com/Touched/asm-tutorial/blob/master/doc.md) summarizes the usual **32-bit ARM (APCS-family)** rules:

| Rule | Typical meaning on GBA / ARM |
|------|------------------------------|
| Arguments | **`r0`–`r3`** — first up to four arguments; further arguments on the **stack** (if any). |
| Return value | **`r0`** (and sometimes **`r1`** for 64-bit / struct returns — compiler-dependent). |
| Caller-saved | **`r0`–`r3`**, **`r12`** (`ip`) — may be **clobbered** by the callee; the caller must not rely on them holding the same values **after** a `BL`. |
| Callee-saved | **`r4`–`r11`**, **`SP`** — if a function uses them, it must **restore** them before return (usually via `PUSH`/`POP` in the prologue/epilogue). |
| Return address | Left in **`LR`** by **`BL`**; the function must branch back (e.g. `bx lr`, `pop {pc}`) without corrupting the return path. |

**Typical ARM-shaped prologue/epilogue** (from Touched — adjust for Thumb and for whether you need **`bx`**):

```arm
push {r4, r5, lr}
bl   some_other_function
pop  {r4, r5}
pop  {r1}
bx   r1              @ interworking return: LR was in r1

@ or, if no interworking:
push {r4, r5, lr}
bl   some_other_function
pop  {r4, r5, pc}
```

**Pure vs. impure:** A **pure** function only computes from its inputs and returns a value. An **impure** function also **writes memory** (globals, hardware registers, etc.) — almost all game code is impure.

Wikipedia’s [Calling convention — ARM (A32)](https://en.wikipedia.org/wiki/Calling_convention#ARM_.28A32.29) has more detail; exact rules for your toolchain may follow **AAPCS** with small differences — always check your compiler’s documentation for struct passing and variadic functions.

---

# Part III: GBA-Specific Usage

## 13. GBA Memory Map

The GBA's memory is organized into distinct regions with different characteristics:

| Address Range | Name | Size | Bus Width | Notes |
|---------------|------|------|-----------|-------|
| `0x00000000`–`0x00003FFF` | BIOS | 16 KB | 32-bit | Read-only. Only accessible while executing BIOS code. |
| `0x02000000`–`0x0203FFFF` | EWRAM | 256 KB | 16-bit | External Work RAM. Slower (16-bit bus, wait states). |
| `0x03000000`–`0x03007FFF` | IWRAM | 32 KB | 32-bit | Internal Work RAM. Fast. Best place for ARM code. |
| `0x04000000`–`0x040003FE` | I/O | 1 KB | varies | Hardware registers (display, sound, DMA, timers, etc.) |
| `0x05000000`–`0x050003FF` | Palette RAM | 1 KB | 16-bit | 256 BG colors + 256 sprite colors. |
| `0x06000000`–`0x06017FFF` | VRAM | 96 KB | 16-bit | Video RAM for tiles, maps, and bitmaps. No 8-bit writes. |
| `0x07000000`–`0x070003FF` | OAM | 1 KB | 32-bit | Object Attribute Memory (sprite data). |
| `0x08000000`–`0x09FFFFFF` | ROM | up to 32 MB | 16-bit | Game Pak ROM. Read-only. Wait states apply. |

### Reading addresses: region prefix + offset

As in the [Touched “Assembler for the GBA”](https://github.com/Touched/asm-tutorial/blob/master/doc.md) notes, the CPU sees a flat **32-bit** address space; physically, **different chips** back different ranges, but software uses one contiguous numbering.

A common mental split (especially when reading logs or cheat devices) is **top byte ≈ region**, **lower 24 bits ≈ offset within that region**:

| Example address | Prefix (high byte) | Meaning |
|-----------------|--------------------|---------|
| `0x08123456` | `0x08` | Game Pak ROM; offset `0x123456` bytes from the start of the **CPU’s** ROM window (`0x08000000`). |

Short prefix cheat-sheet (partial — **full map in [GBATEK — Memory Map](https://problemkaputt.de/gbatek.htm)**):

| Address prefix (high byte(s)) | Typical region |
|--------------------------------|----------------|
| `0x00` | BIOS ROM |
| `0x02` | EWRAM |
| `0x03` | IWRAM |
| `0x04` | I/O registers |
| `0x05` | Palette RAM |
| `0x06` | VRAM |
| `0x07` | OAM |
| `0x08`–`0x09` | Game Pak ROM (mirrors / size depend on cart) |

### Data bus width vs. “Thumb is faster in ROM”

The Game Pak interface delivers **16 bits per external bus cycle** for instruction fetches from ROM. A **Thumb** opcode is **16 bits** → often **one** fetch. An **ARM** opcode is **32 bits** → **two** fetches. That is the main reason Thumb **throughput from ROM** is better than ARM, as both [Touched](https://github.com/Touched/asm-tutorial/blob/master/doc.md) and [GBATEK](https://problemkaputt.de/gbatek.htm) emphasize. Copy the same ARM routine into **IWRAM** (32-bit bus) and it can run at full speed there.

**Key takeaway for performance:** IWRAM has a 32-bit bus and no wait states — ARM code runs at full speed here. ROM has a 16-bit bus with wait states — Thumb code is strongly preferred for ROM execution.

## 14. Display Control and Graphics Modes

The GBA's LCD is 240 x 160 pixels. The display is controlled by writing to hardware registers starting at `0x04000000`.

### REG_DISPCNT (0x04000000) — Display Control

This 16-bit register controls which mode and layers are active:

```
Bit:  F E D C  B A 9 8  7 6 5 4  3 2 1 0
      W V U S  L K J I  F D B A  C M M M
```

| Bits | Name | Purpose |
|------|------|---------|
| 0–2 (M) | Mode | Graphics mode (0–5) |
| 4 (A) | Frame select | Selects which frame to display in double-buffered modes (4, 5) |
| 6 (D) | OBJ mapping | 0 = 2D tile mapping, 1 = 1D sequential mapping |
| 7 (F) | Forced blank | Forces display to white; allows faster VRAM access |
| 8–11 (I-L) | BG enable | Enable BG0, BG1, BG2, BG3 respectively |
| 12 (S) | OBJ enable | Enable sprites |
| 13–14 (U-V) | Window enable | Enable Window 0, Window 1 |
| 15 (W) | OBJ window | Enable sprite window |

### Setting Up Mode 3 (Simple Bitmap) in ASM

```arm
.arm
.text
.global main

main:
    mov r0, #0x04000000     @ I/O register base
    mov r1, #0x400          @ Can't load 0x403 directly (not a valid rotated immediate)
    add r1, r1, #3          @ r1 = 0x403 = Mode 3 + BG2 enable
    strh r1, [r0]           @ Write to REG_DISPCNT (16-bit register)

    mov r0, #0x06000000     @ VRAM base address
    mov r1, #0x1F           @ Red color (15-bit: 0BBBBBGGGGGRRRRR)
    mov r2, #0x9600         @ 38400 pixels = 240 * 160

fill_loop:
    strh r1, [r0], #2       @ Store 16-bit color, advance pointer by 2
    subs r2, r2, #1
    bne fill_loop

hang:
    b hang                  @ Infinite loop — program done
```

### The Six Graphics Modes

| Mode | Type | Layers | Notes |
|------|------|--------|-------|
| 0 | Tile | BG0–BG3 | All layers text/scroll. Most versatile tile mode. |
| 1 | Tile | BG0–BG2 | BG0, BG1 text/scroll; BG2 supports rotate/scale. |
| 2 | Tile | BG2–BG3 | Both layers support rotate/scale. |
| 3 | Bitmap | BG2 | 240x160, 15-bit color, single buffer. |
| 4 | Bitmap | BG2 | 240x160, 8-bit palettized, double buffer. |
| 5 | Bitmap | BG2 | 160x128, 15-bit color, double buffer. |

### GBA Color Format

Colors are 15-bit, stored in a halfword:

```
Bit:  15   14-10    9-5    4-0
       X   Blue    Green   Red
```

Each channel is 5 bits (0–31). Bit 15 is unused. Examples:
- Pure red: `0x001F`
- Pure green: `0x03E0`
- Pure blue: `0x7C00`
- White: `0x7FFF`

## 15. VBlank and the Rendering Cycle

The GBA's display behaves like a CRT scan:

1. **HDraw** — Rendering a scanline (240 pixels).
2. **HBlank** — Brief pause after each scanline.
3. After 160 scanlines: **VBlank** — 68 scanlines of idle time.

During VBlank, the display hardware is not reading VRAM, so you can safely update graphics without visual artifacts.

### REG_VCOUNT (0x04000006)

This 16-bit read-only register contains the current scanline number (0–227). Scanlines 160–227 are VBlank.

### Waiting for VBlank

```arm
    ldr r0, =0x04000006       @ REG_VCOUNT address
wait_vblank:
    ldrh r1, [r0]             @ Read current scanline
    cmp r1, #160              @ First VBlank line
    bne wait_vblank           @ Keep polling until VBlank starts
```

This is a "busy wait" — it works but wastes power. The better approach is to use interrupts or the `Halt` BIOS call (SWI 0x02), which puts the CPU to sleep until VBlank.

## 16. The BIOS and SWI

The GBA has a built-in BIOS ROM with pre-coded utility routines. You call them using the `SWI` (Software Interrupt) instruction.

### SWI Syntax

In **ARM state**, the SWI number is shifted left by 16:

```arm
swi 0x60000           @ SWI #6 (Div) in ARM state — 6 << 16 = 0x60000
```

In **Thumb state**, just use the number directly:

```arm
swi 6                 @ SWI #6 (Div) in Thumb state
```

### Commonly Used BIOS Functions

| SWI # | Name | Description |
|-------|------|-------------|
| 0x00 | SoftReset | Resets the GBA. |
| 0x02 | Halt | Low-power halt until an interrupt occurs. |
| 0x05 | VBlankIntrWait | Halts until VBlank interrupt fires. Preferred VBlank sync method. |
| 0x06 | Div | Signed division. r0/r1. Returns quotient in r0, remainder in r1, abs(quotient) in r3. |
| 0x08 | Sqrt | Square root of r0. Result in r0. |
| 0x0B | CpuSet | Memory copy/fill (word or halfword). |
| 0x0C | CpuFastSet | Fast memory copy/fill (word, 32-byte chunks). |
| 0x0E | BgAffineSet | Computes background affine transformation parameters. |
| 0x0F | ObjAffineSet | Computes sprite affine transformation parameters. |

### Division Example

```arm
    mov r0, #100          @ Numerator
    mov r1, #7            @ Denominator
    swi 0x60000           @ Div (ARM state)
    @ r0 = 14 (quotient), r1 = 2 (remainder), r3 = 14 (absolute quotient)
```

## 17. Assembler Directives and Program Structure

When writing GBA ASM for the GCC toolchain (devkitARM), several directives control how your code is assembled.

### Key Directives

| Directive | Purpose |
|-----------|---------|
| `.arm` | Following code uses ARM instruction set. |
| `.thumb` | Following code uses Thumb instruction set. |
| `.text` | Place the following in the code (text) section (typically ROM). |
| `.data` | Place the following in the data section (typically RAM — copied by startup code). |
| `.global name` | Make `name` visible to the linker (required for `main`). |
| `.align N` | Align the next data/instruction to a 2^N byte boundary. `.align 2` = 4-byte align. |
| `.word value` | Insert a 32-bit constant. |
| `.hword value` | Insert a 16-bit constant. |
| `.byte value` | Insert an 8-bit constant. |
| `.incbin "file"` | Include a binary file verbatim (raw image data, etc.). |
| `.ltorg` / `.pool` | Place the literal pool here (for `ldr r0, =value` pseudo-instructions). |

### Typical Program Skeleton

```arm
    .arm
    .text
    .global main

main:
    @ --- your setup code ---

    @ --- your main loop ---
loop:
    @ do work
    b loop

    .ltorg              @ Literal pool goes here

    .align 2
my_data:
    .word 0x12345678
    .hword 0xABCD
```

### Labels and Comments

A **label** is a name followed by a colon. It represents the address of whatever comes next:

```arm
my_function:
    push {lr}
    @ ... function body ...
    pop {pc}
```

**Comments** in GNU assembler (GAS) use `@` for single-line. Since GCC also preprocesses `.S` files, you can use C-style `//` and `/* */` comments too.

### Keywords / Literal Pool Labels

For readability, you can define named constants at the end of your code:

```arm
    ldr r0, .VRAM_ADDR

    @ ...

    .align 2
.VRAM_ADDR:
    .word 0x06000000
```

This is functionally identical to `ldr r0, =0x06000000`, but can improve readability for frequently referenced values.

---

# Part IV: Instruction References

## 18. Thumb Instruction Reference

Each Thumb instruction is 16 bits (2 bytes), except `BL` which is 32 bits (two 16-bit halves).

**Register notation:** "Lo" means `r0`–`r7`. "Hi" means `r8`–`r15`.

### GBATEK summary (clock cycles, flags, and formats)

[GBATEK — THUMB Instruction Summary](https://problemkaputt.de/gbatek.htm#thumbinstructionsummary) lists **every** Thumb opcode with **cycle counts** (e.g. `1S`, `1S+1N+1I` for loads), **which CPSR flags** are updated (`N Z C V` or `-` if unchanged), and a **format number** (1–19) pointing to the bit-level opcode chapter.

**Important blanket rule from GBATEK:** In Thumb, only **`r0`–`r7`** are usable unless the instruction format explicitly allows **`r8`–`r15`**, **`SP`**, or **`PC`**.

**Selected entries** (abbreviated; see GBATEK for the full tables):

| Category | Examples | Cycles / flags (typical) |
|----------|----------|--------------------------|
| Logical / shifts | `MOV`, `AND`, `LSL #imm`, register shifts | `1S`; shifts set **N Z C** (carry only if shift amount **non-zero**); `MOV Rd,#imm8` sets **N Z** only |
| ALU format 4 | `ADC`, `SBC`, `MUL`, `NEG`, etc. | `MUL`: `1S+mI` on ARMv4 (**m** = 1..4 depending on operand); **C** flag on `MUL` is **undefined / implementation-specific** on ARMv4 (GBATEK warns carry is “destroyed”) |
| Branches | `B`, `B{cond}`, `BL`, `BX`, `SWI` | See [§7.1](#71-gbatek-thumb-branches-bl-encoding-and-long-range-calls) |
| Load/store | `LDR`/`STR` with immediates or `[Rb,Ro]` | Loads often `1S+1N+1I`; stores often `2N` |
| `PUSH`/`POP`, `LDM`/`STM` | Register lists | Formulas with **n** registers in list (GBATEK table) |

**NOP:** Disassemblers often show **`MOV r8, r8`** as NOP (opcode pattern documented in GBATEK THUMB.5).

**Immediate `LDR` from PC** ([THUMB.6](https://problemkaputt.de/gbatek.htm#thumbopcodesmemoryloadstoreldrstr)): `LDR Rd,[PC,#imm]` — PC for the purpose of the offset is **`(PC+4) & ~2`** (word-aligned), offset **0–1020** in steps of **4**.

**Shift immediates** ([THUMB.1](https://problemkaputt.de/gbatek.htm#thumbopcodesregisteroperationsalubx)): **`LSL #0`** is a **no-shift** (carry **unchanged**). **`LSR #0`** / **`ASR #0`** in **ARM** are defined as shifts by **32**; assemblers may rewrite these. Register-controlled shifts (`LSL Rd,Rs` etc.) use only the **low byte** of the shift count: **`Rs & 0xFF`**.

**`SWI` from Thumb** ([THUMB.17](https://problemkaputt.de/gbatek.htm#thumbopcodesjumpsandcalls)): enters **Supervisor** in **ARM** state; **`R14_svc = PC + 2`** (halfword after `SWI`). The handler reads the **8-bit immediate** from the **16-bit Thumb opcode** at **`[R14_svc − 2]`**. If you also use **`SWI` from ARM mode**, the handler must check **SPSR T bit** and, for ARM SWIs, decode the **24-bit** field from the **32-bit** word at **`[R14_svc − 4]`** (GBATEK). Return with **`MOVS PC, R14`** in the handler to restore **PC + CPSR + Thumb bit**.

**THUMB opcode format numbers (1–19)** — [GBATEK binary layout table](https://problemkaputt.de/gbatek.htm#thumbinstructionsummary) maps the high bits of each 16-bit halfword to instruction groups. Quick map:

| Format | Leading bits (summary) | Examples |
|--------|------------------------|----------|
| 1 | `000` (not `00011`) | `LSL/LSR/ASR Rd,Rs,#imm` |
| 2 | `00011` | `ADD/SUB` 3-operand or small immediates |
| 3 | `001` | `MOV/CMP/ADD/SUB` with 8-bit immediate |
| 4 | `010000` | ALU (`AND`, `MUL`, register shifts, …) |
| 5 | `010001` | High-register `ADD`/`CMP`/`MOV`, **`BX`** |
| 6–11 | `01001`…`1001` | PC-relative `LDR`, `[Rb,Ro]`, immediates, SP-relative |
| 12–15 | `1010`…`1011` | `ADD PC/SP`, `PUSH`/`POP`, `LDM`/`STM` |
| 16 | `1101` (not `1101 1111`) | Conditional `B{cond}` |
| 17 | `1101 1111` (`SWI`) / `1011 1110` (`BKPT`, not ARM7) | `SWI` / debug breakpoint |
| 18 | `11100` | Unconditional `B` |
| 19 | `11110` / `11111` | **`BL`** (pair of halfwords) |

Reserved / undefined patterns (e.g. certain `1011` and `1110 1` combinations) are listed in GBATEK on the same page.

### Data Movement

| Instruction | Syntax | Operation | Register Restrictions |
|-------------|--------|-----------|----------------------|
| MOV | `mov rD, rS` | rD = rS | Any registers (Hi/Lo) |
| MOV | `mov rD, #imm8` | rD = imm8 | Lo only |
| MVN | `mvn rD, rS` | rD = ~rS | Lo only |

### Arithmetic

| Instruction | Syntax | Operation | Register Restrictions |
|-------------|--------|-----------|----------------------|
| ADD | `add rD, rS, rN` | rD = rS + rN | Lo only |
| ADD | `add rD, rS, #imm3` | rD = rS + imm3 | Lo only |
| ADD | `add rD, #imm8` | rD = rD + imm8 | Lo only |
| ADD | `add rD, rH` | rD = rD + rH | Hi allowed |
| ADD | `add SP, #imm7` | SP = SP ± imm7 | — |
| ADC | `adc rD, rS` | rD = rD + rS + C | Lo only |
| SUB | `sub rD, rS, rN` | rD = rS - rN | Lo only |
| SUB | `sub rD, rS, #imm3` | rD = rS - imm3 | Lo only |
| SUB | `sub rD, #imm8` | rD = rD - imm8 | Lo only |
| SBC | `sbc rD, rS` | rD = rD - rS - ~C | Lo only |
| NEG | `neg rD, rS` | rD = 0 - rS | Lo only |
| MUL | `mul rD, rS` | rD = rD * rS | Lo only |
| CMP | `cmp rD, rS` | flags = rD - rS | Any registers |
| CMP | `cmp rD, #imm8` | flags = rD - imm8 | Lo only |
| CMN | `cmn rD, rS` | flags = rD + rS | Lo only |

### Logic

| Instruction | Syntax | Operation | Register Restrictions |
|-------------|--------|-----------|----------------------|
| AND | `and rD, rS` | rD = rD & rS | Lo only |
| ORR | `orr rD, rS` | rD = rD \| rS | Lo only |
| EOR | `eor rD, rS` | rD = rD ^ rS | Lo only |
| BIC | `bic rD, rS` | rD = rD & ~rS | Lo only |
| TST | `tst rD, rS` | flags = rD & rS | Lo only |

### Shifts

| Instruction | Syntax | Operation | Register Restrictions |
|-------------|--------|-----------|----------------------|
| LSL | `lsl rD, rS, #imm5` | rD = rS << imm5 | Lo only |
| LSL | `lsl rD, rS` | rD = rD << rS | Lo only |
| LSR | `lsr rD, rS, #imm5` | rD = rS >> imm5 (logical) | Lo only |
| LSR | `lsr rD, rS` | rD = rD >> rS (logical) | Lo only |
| ASR | `asr rD, rS, #imm5` | rD = rS >> imm5 (arithmetic) | Lo only |
| ASR | `asr rD, rS` | rD = rD >> rS (arithmetic) | Lo only |
| ROR | `ror rD, rS` | rD = rD rotated right by rS | Lo only |

### Load / Store

| Instruction | Syntax | Operation | Offset restriction |
|-------------|--------|-----------|-------------------|
| LDR | `ldr rD, [rB, #off]` | Load word | off: 0–124, multiples of 4 |
| LDR | `ldr rD, [rB, rO]` | Load word | — |
| LDR | `ldr rD, [PC, #off]` | Load word (PC-relative) | off: 0–1020, multiples of 4 |
| LDR | `ldr rD, [SP, #off]` | Load word (SP-relative) | off: 0–1020, multiples of 4 |
| LDRH | `ldrh rD, [rB, #off]` | Load halfword | off: 0–62, multiples of 2 |
| LDRH | `ldrh rD, [rB, rO]` | Load halfword | — |
| LDRB | `ldrb rD, [rB, #off]` | Load byte | off: 0–31 |
| LDRB | `ldrb rD, [rB, rO]` | Load byte | — |
| LDRSH | `ldrsh rD, [rB, rO]` | Load signed halfword | Register offset only |
| LDRSB | `ldrsb rD, [rB, rO]` | Load signed byte | Register offset only |
| STR | `str rD, [rB, #off]` | Store word | off: 0–124, multiples of 4 |
| STR | `str rD, [rB, rO]` | Store word | — |
| STR | `str rD, [SP, #off]` | Store word (SP-relative) | off: 0–1020, multiples of 4 |
| STRH | `strh rD, [rB, #off]` | Store halfword | off: 0–62, multiples of 2 |
| STRH | `strh rD, [rB, rO]` | Store halfword | — |
| STRB | `strb rD, [rB, #off]` | Store byte | off: 0–31 |
| STRB | `strb rD, [rB, rO]` | Store byte | — |

All load/store registers must be Lo, except SP/PC-relative forms.

### Stack

| Instruction | Syntax | Notes |
|-------------|--------|-------|
| PUSH | `push {rlist}` | Can include LR. Lo regs only otherwise. |
| POP | `pop {rlist}` | Can include PC (returns from function). Lo regs only otherwise. |

### Branch

| Instruction | Syntax | Range |
|-------------|--------|-------|
| B | `b label` | ±2048 bytes |
| B*cond* | `beq label`, etc. | ±256 bytes |
| BL | `bl label` | ±4 MB |
| BX | `bx rS` | Any register. Bit 0 selects state. |

### Block Transfer

| Instruction | Syntax | Notes |
|-------------|--------|-------|
| LDMIA | `ldmia rB!, {rlist}` | Load multiple, increment after, write-back. Lo regs only. |
| STMIA | `stmia rB!, {rlist}` | Store multiple, increment after, write-back. Lo regs only. |

### Software Interrupt

| Instruction | Syntax |
|-------------|--------|
| SWI | `swi #imm8` |

## 19. ARM Instruction Reference

ARM instructions are 32 bits each. The top 4 bits are the condition code field — every instruction can be conditional.

### Condition Code Suffixes

Append to any instruction mnemonic. Omitting the suffix means `AL` (always execute).

| Suffix | Meaning | CPSR Flags |
|--------|---------|-----------|
| EQ | Equal | Z=1 |
| NE | Not equal | Z=0 |
| CS/HS | Unsigned ≥ | C=1 |
| CC/LO | Unsigned < | C=0 |
| MI | Negative | N=1 |
| PL | Positive/zero | N=0 |
| VS | Overflow | V=1 |
| VC | No overflow | V=0 |
| HI | Unsigned > | C=1, Z=0 |
| LS | Unsigned ≤ | C=0 or Z=1 |
| GE | Signed ≥ | N=V |
| LT | Signed < | N≠V |
| GT | Signed > | Z=0, N=V |
| LE | Signed ≤ | Z=1 or N≠V |
| AL | Always | — |

### The S Suffix

Adding `S` to a data processing instruction makes it update the CPSR flags:

```arm
adds r0, r1, r2      @ Sets N, Z, C, V
add r0, r1, r2       @ Does NOT set flags
```

`CMP`, `CMN`, `TST`, `TEQ` always set flags (no S needed).

### Operand 2 and the Barrel Shifter

Most ARM data processing instructions have a flexible second operand (`<Oprnd2>`):

| Form | Example | Meaning |
|------|---------|---------|
| Immediate | `#0xFF` | 8-bit value rotated right by even amount |
| Register | `Rm` | Value in register |
| Register + LSL imm | `Rm, LSL #5` | Rm shifted left by immediate |
| Register + LSR imm | `Rm, LSR #5` | Rm shifted right (logical) by immediate |
| Register + ASR imm | `Rm, ASR #5` | Rm shifted right (arithmetic) by immediate |
| Register + ROR imm | `Rm, ROR #5` | Rm rotated right by immediate |
| Register + RRX | `Rm, RRX` | Rm rotated right through carry by 1 |
| Register + shift by register | `Rm, LSL Rs` | Rm shifted by amount in Rs |

### ARM Immediate Encoding

ARM immediates are formed by rotating an 8-bit value right by an even number of bits (0, 2, 4, ... 30). This means:

- `0xFF` (valid — `0xFF` rotated by 0)
- `0xFF0` (valid — `0xFF` rotated right by 28, equivalently left by 4)
- `0x102` (invalid — cannot be formed this way)

If you cannot express your constant this way, use `ldr rD, =value` to load it from the literal pool, or build it with multiple instructions:

```arm
mov r0, #0x400        @ Valid: 0x01 ROR 22
add r0, r0, #3        @ r0 = 0x403 (built in two steps)
```

### Data Processing Instructions

All follow the format: `OPCODE{cond}{S} Rd, Rn, <Oprnd2>` (or `Rd, <Oprnd2>` for MOV/MVN).

| Mnemonic | Operation |
|----------|-----------|
| MOV | Rd = Oprnd2 |
| MVN | Rd = ~Oprnd2 |
| ADD | Rd = Rn + Oprnd2 |
| ADC | Rd = Rn + Oprnd2 + C |
| SUB | Rd = Rn - Oprnd2 |
| SBC | Rd = Rn - Oprnd2 - ~C |
| RSB | Rd = Oprnd2 - Rn |
| RSC | Rd = Oprnd2 - Rn - ~C |
| AND | Rd = Rn & Oprnd2 |
| ORR | Rd = Rn \| Oprnd2 |
| EOR | Rd = Rn ^ Oprnd2 |
| BIC | Rd = Rn & ~Oprnd2 |
| CMP | Rn - Oprnd2 (flags only) |
| CMN | Rn + Oprnd2 (flags only) |
| TST | Rn & Oprnd2 (flags only) |
| TEQ | Rn ^ Oprnd2 (flags only) |

### Multiply Instructions

| Mnemonic | Syntax | Operation |
|----------|--------|-----------|
| MUL | `MUL{S} Rd, Rm, Rs` | Rd = Rm * Rs |
| MLA | `MLA{S} Rd, Rm, Rs, Rn` | Rd = (Rm * Rs) + Rn |
| UMULL | `UMULL{S} RdLo, RdHi, Rm, Rs` | (RdHi:RdLo) = Rm * Rs (unsigned) |
| UMLAL | `UMLAL{S} RdLo, RdHi, Rm, Rs` | (RdHi:RdLo) += Rm * Rs (unsigned) |
| SMULL | `SMULL{S} RdLo, RdHi, Rm, Rs` | (RdHi:RdLo) = Rm * Rs (signed) |
| SMLAL | `SMLAL{S} RdLo, RdHi, Rm, Rs` | (RdHi:RdLo) += Rm * Rs (signed) |

### Load/Store Instructions

Single register transfers:

| Mnemonic | Syntax | Operation |
|----------|--------|-----------|
| LDR | `LDR Rd, <addr>` | Load word |
| LDRH | `LDRH Rd, <addr>` | Load unsigned halfword |
| LDRB | `LDRB Rd, <addr>` | Load unsigned byte |
| LDRSH | `LDRSH Rd, <addr>` | Load signed halfword |
| LDRSB | `LDRSB Rd, <addr>` | Load signed byte |
| STR | `STR Rd, <addr>` | Store word |
| STRH | `STRH Rd, <addr>` | Store halfword |
| STRB | `STRB Rd, <addr>` | Store byte |

**Addressing modes** (`<addr>` possibilities):

```
[Rn, #offset]       Pre-indexed, immediate offset (-4095 to +4095 for word/byte)
[Rn, ±Rm]           Pre-indexed, register offset
[Rn, ±Rm, shift]    Pre-indexed, scaled register offset
[Rn, #offset]!      Pre-indexed with write-back
[Rn], #offset       Post-indexed (automatic write-back)
[Rn], ±Rm           Post-indexed, register
```

### Block Transfer Instructions

```
LDM{cond}<mode> Rn{!}, {register_list}{^}
STM{cond}<mode> Rn{!}, {register_list}{^}
```

Modes: `IA` (Increment After), `IB` (Increment Before), `DA` (Decrement After), `DB` (Decrement Before).

The `^` suffix (in privileged modes) accesses user-mode registers, or restores the CPSR from SPSR when loading PC.

### Branch Instructions

| Mnemonic | Syntax | Operation | Range |
|----------|--------|-----------|-------|
| B | `B{cond} label` | Branch | ±32 MB |
| BL | `BL{cond} label` | Branch with Link (LR = return address) | ±32 MB |
| BX | `BX{cond} Rn` | Branch and Exchange state | Any address |

### Swap Instruction

```arm
SWP{cond}{B} Rd, Rm, [Rn]    @ Rd = [Rn]; [Rn] = Rm  (atomic read-write)
```

Reads a word (or byte with `B`) from `[Rn]` into `Rd`, then writes `Rm` to `[Rn]`, in a single atomic bus operation. Useful for semaphores.

### Status Register Access

| Mnemonic | Syntax | Operation |
|----------|--------|-----------|
| MRS | `MRS Rd, CPSR` | Rd = CPSR |
| MRS | `MRS Rd, SPSR` | Rd = SPSR |
| MSR | `MSR CPSR_f, Rm` | CPSR flags = Rm |
| MSR | `MSR CPSR_c, Rm` | CPSR control bits = Rm |

The field suffixes `_f` (flags), `_c` (control), `_s` (status), `_x` (extension) specify which PSR fields to modify.

### Software Interrupt

```arm
SWI{cond} #imm24              @ Call BIOS function (number encoded in imm24)
```

On GBA in ARM state, the function number is `SWI_number << 16`.

---

# Part V: Advanced Topics

## 20. The Instruction Pipeline

The ARM7TDMI uses a **3-stage pipeline**:

1. **Fetch** — The instruction is read from memory.
2. **Decode** — The instruction is decoded and registers are read.
3. **Execute** — The ALU operates, results are written back.

At any given moment, three instructions are in flight. This has a key consequence:

**The PC always points to the instruction being fetched, not the one being executed.**

- In ARM state: `PC` = address of current instruction + 8
- In Thumb state: `PC` = address of current instruction + 4

This means if you read `PC` in your code, you get an address that is 2 instructions ahead.

### Pipeline Flush on Branches

When a branch is taken, the pipeline must be flushed and refilled. This costs extra cycles:

- A taken branch in ARM state typically costs **3 cycles** (1 N-cycle for the branch + 2 S-cycles to refill the pipeline).
- Conditional instructions that are *not taken* cost only **1 cycle** (the fetch cycle; the execute stage is skipped).

This is why conditional execution in ARM state can be more efficient than branching for short sequences.

## 21. Processor Modes and Exceptions

### Processor Modes

The ARM7TDMI has seven operating modes:

| Mode | CPSR M bits | Banked Registers | When entered |
|------|-------------|-----------------|--------------|
| User | `10000` | None (base set) | Normal execution |
| FIQ | `10001` | r8–r14, SPSR | Fast interrupt |
| IRQ | `10010` | r13, r14, SPSR | Normal interrupt |
| Supervisor | `10011` | r13, r14, SPSR | SWI or reset |
| Abort | `10111` | r13, r14, SPSR | Memory fault |
| Undefined | `11011` | r13, r14, SPSR | Undefined instruction |
| System | `11111` | None (shares User regs) | Privileged code |

"Banked registers" are separate physical registers that replace the normal ones when the mode is active. This means each mode has its own `SP` and `LR`, so interrupts don't clobber the main program's stack pointer or return address.

FIQ mode banks the most registers (r8–r14), which is why many FIQ handlers don't need to save any registers.

### Exception Vectors

When an exception occurs, the CPU jumps to a fixed address:

| Address | Exception |
|---------|-----------|
| `0x00000000` | Reset |
| `0x00000004` | Undefined instruction |
| `0x00000008` | SWI (Software Interrupt) |
| `0x0000000C` | Prefetch Abort |
| `0x00000010` | Data Abort |
| `0x00000014` | Reserved |
| `0x00000018` | IRQ |
| `0x0000001C` | FIQ |

On the GBA, these addresses are in the BIOS ROM. The BIOS IRQ handler at `0x00000018` reads the user's IRQ handler address from `0x03007FFC` and jumps there.

### What Happens When an Exception Fires

1. The return address is saved in the new mode's `LR` (r14_mode).
2. The CPSR is copied into the new mode's `SPSR`.
3. The CPSR mode bits are changed to the exception's mode.
4. IRQ is disabled (I bit set). FIQ is also disabled for FIQ and Reset.
5. The processor switches to ARM state (T bit cleared).
6. PC is set to the exception vector address.

### Exception Priority

From highest to lowest:

1. Reset
2. Data Abort
3. FIQ
4. IRQ
5. Prefetch Abort
6. SWI / Undefined Instruction

### IRQ on the GBA

The GBA uses IRQ mode for all hardware interrupts (VBlank, HBlank, timer, DMA, keypad, serial, etc.). A typical IRQ flow:

1. Hardware triggers IRQ.
2. CPU saves state and jumps to BIOS IRQ handler.
3. BIOS handler reads the address at `0x03007FFC` and calls the user's handler.
4. User handler checks `REG_IF` (`0x04000202`) to determine which interrupt fired.
5. Handler services the interrupt, acknowledges it by writing to `REG_IF` and `REG_IFBIOS` (`0x03007FF8`).
6. Returns to BIOS, which restores state and returns to the main program.

## 22. Memory Alignment and Endianness

### Alignment

The ARM7TDMI requires proper data alignment:

| Data type | Must be aligned to |
|-----------|-------------------|
| Word (32-bit) | 4-byte boundary (address ends in `0`, `4`, `8`, or `C`) |
| Halfword (16-bit) | 2-byte boundary (address is even) |
| Byte (8-bit) | Any address |

**Misaligned access** does not fault on the ARM7TDMI — instead, it produces unpredictable, rotated results. A misaligned `LDR` at address `0x03000001` would actually load from `0x03000000` and then rotate the loaded word right by 8 bits. This is almost never what you want.

Always use `.align` directives in your data sections, and keep your addresses naturally aligned.

### Endianness

The GBA uses **little-endian** byte order: the least significant byte is stored at the lowest address.

For the word `0xAABBCCDD` stored at address `0x1000`:

| Address | Byte |
|---------|------|
| `0x1000` | `0xDD` |
| `0x1001` | `0xCC` |
| `0x1002` | `0xBB` |
| `0x1003` | `0xAA` |

This mostly "just works" and you rarely need to think about it, unless you're doing byte-level manipulation of multi-byte values or interacting with raw binary data in a specific format.

## 23. Instruction Cycle Timings

Understanding cycle counts helps you write fast code. The ARM7TDMI has several types of memory cycle:

| Cycle type | Symbol | Description |
|------------|--------|-------------|
| Sequential | S | Accessing the next word in a sequence. Fastest. |
| Non-sequential | N | First access to a new address. Slower (requires address decode). |
| Internal | I | CPU-internal cycle, no memory access. |

Actual wall-clock time for S and N cycles depends on the memory region:

| Region | N-cycle | S-cycle |
|--------|---------|---------|
| IWRAM | 1 | 1 |
| EWRAM | 3 | 3 |
| ROM (WS0 default) | 5 | 3 |
| VRAM / Palette / OAM | 1 | 1 |

### Common Instruction Timings

| Instruction | Cycles | Notes |
|-------------|--------|-------|
| Data processing (no shift) | 1S | ADD, SUB, AND, ORR, MOV, etc. |
| Data processing (reg shift) | 1S + 1I | When the shift amount comes from a register |
| MUL | 1S + mI | m = number of 8-bit multiplier blocks (1–4) |
| LDR | 1S + 1N + 1I | Load single register |
| STR | 2N | Store single register |
| LDM (n regs) | nS + 1N + 1I | Load multiple |
| STM (n regs) | (n-1)S + 2N | Store multiple |
| B / BL (taken) | 2S + 1N | Pipeline refill |
| SWI | 2S + 1N | Exception entry |

For Thumb, the timings are similar but measured in 16-bit fetches.

### Practical Implication

A single `LDR` from ROM costs about 1+5+1 = 7 cycles (1 S-cycle for the instruction fetch, 1 N-cycle for the data fetch at 5 cycles, 1 I-cycle for the internal transfer). An `ADD` costs 1 S-cycle = 1 cycle from IWRAM. The takeaway: avoid unnecessary memory accesses. Keep values in registers as much as possible.

## 24. ARM/Thumb Interworking

Mixing ARM and Thumb code in a single program requires care at the boundaries.

**`BX` vs. other ways to load `PC`:** Only **`BX Rn`** uses **bit 0** of `Rn` to select **ARM (even address)** vs **Thumb (odd address)**. That is why Thumb entry points are often written as **`label+1`** when branching from ARM. By contrast, **`mov pc, lr`**, **`pop {pc}`**, and similar returns **keep the current instruction set** — they are the usual choice when the caller and callee are **both** Thumb or **both** ARM (as in the [Touched tutorial](https://github.com/Touched/asm-tutorial/blob/master/doc.md)). Do **not** assume that stuffing an odd address into `PC` via **`MOV`** behaves identically to **`BX`**; use **`BX`** when you intentionally switch or may switch state.

### Calling Thumb from ARM

```arm
    .arm
    ldr r0, =thumb_func + 1    @ +1 sets bit 0 to enter Thumb state
    bx r0                      @ Switch to Thumb state and jump
```

### Calling ARM from Thumb

```arm
    .thumb
    ldr r0, =arm_func          @ Address is even — bit 0 is 0 for ARM state
    bx r0                      @ Switch to ARM state and jump
```

### Using BL Across States

Within the same state, `BL` works normally. To call across states, use a veneer (trampoline):

```arm
    .thumb
    bl my_veneer               @ BL to a nearby Thumb veneer

    @ ...

    .align 2
my_veneer:
    ldr r3, =arm_target
    bx r3                     @ Switch to ARM and jump
```

The linker can generate these veneers automatically with the `-mthumb-interwork` flag.

### The -mthumb-interwork Flag

When compiling with GCC, use `-mthumb-interwork` to tell the compiler that ARM and Thumb code may call each other. The compiler then emits returns that are **safe across ARM/Thumb boundaries** (often **`BX lr`**), instead of only **`mov pc, lr`**, when a function might be called from the other state.

## 25. Performance Considerations

### Use Thumb in ROM, ARM in IWRAM

The GBA's ROM bus is 16 bits wide. Thumb instructions are 16 bits each and fetch in a single access. ARM instructions are 32 bits and need two accesses from ROM. Thumb code in ROM is roughly 1.6x the performance of ARM code in ROM.

IWRAM has a 32-bit bus. ARM code here runs at full speed. Copy performance-critical routines to IWRAM and run them in ARM state.

### Minimize Memory Access

Register operations are effectively free (1 cycle). Memory loads from ROM can cost 5+ cycles. Keep frequently used values in registers.

### Use Block Transfers

`LDM`/`STM` are significantly faster than individual `LDR`/`STR` for moving blocks of data. Each additional register in the list costs only one S-cycle instead of a full N+S+I cycle per `LDR`.

### Avoid Branches Where Possible (ARM State)

Use conditional execution to replace short `if/else` chains:

```arm
@ Instead of:
cmp r0, #0
beq is_zero
mov r1, #1
b done
is_zero:
mov r1, #0
done:

@ Use:
cmp r0, #0
movne r1, #1
moveq r1, #0
```

The branch version flushes the pipeline; the conditional version does not.

### Alignment Matters

Always align data and code. Unaligned accesses produce garbage results. Use `.align 2` before word data, `.align 1` before halfword data.

### Avoid EWRAM for Frequent Accesses

EWRAM (at `0x02000000`) has a 16-bit bus and 2 wait states, making it slower than IWRAM for anything accessed frequently. Use EWRAM for large data buffers, not for tight loops or frequently read variables.

### Literal Pool Placement

Place `.ltorg` after unconditional branches or at the end of functions. If the literal pool is too far from the `LDR` that references it (more than 4 KB away), the assembler will error.

---

# Glossary

**ALU (Arithmetic Logic Unit):** The part of the CPU that performs arithmetic (add, subtract) and logic (AND, OR, XOR) operations.

**ARM State:** The processor mode where 32-bit ARM instructions are executed.

**Banked Register:** A physical register that is swapped in to replace a normal register when the CPU enters a privileged mode. Each exception mode has its own banked SP, LR, and (for FIQ) r8–r12.

**Barrel Shifter:** Hardware in the ARM7TDMI that can shift or rotate one operand of a data processing instruction at no extra cycle cost (ARM state only).

**BIOS (Basic Input/Output System):** A 16 KB ROM built into the GBA containing utility routines (math functions, memory copy, decompression, etc.) callable via SWI.

**Branch:** An instruction that changes the program counter (PC) to a different address, altering the flow of execution. Equivalent to a "jump" or "goto."

**Byte:** 8 bits of data. Ranges from 0x00 to 0xFF (0–255 unsigned, -128–127 signed).

**Carry Flag (C):** A CPSR flag set when an addition overflows unsigned, when a subtraction does *not* borrow, or when a shift operation shifts out a 1 bit.

**Condition Code:** A 2–4 letter suffix (EQ, NE, GT, etc.) appended to an instruction to make it execute only when the CPSR flags match a condition.

**CPSR (Current Program Status Register):** A special register containing the condition flags (N, Z, C, V), interrupt disable bits (I, F), the Thumb state bit (T), and the processor mode bits (M).

**EWRAM (External Work RAM):** 256 KB of RAM at `0x02000000` with a 16-bit bus. Slower than IWRAM.

**Exception:** An event (interrupt, undefined instruction, SWI, abort, reset) that halts normal execution and forces the CPU to jump to a handler at a fixed vector address.

**FIQ (Fast Interrupt Request):** A high-priority interrupt mode with many banked registers. Not used by the GBA's standard hardware, but available for custom use.

**Flag:** A single bit in the CPSR that records the outcome of an operation (e.g., zero, carry, negative, overflow).

**Halfword:** 16 bits of data. Must be aligned to a 2-byte boundary. Ranges from 0x0000 to 0xFFFF.

**Hi Register:** Registers r8–r15. In Thumb state, only limited instructions can access these.

**I/O Registers:** Memory-mapped hardware control registers in the range `0x04000000`–`0x040003FE`. Writing to these addresses configures the GBA's display, sound, DMA, timers, and other hardware.

**Immediate Value:** A constant encoded directly within an instruction, as opposed to a value loaded from a register or memory.

**IRQ (Interrupt Request):** The standard interrupt mechanism on the GBA. All hardware interrupts (VBlank, timer, DMA, etc.) generate IRQs.

**IWRAM (Internal Work RAM):** 32 KB of fast RAM at `0x03000000` with a 32-bit bus and no wait states. Ideal for ARM code and frequently accessed data.

**Label:** A named location in assembly source code, marked by a name followed by a colon (e.g., `loop:`). Represents the address of the following instruction or data.

**Link Register (LR / r14):** A register that stores the return address when `BL` (Branch with Link) is executed. Subroutines return by branching back to LR.

**Literal Pool:** A region of memory (typically in ROM, near the code that references it) where the assembler stores constants that are too large to encode as immediates. Accessed via PC-relative `LDR` instructions.

**Little-Endian:** A byte ordering where the least significant byte is stored at the lowest memory address. The GBA uses little-endian.

**Lo Register:** Registers r0–r7. Accessible by all Thumb instructions.

**Mnemonic:** The human-readable name for an instruction (e.g., `MOV`, `ADD`, `LDR`).

**N-Cycle (Non-sequential):** A memory access to a new (non-consecutive) address. Slower than an S-cycle because the memory system must decode a new address.

**OAM (Object Attribute Memory):** 1 KB of memory at `0x07000000` holding sprite (object) attributes.

**Opcode:** The binary encoding of an instruction as it exists in memory. In ARM state, opcodes are 32-bit words; in Thumb state, 16-bit halfwords.

**Operand:** A value that an instruction operates on. Can be a register, an immediate, or a memory address.

**Palette RAM:** 1 KB at `0x05000000` storing color palettes (256 BG colors + 256 OBJ colors).

**PC (Program Counter / r15):** The register that holds the address of the instruction currently being fetched. Due to the 3-stage pipeline, it is 8 bytes (ARM) or 4 bytes (Thumb) ahead of the executing instruction.

**Pipeline:** The mechanism by which the CPU overlaps instruction fetch, decode, and execute stages, allowing higher throughput. The ARM7TDMI has a 3-stage pipeline.

**Post-Indexed Addressing:** An addressing mode where the base register is used as-is for the memory access, then the offset is added to the base register afterward.

**Pre-Indexed Addressing:** An addressing mode where the offset is added to the base register to compute the memory address. With write-back (`!`), the computed address is also written back to the base register.

**Pseudo-Instruction:** An assembly instruction that does not directly correspond to a single machine instruction. The assembler translates it into one or more real instructions. Example: `ldr r0, =0x12345678` is translated into a PC-relative load from the literal pool.

**Register:** A small, fast storage location inside the CPU. The ARM7TDMI has 16 visible general-purpose registers (r0–r15) plus the CPSR and banked registers.

**RISC (Reduced Instruction Set Computer):** A CPU design philosophy using simple, uniform instructions that execute in fewer cycles, rather than complex variable-length instructions.

**ROM (Read-Only Memory):** The game cartridge's memory, starting at `0x08000000`. Cannot be written to. Has a 16-bit bus with wait states.

**S-Cycle (Sequential):** A memory access to the next consecutive address. Faster than an N-cycle because the memory system can prefetch.

**Sign Extension:** Widening a signed value to a larger size while preserving its sign. The sign bit is copied into all the new upper bits (e.g., the byte `0xFE` sign-extends to `0xFFFFFFFE`).

**SP (Stack Pointer / r13):** By convention, holds the address of the top of the stack. Each processor mode has its own banked SP.

**SPSR (Saved Program Status Register):** A copy of the CPSR saved when entering an exception mode. Restored to the CPSR when the exception handler returns.

**Stack:** A Last-In-First-Out (LIFO) memory structure used to save registers, return addresses, and local variables. Grows downward on the GBA (from higher addresses to lower).

**SWI (Software Interrupt):** An instruction that triggers a Supervisor mode exception, used to call BIOS routines on the GBA.

**Thumb State:** The processor mode where 16-bit Thumb instructions are executed. Offers better code density and faster ROM execution than ARM state.

**VRAM (Video RAM):** 96 KB of memory at `0x06000000` used for tile data, tile maps, and bitmap graphics. Does not support 8-bit writes.

**Wait State:** Extra clock cycles inserted during a memory access to accommodate slow memory. ROM accesses on the GBA have configurable wait states.

**Word:** 32 bits of data. Must be aligned to a 4-byte boundary. Ranges from 0x00000000 to 0xFFFFFFFF.

**Write-Back:** An addressing mode feature where the computed address is written back to the base register after (or before) the memory access. Indicated by `!` in pre-indexed syntax, or implicit in post-indexed syntax.

**APCS / AAPCS:** ARM Procedure Call Standard — the ABI (older **APCS**, current **AAPCS**) that defines which registers hold arguments (`r0`–`r3`), return values (`r0`), and which registers a callee must preserve (`r4`–`r11`, `sp`).

**Calling convention:** The rules for how subroutines receive parameters, return results, and save/restore registers so separately compiled code can link together.

**Impure function:** A routine that has **side effects** (writes RAM, hardware registers, or global state), not just a return value.

**Interworking:** Calling between **ARM** and **Thumb** code with correct **instruction set** changes at boundaries (typically via **`BX`** and **bit 0** of the target address).

**Memory region (address prefix):** Informally, the **high byte(s)** of a 32-bit address used to recognize which memory chip or mirror is accessed (e.g. `0x08` → Game Pak ROM window).

**Pure function:** A routine whose result depends only on its inputs and which does not modify external state.

**Stack overflow:** Using more stack than is available — often from **unbounded recursion** — corrupting memory beyond the stack region.

**Zero Extension:** Widening an unsigned value to a larger size by filling the new upper bits with zeroes (e.g., the byte `0xFE` zero-extends to `0x000000FE`).
