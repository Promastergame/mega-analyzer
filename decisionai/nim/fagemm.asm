; DecisionAI v1.15 — hand-written AVX (no FMA, no AVX2: runs on Sandy/Ivy Bridge and newer) GEMM kernel, flat assembler.
;   void fa_gemm(const float* x, int n, int in, const float* wp, const float* b, int out, float* y)
;   y[n×out] = x[n×in] · Wᵀ + b, W packed in panels of 8 outputs: wp[(p·in + i)·8 + j] = W[p·8 + j][i]; out % 8 == 0.
; 4 tokens × 8 outputs per register block (4 accumulators, one weight load feeds 4 multiplies).
; Build:  fasm fagemm.asm fagemm.o            (Linux/macOS ELF64, System V ABI)
;         fasm fagemm.asm fagemm.obj -d WIN64=1  (Windows COFF, Microsoft x64 ABI)
; Only ymm0–ymm5 are used, so no xmm6–15 spills are needed for the Windows ABI.
if defined WIN64
  format MS64 COFF
  section '.text' code readable executable
else
  format ELF64
  section '.text' executable
end if
public fa_gemm

fa_gemm:
if defined WIN64
        push    rdi
        push    rsi
        mov     rdi, rcx                ; x
        mov     esi, edx                ; n
        mov     edx, r8d                ; in
        mov     rcx, r9                 ; wp
        mov     r8,  [rsp+16+40]        ; b
        mov     r9d, [rsp+16+48]        ; out
        mov     r10, [rsp+16+56]        ; y
else
        mov     r10, [rsp+8]            ; y (7th argument on the stack)
end if
        push    rbx
        push    rbp
        push    r12
        push    r13
        push    r14
        push    r15
        movsxd  rsi, esi                ; n
        movsxd  rdx, edx                ; in
        movsxd  r9,  r9d                ; out
        lea     rbp, [rdx*4]            ; x row stride (bytes)
        lea     r15, [r9*4]             ; y row stride (bytes)
        lea     r9,  [rbp+rbp*2]        ; 3 · x row stride
        xor     r11, r11                ; t = 0
.tok4:
        lea     rax, [r11+4]
        cmp     rax, rsi
        jg      .tok1
        mov     rax, r11
        imul    rax, rbp
        lea     r12, [rdi+rax]          ; x row t
        mov     rax, r11
        imul    rax, r15
        lea     r13, [r10+rax]          ; y row t
        mov     r14, rcx                ; packed weights, panel 0
        xor     rbx, rbx                ; output byte offset
.ob4:
        cmp     rbx, r15
        jge     .ob4done
        vxorps  ymm0, ymm0, ymm0
        vxorps  ymm1, ymm1, ymm1
        vxorps  ymm2, ymm2, ymm2
        vxorps  ymm3, ymm3, ymm3
        mov     rdx, r12
        lea     rax, [r12+rbp]          ; end of x row
.in4:
        vmovups ymm4, [r14]
        add     r14, 32
        vbroadcastss ymm5, [rdx]
        vmulps  ymm5, ymm5, ymm4
        vaddps  ymm0, ymm0, ymm5
        vbroadcastss ymm5, [rdx+rbp]
        vmulps  ymm5, ymm5, ymm4
        vaddps  ymm1, ymm1, ymm5
        vbroadcastss ymm5, [rdx+rbp*2]
        vmulps  ymm5, ymm5, ymm4
        vaddps  ymm2, ymm2, ymm5
        vbroadcastss ymm5, [rdx+r9]
        vmulps  ymm5, ymm5, ymm4
        vaddps  ymm3, ymm3, ymm5
        add     rdx, 4
        cmp     rdx, rax
        jb      .in4
        vmovups ymm4, [r8+rbx]          ; bias
        lea     rdx, [r13+rbx]
        vaddps  ymm0, ymm0, ymm4
        vmovups [rdx], ymm0
        add     rdx, r15
        vaddps  ymm1, ymm1, ymm4
        vmovups [rdx], ymm1
        add     rdx, r15
        vaddps  ymm2, ymm2, ymm4
        vmovups [rdx], ymm2
        add     rdx, r15
        vaddps  ymm3, ymm3, ymm4
        vmovups [rdx], ymm3
        add     rbx, 32
        jmp     .ob4
.ob4done:
        add     r11, 4
        jmp     .tok4
.tok1:                                  ; remaining 0–3 tokens, one at a time (2 chains to hide add latency)
        cmp     r11, rsi
        jge     .done
        mov     rax, r11
        imul    rax, rbp
        lea     r12, [rdi+rax]
        mov     rax, r11
        imul    rax, r15
        lea     r13, [r10+rax]
        mov     r14, rcx
        xor     rbx, rbx
.ob1:
        cmp     rbx, r15
        jge     .ob1done
        vxorps  ymm0, ymm0, ymm0
        vxorps  ymm1, ymm1, ymm1
        mov     rdx, r12
        lea     rax, [r12+rbp]
        test    rbp, 4                  ; odd length: one step first
        jz      .in1
        vmovups ymm4, [r14]
        add     r14, 32
        vbroadcastss ymm5, [rdx]
        vmulps  ymm5, ymm5, ymm4
        vaddps  ymm0, ymm0, ymm5
        add     rdx, 4
        cmp     rdx, rax
        jae     .in1done
.in1:
        vmovups ymm4, [r14]
        vbroadcastss ymm5, [rdx]
        vmulps  ymm5, ymm5, ymm4
        vaddps  ymm0, ymm0, ymm5
        vmovups ymm4, [r14+32]
        vbroadcastss ymm5, [rdx+4]
        vmulps  ymm5, ymm5, ymm4
        vaddps  ymm1, ymm1, ymm5
        add     r14, 64
        add     rdx, 8
        cmp     rdx, rax
        jb      .in1
.in1done:
        vaddps  ymm0, ymm0, ymm1
        vmovups ymm4, [r8+rbx]
        vaddps  ymm0, ymm0, ymm4
        vmovups [r13+rbx], ymm0
        add     rbx, 32
        jmp     .ob1
.ob1done:
        inc     r11
        jmp     .tok1
.done:
        vzeroupper
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbp
        pop     rbx
if defined WIN64
        pop     rsi
        pop     rdi
end if
        ret
