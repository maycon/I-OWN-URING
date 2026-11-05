; ================================================================
; layer1_runtime.asm — Layer 1: SQE/CQE engine
; ================================================================
; Provides two procedures:
;
;   _get_sqe  → rax = zeroed SQE slot pointer, r15d = slot index
;   _io_enter → calls io_uring_enter(fd, 1, 1, GETEVENTS, 0)
;   _wait_cqe → spins until CQE available, returns ecx = res
;
; Registers assumed set by Layer 0 (bootstrap):
;   r13 = stack frame base pointer
;
; Stack frame offsets (defined in shellcode.asm):
;   F_SQ_TP  = 104   absolute pointer to sq ring tail word
;   F_CQ_HP  = 112   absolute pointer to cq ring head word
;   F_CQ_TP  = 120   absolute pointer to cq ring tail word
;   F_SQESB  = 128   sqes base (absolute)
;   F_SQARR  = 136   sq_array base (absolute)
;   F_CQESB  = 144   cqes base (absolute)
;   F_SQMSK  = 152   sq ring mask value (u32)
;   F_CQMSK  = 156   cq ring mask value (u32)
;   F_URFD   = 160   io_uring fd (s32)
; ================================================================

; ----------------------------------------------------------------
; _get_sqe: allocate next SQE slot
; Returns:
;   rax  = absolute pointer to zeroed 64-byte SQE
;   r15d = slot index (needed for sq_array update)
; Clobbers: rcx, rdi, rdx
; ----------------------------------------------------------------
_get_sqe:
    ; index = *sq_tail & sq_mask
    mov rdx, [r13 + F_SQ_TP]      ; rdx = address of sq ring tail word
    mov r15d, [rdx]                ; r15d = current tail value
    and r15d, [r13 + F_SQMSK]     ; r15d = index = tail & mask

    ; sqe_ptr = sqes_base + index * 64
    mov rax, [r13 + F_SQESB]      ; rax = sqes base
    movzx rdx, r15d
    shl rdx, 6                     ; rdx = index * 64 (sizeof SQE)
    add rax, rdx                   ; rax = &sqes[index]

    ; zero 64 bytes (8 qwords) at sqe_ptr
    push rax                       ; save SQE pointer
    mov rdi, rax
    xor eax, eax
    push 8
    pop rcx                        ; rcx = 8
    rep stosq                      ; zero 64 bytes
    pop rax                        ; restore SQE pointer

    ; update sq_array[index] = index
    mov rdx, [r13 + F_SQARR]      ; rdx = sq_array base
    mov [rdx + r15*4], r15d       ; sq_array[index] = index

    ; advance sq_tail
    mov rdx, [r13 + F_SQ_TP]      ; rdx = address of sq ring tail
    incl dword [rdx]               ; (*sq_tail)++

    ret

; ----------------------------------------------------------------
; _io_enter: submit 1 SQE and wait for 1 completion
; Uses: [r13 + F_URFD]
; Clobbers: rax, rdi, rsi, rdx, r10, r8, r9
; ----------------------------------------------------------------
_io_enter:
    xor eax, eax
    mov ax, 0x1AA              ; SYS_io_uring_enter = 426
    mov edi, [r13 + F_URFD]   ; fd
    push 1
    pop rsi                    ; to_submit = 1
    push 1
    pop rdx                    ; min_complete = 1
    push 1
    pop r10                    ; flags = IORING_ENTER_GETEVENTS
    xor r8, r8                 ; sig = NULL
    xor r9, r9                 ; sigsz = 0
    syscall
    ret

; ----------------------------------------------------------------
; _wait_cqe: spin until a CQE is available, consume it
; Returns:
;   ecx = CQE.res (bytes count, or negative errno)
;   rax = CQE.user_data
; Clobbers: rdx, r8
; ----------------------------------------------------------------
_wait_cqe:
.spin:
    ; load cq_head and cq_tail, compare
    mov rdx, [r13 + F_CQ_HP]
    mov r8d, [rdx]             ; r8d = cq_head
    mov rdx, [r13 + F_CQ_TP]
    cmp r8d, [rdx]             ; head == tail → queue empty
    je .spin                   ; spin until a CQE appears

    ; index = cq_head & cq_mask
    and r8d, [r13 + F_CQMSK]

    ; cqe_ptr = cqes_base + index * 16
    mov rax, [r13 + F_CQESB]
    movzx rdx, r8d
    shl rdx, 4                 ; * 16 (sizeof CQE)
    add rax, rdx               ; rax = &cqes[index]

    ; read user_data and result
    mov r8, [rax + 0]          ; user_data (qword)
    mov ecx, [rax + 8]         ; res (dword)

    ; advance cq_head
    mov rdx, [r13 + F_CQ_HP]
    incl dword [rdx]           ; (*cq_head)++

    mov rax, r8                ; return user_data in rax
    ret
