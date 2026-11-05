// Copyright (C) 2026 Dantiox and sn0wd0wn (gregel, Dantiox, Alexes)
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef HOOK_ENGINE_H
#define HOOK_ENGINE_H

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

static inline int HookFunction(void* target, void* detour, void** original_trampoline, size_t len)
{
    if (len < 5) return 0;

    DWORD old_protect;
    if (!VirtualProtect(target, len, PAGE_EXECUTE_READWRITE, &old_protect))
        return 0;

    // Allocate trampoline: len bytes of original code + 5 bytes for JMP back
    uint8_t* trampoline = (uint8_t*)VirtualAlloc(NULL, len + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline) {
        VirtualProtect(target, len, old_protect, &old_protect);
        return 0;
    }

    // 1. Copy original stolen bytes to trampoline
    memcpy(trampoline, target, len);

    // 2. Trampoline JMP back to (target + len)
    trampoline[len] = 0xE9;
    int32_t jmp_back_rel = (int32_t)((uintptr_t)target + len) - (int32_t)((uintptr_t)trampoline + len + 5);
    memcpy(&trampoline[len + 1], &jmp_back_rel, sizeof(int32_t));

    // 3. Overwrite target with JMP to detour
    uint8_t* target_bytes = (uint8_t*)target;
    target_bytes[0] = 0xE9;
    int32_t jmp_detour_rel = (int32_t)((uintptr_t)detour) - (int32_t)((uintptr_t)target + 5);
    memcpy(&target_bytes[1], &jmp_detour_rel, sizeof(int32_t));

    // NOP remaining bytes if len > 5
    for (size_t i = 5; i < len; i++) {
        target_bytes[i] = 0x90;
    }

    VirtualProtect(target, len, old_protect, &old_protect);
    FlushInstructionCache(GetCurrentProcess(), target, len);
    FlushInstructionCache(GetCurrentProcess(), trampoline, len + 5);

    if (original_trampoline) {
        *original_trampoline = trampoline;
    }

    return 1;
}

#endif // HOOK_ENGINE_H
