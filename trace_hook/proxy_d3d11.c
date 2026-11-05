// Copyright (C) 2026 Dantiox and sn0wd0wn (gregel, Dantiox, Alexes)
// SPDX-License-Identifier: AGPL-3.0-only

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "hook_engine.h"

// --- Global Log File & Mutex ---
static CRITICAL_SECTION g_LogLock;
static FILE* g_LogFile = NULL;

static void LogTrace(const char* fmt, ...)
{
    EnterCriticalSection(&g_LogLock);

    char buffer[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    // 1. OutputDebugStringA -> visible in Proton logs (PROTON_LOG=1) and debuggers
    OutputDebugStringA(buffer);

    // 2. stdout/stderr -> visible in Linux terminal when running Proton/Wine
    fprintf(stderr, "%s", buffer);

    // 3. Persistent log file in game directory
    if (g_LogFile) {
        fprintf(g_LogFile, "%s", buffer);
        fflush(g_LogFile);
    }

    LeaveCriticalSection(&g_LogLock);
}

static void HexDump(const void* data, size_t size, const char* label)
{
    if (!data || IsBadReadPtr(data, size)) {
        LogTrace("--- HEX DUMP [%s] (Unreadable pointer %p, %zu bytes) ---\n", label, data, size);
        return;
    }
    const uint8_t* p = (const uint8_t*)data;
    LogTrace("--- HEX DUMP [%s] (%zu bytes) ---\n", label, size);
    for (size_t i = 0; i < size; i += 16) {
        char line[128];
        int off = snprintf(line, sizeof(line), "  %04zx: ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size)
                off += snprintf(line + off, sizeof(line) - off, "%02x ", p[i + j]);
            else
                off += snprintf(line + off, sizeof(line) - off, "   ");
        }
        off += snprintf(line + off, sizeof(line) - off, " | ");
        for (size_t j = 0; j < 16 && (i + j) < size; j++) {
            uint8_t c = p[i + j];
            line[off++] = (c >= 32 && c <= 126) ? (char)c : '.';
        }
        line[off++] = '\n';
        line[off] = '\0';
        LogTrace("%s", line);
    }
    LogTrace("----------------------------------\n");
}

// ===========================================================================
// D3D11 Proxy Exports
// ===========================================================================
typedef HRESULT (WINAPI *PFN_D3D11CreateDevice)(
    void* pAdapter, int DriverType, HMODULE Software, UINT Flags,
    const void* pFeatureLevels, UINT FeatureLevels, UINT SDKVersion,
    void** ppDevice, void* pFeatureLevel, void** ppImmediateContext);

typedef HRESULT (WINAPI *PFN_D3D11CreateDeviceAndSwapChain)(
    void* pAdapter, int DriverType, HMODULE Software, UINT Flags,
    const void* pFeatureLevels, UINT FeatureLevels, UINT SDKVersion,
    const void* pSwapChainDesc, void** ppSwapChain, void** ppDevice,
    void* pFeatureLevel, void** ppImmediateContext);

static HMODULE g_RealD3D11 = NULL;
static PFN_D3D11CreateDevice g_RealCreateDevice = NULL;
static PFN_D3D11CreateDeviceAndSwapChain g_RealCreateDeviceAndSwapChain = NULL;

static void LoadRealD3D11(void)
{
    if (g_RealD3D11) return;

    char sysDir[MAX_PATH];
    GetSystemDirectoryA(sysDir, MAX_PATH);

    char realPath[MAX_PATH];
    snprintf(realPath, sizeof(realPath), "%s\\d3d11.dll", sysDir);

    g_RealD3D11 = LoadLibraryA(realPath);
    if (!g_RealD3D11) {
        LogTrace("[MW_PROXY] ERROR: Failed to load real system d3d11.dll from %s\n", realPath);
        return;
    }

    g_RealCreateDevice = (PFN_D3D11CreateDevice)GetProcAddress(g_RealD3D11, "D3D11CreateDevice");
    g_RealCreateDeviceAndSwapChain = (PFN_D3D11CreateDeviceAndSwapChain)GetProcAddress(g_RealD3D11, "D3D11CreateDeviceAndSwapChain");
    LogTrace("[MW_PROXY] Successfully hooked d3d11 forwarders to %s\n", realPath);
}

HRESULT WINAPI proxy_D3D11CreateDevice(
    void* pAdapter, int DriverType, HMODULE Software, UINT Flags,
    const void* pFeatureLevels, UINT FeatureLevels, UINT SDKVersion,
    void** ppDevice, void* pFeatureLevel, void** ppImmediateContext)
{
    LoadRealD3D11();
    if (!g_RealCreateDevice) return E_FAIL;
    return g_RealCreateDevice(pAdapter, DriverType, Software, Flags,
                              pFeatureLevels, FeatureLevels, SDKVersion,
                              ppDevice, pFeatureLevel, ppImmediateContext);
}

// ===========================================================================
// DXGI SwapChain Present Hook & 60 FPS Frame Limiter
// ===========================================================================
typedef HRESULT (WINAPI *PFN_Present)(void* this_ptr, UINT SyncInterval, UINT Flags);
static PFN_Present g_Original_Present = NULL;

static HRESULT WINAPI Hook_Present(void* this_ptr, UINT SyncInterval, UINT Flags)
{
    static LARGE_INTEGER freq;
    static LARGE_INTEGER last_time;
    static BOOL timer_initialized = FALSE;

    if (!timer_initialized) {
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&last_time);
        timer_initialized = TRUE;
    }

    // Precision frame limiter: target 16.66 ms (60 FPS)
    if (freq.QuadPart > 0) {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        double elapsed_ms = (double)(now.QuadPart - last_time.QuadPart) * 1000.0 / (double)freq.QuadPart;
        if (elapsed_ms < 16.0) {
            DWORD sleep_ms = (DWORD)(16.0 - elapsed_ms);
            if (sleep_ms > 0) {
                Sleep(sleep_ms);
            }
        }
        QueryPerformanceCounter(&last_time);
    }

    // Enforce VSync (SyncInterval = 1) if game passes 0 (uncapped)
    UINT effective_sync = (SyncInterval == 0) ? 1 : SyncInterval;
    return g_Original_Present(this_ptr, effective_sync, Flags);
}

static void HookSwapChain(void* pSwapChain)
{
    if (!pSwapChain || IsBadReadPtr(pSwapChain, sizeof(void*))) return;

    void*** pVtbl = (void***)pSwapChain;
    void** vtbl = *pVtbl;
    if (!vtbl || IsBadReadPtr(vtbl, 9 * sizeof(void*))) return;

    if (vtbl[8] == (void*)Hook_Present) return;

    DWORD oldProtect;
    if (VirtualProtect(&vtbl[8], sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        g_Original_Present = (PFN_Present)vtbl[8];
        vtbl[8] = (void*)Hook_Present;
        VirtualProtect(&vtbl[8], sizeof(void*), oldProtect, &oldProtect);
        LogTrace("[MW_PROXY] Hooked IDXGISwapChain::Present! Hardware 60 FPS limiter & VSync active.\n");
    }
}

HRESULT WINAPI proxy_D3D11CreateDeviceAndSwapChain(
    void* pAdapter, int DriverType, HMODULE Software, UINT Flags,
    const void* pFeatureLevels, UINT FeatureLevels, UINT SDKVersion,
    const void* pSwapChainDesc, void** ppSwapChain, void** ppDevice,
    void* pFeatureLevel, void** ppImmediateContext)
{
    LoadRealD3D11();
    if (!g_RealCreateDeviceAndSwapChain) return E_FAIL;
    HRESULT hr = g_RealCreateDeviceAndSwapChain(pAdapter, DriverType, Software, Flags,
                                                pFeatureLevels, FeatureLevels, SDKVersion,
                                                pSwapChainDesc, ppSwapChain, ppDevice,
                                                pFeatureLevel, ppImmediateContext);
    if (SUCCEEDED(hr) && ppSwapChain && *ppSwapChain) {
        HookSwapChain(*ppSwapChain);
    }
    return hr;
}

// ===========================================================================
// Target Function Hooks
// ===========================================================================

// --- 1. NotifyGameSetup (VA: 0x00BBF3C0, 7 bytes) ---
typedef void (__thiscall *PFN_NotifyGameSetup)(void* this_ptr, void* pGameSetup);
static PFN_NotifyGameSetup g_Original_NotifyGameSetup = NULL;

void __thiscall Detour_NotifyGameSetup(void* this_ptr, void* pGameSetup)
{
    LogTrace("\n=======================================================\n");
    LogTrace("[NOTIFY_GAME_SETUP] >>> TRIGGERED at 0x00BBF3C0!\n");
    LogTrace("  this: 0x%p, pGameSetup: 0x%p\n", this_ptr, pGameSetup);

    if (pGameSetup && !IsBadReadPtr(pGameSetup, 0x110)) {
        uint32_t game_id       = *(uint32_t*)((char*)pGameSetup + 0x18);
        uint32_t state         = *(uint32_t*)((char*)pGameSetup + 0x1c);
        uint32_t topology_host = *(uint32_t*)((char*)pGameSetup + 0x10c);
        uint32_t mesh_ip       = *(uint32_t*)((char*)pGameSetup + 0x98);
        uint16_t mesh_port     = *(uint16_t*)((char*)pGameSetup + 0x9c);

        LogTrace("  Decoded Fields:\n");
        LogTrace("    GameID (GID)       : %u (0x%08X)\n", game_id, game_id);
        LogTrace("    GameState          : %u\n", state);
        LogTrace("    TopologyHost (THST): %u (0x%08X) %s\n",
                 topology_host, topology_host,
                 topology_host == 0 ? "[!] WARNING: THST IS NULL/ZERO!" : "[+] THST PRESENT!");
        LogTrace("    Mesh Endpoint      : %u.%u.%u.%u:%u\n",
                 (mesh_ip >> 24) & 0xFF, (mesh_ip >> 16) & 0xFF,
                 (mesh_ip >> 8) & 0xFF, mesh_ip & 0xFF, mesh_port);

        HexDump(pGameSetup, 256, "pGameSetup Data Dump");
    } else {
        LogTrace("  [!] pGameSetup is NULL or unreadable!\n");
    }
    LogTrace("=======================================================\n");

    // Call original function
    g_Original_NotifyGameSetup(this_ptr, pGameSetup);

    LogTrace("[NOTIFY_GAME_SETUP] <<< Returned cleanly.\n");
}

// --- 2. StartNetworkMesh (VA: 0x00BC8630, 7 bytes) ---
typedef int (__thiscall *PFN_StartNetworkMesh)(void* this_ptr, void* pConfig);
static PFN_StartNetworkMesh g_Original_StartNetworkMesh = NULL;

int __thiscall Detour_StartNetworkMesh(void* this_ptr, void* pConfig)
{
    LogTrace("\n=======================================================\n");
    LogTrace("[START_NETWORK_MESH] >>> TRIGGERED at 0x00BC8630!\n");
    LogTrace("  this: 0x%p, pConfig: 0x%p\n", this_ptr, pConfig);

    if (pConfig && !IsBadReadPtr(pConfig, 0x220)) {
        void* sub = *(void**)((char*)pConfig + 0x218);
        LogTrace("  Config Sub-Object: 0x%p\n", sub);
        if (sub && !IsBadReadPtr(sub, 0x20)) {
            uint32_t host_ip   = *(uint32_t*)((char*)sub + 0x18);
            uint32_t host_port = *(uint32_t*)((char*)sub + 0x1c);
            LogTrace("  Connecting to P2P Host: %u.%u.%u.%u:%u\n",
                     (host_ip >> 24) & 0xFF, (host_ip >> 16) & 0xFF,
                     (host_ip >> 8) & 0xFF, host_ip & 0xFF, host_port);
        }
        HexDump(pConfig, 128, "pConfig Mesh Setup Dump");
    } else {
        LogTrace("  [!] pConfig is NULL or unreadable!\n");
    }
    LogTrace("=======================================================\n");

    int result = g_Original_StartNetworkMesh(this_ptr, pConfig);

    LogTrace("[START_NETWORK_MESH] <<< Returned status: %d (0x%08X)\n", result, result);
    return result;
}

// --- 3. IsConnectedOrReady (VA: 0x00A82E60, 9 bytes) ---
typedef bool (__thiscall *PFN_IsConnectedOrReady)(void* this_ptr);
static PFN_IsConnectedOrReady g_Original_IsConnectedOrReady = NULL;

bool __thiscall Detour_IsConnectedOrReady(void* this_ptr)
{
    bool ready = g_Original_IsConnectedOrReady(this_ptr);
    static int s_LastState = -1;

    // Throttle logging so we don't spam every frame when state doesn't change
    if ((int)ready != s_LastState) {
        s_LastState = (int)ready;
        LogTrace("[ONLINE_STATUS] NetManager_IsConnectedOrReady state changed -> %s\n",
                 ready ? "ONLINE / READY [OK]" : "OFFLINE / NOT READY");
    }
    return ready;
}

// --- 4. ProtoSslProcessServerCertificate (VA: 0x00B91E70, 8 bytes) ---
typedef int (__cdecl *PFN_ProtoSslProcessServerCert)(void* ssl, const uint8_t* cert);
static PFN_ProtoSslProcessServerCert g_Original_ProtoSslProcessServerCert = NULL;

int __cdecl Detour_ProtoSslProcessServerCert(void* ssl, const uint8_t* cert)
{
    uint32_t cert_len = 0;
    if (cert && !IsBadReadPtr(cert, 3)) {
        cert_len = ((uint32_t)cert[0] << 16) | ((uint32_t)cert[1] << 8) | (uint32_t)cert[2];
    }
    LogTrace("[PROTOSSL] Handshake Server Certificate received! cert_len=%u, ssl=0x%p\n", cert_len, ssl);
    int res = g_Original_ProtoSslProcessServerCert(ssl, cert);
    LogTrace("[PROTOSSL] Certificate process result: 0x%X (%s)\n",
             res, res == 0x15 ? "SUCCESS: STATE 21 ACCEPTED" : "RETURNED CODE");
    return res;
}

// ===========================================================================
// Mesh connection path (who connects to whom after NotifyGameSetup)
// ===========================================================================
// Game: +0x08 id, +0x1c, +0x20 state, +0x150 topology host id, +0x168 mesh,
//       +0x204/+0x208 active players, +0x294 host player, +0x2c4 local player,
//       +0x2cc topology, +0x2d1/+0x2d4 mesh start flags.
// Player: +0x10 id, +0x1c state, +0x58 mesh endpoint.
static uint32_t ReadU32(const void* base, size_t off)
{
    const char* p = (const char*)base + off;
    return (base && !IsBadReadPtr(p, 4)) ? *(const uint32_t*)p : 0xFFFFFFFFu;
}

static uint8_t ReadU8(const void* base, size_t off)
{
    const char* p = (const char*)base + off;
    return (base && !IsBadReadPtr(p, 1)) ? *(const uint8_t*)p : 0xFF;
}

static void LogPlayer(const char* label, const void* player)
{
    LogTrace("    %s: %p id=%u state=%u\n", label, player,
             ReadU32(player, 0x10), ReadU32(player, 0x1c));
}

static void LogGame(const void* game)
{
    const void* local = (const void*)(uintptr_t)ReadU32(game, 0x2c4);
    const void* host = (const void*)(uintptr_t)ReadU32(game, 0x294);
    uint32_t first = ReadU32(game, 0x204);
    uint32_t last = ReadU32(game, 0x208);
    LogTrace("    game=%p gid=%u +1c=%u state=0x%X topoHost=%u ntop=0x%X flags2d1=%u flags2d4=%u\n",
             game, ReadU32(game, 0x08), ReadU32(game, 0x1c), ReadU32(game, 0x20),
             ReadU32(game, 0x150), ReadU32(game, 0x2cc),
             ReadU8(game, 0x2d1), ReadU8(game, 0x2d4));
    LogPlayer("local", local);
    LogPlayer("host ", host);
    if (first != 0xFFFFFFFFu && last != 0xFFFFFFFFu && last >= first && last - first <= 0x80) {
        for (uint32_t it = first; it < last; it += 8) {
            LogPlayer("activ", (const void*)(uintptr_t)ReadU32((const void*)(uintptr_t)it, 4));
        }
    }
}

typedef void (__thiscall *PFN_BeginMesh)(void* api, void* game);
static PFN_BeginMesh g_Original_BeginMesh = NULL;

void __thiscall Detour_BeginMesh(void* api, void* game)
{
    LogTrace("[MESH] BeginMesh 0x00BBDF90 api=%p\n", api);
    LogGame(game);
    g_Original_BeginMesh(api, game);
    LogTrace("[MESH] BeginMesh returned, flags2d1=%u flags2d4=%u\n",
             ReadU8(game, 0x2d1), ReadU8(game, 0x2d4));
}

typedef void (__thiscall *PFN_MeshCreated)(void* listener, void* mesh, int error);
static PFN_MeshCreated g_Original_MeshCreated = NULL;

void __thiscall Detour_MeshCreated(void* listener, void* mesh, int error)
{
    LogTrace("[MESH] MeshCreated 0x00BC5A90 error=%d\n", error);
    if (mesh) {
        LogGame((const char*)mesh - 0x168);
    }
    g_Original_MeshCreated(listener, mesh, error);
    LogTrace("[MESH] MeshCreated returned\n");
}

typedef void (__thiscall *PFN_AfterMeshCreated)(void* api, int error, uint32_t gid_lo, uint32_t gid_hi);
static PFN_AfterMeshCreated g_Original_AfterMeshCreated = NULL;

void __thiscall Detour_AfterMeshCreated(void* api, int error, uint32_t gid_lo, uint32_t gid_hi)
{
    LogTrace("[MESH] AfterMeshCreated 0x00BBB750 error=%d gid=%u\n", error, gid_lo);
    g_Original_AfterMeshCreated(api, error, gid_lo, gid_hi);
    LogTrace("[MESH] AfterMeshCreated returned\n");
}

typedef void (__fastcall *PFN_ConnectLocal)(void* game, void* edx);
static PFN_ConnectLocal g_Original_ConnectLocal = NULL;

void __fastcall Detour_ConnectLocal(void* game, void* edx)
{
    LogTrace("[MESH] ConnectLocal 0x00BB8E80\n");
    LogGame(game);
    g_Original_ConnectLocal(game, edx);
}

static PFN_ConnectLocal g_Original_FlushDeferred = NULL;

void __fastcall Detour_FlushDeferred(void* game, void* edx)
{
    LogTrace("[MESH] FlushDeferred 0x00BB65F0 count=%u\n", ReadU32(game, 0x27c));
    g_Original_FlushDeferred(game, edx);
}

typedef void (__thiscall *PFN_ConnectPlayer)(void* game, void* player);
static PFN_ConnectPlayer g_Original_ConnectPlayer = NULL;

void __thiscall Detour_ConnectPlayer(void* game, void* player)
{
    LogTrace("[MESH] ConnectPlayer 0x00BB64D0\n");
    LogPlayer("arg  ", player);
    LogGame(game);
    g_Original_ConnectPlayer(game, player);
}

typedef void* (__thiscall *PFN_DeferPlayer)(void* map, void* result, void* entry, int flag);
static PFN_DeferPlayer g_Original_DeferPlayer = NULL;

void* __thiscall Detour_DeferPlayer(void* map, void* result, void* entry, int flag)
{
    LogTrace("[MESH] DeferPlayer 0x00BB3820 map=%p entryId=%u\n", map, ReadU32(entry, 0));
    return g_Original_DeferPlayer(map, result, entry, flag);
}

typedef void (__thiscall *PFN_AdapterInit)(void* adapter, void* mesh, void* a2, void* a3);
static PFN_AdapterInit g_Original_AdapterInit = NULL;

void __thiscall Detour_AdapterInit(void* adapter, void* mesh, void* a2, void* a3)
{
    LogTrace("[ADAPTER] InitNetworkMesh 0x00C0FA50 mesh=%p a2=%p a3=%p\n", mesh, a2, a3);
    g_Original_AdapterInit(adapter, mesh, a2, a3);
    LogTrace("[ADAPTER] InitNetworkMesh returned\n");
}

typedef void (__thiscall *PFN_AdapterConnect)(void* adapter, void* a1, void* endpoint);
static PFN_AdapterConnect g_Original_AdapterConnect = NULL;

void __thiscall Detour_AdapterConnect(void* adapter, void* a1, void* endpoint)
{
    LogTrace("[ADAPTER] Connect 0x00C0E4F0 a1=%p endpoint=%p\n", a1, endpoint);
    if (endpoint) {
        LogPlayer("peer ", (const char*)endpoint - 0x58);
    }
    g_Original_AdapterConnect(adapter, a1, endpoint);
    LogTrace("[ADAPTER] Connect returned\n");
}

typedef void (__thiscall *PFN_NetworkAddPeer)(void* network, void* endpoint);
static PFN_NetworkAddPeer g_Original_NetworkAddPeer = NULL;

void __thiscall Detour_NetworkAddPeer(void* network, void* endpoint)
{
    LogTrace("[ADAPTER] AddPeer 0x00C0E1B0 network=%p connapi=%p pending=%u\n",
             network, (void*)(uintptr_t)ReadU32(network, 0x27a0), ReadU8(network, 0x27bc));
    if (endpoint) {
        LogPlayer("peer ", (const char*)endpoint - 0x58);
    }
    g_Original_NetworkAddPeer(network, endpoint);
}

typedef int (__cdecl *PFN_ConnApiAddClient)(void* connapi, void* client, int index);
static PFN_ConnApiAddClient g_Original_ConnApiAddClient = NULL;

int __cdecl Detour_ConnApiAddClient(void* connapi, void* client, int index)
{
    LogTrace("[CONNAPI] AddClient 0x00B84430 connapi=%p client=%p index=%d\n", connapi, client, index);
    HexDump(client, 0x80, "ConnApi client");
    int result = g_Original_ConnApiAddClient(connapi, client, index);
    LogTrace("[CONNAPI] AddClient returned %d\n", result);
    return result;
}

// Refuses to patch when the prologue is not the one the stolen length was
// worked out for, so a different build cannot end up with a split instruction.
typedef uint32_t (__thiscall *PFN_ParsePlaylist)(void* manager, void* json);
static PFN_ParsePlaylist g_Original_ParsePlaylist = NULL;

uint32_t __thiscall Detour_ParsePlaylist(void* manager, void* json)
{
    uint32_t result = g_Original_ParsePlaylist(manager, json);
    LogTrace("[PLAYLIST] Parse 0x006EB0D0 result=%u active=%d\n", result & 0xff, (int)ReadU32(manager, 0x3c));
    return result;
}

typedef uint8_t (__thiscall *PFN_ValidatePlaylist)(void* playlist);
static PFN_ValidatePlaylist g_Original_ValidatePlaylist = NULL;

uint8_t __thiscall Detour_ValidatePlaylist(void* playlist)
{
    uint8_t result = g_Original_ValidatePlaylist(playlist);
    if (ReadU32(playlist, 0x140) != 0)
        LogTrace("[PLAYLIST] Validate 0x006EA460 result=%u count=%u first=%u\n", result, ReadU32(playlist, 0x140), ReadU32(playlist, 0));
    return result;
}

typedef void (__thiscall *PFN_AutologLost)(void* online);
static PFN_AutologLost g_Original_AutologLost = NULL;

void __thiscall Detour_AutologLost(void* online)
{
    LogTrace("[PLAYLIST] AutologLost 0x006E7410 caller=%p\n", __builtin_return_address(0));
    g_Original_AutologLost(online);
}

typedef int* (__thiscall *PFN_EventLookup)(void* manager, int* out, int id);
static PFN_EventLookup g_Original_EventLookup = NULL;
static int g_EventTableDumped = 0;
static int g_EventIdsSeen[256];
static int g_EventIdsSeenCount = 0;

static void DumpEventTable(void* manager)
{
    uint32_t collection = ReadU32(manager, 0x11c);
    uint32_t layout = ReadU32((void*)(uintptr_t)collection, 0x28);
    uint32_t offset = ReadU32(manager, 0x120);
    if (layout == 0 || IsBadReadPtr((void*)(uintptr_t)(layout + offset + 0x14), 2))
        return;
    uint32_t count = *(uint16_t*)(uintptr_t)(layout + offset + 0x14);
    if (count == 0 || count > 2048)
        return;
    g_EventTableDumped = 1;
    LogTrace("[PLAYLIST] EventTable manager=%p count=%u\n", manager, count);
    for (uint32_t i = 0; i < count; i++)
        LogTrace("[PLAYLIST] EventKey %u %u\n", i, ReadU32(manager, 0x134 + i * 4));
}

int* __thiscall Detour_EventLookup(void* manager, int* out, int id)
{
    int* result = g_Original_EventLookup(manager, out, id);
    if (!g_EventTableDumped)
        DumpEventTable(manager);
    if (id != 0) {
        int seen = 0;
        for (int i = 0; i < g_EventIdsSeenCount; i++)
            if (g_EventIdsSeen[i] == id)
                seen = 1;
        if (!seen && g_EventIdsSeenCount < 256) {
            g_EventIdsSeen[g_EventIdsSeenCount++] = id;
            LogTrace("[PLAYLIST] EventLookup id=%d found=%d\n", id,
                     out[0] != *(int*)0x01179528 || out[1] != *(int*)0x0117952C);
        }
    }
    return result;
}

static void InstallChecked(const char* name, uintptr_t addr, void* detour, void** original,
                           const char* expected, size_t len)
{
    if (IsBadReadPtr((void*)addr, len) || memcmp((void*)addr, expected, len) != 0) {
        LogTrace("[-] SKIPPED %s at 0x%08X: unexpected prologue\n", name, (unsigned)addr);
        return;
    }
    if (HookFunction((void*)addr, detour, original, len)) {
        LogTrace("[+] Hooked %s at 0x%08X\n", name, (unsigned)addr);
    } else {
        LogTrace("[-] FAILED to hook %s at 0x%08X\n", name, (unsigned)addr);
    }
}

static void InstallMeshHooks(void)
{
    static const char kFrame18[] = "\x55\x8b\xec\x83\xec\x18";
    static const char kFrame28[] = "\x55\x8b\xec\x83\xec\x28";
    static const char kFrame50[] = "\x55\x8b\xec\x83\xec\x50";
    static const char kFrame0c[] = "\x55\x8b\xec\x83\xec\x0c";
    static const char kFrame1c[] = "\x55\x8b\xec\x83\xec\x1c";
    static const char kFrame10[] = "\x55\x8b\xec\x83\xec\x10";

    InstallChecked("EventLookup", 0x006E5DC0, (void*)Detour_EventLookup,
                   (void**)&g_Original_EventLookup, "\x53\x55\x8b\x6c\x24\x10\x57", 7);
    InstallChecked("ParsePlaylist", 0x006EB0D0, (void*)Detour_ParsePlaylist,
                   (void**)&g_Original_ParsePlaylist, "\x81\xec\x94\x00\x00\x00", 6);
    InstallChecked("ValidatePlaylist", 0x006EA460, (void*)Detour_ValidatePlaylist,
                   (void**)&g_Original_ValidatePlaylist, "\x56\x8b\xf1\x83\xbe\x40\x01\x00\x00\x00", 10);
    InstallChecked("AutologLost", 0x006E7410, (void*)Detour_AutologLost,
                   (void**)&g_Original_AutologLost, "\xc6\x81\x9a\x2e\x00\x00\x01", 7);
    InstallChecked("BeginMesh", 0x00BBDF90, (void*)Detour_BeginMesh,
                   (void**)&g_Original_BeginMesh, kFrame18, 6);
    InstallChecked("MeshCreated", 0x00BC5A90, (void*)Detour_MeshCreated,
                   (void**)&g_Original_MeshCreated, kFrame28, 6);
    InstallChecked("AfterMeshCreated", 0x00BBB750, (void*)Detour_AfterMeshCreated,
                   (void**)&g_Original_AfterMeshCreated, kFrame50, 6);
    InstallChecked("ConnectLocal", 0x00BB8E80, (void*)Detour_ConnectLocal,
                   (void**)&g_Original_ConnectLocal,
                   "\x56\x8b\xf1\x81\x7e\x20\x83\x00\x00\x00", 10);
    InstallChecked("FlushDeferred", 0x00BB65F0, (void*)Detour_FlushDeferred,
                   (void**)&g_Original_FlushDeferred, kFrame0c, 6);
    InstallChecked("ConnectPlayer", 0x00BB64D0, (void*)Detour_ConnectPlayer,
                   (void**)&g_Original_ConnectPlayer, kFrame1c, 6);
    InstallChecked("DeferPlayer", 0x00BB3820, (void*)Detour_DeferPlayer,
                   (void**)&g_Original_DeferPlayer, kFrame0c, 6);
    InstallChecked("AdapterInit", 0x00C0FA50, (void*)Detour_AdapterInit,
                   (void**)&g_Original_AdapterInit, kFrame10, 6);
    InstallChecked("AdapterConnect", 0x00C0E4F0, (void*)Detour_AdapterConnect,
                   (void**)&g_Original_AdapterConnect,
                   "\x55\x8b\xec\x56\x8b\x75\x0c", 7);
    InstallChecked("NetworkAddPeer", 0x00C0E1B0, (void*)Detour_NetworkAddPeer,
                   (void**)&g_Original_NetworkAddPeer,
                   "\x55\x8b\xec\x81\xec\x9c\x00\x00\x00", 9);
    InstallChecked("ConnApiAddClient", 0x00B84430, (void*)Detour_ConnApiAddClient,
                   (void**)&g_Original_ConnApiAddClient,
                   "\x55\x8b\xec\x56\x8b\x75\x08", 7);
}

// ===========================================================================
// Winsock 2 Network Stack Hooks (Full UDP & TCP Packet Telemetry)
// ===========================================================================
typedef int (WSAAPI *PFN_sendto)(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen);
static PFN_sendto g_Original_sendto = NULL;

typedef int (WSAAPI *PFN_recvfrom)(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);
static PFN_recvfrom g_Original_recvfrom = NULL;

typedef int (WSAAPI *PFN_WSARecvFrom)(
    SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd,
    LPDWORD lpFlags, struct sockaddr* lpFrom, LPINT lpFromlen,
    LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
static PFN_WSARecvFrom g_Original_WSARecvFrom = NULL;

typedef int (WSAAPI *PFN_bind)(SOCKET s, const struct sockaddr* name, int namelen);
static PFN_bind g_Original_bind = NULL;

typedef int (WSAAPI *PFN_connect)(SOCKET s, const struct sockaddr* name, int namelen);
static PFN_connect g_Original_connect = NULL;

typedef SOCKET (WSAAPI *PFN_socket)(int af, int type, int protocol);
static PFN_socket g_Original_socket = NULL;

typedef int (WSAAPI *PFN_closesocket)(SOCKET s);
static PFN_closesocket g_Original_closesocket = NULL;

typedef struct hostent* (WSAAPI *PFN_gethostbyname)(const char* name);
static PFN_gethostbyname g_Original_gethostbyname = NULL;

static void FormatSockAddr(const struct sockaddr* addr, int addrlen, char* out, size_t outLen)
{
    if (!addr || addrlen < (int)sizeof(struct sockaddr_in)) {
        snprintf(out, outLen, "NULL/UNKNOWN");
        return;
    }
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in* sin = (const struct sockaddr_in*)addr;
        uint32_t ip = ntohl(sin->sin_addr.s_addr);
        uint16_t port = ntohs(sin->sin_port);
        snprintf(out, outLen, "%u.%u.%u.%u:%u",
                 (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF, port);
    } else {
        snprintf(out, outLen, "Family-%d", addr->sa_family);
    }
}

int WSAAPI Detour_sendto(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen)
{
    char addrStr[64];
    FormatSockAddr(to, tolen, addrStr, sizeof(addrStr));

    int ret = g_Original_sendto(s, buf, len, flags, to, tolen);

    LogTrace("[NET_UDP_SEND] sock=%u -> %s | len=%d | ret=%d%s\n",
             (unsigned)s, addrStr, len, ret,
             (ret < 0) ? " [FAILED!]" : "");

    if (len > 0 && buf && !IsBadReadPtr(buf, len > 48 ? 48 : len)) {
        HexDump(buf, len > 48 ? 48 : len, "UDP Outgoing Packet");
    }
    return ret;
}

int WSAAPI Detour_recvfrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen)
{
    int ret = g_Original_recvfrom(s, buf, len, flags, from, fromlen);
    if (ret > 0) {
        char addrStr[64];
        FormatSockAddr(from, (fromlen ? *fromlen : 0), addrStr, sizeof(addrStr));
        LogTrace("[NET_UDP_RECV] sock=%u <- %s | recvd=%d bytes\n", (unsigned)s, addrStr, ret);
        if (buf && !IsBadReadPtr(buf, ret > 48 ? 48 : ret)) {
            HexDump(buf, ret > 48 ? 48 : ret, "UDP Incoming Packet");
        }
    } else if (ret < 0) {
        int err = WSAGetLastError();
        // Ignore WSAEWOULDBLOCK (10035) because sockets poll constantly in game loops
        if (err != 10035 && err != 0) {
            LogTrace("[NET_UDP_RECV_ERR] sock=%u | WSAGetLastError=%d\n", (unsigned)s, err);
        }
    }
    return ret;
}

int WSAAPI Detour_WSARecvFrom(
    SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd,
    LPDWORD lpFlags, struct sockaddr* lpFrom, LPINT lpFromlen,
    LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    int ret = g_Original_WSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd,
                                     lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
    if (ret == 0 && lpNumberOfBytesRecvd && *lpNumberOfBytesRecvd > 0) {
        char addrStr[64];
        FormatSockAddr(lpFrom, (lpFromlen ? *lpFromlen : 0), addrStr, sizeof(addrStr));
        LogTrace("[NET_WSA_RECV] sock=%u <- %s | bytes=%u\n",
                 (unsigned)s, addrStr, (unsigned)*lpNumberOfBytesRecvd);
        if (lpBuffers && dwBufferCount > 0 && lpBuffers[0].buf) {
            size_t bytes = *lpNumberOfBytesRecvd > 48 ? 48 : *lpNumberOfBytesRecvd;
            HexDump(lpBuffers[0].buf, bytes, "WSARecvFrom Incoming");
        }
    }
    return ret;
}

int WSAAPI Detour_bind(SOCKET s, const struct sockaddr* name, int namelen)
{
    char addrStr[64];
    FormatSockAddr(name, namelen, addrStr, sizeof(addrStr));

    int ret = g_Original_bind(s, name, namelen);
    LogTrace("[NET_SOCKET_BIND] sock=%u bound to %s | ret=%d (err=%d)\n",
             (unsigned)s, addrStr, ret, ret < 0 ? WSAGetLastError() : 0);
    return ret;
}

int WSAAPI Detour_connect(SOCKET s, const struct sockaddr* name, int namelen)
{
    char addrStr[64];
    FormatSockAddr(name, namelen, addrStr, sizeof(addrStr));

    int ret = g_Original_connect(s, name, namelen);
    LogTrace("[NET_SOCKET_CONNECT] sock=%u connecting to %s | ret=%d (err=%d)\n",
             (unsigned)s, addrStr, ret, ret < 0 ? WSAGetLastError() : 0);
    return ret;
}

SOCKET WSAAPI Detour_socket(int af, int type, int protocol)
{
    SOCKET s = g_Original_socket(af, type, protocol);
    const char* typeStr = (type == SOCK_DGRAM) ? "SOCK_DGRAM (UDP)" :
                          (type == SOCK_STREAM) ? "SOCK_STREAM (TCP)" : "OTHER";
    LogTrace("[NET_SOCKET_CREATE] sock=%u created | af=%d type=%s proto=%d\n",
             (unsigned)s, af, typeStr, protocol);
    return s;
}

int WSAAPI Detour_closesocket(SOCKET s)
{
    LogTrace("[NET_SOCKET_CLOSE] sock=%u closed\n", (unsigned)s);
    return g_Original_closesocket(s);
}

struct hostent* WSAAPI Detour_gethostbyname(const char* name)
{
    struct hostent* ret = g_Original_gethostbyname(name);
    if (ret && ret->h_addr_list && ret->h_addr_list[0]) {
        struct in_addr* in = (struct in_addr*)ret->h_addr_list[0];
        LogTrace("[NET_DNS_RESOLVE] gethostbyname('%s') -> %s\n",
                 name ? name : "NULL", inet_ntoa(*in));
    } else {
        LogTrace("[NET_DNS_RESOLVE] gethostbyname('%s') -> FAILED (err=%d)\n",
                 name ? name : "NULL", WSAGetLastError());
    }
    return ret;
}

static inline void* HookIAT(void* pIatEntry, void* detour)
{
    DWORD oldProtect;
    if (!VirtualProtect(pIatEntry, sizeof(void*), PAGE_READWRITE, &oldProtect))
        return NULL;
    void* original = *(void**)pIatEntry;
    *(void**)pIatEntry = detour;
    VirtualProtect(pIatEntry, sizeof(void*), oldProtect, &oldProtect);
    return original;
}

static void InstallWinsockIATHooks(void)
{
    HMODULE hExe = GetModuleHandleA(NULL);
    if (!hExe) return;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hExe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((char*)hExe + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    DWORD importRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!importRva) return;

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((char*)hExe + importRva);

    for (; importDesc->Name; importDesc++) {
        const char* modName = (const char*)((char*)hExe + importDesc->Name);
        if (strcasecmp(modName, "ws2_32.dll") == 0 || strcasecmp(modName, "wsock32.dll") == 0) {
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((char*)hExe + importDesc->FirstThunk);
            PIMAGE_THUNK_DATA origThunk = importDesc->OriginalFirstThunk ?
                (PIMAGE_THUNK_DATA)((char*)hExe + importDesc->OriginalFirstThunk) : thunk;

            for (; origThunk->u1.AddressOfData; origThunk++, thunk++) {
                if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) {
                    WORD ord = IMAGE_ORDINAL(origThunk->u1.Ordinal);
                    switch (ord) {
                    case 20: // sendto
                        g_Original_sendto = (PFN_sendto)HookIAT(&thunk->u1.Function, (void*)Detour_sendto);
                        LogTrace("[+] IAT Hooked ws2_32.dll sendto (Ord 20) at %p\n", &thunk->u1.Function);
                        break;
                    case 17: // recvfrom
                        g_Original_recvfrom = (PFN_recvfrom)HookIAT(&thunk->u1.Function, (void*)Detour_recvfrom);
                        LogTrace("[+] IAT Hooked ws2_32.dll recvfrom (Ord 17) at %p\n", &thunk->u1.Function);
                        break;
                    case 2: // bind
                        g_Original_bind = (PFN_bind)HookIAT(&thunk->u1.Function, (void*)Detour_bind);
                        LogTrace("[+] IAT Hooked ws2_32.dll bind (Ord 2) at %p\n", &thunk->u1.Function);
                        break;
                    case 4: // connect
                        g_Original_connect = (PFN_connect)HookIAT(&thunk->u1.Function, (void*)Detour_connect);
                        LogTrace("[+] IAT Hooked ws2_32.dll connect (Ord 4) at %p\n", &thunk->u1.Function);
                        break;
                    case 23: // socket
                        g_Original_socket = (PFN_socket)HookIAT(&thunk->u1.Function, (void*)Detour_socket);
                        LogTrace("[+] IAT Hooked ws2_32.dll socket (Ord 23) at %p\n", &thunk->u1.Function);
                        break;
                    case 3: // closesocket
                        g_Original_closesocket = (PFN_closesocket)HookIAT(&thunk->u1.Function, (void*)Detour_closesocket);
                        LogTrace("[+] IAT Hooked ws2_32.dll closesocket (Ord 3) at %p\n", &thunk->u1.Function);
                        break;
                    case 52: // gethostbyname
                        g_Original_gethostbyname = (PFN_gethostbyname)HookIAT(&thunk->u1.Function, (void*)Detour_gethostbyname);
                        LogTrace("[+] IAT Hooked ws2_32.dll gethostbyname (Ord 52) at %p\n", &thunk->u1.Function);
                        break;
                    }
                } else {
                    PIMAGE_IMPORT_BY_NAME impName = (PIMAGE_IMPORT_BY_NAME)((char*)hExe + origThunk->u1.AddressOfData);
                    if (strcmp((char*)impName->Name, "WSARecvFrom") == 0) {
                        g_Original_WSARecvFrom = (PFN_WSARecvFrom)HookIAT(&thunk->u1.Function, (void*)Detour_WSARecvFrom);
                        LogTrace("[+] IAT Hooked ws2_32.dll WSARecvFrom at %p\n", &thunk->u1.Function);
                    }
                }
            }
        }
    }
}

// ===========================================================================
// Hook Initialization Thread
// ===========================================================================
static DWORD WINAPI HookWorkerThread(LPVOID param)
{
    (void)param;
    // Wait for the executable image to be fully loaded into memory
    Sleep(500);

    HMODULE hExe = GetModuleHandleA(NULL);
    LogTrace("\n==================================================\n");
    LogTrace(" [NFS13 P2P & BLAZE TRACE HOOK INJECTED]\n");
    LogTrace(" Target Base Address: 0x%p\n", hExe);
    LogTrace("==================================================\n");

    // Intercept full Winsock 2 network stack via IAT
    InstallWinsockIATHooks();

    // 1. Hook NotifyGameSetup (0x00BBF3C0, 7 bytes)
    void* target_NotifyGameSetup = (void*)0x00BBF3C0;
    if (HookFunction(target_NotifyGameSetup, (void*)Detour_NotifyGameSetup,
                     (void**)&g_Original_NotifyGameSetup, 7)) {
        LogTrace("[+] Hooked NotifyGameSetup at 0x%p\n", target_NotifyGameSetup);
    } else {
        LogTrace("[-] FAILED to hook NotifyGameSetup at 0x%p\n", target_NotifyGameSetup);
    }

    // 2. Hook StartNetworkMesh (0x00BC8630, 7 bytes)
    void* target_StartMesh = (void*)0x00BC8630;
    if (HookFunction(target_StartMesh, (void*)Detour_StartNetworkMesh,
                     (void**)&g_Original_StartNetworkMesh, 7)) {
        LogTrace("[+] Hooked StartNetworkMesh at 0x%p\n", target_StartMesh);
    } else {
        LogTrace("[-] FAILED to hook StartNetworkMesh at 0x%p\n", target_StartMesh);
    }

    // 3. Hook IsConnectedOrReady (0x00A82E60, 9 bytes)
    void* target_OnlineCheck = (void*)0x00A82E60;
    if (HookFunction(target_OnlineCheck, (void*)Detour_IsConnectedOrReady,
                     (void**)&g_Original_IsConnectedOrReady, 9)) {
        LogTrace("[+] Hooked IsConnectedOrReady at 0x%p\n", target_OnlineCheck);
    } else {
        LogTrace("[-] FAILED to hook IsConnectedOrReady at 0x%p\n", target_OnlineCheck);
    }

    // 4. Hook ProtoSslProcessServerCertificate (0x00B91E70, 8 bytes)
    void* target_ProtoSsl = (void*)0x00B91E70;
    if (HookFunction(target_ProtoSsl, (void*)Detour_ProtoSslProcessServerCert,
                     (void**)&g_Original_ProtoSslProcessServerCert, 8)) {
        LogTrace("[+] Hooked ProtoSslProcessServerCertificate at 0x%p\n", target_ProtoSsl);
    } else {
        LogTrace("[-] FAILED to hook ProtoSslProcessServerCertificate at 0x%p\n", target_ProtoSsl);
    }

    InstallMeshHooks();

    LogTrace("[MW_HOOK] All hooks initialized. Ready for matchmaking and gameplay!\n\n");
    return 0;
}

static void EnsureRussianLocale(void)
{
    HKEY hKey;
    const char* loc = "ru_RU";
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\EA Games\\Need for Speed(TM) Most Wanted", 0, NULL, 0, KEY_SET_VALUE | 0x0200, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "Locale", 0, REG_SZ, (const BYTE*)loc, 6);
        RegCloseKey(hKey);
    }
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\EA Games\\Need for Speed(TM) Most Wanted", 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "Locale", 0, REG_SZ, (const BYTE*)loc, 6);
        RegCloseKey(hKey);
    }
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\EA Games\\Need for Speed(TM) Most Wanted", 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "Locale", 0, REG_SZ, (const BYTE*)loc, 6);
        RegCloseKey(hKey);
    }
    LogTrace("[MW_PROXY] Set registry locale to ru_RU (Russian)\n");
}

// ===========================================================================
// DLL Entry Point
// ===========================================================================
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)lpvReserved;

    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        InitializeCriticalSection(&g_LogLock);
        g_LogFile = fopen("nfs13_trace.log", "w");
        if (g_LogFile) {
            fprintf(g_LogFile, "=== NFS13 Network & P2P Trace Log Started ===\n");
            fflush(g_LogFile);
        }
        EnsureRussianLocale();
        SetEnvironmentVariableA("DXVK_CONFIG", "dxgi.maxFrameRate=60;d3d11.maxFrameRate=60;dxvk.maxFrameRate=60;dxgi.syncInterval=1");
        SetEnvironmentVariableA("DXVK_FRAME_RATE", "60");
        CreateThread(NULL, 0, HookWorkerThread, NULL, 0, NULL);
        break;

    case DLL_PROCESS_DETACH:
        if (g_LogFile) {
            fclose(g_LogFile);
            g_LogFile = NULL;
        }
        DeleteCriticalSection(&g_LogLock);
        break;
    }
    return TRUE;
}
