// Self
#include "d2fixups.h"

// SDK
#include <icvar.h>
#include <iserver.h>
#include <steam/steamclientpublic.h>
#include <tier0/platform.h>
#include <tier1/fmtstr.h>
#include <tier1/iconvar.h>
#include <vstdlib/random.h>

// SourceHook
#include <sh_memory.h>

#define OPCODE_JZ_1 0x74
#define OPCODE_JMP_1 0xEB

static struct SrcdsPatch
{
	const char *sig;
	int sigsize;
	int patchOffs;
	uint8 patchFrom;
	uint8 patchTo;
	void *addr;
	const char *name;
	PatchAddressType ptype;
} s_Patches[] = {
	// Test Client
	{ "\x5E\x5B\x74\x2A\xE8\x2A\x2A\x2A\x2A\x83\xF8\x02\x74\x2A\x32",
		15, // siglen
		12, // offset
		OPCODE_JZ_1, OPCODE_JMP_1,
		NULL,
		"Test Client shutdown patch",
		Engine,
	},
	// Main Client (463)
	{ "\x8B\x11\x8B\x42\x2A\xFF\xD0\xA3\x2A\x2A\x2A\x2A\x83\xF8\x02\x74\x2A\x85",
		18, // siglen
		15, // offset
		OPCODE_JZ_1, OPCODE_JMP_1,
		NULL,
		"Shutdown patch",
		Engine,
	},
#if 0
	// version check - doesn't work yet
	{ "\x8B\x11\x8B\x2A\x2A\x2A\x2A\x2A\xFF\xD0\x85\xC0\x74\x2A\x8B\x2A\x2A\x2A\x2A\x2A\x85\xC9\x74",
		23, // siglen
		12, // offset
		OPCODE_JZ_1, OPCODE_JMP_1,
		NULL,
		"Version check patch",
		Server,
	},
#endif
};

SH_DECL_HOOK1(IServerGCLobby, SteamIDAllowedToConnect, const, 0, bool, const CSteamID &);

static D2Fixups g_D2Fixups;
static IVEngineServer *engine = NULL;
static IServerGameDLL *gamedll = NULL;

static class BaseAccessor : public IConCommandBaseAccessor
{
public:
	bool RegisterConCommandBase(ConCommandBase *pVar)
	{
		return META_REGCVAR(pVar);
	}
} s_BaseAccessor;

PLUGIN_EXPOSE(D2Fixups, g_D2Fixups);

bool D2Fixups::Load(PluginId id, ISmmAPI *ismm, char *error, size_t maxlen, bool late)
{
	PLUGIN_SAVEVARS();

	for (int i = 0; i < ARRAYSIZE(s_Patches); ++i)
	{
		void *addr = FindPatchAddress(s_Patches[i].sig, s_Patches[i].sigsize, s_Patches[i].ptype);
		s_Patches[i].addr = addr;
		if (addr)
		{
			s_Patches[i].addr = addr = (void *)((intp)addr + s_Patches[i].patchOffs);
			SourceHook::SetMemAccess(addr, sizeof(uint8), SH_MEM_READ|SH_MEM_WRITE|SH_MEM_EXEC);
			if (*reinterpret_cast<uint8 *>(addr) == s_Patches[i].patchFrom)
			{
				*reinterpret_cast<uint8 *>(addr) = s_Patches[i].patchTo;
				continue;
			}
		}

		ismm->Format(error, maxlen, "Failed to setup %s.", s_Patches[i].name);
		META_CONPRINTF("[D2Fixups] Warning: Failed to setup %s.\n", s_Patches[i].name);
	}

	if (!InitGlobals(error, maxlen))
	{
		ismm->Format(error, maxlen, "Failed to setup globals");
		return false;
	}

	InitHooks();

	return true;
}

bool D2Fixups::InitGlobals(char *error, size_t maxlen)
{
	// For compat with GET_V_IFACE macros
	ISmmAPI *ismm = g_SMAPI;

	GET_V_IFACE_CURRENT(GetServerFactory, gamedll, IServerGameDLL, INTERFACEVERSION_SERVERGAMEDLL);
	GET_V_IFACE_CURRENT(GetEngineFactory, engine, IVEngineServer, INTERFACEVERSION_VENGINESERVER);

	ICvar *icvar;
	GET_V_IFACE_CURRENT(GetEngineFactory, icvar, ICvar, CVAR_INTERFACE_VERSION);
	g_pCVar = icvar;
	ConVar_Register(0, &s_BaseAccessor);

	return true;
}

void D2Fixups::InitHooks()
{
	SH_ADD_HOOK(IServerGCLobby, SteamIDAllowedToConnect, gamedll->GetServerGCLobby(), SH_MEMBER(this, &D2Fixups::SteamIDAllowedToConnect), false);
}

void D2Fixups::ShutdownHooks()
{
	SH_REMOVE_HOOK(IServerGCLobby, SteamIDAllowedToConnect, gamedll->GetServerGCLobby(), SH_MEMBER(this, &D2Fixups::SteamIDAllowedToConnect), false);
}

bool D2Fixups::Unload(char *error, size_t maxlen)
{
	ShutdownHooks();

	for (size_t i = 0; i < ARRAYSIZE(s_Patches); ++i)
	{
		if (!s_Patches[i].addr)
			continue;

		*reinterpret_cast<uint8 *>(s_Patches[i].addr) = s_Patches[i].patchFrom;
	}

	return true;
}

static void WfpCountChanged(IConVar *pConVar, const char *pOldValue, float flOldValue);
static ConVar dota_wfp_count( "dota_wait_for_players_to_load_count", "10", FCVAR_NONE, "Number of players to wait for before starting game", true, 0.f, true, 24.f, WfpCountChanged);

static void WfpCountChanged(IConVar *pConVar, const char *pOldValue, float flOldValue)
{
	static const char * const sig = "\x89\xB7\x2A\x2A\x2A\x2A\xA1\x2A\x2A\x2A\x2A\x8B\xF0\x39";
	static const int siglen = 14;
	static const int offset = 7;

	static void *addr = NULL;
	if (addr == NULL)
	{
		addr = D2Fixups::FindPatchAddress(sig, siglen, Server);
		if (addr)
		{
			addr = (void *)((intp)addr + offset);
			SourceHook::SetMemAccess(addr, sizeof(int *), SH_MEM_READ|SH_MEM_WRITE|SH_MEM_EXEC);
		}
	}

	if (addr == NULL)
	{
		META_CONPRINT("Failed to update waiting for players count.\n");
		return;
	}

	**((int **)addr) = dota_wfp_count.GetInt();
}

bool D2Fixups::SteamIDAllowedToConnect(const CSteamID &steamId) const
{
	RETURN_META_VALUE(MRES_SUPERCEDE, true);
}

void *D2Fixups::FindPatchAddress(const char *sig, size_t len, PatchAddressType type)
{
	bool found;
	char *ptr, *end;

	LPCVOID startAddr;
	switch (type)
	{
	case Engine:
		startAddr = g_SMAPI->GetEngineFactory(false);
		break;
	case Server:
		startAddr = g_SMAPI->GetServerFactory(false);
		break;
	default:
		return NULL;
	}

	MEMORY_BASIC_INFORMATION mem;
 
	if (!startAddr)
		return NULL;
 
	if (!VirtualQuery(startAddr, &mem, sizeof(mem)))
		return NULL;
 
	IMAGE_DOS_HEADER *dos = reinterpret_cast<IMAGE_DOS_HEADER *>(mem.AllocationBase);
	IMAGE_NT_HEADERS *pe = reinterpret_cast<IMAGE_NT_HEADERS *>((intp)dos + dos->e_lfanew);
 
	if (pe->Signature != IMAGE_NT_SIGNATURE)
	{
		// GetDllMemInfo failedpe points to a bad location
		return NULL;
	}

	ptr = reinterpret_cast<char *>(mem.AllocationBase);
	end = ptr + pe->OptionalHeader.SizeOfImage - len;

	while (ptr < end)
	{
		found = true;
		for (size_t i = 0; i < len; i++)
		{
			if (sig[i] != '\x2A' && sig[i] != ptr[i])
			{
				found = false;
				break;
			}
		}

		if (found)
			return ptr;

		ptr++;
	}

	return NULL;
}

const char *D2Fixups::GetLicense()
{
	return "None.";
}

const char *D2Fixups::GetVersion()
{
	return "1.7.0.0";
}

const char *D2Fixups::GetDate()
{
	return __DATE__;
}

const char *D2Fixups::GetLogTag()
{
	return "D2FIXUPS";
}

const char *D2Fixups::GetAuthor()
{
	return "Nicholas Hastings";
}

const char *D2Fixups::GetDescription()
{
	return "Provides SRCDS shutdown fix and no-lobby connect fix for Dota 2.";
}

const char *D2Fixups::GetName()
{
	return "Dota 2 Fixups";
}

const char *D2Fixups::GetURL()
{
	return "http://www.sourcemod.net/";
}
