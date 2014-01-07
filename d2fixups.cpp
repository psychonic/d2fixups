/**
 * =============================================================================
 * D2Fixups
 * Copyright (C) 2013 Nicholas Hastings
 * =============================================================================
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License, version 2.0 or later, as published
 * by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * As a special exception, you are also granted permission to link the code
 * of this program (as well as its derivative works) to "Dota 2," the
 * "Source Engine, and any Game MODs that run on software by the Valve Corporation.
 * You must obey the GNU General Public License in all respects for all other
 * code used.  Additionally, this exception is granted to all derivative works.
 */

// Self
#include "d2fixups.h"

// SDK
#include <filesystem.h>
#include <icvar.h>
#include <tier0/platform.h>
#include <tier1/fmtstr.h>
#include <tier1/iconvar.h>
#include <vstdlib/random.h>

// Msg types have the high bit set if it's a protobuf msg (which are all that we care about).
const int MSG_PROTOBUF_BIT = (1 << 31);

const int k_EMsgGCServerVersionUpdated = 2522;
const int k_EMsgGCServerWelcome = 4005;
const int k_EMsgGCToServerConsoleCommand = 7418;

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
};

SH_DECL_HOOK1(IServerGCLobby, SteamIDAllowedToConnect, const, 0, bool, const CSteamID &);
SH_DECL_HOOK0(IVEngineServer, IsServerLocalOnly, SH_NOATTRIB, 0, bool);
SH_DECL_HOOK0(IServerGameDLL, GameInit, SH_NOATTRIB, 0, bool);
SH_DECL_HOOK6(IServerGameDLL, LevelInit, SH_NOATTRIB, 0, bool, const char *, const char *, const char *, const char *, bool, bool);
SH_DECL_HOOK4(ISteamGameCoordinator, RetrieveMessage, SH_NOATTRIB, 0, EGCResults, uint32 *, void *, uint32, uint32 *);
SH_DECL_HOOK0_void(IServerGameDLL, GameServerSteamAPIActivated, SH_NOATTRIB, 0);
SH_DECL_HOOK0_void(IServerGameDLL, GameServerSteamAPIShutdown, SH_NOATTRIB, 0);
SH_DECL_HOOK0(IVEngineServer, GetServerVersion, SH_NOATTRIB, 0, int);

static D2Fixups g_D2Fixups;
static IVEngineServer *engine = NULL;
static IServerGameDLL *gamedll = NULL;
static IFileSystem *filesystem = NULL;
static ISteamGameCoordinator *gamecoordinator = NULL;

ConVar dota_local_custom_allow_multiple("dota_local_custom_allow_multiple", "0", FCVAR_NONE, "0 - Only load selected mode's addon. 1 - Load all addons giving selected mode priority");

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
	m_bPretendToBeLocal = false;
	m_bCheatGameVersion = false;
	m_iRetrieveMsgHook = 0;

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
	GET_V_IFACE_CURRENT(GetFileSystemFactory, filesystem, IFileSystem, FILESYSTEM_INTERFACE_VERSION);

	ICvar *icvar;
	GET_V_IFACE_CURRENT(GetEngineFactory, icvar, ICvar, CVAR_INTERFACE_VERSION);
	g_pCVar = icvar;
	ConVar_Register(0, &s_BaseAccessor);

	return true;
}

void D2Fixups::InitHooks()
{
	SH_ADD_HOOK(IServerGCLobby, SteamIDAllowedToConnect, gamedll->GetServerGCLobby(), SH_MEMBER(this, &D2Fixups::Hook_SteamIDAllowedToConnect), false);
	SH_ADD_HOOK(IVEngineServer, IsServerLocalOnly, engine, SH_MEMBER(this, &D2Fixups::Hook_IsServerLocalOnly), false);
	SH_ADD_HOOK(IServerGameDLL, GameInit, gamedll, SH_MEMBER(this, &D2Fixups::Hook_GameInit), false);
	SH_ADD_HOOK(IServerGameDLL, LevelInit, gamedll, SH_MEMBER(this, &D2Fixups::Hook_LevelInit), false);
	SH_ADD_HOOK(IServerGameDLL, LevelInit, gamedll, SH_MEMBER(this, &D2Fixups::Hook_LevelInit_Post), true);
	SH_ADD_HOOK(IServerGameDLL, GameServerSteamAPIActivated, gamedll, SH_MEMBER(this, &D2Fixups::Hook_GameServerSteamAPIActivated), true);
	SH_ADD_HOOK(IServerGameDLL, GameServerSteamAPIShutdown, gamedll, SH_MEMBER(this, &D2Fixups::Hook_GameServerSteamAPIShutdown), false);
	SH_ADD_HOOK(IVEngineServer, GetServerVersion, engine, SH_MEMBER(this, &D2Fixups::Hook_GetServerVersion), true);
}

void D2Fixups::ShutdownHooks()
{
	SH_REMOVE_HOOK(IVEngineServer, GetServerVersion, engine, SH_MEMBER(this, &D2Fixups::Hook_GetServerVersion), true);
	SH_REMOVE_HOOK(IServerGameDLL, GameServerSteamAPIShutdown, gamedll, SH_MEMBER(this, &D2Fixups::Hook_GameServerSteamAPIActivated), true);
	SH_REMOVE_HOOK(IServerGameDLL, GameServerSteamAPIActivated, gamedll, SH_MEMBER(this, &D2Fixups::Hook_GameServerSteamAPIShutdown), false);
	SH_REMOVE_HOOK(IServerGameDLL, LevelInit, gamedll, SH_MEMBER(this, &D2Fixups::Hook_LevelInit_Post), true);
	SH_REMOVE_HOOK(IServerGameDLL, LevelInit, gamedll, SH_MEMBER(this, &D2Fixups::Hook_LevelInit), false);
	SH_REMOVE_HOOK(IServerGameDLL, GameInit, gamedll, SH_MEMBER(this, &D2Fixups::Hook_GameInit), false);
	SH_REMOVE_HOOK(IVEngineServer, IsServerLocalOnly, engine, SH_MEMBER(this, &D2Fixups::Hook_IsServerLocalOnly), false);
	SH_REMOVE_HOOK(IServerGCLobby, SteamIDAllowedToConnect, gamedll->GetServerGCLobby(), SH_MEMBER(this, &D2Fixups::Hook_SteamIDAllowedToConnect), false);	

	if (m_iRetrieveMsgHook != 0)
	{
		SH_REMOVE_HOOK_ID(m_iRetrieveMsgHook);
		m_iRetrieveMsgHook = 0;
	}
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

bool D2Fixups::Hook_SteamIDAllowedToConnect(const CSteamID &steamId) const
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

bool D2Fixups::Hook_GameInit()
{
	static ConVarRef dota_local_custom_game("dota_local_custom_game");

	// If we're not running a custom game when 'map' is executed, then nothing to do.
	const char *pszDesiredAddon = dota_local_custom_game.GetString();
	if (!pszDesiredAddon[0])
	{
		RETURN_META_VALUE(MRES_IGNORED, true);
	}

	// This should be our 'dota' gamedir.
	char modPath[MAX_PATH];
	filesystem->GetSearchPath("MOD", false, modPath, sizeof(modPath));

	// This is the full path to the addon we want.
	char desiredAddonPath[MAX_PATH];
	V_snprintf(desiredAddonPath, sizeof(desiredAddonPath), "%s%s\\%s\\", modPath, "addons", pszDesiredAddon);

	// If it doesn't exist, the rest is pointless.
	if (!filesystem->IsDirectory(desiredAddonPath))
	{
		RETURN_META_VALUE(MRES_IGNORED, true);
	}

	char gameSearchPath[10 * MAX_PATH];
	char addonsSearchString[MAX_PATH];	
	CUtlStringList gameSearchPathList;
	CUtlVector<const char *> demotedSearchPathList;

	// This should match any GAME path under the addons dir.
	V_snprintf(addonsSearchString, sizeof(addonsSearchString), "%s%s", modPath, "addons");	

	filesystem->GetSearchPath("GAME", false, gameSearchPath, sizeof(gameSearchPath));
	V_SplitString(gameSearchPath, ";", gameSearchPathList);

	bool foundDesired = false;
	FOR_EACH_VEC(gameSearchPathList, i)
	{
		if (V_stristr(gameSearchPathList[i], addonsSearchString))
		{
			if (!V_stricmp(gameSearchPathList[i], desiredAddonPath))
			{
				foundDesired = true;
				continue;
			}

			// We'll re-add these to the tail.
			demotedSearchPathList.AddToTail(gameSearchPathList[i]);
			filesystem->RemoveSearchPath(gameSearchPathList[i], "GAME");
		}
	}

	if (!foundDesired)
	{
		filesystem->AddSearchPath(desiredAddonPath, "GAME", PATH_ADD_TO_TAIL);
	}

	if (dota_local_custom_allow_multiple.GetBool())
	{
		FOR_EACH_VEC(demotedSearchPathList, i)
		{
			filesystem->AddSearchPath(demotedSearchPathList[i], "GAME", PATH_ADD_TO_TAIL);
		}
	}

	demotedSearchPathList.RemoveAll();

	RETURN_META_VALUE(MRES_IGNORED, true);
}

bool D2Fixups::Hook_LevelInit(const char *pMapName, const char *pMapEntities, const char *pOldLevel, const char *pLandmarkName, bool loadGame, bool background)
{
	m_bPretendToBeLocal = true;
	RETURN_META_VALUE(MRES_IGNORED, true);
}

bool D2Fixups::Hook_LevelInit_Post(const char *pMapName, const char *pMapEntities, const char *pOldLevel, const char *pLandmarkName, bool loadGame, bool background)
{
	m_bPretendToBeLocal = false;
	RETURN_META_VALUE(MRES_IGNORED, true);
}

bool D2Fixups::Hook_IsServerLocalOnly()
{
	if (m_bPretendToBeLocal)
	{
		RETURN_META_VALUE(MRES_SUPERCEDE, true);
	}

	RETURN_META_VALUE(MRES_IGNORED, true);
}

void D2Fixups::Hook_GameServerSteamAPIActivated()
{
	HSteamUser hSteamUser = SteamGameServer_GetHSteamUser();
	HSteamPipe hSteamPipe = SteamGameServer_GetHSteamPipe();

	gamecoordinator = (ISteamGameCoordinator *) g_pSteamClientGameServer->GetISteamGenericInterface(hSteamUser, hSteamPipe, STEAMGAMECOORDINATOR_INTERFACE_VERSION);

	m_iRetrieveMsgHook = SH_ADD_HOOK(ISteamGameCoordinator, RetrieveMessage, gamecoordinator, SH_MEMBER(this, &D2Fixups::Hook_RetrieveMessage), false);

	RETURN_META(MRES_IGNORED);
}

void D2Fixups::Hook_GameServerSteamAPIShutdown()
{
	if (m_iRetrieveMsgHook != 0)
	{
		SH_REMOVE_HOOK_ID(m_iRetrieveMsgHook);
		m_iRetrieveMsgHook = 0;
	}

	RETURN_META(MRES_IGNORED);
}

EGCResults D2Fixups::Hook_RetrieveMessage(uint32 *punMsgType, void *pubDest, uint32 cubDest, uint32 *pcubMsgSize)
{
	EGCResults ret = SH_CALL(gamecoordinator, &ISteamGameCoordinator::RetrieveMessage)(punMsgType, pubDest, cubDest, pcubMsgSize);
	int msgType = *punMsgType & ~MSG_PROTOBUF_BIT;

	switch (msgType)
	{
	case k_EMsgGCToServerConsoleCommand:
		RETURN_META_VALUE(MRES_SUPERCEDE, k_EGCResultNoMessage);
	case k_EMsgGCServerVersionUpdated:
	case k_EMsgGCServerWelcome:
		m_bCheatGameVersion = true;
		break;
	}

	RETURN_META_VALUE(MRES_SUPERCEDE, ret);
}

int D2Fixups::Hook_GetServerVersion()
{
	// After the initial GC welcome or a GC server update notice, the game server will
	// query its server version from the engine to see if it's out of date. That check has
	// the handy logic of just skipping the check if either server or GC version are 0.

	if (m_bCheatGameVersion)
	{
		m_bCheatGameVersion = false;
		RETURN_META_VALUE(MRES_SUPERCEDE, 0);
	}

	RETURN_META_VALUE(MRES_IGNORED, 0);
}


const char *D2Fixups::GetLicense()
{
	return "GPLv2";
}

const char *D2Fixups::GetVersion()
{
	return "1.8.2.0";
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
