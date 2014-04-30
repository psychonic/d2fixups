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
const uint32 MSG_PROTOBUF_BIT = (1 << 31);

const uint32 k_EMsgGCServerVersionUpdated = 2522;
const uint32 k_EMsgGCServerWelcome = 4005;
const uint32 k_EMsgGCGCToRelayConnect = 7089;
const uint32 k_EMsgGCToServerConsoleCommand = 7418;

#define MSG_TAG "[D2Fixups] "

// SourceHook
#include <sh_memory.h>

// Platform specific
#if defined(LINUX)
#include <elf.h>
#elif defined(OSX)
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#endif

#if !defined(PAGE_SIZE)
#define PAGE_SIZE 4096
#endif
#define PAGE_ALIGN_UP(x) ((x + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

#define OPCODE_JZ_1 0x74
#define OPCODE_JMP_1 0xEB

#if defined(WIN32)
static struct SrcdsPatch
{
	const char *sig;
	int sigsize;
	int patchOffs;
	uint8 patchFrom;
	uint8 patchTo;
	void *addr;
	const char *name;
	GameLibraryType ptype;
} s_Patches[] = {
	// Test Client
	{ "\x68\x2A\x2A\x2A\x2A\xFF\xD3\x83\x2A\x04\xE8\x2A\x2A\x2A\x2A\x80\x2A\x2A\x2A\x2A\x2A\x2A\x5B\x74\x2A\xE8",
		26, // siglen
		23, // offset
		OPCODE_JZ_1, OPCODE_JMP_1,
		NULL,
		"Test Client shutdown patch",
		Engine,
	},
	// Main Client (463) - This matches twice, but the first one is the one we want.
	{ "\x8B\x2A\x8B\x2A\x08\xFF\xD0\xA3\x2A\x2A\x2A\x2A\x83\xF8\x02\x74\x2A\x85",
		18, // siglen
		15, // offset
		OPCODE_JZ_1, OPCODE_JMP_1,
		NULL,
		"Shutdown patch",
		Engine,
	},
};
#endif

SH_DECL_HOOK1(IServerGCLobby, SteamIDAllowedToConnect, const, 0, bool, const CSteamID &);
SH_DECL_HOOK0(IVEngineServer, IsServerLocalOnly, SH_NOATTRIB, 0, bool);
SH_DECL_HOOK0(IServerGameDLL, GameInit, SH_NOATTRIB, 0, bool);
SH_DECL_HOOK6(IServerGameDLL, LevelInit, SH_NOATTRIB, 0, bool, const char *, const char *, const char *, const char *, bool, bool);
SH_DECL_HOOK4(ISteamGameCoordinator, RetrieveMessage, SH_NOATTRIB, 0, EGCResults, uint32 *, void *, uint32, uint32 *);
SH_DECL_HOOK0_void(IServerGameDLL, GameServerSteamAPIActivated, SH_NOATTRIB, 0);
SH_DECL_HOOK0(IVEngineServer, GetServerVersion, SH_NOATTRIB, 0, int);

static D2Fixups g_D2Fixups;
static IVEngineServer *engine = NULL;
static IServerGameDLL *gamedll = NULL;
static IFileSystem *filesystem = NULL;
static IGameEventManager2 *eventmgr = NULL;
static ISteamGameCoordinator *gamecoordinator = NULL;

ConVar dota_local_custom_allow_multiple("dota_local_custom_allow_multiple", "0", FCVAR_RELEASE, "0 - Only load selected mode's addon. 1 - Load all addons giving selected mode priority");
ConVar d2f_allow_all("d2f_allow_all", "1", FCVAR_RELEASE, "0 - Dota 2 default of disallowing players not in a lobby (all). 1 (default) - Allow all players to join");
ConVar d2f_blockgc_server_command("d2f_blockgc_server_command", "1", FCVAR_RELEASE);

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
	m_iCheatGameVersionCount = 0;
	m_iRetrieveMsgHook = 0;
	m_iRetrieveMsgHookPost = 0;

	PLUGIN_SAVEVARS();

#if defined(WIN32)
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
		META_CONPRINTF(MSG_TAG "Warning: Failed to setup %s.\n", s_Patches[i].name);
	}
#endif

	if (!InitGlobals(error, maxlen))
	{
		ismm->Format(error, maxlen, "Failed to setup globals");
		return false;
	}

	InitHooks();

	eventmgr->AddListener(this, "server_pre_shutdown", true);

	return true;
}

bool D2Fixups::InitGlobals(char *error, size_t maxlen)
{
	// For compat with GET_V_IFACE macros
	ISmmAPI *ismm = g_SMAPI;

	GET_V_IFACE_CURRENT(GetServerFactory, gamedll, IServerGameDLL, INTERFACEVERSION_SERVERGAMEDLL);
	GET_V_IFACE_CURRENT(GetEngineFactory, engine, IVEngineServer, INTERFACEVERSION_VENGINESERVER);
	GET_V_IFACE_CURRENT(GetEngineFactory, eventmgr, IGameEventManager2, INTERFACEVERSION_GAMEEVENTSMANAGER2);
	GET_V_IFACE_CURRENT(GetFileSystemFactory, filesystem, IFileSystem, FILESYSTEM_INTERFACE_VERSION);

	ICvar *icvar;
	GET_V_IFACE_CURRENT(GetEngineFactory, icvar, ICvar, CVAR_INTERFACE_VERSION);
	g_pCVar = icvar;
	ConVar_Register(0, &s_BaseAccessor);

	return true;
}

void D2Fixups::InitHooks()
{
	int h;
	
	h = SH_ADD_HOOK(IServerGCLobby, SteamIDAllowedToConnect, gamedll->GetServerGCLobby(), SH_MEMBER(this, &D2Fixups::Hook_SteamIDAllowedToConnect), false);
	m_GlobalHooks.push_back(h);

	h = SH_ADD_HOOK(IVEngineServer, IsServerLocalOnly, engine, SH_MEMBER(this, &D2Fixups::Hook_IsServerLocalOnly), false);
	m_GlobalHooks.push_back(h);

	h = SH_ADD_HOOK(IServerGameDLL, GameInit, gamedll, SH_MEMBER(this, &D2Fixups::Hook_GameInit), false);
	m_GlobalHooks.push_back(h);

	h = SH_ADD_HOOK(IServerGameDLL, LevelInit, gamedll, SH_MEMBER(this, &D2Fixups::Hook_LevelInit), false);
	m_GlobalHooks.push_back(h);

	h = SH_ADD_HOOK(IServerGameDLL, LevelInit, gamedll, SH_MEMBER(this, &D2Fixups::Hook_LevelInit_Post), true);
	m_GlobalHooks.push_back(h);

	h = SH_ADD_HOOK(IServerGameDLL, GameServerSteamAPIActivated, gamedll, SH_MEMBER(this, &D2Fixups::Hook_GameServerSteamAPIActivated), true);
	m_GlobalHooks.push_back(h);
	
	h = SH_ADD_HOOK(IVEngineServer, GetServerVersion, engine, SH_MEMBER(this, &D2Fixups::Hook_GetServerVersion), true);
	m_GlobalHooks.push_back(h);
}

void D2Fixups::UnhookGC()
{
	if (m_iRetrieveMsgHook != 0)
	{
		SH_REMOVE_HOOK_ID(m_iRetrieveMsgHook);
		m_iRetrieveMsgHook = 0;
	}

	if (m_iRetrieveMsgHookPost != 0)
	{
		SH_REMOVE_HOOK_ID(m_iRetrieveMsgHookPost);
		m_iRetrieveMsgHookPost = 0;
	}
}

void D2Fixups::ShutdownHooks()
{
	UnhookGC();

	SourceHook::List<int>::iterator iter;
	for (iter = m_GlobalHooks.begin(); iter != m_GlobalHooks.end(); ++iter)
	{
		SH_REMOVE_HOOK_ID(*iter);
	}

	m_GlobalHooks.clear();
}

bool D2Fixups::Unload(char *error, size_t maxlen)
{
	eventmgr->RemoveListener(this);

	ShutdownHooks();

#if defined(WIN32)
	for (size_t i = 0; i < ARRAYSIZE(s_Patches); ++i)
	{
		if (!s_Patches[i].addr)
			continue;

		*reinterpret_cast<uint8 *>(s_Patches[i].addr) = s_Patches[i].patchFrom;
	}
#endif

	return true;
}

void D2Fixups::FireGameEvent(IGameEvent *pEvent)
{
	if (!strcmp(pEvent->GetName(), "server_pre_shutdown"))
	{
		UnhookGC();
	}
}

static void WfpCountChanged(IConVar *pConVar, const char *pOldValue, float flOldValue);
static ConVar dota_wfp_count("dota_wait_for_players_to_load_count", "10", FCVAR_RELEASE, "Number of players to wait for before starting game", true, 0.f, true, 32.f, WfpCountChanged);

static void WfpCountChanged(IConVar *pConVar, const char *pOldValue, float flOldValue)
{
	D2Fixups::RefreshWaitForPlayersCount();
}

void D2Fixups::RefreshWaitForPlayersCount()
{
#if defined(WIN32)
	// Find unique string "exec lan_server.cfg\n".
	// In same block as "tutorial_m1", above it, look for global ptr being set to new value.
	static const char * const sig = "\xC6\x81\x2A\x2A\x2A\x2A\x01\x8D\x8E\x2A\x2A\x2A\x2A\x8B\x01\xFF\x50\x08\x8B\x0D\x2A\x2A\x2A\x2A\xA3";
	static const int siglen = 25;
	static const int offset = 25;
#elif defined(LINUX)
	// Find unique string "Loading unit...%s\n".
	// At the beginning of the function, the first call will be to DOTAGameManager().
	// There are two matches for the signature but either will work.
	static const char * const sig = "\x55\x89\xE5\x57\x56\x53\x83\xEC\x2A\x8B\x5D\x08\xE8\x2A\x2A\x2A\x2A\x89\xC6\xE8";
	static const int siglen = 20;
	static const int offset = 13;
	// Look for "exec lan_server.cfg\n" as on Windows
	// Toward the beginning of the function, DOTAGameManager() is called and the mov instruction after it should have the needed offset.
	static const int playerCountOffset = 0x3DC;
#elif defined(OSX)
	static const char * const symbol = "_Z15DOTAGameManagerv";
	// This offset can be found the same way as on Linux except that that mov instruction with an offset is directly before a cmp instruction testing for a value of 10.
	static const int playerCountOffset = 0x3DC;
#endif

	static void *addr = NULL;

	if (addr == NULL)
	{
#if defined(WIN32)
		addr = D2Fixups::FindPatchAddress(sig, siglen, Server);

		if (addr)
			addr = *(void **)((intp)addr + offset);
#elif defined(LINUX) || defined(OSX)

#if defined(LINUX)
		addr = D2Fixups::FindPatchAddress(sig, siglen, Server);

		if (addr)
		{
			// Get relative offset to DOTAGameManager()
			int32_t funcOffset = *(int32_t *)((intp)addr + offset);

			// Get real address of function:
			// Address of signature + offset of relative offset + sizeof(int32_t) offset + relative offset
			addr = (void *)((intp)addr + offset + 4 + funcOffset);
		}
#elif defined(OSX)
		addr = D2Fixups::ResolveSymbol(symbol, Server);
#endif

		if (addr)
		{
			typedef void *(*GameManagerFn)(void);
			void *objAddr = reinterpret_cast<GameManagerFn>(addr)();
			
			if (objAddr)
				addr = (void *)((intp)objAddr + playerCountOffset);
		}
#endif // LINUX || OSX
	}

	if (addr == NULL)
	{
		META_CONPRINT(MSG_TAG "Failed to update waiting for players count.\n");
		return;
	}

	*((int *)addr) = dota_wfp_count.GetInt();
}

bool D2Fixups::Hook_SteamIDAllowedToConnect(const CSteamID &steamId) const
{
	if (d2f_allow_all.GetBool())
	{
		RETURN_META_VALUE(MRES_SUPERCEDE, true);
	}

	RETURN_META_VALUE(MRES_IGNORED, true);
}

bool D2Fixups::GetLibraryInfo(GameLibraryType type, LibraryInfo &libraryInfo)
{
	void *libraryPtr;

	switch (type)
	{
	case Engine:
		libraryPtr = (void*)g_SMAPI->GetEngineFactory(false);
		break;
	case Server:
		libraryPtr = (void*)g_SMAPI->GetServerFactory(false);
		break;
	default:
		return false;
	}

	if (!libraryPtr)
		return false;

#if defined(WIN32)
	MEMORY_BASIC_INFORMATION mem;

	if (!VirtualQuery(libraryPtr, &mem, sizeof(mem)))
		return false;

	IMAGE_DOS_HEADER *dos = reinterpret_cast<IMAGE_DOS_HEADER *>(mem.AllocationBase);
	IMAGE_NT_HEADERS *pe = reinterpret_cast<IMAGE_NT_HEADERS *>((intp)dos + dos->e_lfanew);

	if (pe->Signature != IMAGE_NT_SIGNATURE)
	{
		// GetDllMemInfo failedpe points to a bad location
		return false;
	}

	libraryInfo.base = mem.AllocationBase;
	libraryInfo.size = pe->OptionalHeader.SizeOfImage;
#elif defined(POSIX)
	Dl_info info;
	uint32_t segmentCount;
	size_t memorySize = 0;

	if (!dladdr(libraryPtr, &info) || !info.dli_fbase || !info.dli_fname)
		return false;

#if defined(LINUX)
	Elf32_Ehdr *file = reinterpret_cast<Elf32_Ehdr *>(info.dli_fbase);
	Elf32_Phdr *phdr = reinterpret_cast<Elf32_Phdr *>((intp)file + file->e_phoff);

	if (memcmp(ELFMAG, file->e_ident, SELFMAG) != 0)
		return false;

	segmentCount = file->e_phnum;

	for (uint32_t i = 0; i < segmentCount; i++)
	{
		if (phdr[i].p_type == PT_LOAD && phdr[i].p_flags == (PF_X|PF_R))
			memorySize += PAGE_ALIGN_UP(phdr[i].p_filesz);
	}
#elif defined(OSX)
	struct mach_header *file = reinterpret_cast<struct mach_header *>(info.dli_fbase);
	struct segment_command *seg = reinterpret_cast<struct segment_command *>((intp)file + sizeof(mach_header));

	if (file->magic != MH_MAGIC)
		return false;

	segmentCount = file->ncmds;

	for (uint32_t i = 0; i < segmentCount; i++)
	{
		if (seg->cmd == LC_SEGMENT)
			memorySize += seg->vmsize;
		seg = reinterpret_cast<struct segment_command *>((intp)seg + seg->cmdsize);
	}
#endif // LINUX || OSX

	libraryInfo.base = info.dli_fbase;
	libraryInfo.size = memorySize;
#endif // POSIX

	return true;
}

void *D2Fixups::FindPatchAddress(const char *sig, size_t len, GameLibraryType type)
{
	bool found;
	char *ptr, *end;
	LibraryInfo info;

	if (!GetLibraryInfo(type, info))
		return NULL;

	ptr = reinterpret_cast<char *>(info.base);
	end = ptr + info.size - len;
	
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

void *D2Fixups::ResolveSymbol(const char *symbol, GameLibraryType type)
{
	LibraryInfo info;

	if (!GetLibraryInfo(type, info))
		return NULL;

#if defined(WIN32)
	// No hidden symbols on Windows
	return GetProcAddress((HMODULE)info.base, symbol);
#elif defined(LINUX)
	// Symbols are stripped on Linux, so just use dlsym() for any visible symbols

	Dl_info dlinfo;
	void *handle;
	void *symAddr;

	if (!dladdr(info.base, &dlinfo))
		return NULL;

	handle = dlopen(dlinfo.dli_fname, RTLD_NOLOAD);

	if (!handle)
		return NULL;

	symAddr = dlsym(handle, symbol);
	dlclose(handle);

	return symAddr;
#elif defined(OSX)

	uintptr_t linkEditAddr;
	struct mach_header *file;
	struct load_command *loadcmds;
	struct segment_command *linkEditHdr;
	struct symtab_command *symTabHdr;
	struct nlist *symtab;
	const char *strtab;
	uint32_t loadcmdCount;
	uint32_t symbolCount;

	linkEditHdr = NULL;
	symTabHdr = NULL;

	file = reinterpret_cast<struct mach_header *>(info.base);
	loadcmds = reinterpret_cast<struct load_command *>((intp)info.base + sizeof(mach_header));
	loadcmdCount = file->ncmds;

	for (uint32_t i = 0; i < loadcmdCount; i++)
	{
		if (loadcmds->cmd == LC_SEGMENT && !linkEditHdr)
		{
			struct segment_command *seg = reinterpret_cast<struct segment_command *>(loadcmds);
			if (strcmp(seg->segname, "__LINKEDIT") == 0)
			{
				linkEditHdr = seg;
				if (symTabHdr)
					break;
			}
		}
		else if (loadcmds->cmd == LC_SYMTAB)
		{
			symTabHdr = reinterpret_cast<struct symtab_command *>(loadcmds);
			if (linkEditHdr)
				break;
		}

		loadcmds = reinterpret_cast<struct load_command *>((intp)loadcmds + loadcmds->cmdsize);
	}

	if (!linkEditHdr || !symTabHdr || !symTabHdr->symoff || !symTabHdr->stroff)
		return NULL;

	linkEditAddr = (intp)info.base + linkEditHdr->vmaddr;
	symtab = reinterpret_cast<struct nlist *>(linkEditAddr + symTabHdr->symoff - linkEditHdr->fileoff);
	strtab = reinterpret_cast<const char *>(linkEditAddr + symTabHdr->stroff - linkEditHdr->fileoff);
	symbolCount = symTabHdr->nsyms;

	for (uint32_t i = 0; i < symbolCount; i++)
	{
		struct nlist &sym = symtab[i];

		// Skip undefined symbols
		if (sym.n_sect == NO_SECT)
			continue;

		// Ignore prepended underscore on symbol name comparison
		if (strcmp(symbol, strtab + sym.n_un.n_strx + 1) == 0)
			return reinterpret_cast<void *>((intp)info.base + sym.n_value);
	}

	return NULL;
#endif
}

bool D2Fixups::Hook_GameInit()
{
	static ConVarRef dota_local_addon_game("dota_local_addon_game");

	// If we're not running a custom game when 'map' is executed, then nothing to do.
	const char *pszDesiredAddon = dota_local_addon_game.GetString();
	if (!pszDesiredAddon[0])
	{
		RETURN_META_VALUE(MRES_IGNORED, true);
	}

	// This should be our 'dota' gamedir.
	char modPath[MAX_PATH];
	filesystem->GetSearchPath("MOD", false, modPath, sizeof(modPath));

	// This is the full path to the addon we want.
	char desiredAddonPath[MAX_PATH];
	V_snprintf(desiredAddonPath, sizeof(desiredAddonPath), "%s%s" CORRECT_PATH_SEPARATOR_S "%s" CORRECT_PATH_SEPARATOR_S, modPath, "addons", pszDesiredAddon);

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

	RefreshWaitForPlayersCount();

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
	m_iRetrieveMsgHookPost = SH_ADD_HOOK(ISteamGameCoordinator, RetrieveMessage, gamecoordinator, SH_MEMBER(this, &D2Fixups::Hook_RetrieveMessagePost), true);

	RETURN_META(MRES_IGNORED);
}

EGCResults D2Fixups::Hook_RetrieveMessage(uint32 *punMsgType, void *pubDest, uint32 cubDest, uint32 *pcubMsgSize)
{
	if (!d2f_blockgc_server_command.GetBool())
	{
		RETURN_META_VALUE(MRES_IGNORED, k_EGCResultOK);
	}

	EGCResults ret = SH_CALL(gamecoordinator, &ISteamGameCoordinator::RetrieveMessage)(punMsgType, pubDest, cubDest, pcubMsgSize);
	uint32 msgType = *punMsgType & ~MSG_PROTOBUF_BIT;

	switch (msgType)
	{
	case k_EMsgGCGCToRelayConnect:
	case k_EMsgGCToServerConsoleCommand:
		RETURN_META_VALUE(MRES_SUPERCEDE, k_EGCResultNoMessage);
	}

	RETURN_META_VALUE(MRES_SUPERCEDE, ret);
}

EGCResults D2Fixups::Hook_RetrieveMessagePost(uint32 *punMsgType, void *pubDest, uint32 cubDest, uint32 *pcubMsgSize)
{
	uint32 msgType = *punMsgType & ~MSG_PROTOBUF_BIT;

	switch (msgType)
	{
	case k_EMsgGCServerWelcome:
		m_iCheatGameVersionCount = 2;
		break;
	case k_EMsgGCServerVersionUpdated:
		m_iCheatGameVersionCount = 1;
		break;
	}

	RETURN_META_VALUE(MRES_IGNORED, k_EGCResultOK);
}

int D2Fixups::Hook_GetServerVersion()
{
	// After the initial GC welcome or a GC server update notice, the game server will
	// query its server version from the engine to see if it's out of date. That check has
	// the handy logic of just skipping the check if either server or GC version are 0.

	if (m_iCheatGameVersionCount)
	{
		--m_iCheatGameVersionCount;
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
	return "2.0.2";
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
