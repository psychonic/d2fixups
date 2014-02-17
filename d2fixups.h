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

#ifndef _INCLUDE_METAMOD_SOURCE_STUB_PLUGIN_H_
#define _INCLUDE_METAMOD_SOURCE_STUB_PLUGIN_H_

#include <ISmmPlugin.h>

#include <igameevents.h>

#include <steam_gameserver.h>
#include <isteamgamecoordinator.h>

#include <sh_list.h>

enum PatchAddressType
{
	Engine,
	Server,
};

class D2Fixups : public ISmmPlugin,
	public IGameEventListener2
{
public: // ISmmPlugin
	bool Load(PluginId id, ISmmAPI *ismm, char *error, size_t maxlen, bool late);
	bool Unload(char *error, size_t maxlen);
	const char *GetAuthor();
	const char *GetName();
	const char *GetDescription();
	const char *GetURL();
	const char *GetLicense();
	const char *GetVersion();
	const char *GetDate();
	const char *GetLogTag();

public: // IGameEventListener2
	void FireGameEvent(IGameEvent *pEvent);
	int GetEventDebugID() { return EVENT_DEBUG_ID_INIT; }

private:
	bool InitGlobals(char *error, size_t maxlen);
	void InitHooks();
	void ShutdownHooks();
	void UnhookGC();

public:
	static void *FindPatchAddress(const char *sig, size_t len, PatchAddressType type);
	static void RefreshWaitForPlayersCount();

private:
	bool Hook_SteamIDAllowedToConnect(const CSteamID &steamId) const;
	bool Hook_IsServerLocalOnly();
	bool Hook_GameInit();
	bool Hook_LevelInit(const char *pMapName, const char *pMapEntities, const char *pOldLevel, const char *pLandmarkName, bool loadGame, bool background);
	bool Hook_LevelInit_Post(const char *pMapName, const char *pMapEntities, const char *pOldLevel, const char *pLandmarkName, bool loadGame, bool background);
	void Hook_GameServerSteamAPIActivated();
	int Hook_GetServerVersion();
	EGCResults Hook_RetrieveMessage(uint32 *punMsgType, void *pubDest, uint32 cubDest, uint32 *pcubMsgSize);
	EGCResults Hook_RetrieveMessagePost(uint32 *punMsgType, void *pubDest, uint32 cubDest, uint32 *pcubMsgSize);

private:
	bool m_bPretendToBeLocal;
	int m_iCheatGameVersionCount;
	int m_iRetrieveMsgHook;
	int m_iRetrieveMsgHookPost;
	SourceHook::List<int> m_GlobalHooks;
};

extern D2Fixups g_D2Fixups;

PLUGIN_GLOBALVARS();

#endif //_INCLUDE_METAMOD_SOURCE_STUB_PLUGIN_H_
