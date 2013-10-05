#ifndef _INCLUDE_METAMOD_SOURCE_STUB_PLUGIN_H_
#define _INCLUDE_METAMOD_SOURCE_STUB_PLUGIN_H_

#include <ISmmPlugin.h>

enum PatchAddressType
{
	Engine,
	Server,
};

class D2Fixups : public ISmmPlugin
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

private:
	bool InitGlobals(char *error, size_t maxlen);
	void InitHooks();
	void ShutdownHooks();

public:
	static void *FindPatchAddress(const char *sig, size_t len, PatchAddressType type);

private:
	bool SteamIDAllowedToConnect(const CSteamID &steamId) const;
};

extern D2Fixups g_D2Fixups;

PLUGIN_GLOBALVARS();

#endif //_INCLUDE_METAMOD_SOURCE_STUB_PLUGIN_H_
