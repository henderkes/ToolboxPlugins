#include "TargetEverything.h"

#include <GWCA/GWCA.h>
#include <GWCA/Managers/AgentMgr.h>
#include <GWCA/Managers/ChatMgr.h>
#include <ToolboxPlugin.h>

#include <GWCA/Utilities/Hooker.h>
#include <GWCA/Utilities/Scanner.h>

using GetIsAgentTargettableFn = decltype(&GW::Agents::GetIsAgentTargettable);
GetIsAgentTargettableFn GetIsAgentTargettable_Func = nullptr;
GetIsAgentTargettableFn RetGetIsAgentTargettable = nullptr;

bool GetIsAgentTargettableOverride(const GW::Agent* agent)
{
    return agent != nullptr;
}

DLLAPI ToolboxPlugin* ToolboxPluginInstance()
{
    static TargetEverything instance;
    return &instance;
}

void TargetEverything::Initialize(ImGuiContext* ctx, const ImGuiAllocFns fns, const HMODULE toolbox_dll)
{
    ToolboxPlugin::Initialize(ctx, fns, toolbox_dll);

    GW::Scanner::Initialize(toolbox_dll);
    // find in ChatCommands::TargetNearest
    if (const auto addr = GW::Scanner::Find("\xE8\xCC\xCC\xCC\xCC\x83\xC4\x04\x0F\xB6\xC8\x85\xC9\x75\x02\xEB\xC6", "x????xxxxxxxxxxxx")) {
        GetIsAgentTargettable_Func = reinterpret_cast<GetIsAgentTargettableFn>(GW::Scanner::FunctionFromNearCall(addr));
    }
    else {
        // RelWithDebInfo toolbox 6.17
        GetIsAgentTargettable_Func = reinterpret_cast<GetIsAgentTargettableFn>(
            GW::Scanner::Find("\x55\x8B\xEC\x8B\x45\x08\x85\xC0\x74\x65", "xxxxxxxxxx")
        );
    }

    if (!GetIsAgentTargettable_Func) {
        GW::Initialize();
        GW::Chat::WriteChat(GW::Chat::CHANNEL_WARNING, L"Failed to find GetIsAgentTargettable_Func in GWToolboxdll.dll", L"TargetEverything");
        GW::Scanner::Initialize();
        GW::Terminate();
        return;
    }
    GW::Hook::Initialize();
    GW::Hook::CreateHook(reinterpret_cast<void**>(&GetIsAgentTargettable_Func), GetIsAgentTargettableOverride, reinterpret_cast<void**>(&RetGetIsAgentTargettable));
    GW::Hook::EnableHooks(GetIsAgentTargettable_Func);
    GW::Scanner::Initialize();
}

void TargetEverything::SignalTerminate()
{
    ToolboxPlugin::SignalTerminate();
    GW::DisableHooks();
}

bool TargetEverything::CanTerminate()
{
    return GW::Hook::GetInHookCount() == 0;
}

void TargetEverything::Terminate()
{
    ToolboxPlugin::Terminate();
    if (GetIsAgentTargettable_Func) {
        GW::Hook::RemoveHook(GetIsAgentTargettable_Func);
    }
    GW::Hook::Deinitialize();
}
