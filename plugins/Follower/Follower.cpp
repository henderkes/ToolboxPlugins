#include "stl.h"
#include "Follower.h"

#include <GWCA/GWCA.h>
#include <GWCA/GameEntities/Party.h>
#include <GWCA/Utilities/Hooker.h>
#include <GWCA/Managers/PartyMgr.h>

#include "GWCA/GameEntities/Agent.h"
#include "GWCA/Managers/AgentMgr.h"

namespace {
    int following_index = -1;
    int polling_rate = 1000;
}

DLLAPI ToolboxPlugin* ToolboxPluginInstance()
{
    static Follower instance;
    return &instance;
}

void Follower::Initialize(ImGuiContext* ctx, const ImGuiAllocFns fns, const HMODULE toolbox_dll)
{
    ToolboxUIPlugin::Initialize(ctx, fns, toolbox_dll);

    GW::Initialize();
}

void Follower::Update(const float diff)
{
    ToolboxUIPlugin::Update(diff);
    const auto time = clock();
    static auto last_update_time = time;
    if (time - last_update_time < polling_rate) {
        return;
    }
    if (following_index == -1) {
        return;
    }
    const auto me = GW::Agents::GetControlledCharacter();
    if (!me || me->GetIsDead()) return;
    const auto party = GW::PartyMgr::GetPartyInfo();
    if (!party) {
        return;
    }
    GW::Agent* target = nullptr;
    if (following_index < party->players.size()) {
        const auto player = party->players[following_index];
        target = GW::Agents::GetPlayerByID(player.login_number);
    }
    else if (following_index < party->players.size() + party->heroes.size()) {
        const auto hero = party->heroes[following_index - party->players.size()];
        target = GW::Agents::GetAgentByID(hero.agent_id);
    }
    else if (following_index < party->players.size() + party->heroes.size() + party->henchmen.size()) {
        const auto henchman = party->henchmen[following_index - party->players.size() - party->heroes.size()];
        target = GW::Agents::GetAgentByID(henchman.agent_id);
    }
    if (target && target != reinterpret_cast<GW::Agent*>(me)) {
        GW::Agents::InteractAgent(target);
    }
}

void Follower::Draw(IDirect3DDevice9* direct_3d_device9)
{
    ImGui::Begin(Name(), GetVisiblePtr(), GetWinFlags(ImGuiWindowFlags_AlwaysAutoResize));
    ImGui::Text("Select the index to follow.");
    if (ImGui::Selectable("Off", following_index == -1)) {
        following_index = -1;
    }
    for (int i = 0; i < GW::PartyMgr::GetPartySize(); ++i) {
        if (ImGui::Selectable(std::to_string(i).c_str(), following_index == i)) {
            following_index = i;
        }
    }
    ImGui::End();
}

void Follower::SignalTerminate()
{
    ToolboxUIPlugin::SignalTerminate();
    GW::DisableHooks();
}

bool Follower::CanTerminate()
{
    return GW::Hook::GetInHookCount() == 0;
}

void Follower::Terminate()
{
    ToolboxUIPlugin::Terminate();
    GW::Hook::Deinitialize();
}

void Follower::LoadSettings(const wchar_t* folder)
{
    ToolboxUIPlugin::LoadSettings(folder);

    polling_rate = ini.GetLongValue(Name(), "polling_rate", polling_rate);
    following_index = ini.GetLongValue(Name(), "following_index", following_index);
}

void Follower::SaveSettings(const wchar_t* folder)
{
    ToolboxUIPlugin::SaveSettings(folder);
    ini.SetLongValue(Name(), "polling_rate", polling_rate);
    ini.SetLongValue(Name(), "following_index", following_index);

    PLUGIN_ASSERT(ini.SaveFile(GetSettingFile(folder).c_str()) == SI_OK);
}

void Follower::DrawSettings()
{
    ToolboxUIPlugin::DrawSettings();
    ImGui::SliderInt("Polling rate (ms)", &polling_rate, 0, 10'000);
}
