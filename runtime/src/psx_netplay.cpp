/* psx_netplay.cpp — the runtime's half of a NeoGeo Hub Online match.
 *
 * See psx_netplay.h for the model. This file is deliberately thin: the whole
 * protocol — the loopback channel to the Online client, the relay binding, the
 * hole punching, the lockstep ring and the desync detector — lives in the
 * netplay library the client and every game share, so a recompiled PlayStation
 * title, an engine game and the client cannot drift apart in their idea of what
 * a frame is. What is left here is the runtime's own policy: when the restart
 * point exists, when this machine is ready, and how a session's state reads to
 * a player looking at the pause menu.
 */

#include "psx_netplay.h"

#include "netplay/NetplayClient.h"

#include <cstdio>
#include <cstring>
#include <string>

namespace np = neogeohub::netplay;

namespace {

np::NetplayClient s_client;
bool        s_started     = false;   /* the channel was opened                   */
bool        s_reset_ready = false;   /* the restart snapshot exists              */
bool        s_connected   = false;   /* we told the organizer we are ready       */
bool        s_reset_asked = false;   /* a restart request is waiting to be taken */
bool        s_restarting  = false;   /* taken, and the restore has not finished  */
std::string s_digest;
std::string s_note;                  /* the runtime's own last word to the player */

void copy_into(char* dst, std::size_t cap, const std::string& text) {
    if (cap == 0) return;
    const std::size_t n = text.size() < cap - 1 ? text.size() : cap - 1;
    std::memcpy(dst, text.data(), n);
    dst[n] = '\0';
}

bool is_tournament() { return s_client.session().kind == "tournament"; }

const char* state_name(np::NetplayPhase phase) {
    switch (phase) {
        case np::NetplayPhase::Offline:      return "offline";
        case np::NetplayPhase::Connecting:   return "connecting";
        case np::NetplayPhase::Waiting:      return "waiting";
        case np::NetplayPhase::Countdown:    return "countdown";
        case np::NetplayPhase::ResetPending: return "restarting";
        case np::NetplayPhase::Running:      return "playing";
        case np::NetplayPhase::Finished:     return "finished";
        case np::NetplayPhase::Error:        return "error";
    }
    return "offline";
}

/* Say it once. The channel is polled every frame, so anything printed from a
 * state test would otherwise print sixty times a second. */
void note(const std::string& text) {
    if (text == s_note) return;
    s_note = text;
    std::fprintf(stdout, "psxrecomp/online: %s\n", text.c_str());
    std::fflush(stdout);
}

} // namespace

int psx_netplay_available(void) { return np::SessionBridge::available() ? 1 : 0; }

int psx_netplay_start(const char* product, const char* version) {
    if (s_started) return 1;
    if (!np::SessionBridge::available()) return 0;
    if (!s_client.start(product ? product : "psxrecomp", version ? version : "0")) {
        note("could not reach the Online client: " + s_client.message());
        return 0;
    }
    s_started = true;
    note("connected to the Online client; waiting for the match");
    return 1;
}

void psx_netplay_shutdown(void) {
    if (!s_started) return;
    s_client.shutdown();
    s_started = false;
    s_reset_ready = false;
    s_connected = false;
    s_reset_asked = false;
    s_restarting = false;
}

int psx_netplay_active(void) {
    return s_started && s_client.phase() != np::NetplayPhase::Offline ? 1 : 0;
}

int psx_netplay_running(void) { return s_started && s_client.isRunning() ? 1 : 0; }

void psx_netplay_update(void) {
    if (!s_started) return;
    s_client.update();

    /* A bracket match starts itself. The player accepted it in the Online
     * client and the organizer scheduled it; making them press a button here
     * would only be a way for a tournament to stall on someone who walked
     * away. A casual set is the opposite case, and waits for the panel. */
    if (s_reset_ready && !s_connected && is_tournament()) {
        psx_netplay_connect();
    }

    if (!s_restarting && s_client.consumeResetRequest()) {
        s_reset_asked = true;
        s_restarting = true;
    }
    if (!s_client.message().empty()) note(s_client.message());
}

void psx_netplay_set_content(const char* digest) {
    s_digest = digest ? digest : "";
}

void psx_netplay_note_reset_point(int ok) {
    if (!s_started || s_reset_ready) return;
    if (!ok) {
        note("this machine has no restart point, so the match cannot be played; "
             "leaving it to your opponent");
        s_client.abort(np::QuitReason::PlayerLeft);
        return;
    }
    s_reset_ready = true;
    note(is_tournament() ? "ready — the match will restart both games automatically"
                         : "ready — open the pause menu and connect to start the match");
}

int psx_netplay_take_reset_request(void) {
    if (!s_reset_asked) return 0;
    s_reset_asked = false;
    return 1;
}

void psx_netplay_note_reset_done(int ok) {
    if (!s_started) return;
    s_restarting = false;
    if (!ok) {
        note("the game could not be restarted, so the match was stopped");
        s_client.abort(np::QuitReason::PlayerLeft);
        return;
    }
    s_client.confirmReset();
}

int psx_netplay_frame(uint16_t local_buttons, const uint8_t local_axes[4],
                      PsxNetplayPads* out) {
    if (!s_started || !s_client.isRunning() || out == nullptr) return 0;

    np::Input local;
    local.buttons = local_buttons;
    if (local_axes != nullptr) {
        for (int i = 0; i < 4; ++i) local.axes[i] = local_axes[i];
    }
    if (!s_client.advance(local)) return 0;

    for (int slot = 1; slot <= 2; ++slot) {
        const np::Input& in = s_client.input(slot);
        out->buttons[slot - 1] = in.buttons;
        for (int i = 0; i < 4; ++i) out->axes[slot - 1][i] = in.axes[i];
    }
    return 1;
}

void psx_netplay_submit_checksum(uint32_t checksum) {
    if (!s_started || !s_client.isRunning()) return;
    s_client.submitChecksum(checksum);
}

void psx_netplay_status(PsxNetplayStatus* out) {
    if (out == nullptr) return;
    std::memset(out, 0, sizeof(*out));
    out->available = np::SessionBridge::available() ? 1 : 0;
    out->starts_in_ms = -1;
    if (!s_started) {
        copy_into(out->state, sizeof(out->state), "offline");
        return;
    }

    const np::SessionInfo& info = s_client.session();
    const np::SessionStats stats = s_client.stats();

    out->active = psx_netplay_active();
    out->running = psx_netplay_running();
    out->reset_ready = s_reset_ready ? 1 : 0;
    out->connected = s_connected ? 1 : 0;
    out->can_connect = (out->active && s_reset_ready && !s_connected) ? 1 : 0;
    out->tournament = is_tournament() ? 1 : 0;
    out->local_slot = info.localSlot;
    out->direct = stats.path == np::LinkPath::Direct ? 1 : 0;
    out->round_trip_ms = static_cast<int>(stats.roundTripMillis);
    out->input_delay = info.inputDelay;
    out->frame = stats.frame;
    out->stalled_frames = stats.stalledFrames;
    out->starts_in_ms = s_client.millisUntilReset();
    copy_into(out->state, sizeof(out->state), state_name(s_client.phase()));
    copy_into(out->label, sizeof(out->label), info.label);
    if (const np::PeerInfo* other = info.opponent()) {
        out->peer_present = other->connected ? 1 : 0;
        copy_into(out->opponent, sizeof(out->opponent), other->name);
    }
    copy_into(out->message, sizeof(out->message),
      s_client.message().empty() ? s_note : s_client.message());
}

void psx_netplay_connect(void) {
    if (!s_started || s_connected || !s_reset_ready) return;
    s_connected = true;
    /* The digest is what stops two players on different discs — or on different
     * recompiler output — from being paired at all. */
    s_client.markContentReady(s_digest);
    note("waiting for your opponent; both games restart together");
}

void psx_netplay_leave(int reason) {
    if (!s_started) return;
    s_client.abort(reason == PSX_NETPLAY_LEFT_FINISHED ? np::QuitReason::Finished
                                                       : np::QuitReason::PlayerLeft);
    s_connected = false;
    s_reset_asked = false;
    s_restarting = false;
}
