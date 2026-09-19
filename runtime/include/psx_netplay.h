#ifndef PSX_NETPLAY_H
#define PSX_NETPLAY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * psx_netplay — two machines, one match.
 *
 * The NeoGeo Hub Online client owns everything about accounts, matches and
 * brackets. It launches this process with a loopback channel in the
 * environment; everything below is the runtime's half of that conversation.
 *
 * The netcode is lockstep, not rollback: both machines restart from the same
 * point and run the same frames from the same inputs, so nothing but a pad
 * word per frame ever crosses the network. That is why a session begins by
 * restarting both games — agreeing on nothing is far cheaper than agreeing on
 * everything, and it is why no save state, memory dump or progression data is
 * ever transferred.
 *
 * The restart is not a re-launch: it is a restore of the complete machine
 * snapshot taken the moment the guest first reached the game's entry PC, using
 * the same serializer and the same block-leader boundary a user save state
 * uses (savestate.h). Both machines took that snapshot at the same guest
 * instant, so restoring it puts them on the same frame with the same RAM, VRAM,
 * SPU, CD and timer state, and the first lockstep frame is frame 0 on both.
 *
 * Determinism is the whole contract, so a netplay run is pinned by the host
 * (see main.cpp): both ports present the same pad the game asked for rather
 * than whatever each player happens to have plugged in, both memory cards are
 * absent (a card's contents are per-player, and a game that read them would
 * diverge on the first read), and the local pad reaches the guest only through
 * the session.
 *
 * Everything here is a no-op when the process was started by a player rather
 * than by the Online client, which is the ordinary single-player case.
 *
 * What this module deliberately does NOT do is decide who won. A recompiled
 * title has no portable notion of a score, and inventing one per game is the
 * kind of per-game special case this project does not allow. The players report
 * the result in the Online client, which already has a screen for it; all the
 * runtime reports is that the match ended, and why.
 */

/* The two guest ports for one frame, as the session agreed them. */
typedef struct {
    uint16_t buttons[2]; /* PSX active-low pad word, index 0 = port 1 */
    uint8_t  axes[2][4]; /* lx, ly, rx, ry — 0..255, 128 at rest        */
} PsxNetplayPads;

/* Session state for the pause menu's ONLINE panel. */
typedef struct {
    int          available;      /* the Online client launched this process       */
    int          active;         /* a session channel is open                     */
    int          running;        /* frames are being exchanged                    */
    int          reset_ready;    /* the restart point has been captured           */
    int          connected;      /* this machine has said it is ready to restart  */
    int          can_connect;    /* the Connect action would do something now     */
    int          tournament;     /* a bracket match rather than a casual set      */
    int          local_slot;     /* 1 or 2 — which port this player holds         */
    int          peer_present;   /* the opponent has joined the session           */
    int          direct;         /* peer-to-peer rather than relayed              */
    int          round_trip_ms;
    int          input_delay;    /* frames of delay the session runs with         */
    unsigned int frame;          /* frames played so far                          */
    unsigned int stalled_frames; /* frames spent waiting on the opponent          */
    long long    starts_in_ms;   /* until the shared restart; -1 = unscheduled    */
    char         state[24];      /* offline|connecting|waiting|countdown|         */
                                 /* restarting|playing|finished|error             */
    char         opponent[64];
    char         label[96];      /* "Ada vs Grace", from the organizer            */
    char         message[192];   /* the last thing worth telling the player       */
} PsxNetplayStatus;

/* Reasons a match ended, for psx_netplay_leave. */
enum {
    PSX_NETPLAY_LEFT_FINISHED = 0,
    PSX_NETPLAY_LEFT_QUIT     = 1,
};

/* True when the Online client launched this process. Cheap; reads the
 * environment and opens nothing. Call it before configuring pads and memory
 * cards, because a netplay run pins both. */
int  psx_netplay_available(void);

/* Open the session channel. Returns 1 when a session is being negotiated. */
int  psx_netplay_start(const char* product, const char* version);
void psx_netplay_shutdown(void);

int  psx_netplay_active(void);
int  psx_netplay_running(void);

/* Service the channel and the transport. Safe (and required) in every phase,
 * including while the pause menu holds the guest: the opponent is still there
 * and still waiting, and the path to them is still being probed. */
void psx_netplay_update(void);

/* What this machine is about to play. The organizer refuses to pair two players
 * whose digests differ rather than let them desync three seconds in, so this
 * should name the disc AND the build: same game, different recompiler output is
 * still two different machines. */
void psx_netplay_set_content(const char* digest);

/* The restart point has been written (ok = 1) or could not be (ok = 0). Until
 * it exists there is nothing to restart to, so the match cannot be joined. */
void psx_netplay_note_reset_point(int ok);

/* Returns 1 exactly once, on the frame both machines must restart. */
int  psx_netplay_take_reset_request(void);
/* The machine is back at the game's entry point (ok = 1), or the restore could
 * not be honoured (ok = 0), which ends the match rather than playing on out of
 * step with the opponent. */
void psx_netplay_note_reset_done(int ok);

/* One frame of input. local_buttons / local_axes are this player's own pad.
 * Returns 1 when the frame may run, with out holding both guest ports; returns
 * 0 while the opponent's input for this frame has not arrived, in which case
 * the caller must not run the frame — hold the machine and try again. Check
 * psx_netplay_running() after a 0: the session may have ended rather than
 * stalled. Never blocks. */
int  psx_netplay_frame(uint16_t local_buttons, const uint8_t local_axes[4],
                       PsxNetplayPads* out);

/* A hash of whatever must match on both machines. Submitted about once a
 * second, this is how a desync is caught in the second it happens instead of
 * at the end of a match nobody can score. */
void psx_netplay_submit_checksum(uint32_t checksum);

/* The pause menu's ONLINE panel. */
void psx_netplay_status(PsxNetplayStatus* out);
/* "Connect player 2": tell the organizer this machine is loaded and ready to
 * restart. A bracket match does this by itself — the player already accepted
 * the match in the Online client, and a tournament is meant to run without
 * anyone pressing anything. A casual set waits for this. */
void psx_netplay_connect(void);
void psx_netplay_leave(int reason);

#ifdef __cplusplus
}
#endif

#endif /* PSX_NETPLAY_H */
