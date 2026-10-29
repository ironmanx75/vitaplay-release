/*
 * vitabt minimal example — the smallest useful driver of the iAP2 byte pipe.
 *
 * It waits for an iPhone to connect (vpbt_status), runs the iap2c link over the pipe until it
 * reaches NORMAL, and logs each iAP2 control message the phone sends (the first will be 0x1D00,
 * StartIdentification). From there a real accessory would answer identification, MFi authentication
 * and the Wi-Fi/CarPlay handoff — see vitaplay/src/btboot.c + iap2_ident.c in this repo for the
 * full worked version.
 *
 * This is illustrative: it is not a complete VPK on its own. Build it against the iap2c link layer
 * and link the plugin's weak stub (see README.md). The plugin must be boot-loaded via taiHEN
 * config.txt first.
 */
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/threadmgr.h>
#include <stdio.h>

#include "vitaplaybt.h"     /* vitabt/include */
#include "iap2_link.h"      /* vitabt/iap2c  */

static int64_t now_ms(void) { return (int64_t)(sceKernelGetProcessTimeWide() / 1000); }

int main(void) {
    iap2_link *link = NULL;

    for (;;) {
        int up = vpbt_status();

        if (up == 1 && !link) {
            /* Fresh connection: start the link. We are the accessory, so on Bluetooth the iPhone
             * initiates synchronization -> start as a non-initiator. */
            iap2_link_config cfg;
            iap2_link_config_wireless(&cfg);
            link = iap2_link_new(&cfg);
            if (link) iap2_link_start(link, false, now_ms());
        } else if (up != 1 && link) {
            /* iPhone dropped the DLC: tear down and wait for the next connection. */
            iap2_link_free(link);
            link = NULL;
        }

        if (link) {
            int64_t t = now_ms();

            /* 1. Pump inbound bytes from the pipe into the link. */
            unsigned char buf[512];
            int n;
            while ((n = vpbt_read(buf, sizeof(buf))) > 0) iap2_link_feed(link, buf, (size_t)n, t);

            /* 2. Run any due link timer. */
            int64_t deadline = iap2_link_next_deadline(link);
            if (deadline >= 0 && t >= deadline) iap2_link_advance(link, t);

            /* 3. Flush the link's outbound bytes back to the pipe. */
            unsigned char out[512];
            size_t m;
            while ((m = iap2_link_output(link, out, sizeof(out))) > 0) vpbt_write(out, (int)m);

            /* 4. Handle events: each CONTROL event is one iAP2 CSM message (40 40 | len | msgId). */
            iap2_link_event ev;
            while (iap2_link_poll_event(link, &ev)) {
                if (ev.type == IAP2_LINK_EVENT_CONTROL && ev.len >= 6) {
                    unsigned msgid = (ev.data[4] << 8) | ev.data[5];
                    printf("iAP2 control msgid=0x%04x len=%u\n", msgid, (unsigned)ev.len);
                    /* Answer 0x1D00 with IdentificationInformation (0x1D01), then MFi, then the
                     * Wi-Fi/CarPlay handoff — see the worked driver referenced above. */
                }
            }
        }

        sceKernelDelayThread(5000); /* 5 ms: responsive without busy-spinning */
    }

    if (link) iap2_link_free(link);
    sceKernelExitProcess(0);
    return 0;
}
