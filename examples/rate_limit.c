// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/*
 * Rate limit packets per source IP.
 *
 * Implements a fixed-window rate limit with the source IP state table: each
 * source IP may send at most RATE_LIMIT packets per WINDOW_SECONDS. State is
 * kept per Cloudflare server, so the limit applies to the traffic that each
 * server receives, not to the global traffic from a source IP.
 */

#define CF_EBPF_HELPER_V0

#include <cf_ebpf_defs.h>
#include <cf_ebpf_helper.h>

#define RATE_LIMIT 100     /* Packets allowed per window. */
#define WINDOW_SECONDS 10  /* Window length in seconds. */

/*
 * The source IP state table stores one u64 of user data per source IP. Pack
 * the window start time (upper 32 bits) and the packet count (lower 32 bits)
 * into it.
 */
#define PACK_STATE(start, count) (((uint64_t)(start) << 32) | (uint32_t)(count))
#define STATE_START(data) ((uint32_t)((data) >> 32))
#define STATE_COUNT(data) ((uint32_t)(data))

uint64_t cf_ebpf_main(void *state)
{
    (void)state; /* This program does not inspect packet contents. */

    int64_t now = timestamp();
    if (now < 0) {
        return CF_EBPF_PASS;
    }
    uint32_t now_secs = (uint32_t)now;

    uint64_t data;
    uint32_t window_start;
    uint32_t count;

    int ret = get_src_ip_data(&data);
    if (ret == -1) {
        /* No entry: first packet from this source IP. */
        window_start = now_secs;
        count = 1;
    } else if (ret != 0) {
        /* Any other error, for example state not enabled: fail open. */
        return CF_EBPF_PASS;
    } else {
        window_start = STATE_START(data);
        count = STATE_COUNT(data);

        if (now_secs - window_start >= WINDOW_SECONDS) {
            /* The window has ended: start a new one. */
            window_start = now_secs;
            count = 1;
        } else if (count >= RATE_LIMIT) {
            /* Over the limit for this window. */
            return CF_EBPF_DROP;
        } else {
            count++;
        }
    }

    set_src_ip_data(PACK_STATE(window_start, count));
    return CF_EBPF_PASS;
}
