/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#include "hal/ccm.h"

#include "util/util.h"
#include "util/memq.h"

#include "pdu_df.h"
#include "lll/pdu_vendor.h"
#include "pdu.h"

#include "lll.h"
#include "lll_sync_iso.h"

#include "bison_sniff.h"

static struct bison_snapshot snap;
static struct k_spinlock     snap_lock;

static uint32_t pending_anchor_ticks;

void bison_sniff_set_anchor(uint32_t ticks_at_event)
{
	pending_anchor_ticks = ticks_at_event;
}

void bison_sniff_pdu_hdr(const struct pdu_bis *pdu)
{
	k_spinlock_key_t key;

	if (!pdu) {
		return;
	}

	key = k_spin_lock(&snap_lock);
	/* The first byte of the PDU carries ll_id (bits 0-1),
	 * cssn (bits 2-4), cstf (bit 5), rfu (bits 6-7). Store
	 * it raw so the shell can print the exact wire byte.
	 */
	snap.pdu_hdr_last_byte = ((uint8_t *)pdu)[0];
	if (pdu->cstf) {
		snap.cstf_observed_count++;
	}
	snap.cssn_data_last = (uint8_t)pdu->cssn;
	snap.data_pdu_snoop_count++;
	k_spin_unlock(&snap_lock, key);
}

void bison_sniff_note_hijack_fired(void)
{
	k_spinlock_key_t key;

	key = k_spin_lock(&snap_lock);
	snap.hijack_fired_count++;
	k_spin_unlock(&snap_lock, key);
}

void bison_sniff_note_hijack_chain_armed(uint32_t start_us, uint8_t chan,
					  const uint8_t aa[4])
{
	k_spinlock_key_t key;

	key = k_spin_lock(&snap_lock);
	snap.hijack_chain_armed_count++;
	snap.hijack_last_chain_start_us = start_us;
	snap.hijack_last_chain_chan     = chan;
	memcpy(snap.hijack_last_chain_aa, aa, 4);
	k_spin_unlock(&snap_lock, key);
}

void bison_sniff_note_hijack_tx_done(void)
{
	k_spinlock_key_t key;

	key = k_spin_lock(&snap_lock);
	snap.hijack_tx_done_count++;
	k_spin_unlock(&snap_lock, key);
}

bool bison_sniff_snapshot(struct bison_snapshot *out)
{
	k_spinlock_key_t key;
	bool valid;

	if (!out) {
		return false;
	}

	key = k_spin_lock(&snap_lock);
	valid = snap.valid;
	if (valid) {
		*out = snap;
	}
	k_spin_unlock(&snap_lock, key);

	return valid;
}

void bison_sniff_isr_update(const struct lll_sync_iso *lll,
			    uint16_t event_counter)
{
	uint32_t anchor_ticks = pending_anchor_ticks;
	k_spinlock_key_t key;

	if (!lll) {
		return;
	}

	key = k_spin_lock(&snap_lock);

	snap.valid = true;

	memcpy(snap.seed_access_addr, lll->seed_access_addr,
	       sizeof(snap.seed_access_addr));
	memcpy(snap.base_crc_init, lll->base_crc_init,
	       sizeof(snap.base_crc_init));

	snap.iso_interval     = lll->iso_interval;
	snap.sub_interval_us  = lll->sub_interval;
	snap.bis_spacing_us   = lll->bis_spacing;
	snap.num_bis          = lll->num_bis;
	snap.nse              = lll->nse;
	snap.bn               = lll->bn;
	snap.irc              = lll->irc;
	snap.pto              = lll->pto;
	snap.phy              = lll->phy;
	snap.framing          = (uint8_t)lll->framing;
	snap.encrypted        = (uint8_t)lll->enc;
	snap.max_pdu          = lll->max_pdu;

	memcpy(snap.data_chan_map, lll->data_chan_map,
	       sizeof(snap.data_chan_map));
	snap.data_chan_count = lll->data_chan_count;

	if (lll->chm_chan_count) {
		snap.chm_update_pending = true;
		memcpy(snap.chm_chan_map, lll->chm_chan_map,
		       sizeof(snap.chm_chan_map));
		snap.chm_chan_count = lll->chm_chan_count;
		snap.ctrl_instant   = lll->ctrl_instant;
	} else {
		snap.chm_update_pending = false;
	}

	snap.payload_count = lll->payload_count;
	snap.event_counter = event_counter;
	snap.anchor_ticks  = anchor_ticks;
	snap.cssn_curr     = (uint8_t)lll->cssn_curr;
	snap.cssn_next     = (uint8_t)lll->cssn_next;

	k_spin_unlock(&snap_lock, key);

}
