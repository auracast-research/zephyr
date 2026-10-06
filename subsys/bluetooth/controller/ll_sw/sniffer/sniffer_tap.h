/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * BIS/PA LLL packet sniffer.
 *
 * The LLL stashes the RF channel via sniffer_tap_chan_set(); on each
 * BIS RX, sniffer_tap_rx_done() wraps the just-received PDU plus
 * radio/anchor state in a struct sniffer_tap_pdu and publishes it to
 * the registered consumer.
 */

#ifndef ZEPHYR_INCLUDE_BT_CTLR_SNIFFER_TAP_H_
#define ZEPHYR_INCLUDE_BT_CTLR_SNIFFER_TAP_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <cmsis_core.h>

/*
 * Cortex-M4 DWT cycle counter (1-cycle read), used instead of
 * k_cycle_get_32(), which on nRF52 can block ~90 us on an RTC read.
 * Enabled once at boot in sniffer_tap_register().
 */
static inline uint32_t sniffer_tap_dwt_cyc(void)
{
	return DWT->CYCCNT;
}

#define SNIFFER_TAP_PDU_MAX 256

#define SNIFFER_TAP_FLAG_CRC_OK   (1U << 0)
#define SNIFFER_TAP_FLAG_RSSI_VAL (1U << 1)
#define SNIFFER_TAP_FLAG_ENC      (1U << 2)
#define SNIFFER_TAP_FLAG_MIC_OK   (1U << 3)
/* Header-only capture mode, pdu_len still reports the true PDU length, but pdu[] holds only the
 * 2-byte header (LLID + length). The consumer fills the packet with a fake byte pattern.
 */
#define SNIFFER_TAP_FLAG_PAYLOAD_OMITTED (1U << 4)

/* Derived flags for the BIS-record extended metadata (BIS kind only). */
#define SNIFFER_TAP_DFLAG_RETRANSMISSION   (1U << 0)  /* irc_curr > 1: identical retransmission for reliability */
#define SNIFFER_TAP_DFLAG_PRETRANSMISSION  (1U << 1)  /* ptc_curr > 0: pre-transmission of a future-event PDU   */
#define SNIFFER_TAP_DFLAG_CONTROL          (1U << 2)  /* lll->ctrl set at RX time (BIG Control Subevent)         */
#define SNIFFER_TAP_DFLAG_INTERLEAVED      (1U << 3)  /* BIG uses interleaved packing (lll->interleaved)         */
#define SNIFFER_TAP_DFLAG_FIRST_EVENT_RX   (1U << 4)  /* first successful RX in this BIG event (anchor RX)       */
#define SNIFFER_TAP_DFLAG_CIPHERTEXT       (1U << 5)  /* wire was encrypted, PDU bytes emitted as ciphertext + MIC (no bcode) */

#define SNIFFER_TAP_KIND_BIS       0U  /* BIS Data / Control PDU on data channel      */
#define SNIFFER_TAP_KIND_PA        1U  /* Periodic-adv PDU (AUX_SYNC_IND / chain)     */

struct sniffer_tap_pdu {
	uint64_t timestamp_us;    /* device uptime in microseconds              */
	uint32_t access_addr;     /* AA on the wire, little-endian layout       */
	uint16_t event_counter;   /* BIG event counter (BIS kind only)          */
	uint8_t  subevent;        /* linear within-BIS SE index (BIS only)      */
	uint8_t  bis;             /* 1..num_bis (BIS only, 0 otherwise)         */
	uint8_t  chan;            /* 0..36 data channel index                    */
	uint8_t  phy;             /* PHY_1M=1, PHY_2M=2, PHY_CODED=4             */
	int8_t   rssi_dbm;        /* absolute dBm, negative                      */
	uint8_t  flags;           /* SNIFFER_TAP_FLAG_*                          */
	uint8_t  pdu_kind;        /* SNIFFER_TAP_KIND_*                          */
	uint16_t pdu_len;         /* wire bytes in pdu[]: 2 hdr + payload        */

	/* Extended per-PDU BIG state (BIS kind only; zero for PA).  */
	uint8_t  bn_curr;         /* 1..bn                                       */
	uint8_t  irc_curr;        /* 1..irc                                      */
	uint8_t  ptc_curr;        /* 0..ptc                                      */
	uint8_t  cssn_curr;       /* 0..7 snapshot at RX                         */
	uint8_t  cssn_next;       /* 0..7 latest observed from CSTF-flagged PDU  */
	uint8_t  derived;         /* SNIFFER_TAP_DFLAG_* bitmap                  */

	uint16_t seq_ctr;
	uint64_t payload_number;  /* 39-bit BIS payload counter (SDU identifier) */

	const uint8_t *_deferred_raw;   /* NULL = pdu[] already filled in ISR */
	uint16_t       _deferred_len;   /* bytes to memcpy from _deferred_raw */

	uint8_t  pdu[SNIFFER_TAP_PDU_MAX];
};

typedef void (*sniffer_tap_cb_t)(const struct sniffer_tap_pdu *rec);

/**
 * @brief Register a consumer for tap records.
 */
int sniffer_tap_register(sniffer_tap_cb_t cb);

/**
 * @brief Number of PDU records dropped because the ring was full.
 */
uint32_t sniffer_tap_dropped(void);

/**
 * @brief Diagnostic: number of RX ISRs where we identified the current
 * subevent as a BIG Control Subevent (last se of last BIS, lll->ctrl set).
 */
uint32_t sniffer_tap_ctrl_se_detected(void);

/**
 * @brief Diagnostic: subset of detected control subevents that made it
 * into the ring (i.e. not dropped by backpressure).
 */
uint32_t sniffer_tap_ctrl_se_forwarded(void);

/** Diagnostic: total BIS-side tap invocations (every isr_rx). */
uint32_t sniffer_tap_bis_hook_calls(void);

/** Diagnostic: count of taps where lll->bis_curr == lll->num_bis. */
uint32_t sniffer_tap_bis_max_at_hook(void);

/** Diagnostic: count of taps where lll->ctrl == 1 (any reason). */
uint32_t sniffer_tap_ctrl_flag_at_hook(void);

/** Diagnostic: latest CSSN state observed at any BIS tap. */
void sniffer_tap_last_cssn(uint16_t *cssn_curr, uint16_t *cssn_next);

/*
 * LLL state-machine probes. Called from lll_sync_iso.c at key points to
 * let the app-side status command trace which branches actually execute.
 * All are ISR-safe (increment atomic counters only).
 */
void sniffer_tap_mark_bis_curr_max(void);
void sniffer_tap_mark_ctrl_check(bool cond);
void sniffer_tap_mark_ctrl_set(void);
void sniffer_tap_mark_ctrl_recv(uint8_t b0, uint8_t len);

uint32_t sniffer_tap_bis_max_marked(void);
uint32_t sniffer_tap_ctrl_check_reached(void);
uint32_t sniffer_tap_ctrl_check_true(void);
uint32_t sniffer_tap_ctrl_set_marked(void);
uint32_t sniffer_tap_ctrl_recv_marked(void);

/** Forwarded (as tap records) direct captures from the LLL control path. */
uint32_t sniffer_tap_ctrl_recv_forwarded(void);

struct lll_sync_iso;
void sniffer_tap_notrx(const struct lll_sync_iso *lll);
uint32_t sniffer_tap_notrx_total(void);
uint32_t sniffer_tap_notrx_ctrl(void);

void sniffer_tap_note_arm_miss(void);
uint32_t sniffer_tap_arm_misses(void);

uint32_t sniffer_tap_events_seen(void);
uint32_t sniffer_tap_events_full_data(void);
uint32_t sniffer_tap_events_no_arm_miss(void);
uint32_t sniffer_tap_payloads_captured(void);
uint32_t sniffer_tap_payloads_expected(void);

void sniffer_tap_note_latency(uint16_t latency);
uint32_t sniffer_tap_latency_events(void);
uint32_t sniffer_tap_latency_max(void);
uint32_t sniffer_tap_latency_bin(uint8_t bin);
uint8_t sniffer_tap_latency_bins(void);

void sniffer_tap_note_event_start(uint32_t widening_us);
uint32_t sniffer_tap_events_prepared(void);
uint32_t sniffer_tap_events_with_slot0(void);
uint32_t sniffer_tap_widening_last_us(void);
uint32_t sniffer_tap_widening_max_us(void);

void sniffer_tap_note_anchor_delta(uint32_t delta_us);
uint32_t sniffer_tap_anchor_delta_min(void);
uint32_t sniffer_tap_anchor_delta_max(void);
uint32_t sniffer_tap_anchor_delta_last(void);
uint32_t sniffer_tap_anchor_delta_mean(void);
uint32_t sniffer_tap_anchor_delta_count(void);

void sniffer_tap_note_latency(uint16_t latency);
uint32_t sniffer_tap_latency_events(void);
uint32_t sniffer_tap_latency_max(void);
uint32_t sniffer_tap_latency_bin(uint8_t bin);
uint8_t sniffer_tap_latency_bins(void);

void sniffer_tap_note_event_start(uint32_t widening_us);
uint32_t sniffer_tap_events_prepared(void);
uint32_t sniffer_tap_events_with_slot0(void);
uint32_t sniffer_tap_widening_last_us(void);
uint32_t sniffer_tap_widening_max_us(void);

void sniffer_tap_note_anchor_delta(uint32_t delta_us);
uint32_t sniffer_tap_anchor_delta_min(void);
uint32_t sniffer_tap_anchor_delta_max(void);
uint32_t sniffer_tap_anchor_delta_last(void);
uint32_t sniffer_tap_anchor_delta_mean(void);
uint32_t sniffer_tap_anchor_delta_count(void);

/* CTRL Probe: always try to receive CTRL PDUs even when none
 * have been indicated by the subevents in this event.
 * For diagnostic reasons, or to debug attacks.
 */
void sniffer_tap_ctrl_probe_set(bool on);
bool sniffer_tap_ctrl_probe_get(void);

/*
 * Greedy Capture: Capture all subevents, including all pre- and
 * retransmissions for PDUs that might have already been received.
 */
void sniffer_tap_greedy_set(bool on);
bool sniffer_tap_greedy_get(void);

/*
 * Raw encrypted capture: capture RAW encrypted PDUs even without knowledge
 * of the Broadcast Code. Does not decrypt and circumvents the MIC check.
 */
void sniffer_tap_raw_enc_set(bool on);
bool sniffer_tap_raw_enc_get(void);

/*
 * Header-only capture mode: when due to resources capturing every PDU in full
 * isn't possible. rx_done() skips copying payload bytes entirely 
 * only the 2-byte header is kept. */
void sniffer_tap_payload_omit_set(bool on);
bool sniffer_tap_payload_omit_get(void);

/*
 * Follow encrypted channel-map updates via the cleartext BIGInfo.
 *
 * For an encrypted BIG synced without the Broadcast Code, the
 * BIG_CHANNEL_MAP_IND control PDU cannot be decrypted, so the LLL never learns
 * the new channel map and desyncs after the switch. When this is on, the
 * PA-report path tracks the cleartext BIGInfo channel map directly and stages
 * it into the running BIG sync when it changes. See ull_sync_iso_chm_follow().
 */
void sniffer_tap_chm_follow_set(bool on);
bool sniffer_tap_chm_follow_get(void);

/* Diagnostic: count BIG control PDUs observed on the wire (ISR context). */
void sniffer_tap_note_ctrl_seen(void);
uint32_t sniffer_tap_ctrl_seen_total(void);

/* Count of channel maps applied to a running BIG sync from BIGInfo. */
void sniffer_tap_note_chm_follow_applied(void);
uint32_t sniffer_tap_chm_follow_applied(void);

/*
 * Cycle-counter profiling of the BIS RX ISR. Uses k_cycle_get_32() which
 * on Cortex-M reads DWT->CYCCNT (1 cycle). Two probe points are exposed:
 *   isr:   full lll_sync_iso.c:isr_rx() body, entry to exit
 *   tap:   just sniffer_tap_rx_done() from entry to msgq_put (measures
 *          tap producer overhead in ISR context)
 *
 * All getters return microseconds. Sum/count for mean, max for worst-case.
 */
void sniffer_tap_probe_isr_record(uint32_t cycles);
uint32_t sniffer_tap_probe_isr_max_us(void);
uint32_t sniffer_tap_probe_isr_mean_us(void);
uint32_t sniffer_tap_probe_isr_count(void);
uint32_t sniffer_tap_probe_tap_max_us(void);
uint32_t sniffer_tap_probe_tap_mean_us(void);
/* Three-phase tap bisect: phase A = entry -> before PDU memcpy,
 * phase B = PDU memcpy, phase C = k_msgq_put + k_work_submit. Reported
 * as max/mean us of each. */
uint32_t sniffer_tap_probe_a_mean_us(void);
uint32_t sniffer_tap_probe_b_mean_us(void);
uint32_t sniffer_tap_probe_c_mean_us(void);
void sniffer_tap_probe_reset(void);

struct lll_sync_iso;
struct lll_sync;

/**
 * @brief Stash the just-programmed RF channel for the next RX ISR.
 *
 * Call from the LLL immediately after every lll_chan_set().
 */
void sniffer_tap_chan_set(uint8_t chan);

/**
 * @brief Capture the current BIS RX event.
 */
void sniffer_tap_rx_done(const struct lll_sync_iso *lll,
			 uint8_t crc_ok, uint8_t rssi_ready,
			 uint8_t bis_idx);

/**
 * @brief Capture the current periodic-advertising RX event.
 */
void sniffer_tap_pa_rx_done(const struct lll_sync *lll,
			    uint8_t crc_ok, uint8_t rssi_ready);

#endif /* ZEPHYR_INCLUDE_BT_CTLR_SNIFFER_TAP_H_ */
