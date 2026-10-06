/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sniffer_tap.h"

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/util.h>
#include <cmsis_core.h>

#include "hal/ccm.h"
#include "hal/radio.h"

/* DWT reader is inlined in the header for both this file and the LLL to
 * share. Local helpers below use it. */

static inline uint32_t sniffer_dwt_cyc_to_us(uint32_t cyc)
{
	/* CPU is 64 MHz on nRF52840, so 64 cycles / us. */
	return cyc >> 6;
}

static uint64_t tap_ts_wrap_base_us;
static uint32_t tap_ts_last_us;
static bool     tap_ts_init;

static uint64_t sniffer_tap_timestamp_us(void)
{
	uint32_t raw_us = sniffer_dwt_cyc_to_us(sniffer_tap_dwt_cyc());
	unsigned int key;
	uint64_t result;

	key = irq_lock();

	if (!tap_ts_init) {
		tap_ts_init = true;
	} else if (raw_us < tap_ts_last_us) {
		/* One full wrap elapsed since the last reading. */
		tap_ts_wrap_base_us += (UINT64_C(1) << 32) >> 6;
	}
	tap_ts_last_us = raw_us;
	result = tap_ts_wrap_base_us + raw_us;

	irq_unlock(key);

	return result;
}

static void sniffer_dwt_enable(void)
{
	static bool enabled;

	if (enabled) {
		return;
	}
	CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
	DWT->CYCCNT = 0U;
	DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
	enabled = true;
}

#include "util/util.h"
#include "util/memq.h"

#include "pdu_df.h"
#include "lll/pdu_vendor.h"
#include "pdu.h"

#include "lll.h"
#include "lll_sync.h"
#include "lll_sync_iso.h"

#define LOG_LEVEL CONFIG_BT_LOG_LEVEL
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(sniffer_tap);

#define TAP_RING_DEPTH 32

K_MSGQ_DEFINE(tap_msgq, sizeof(struct sniffer_tap_pdu), TAP_RING_DEPTH, 4);

#define TAP_HOT_RING_LOG2 7U
#define TAP_HOT_RING_SIZE (1U << TAP_HOT_RING_LOG2)
#define TAP_HOT_RING_MASK (TAP_HOT_RING_SIZE - 1U)

static struct sniffer_tap_pdu tap_hot_ring[TAP_HOT_RING_SIZE];
static atomic_t tap_hot_write_idx;
static uint32_t tap_hot_read_idx;

static struct sniffer_tap_pdu *tap_hot_ring_alloc(void)
{
	uint32_t w = (uint32_t)atomic_get(&tap_hot_write_idx);
	uint32_t r = tap_hot_read_idx;

	if ((w - r) >= TAP_HOT_RING_SIZE) {
		return NULL;
	}
	return &tap_hot_ring[w & TAP_HOT_RING_MASK];
}

static inline void tap_hot_ring_commit(void)
{
	atomic_inc(&tap_hot_write_idx);
}

static sniffer_tap_cb_t user_cb;
static atomic_t drop_count;
static atomic_t ctrl_se_detected;
static atomic_t ctrl_se_forwarded;

/* Diagnostic counters to understand why ctrl_se_detected might be 0. */
static atomic_t bis_hook_calls;      /* every isr_rx tap fire on lll_sync_iso  */
static atomic_t bis_max_at_hook;     /* count where lll->bis_curr == num_bis   */
static atomic_t ctrl_flag_at_hook;   /* count where lll->ctrl == 1             */
static uint16_t last_cssn_curr;
static uint16_t last_cssn_next;

static uint32_t last_tap_event_counter = 0xffffffffU;

static uint16_t bis_seq_ctr;

/* LLL probe counters. */
static atomic_t bis_max_marked;
static atomic_t ctrl_check_reached;
static atomic_t ctrl_check_true;
static atomic_t ctrl_set_marked;
static atomic_t ctrl_recv_marked;
static atomic_t ctrl_recv_forwarded;
static atomic_t notrx_total;
static atomic_t notrx_with_ctrl;
static atomic_t arm_misses;

#define EVENT_WINDOW      32
#define EVENT_WINDOW_MASK 31
static uint32_t payload_seen[EVENT_WINDOW];   /* (bis-1)*bn + bn_offset bitmask */
static atomic_t events_seen;
static atomic_t events_full_data;
static atomic_t events_no_arm_miss;
static atomic_t payloads_captured;      /* summed across events (soft coverage) */
static atomic_t payloads_expected;      /* summed across events */
static uint32_t cur_event_arm_miss;     /* arm_miss fires during current event */

static atomic_t ctrl_probe_on;          /* debug: force-listen every event      */
static atomic_t greedy_on;              /* debug: bypass "already received" skip */
static atomic_t raw_enc_on;             /* sniff encrypted BIG without bcode     */
static atomic_t payload_omit_on;        /* header-only capture: skip payload copy */

/* Channel-map following for encrypted BIGs without the Broadcast Code.
 * The BIG_CHANNEL_MAP_IND control PDU is encrypted and unparsable, but the
 * cleartext BIGInfo carries the new channel map, which the PA-report path
 * tracks directly (see ull_sync_iso_chm_follow). ctrl_seen_total just counts
 * observed BIG control PDUs for diagnostics. */
static atomic_t chm_follow_on;          /* follow chan-map updates via BIGInfo   */
static atomic_t ctrl_seen_total;        /* diagnostic: BIG control PDUs observed */
static atomic_t chm_follow_applied;     /* chan maps applied from BIGInfo         */

/* prepare_cb latency accounting -- lll->latency_event at prepare time.
 * 0 = we ran the event on schedule; >0 = we missed N events since the
 * last successful prepare (peer's event_counter jumped that far). If
 * this ever climbs mid-run, it means our ULL got behind and per-BIS
 * PRN state (which is re-initialized from event_counter each prepare)
 * jumps N events forward while ours starts N events behind */
#define LATENCY_HIST_BINS 8U
static atomic_t latency_events;         /* prepare_cb calls scored          */
static atomic_t latency_max;            /* max latency observed             */
static atomic_t latency_histogram[LATENCY_HIST_BINS];

/* Window widening at prepare time: window_widening_event_us grows each
 * event by ~ppm * iso_interval us and caps at (iso_int/2 - EVENT_IFS).
 * If it saturates near the cap when coverage degrades, peer clock drift
 * crossing our HCTO window is a likely mechanism. */
static atomic_t widening_max_us;
static atomic_t widening_last_us;

/* Per-event slot-0 (nse=0, BIS1 subevent 0) capture accounting. If
 * `events_with_slot0` tracks `events_prepared` closely, the LLL is
 * catching the first subevent of every event; degradation is happening
 * further into the walk. If it lags, some events start bad from nse=0
 * itself, pointing to a sync-plane issue rather than mid-walk drift. */
static atomic_t events_prepared;
static atomic_t events_with_slot0;
static uint8_t cur_event_slot0_seen;    /* reset at prepare, set at slot 0 RX */

static uint32_t anchor_delta_min = UINT32_MAX;
static uint32_t anchor_delta_max;
static uint64_t anchor_delta_sum;
static uint32_t anchor_delta_count;
static uint32_t anchor_delta_last;

static uint32_t probe_isr_max_cyc;
static uint64_t probe_isr_sum_cyc;
static uint32_t probe_isr_count;
static uint32_t probe_tap_max_cyc;
static uint64_t probe_tap_sum_cyc;
static uint32_t probe_tap_count;
static uint64_t probe_a_sum_cyc;
static uint64_t probe_b_sum_cyc;
static uint64_t probe_c_sum_cyc;
static uint32_t probe_a_count;
static uint32_t probe_b_count;
static uint32_t probe_c_count;

static volatile uint8_t pending_chan;

static void drain_work_handler(struct k_work *w);
static K_WORK_DEFINE(drain_work, drain_work_handler);

static struct sniffer_tap_pdu drain_scratch;

static void drain_work_handler(struct k_work *w)
{
	ARG_UNUSED(w);

	while (k_msgq_get(&tap_msgq, &drain_scratch, K_NO_WAIT) == 0) {
		sniffer_tap_cb_t cb = user_cb;

		if (cb != NULL) {
			cb(&drain_scratch);
		}
	}
}

#define TAP_HOT_DRAIN_STACK 2048
#define TAP_HOT_DRAIN_PRIO 5
#define TAP_HOT_DRAIN_POLL_US 150
K_THREAD_STACK_DEFINE(tap_hot_drain_stack, TAP_HOT_DRAIN_STACK);
static struct k_thread tap_hot_drain_thread;

static inline void tap_hot_process_one(struct sniffer_tap_pdu *rec)
{
	sniffer_tap_cb_t cb = user_cb;

	if (rec->_deferred_raw != NULL) {
		memcpy(&rec->pdu[2],
		       rec->_deferred_raw + PDU_BIS_LL_HEADER_SIZE,
		       rec->_deferred_len);
		rec->_deferred_raw = NULL;
	}

	if (cb != NULL) {
		cb(rec);
	}
}

static void tap_hot_drain_fn(void *a, void *b, void *c)
{
	ARG_UNUSED(a); ARG_UNUSED(b); ARG_UNUSED(c);

	while (true) {
		uint32_t r;
		uint32_t w;

		r = tap_hot_read_idx;
		w = (uint32_t)atomic_get(&tap_hot_write_idx);

		if (r == w) {
			k_usleep(TAP_HOT_DRAIN_POLL_US);
			continue;
		}

		while (r != w) {
			tap_hot_process_one(&tap_hot_ring[r & TAP_HOT_RING_MASK]);
			r++;
			tap_hot_read_idx = r;
			w = (uint32_t)atomic_get(&tap_hot_write_idx);
		}
	}
}

int sniffer_tap_register(sniffer_tap_cb_t cb)
{
	static bool drain_started;

	sniffer_dwt_enable();
	user_cb = cb;
	if (!drain_started) {
		drain_started = true;
		k_thread_create(&tap_hot_drain_thread, tap_hot_drain_stack,
				K_THREAD_STACK_SIZEOF(tap_hot_drain_stack),
				tap_hot_drain_fn, NULL, NULL, NULL,
				TAP_HOT_DRAIN_PRIO, 0, K_NO_WAIT);
		k_thread_name_set(&tap_hot_drain_thread, "sniffer_tap");
	}
	return 0;
}

uint32_t sniffer_tap_dropped(void)
{
	return (uint32_t)atomic_get(&drop_count);
}

uint32_t sniffer_tap_ctrl_se_detected(void)
{
	return (uint32_t)atomic_get(&ctrl_se_detected);
}

uint32_t sniffer_tap_ctrl_se_forwarded(void)
{
	return (uint32_t)atomic_get(&ctrl_se_forwarded);
}

uint32_t sniffer_tap_bis_hook_calls(void)
{
	return (uint32_t)atomic_get(&bis_hook_calls);
}

uint32_t sniffer_tap_bis_max_at_hook(void)
{
	return (uint32_t)atomic_get(&bis_max_at_hook);
}

uint32_t sniffer_tap_ctrl_flag_at_hook(void)
{
	return (uint32_t)atomic_get(&ctrl_flag_at_hook);
}

void sniffer_tap_last_cssn(uint16_t *curr, uint16_t *next)
{
	if (curr) *curr = last_cssn_curr;
	if (next) *next = last_cssn_next;
}

void sniffer_tap_mark_bis_curr_max(void)
{
	atomic_inc(&bis_max_marked);
}

void sniffer_tap_mark_ctrl_check(bool cond)
{
	atomic_inc(&ctrl_check_reached);
	if (cond) {
		atomic_inc(&ctrl_check_true);
	}
}

void sniffer_tap_mark_ctrl_set(void)
{
	atomic_inc(&ctrl_set_marked);
}

void sniffer_tap_mark_ctrl_recv(uint8_t b0, uint8_t len)
{
	ARG_UNUSED(b0);
	ARG_UNUSED(len);

	atomic_inc(&ctrl_recv_marked);

	atomic_inc(&ctrl_recv_forwarded);
}

uint32_t sniffer_tap_bis_max_marked(void)     { return atomic_get(&bis_max_marked); }
uint32_t sniffer_tap_ctrl_check_reached(void) { return atomic_get(&ctrl_check_reached); }
uint32_t sniffer_tap_ctrl_check_true(void)    { return atomic_get(&ctrl_check_true); }
uint32_t sniffer_tap_ctrl_set_marked(void)    { return atomic_get(&ctrl_set_marked); }
uint32_t sniffer_tap_ctrl_recv_marked(void)   { return atomic_get(&ctrl_recv_marked); }
uint32_t sniffer_tap_ctrl_recv_forwarded(void){ return atomic_get(&ctrl_recv_forwarded); }

void sniffer_tap_notrx(const struct lll_sync_iso *lll)
{
	atomic_inc(&notrx_total);
	if (lll != NULL && lll->ctrl) {
		atomic_inc(&notrx_with_ctrl);
	}
}
uint32_t sniffer_tap_notrx_total(void) { return atomic_get(&notrx_total); }
uint32_t sniffer_tap_notrx_ctrl(void)  { return atomic_get(&notrx_with_ctrl); }

void sniffer_tap_note_arm_miss(void)
{
	atomic_inc(&arm_misses);
	cur_event_arm_miss++;
}
uint32_t sniffer_tap_arm_misses(void) { return atomic_get(&arm_misses); }

void sniffer_tap_note_anchor_delta(uint32_t delta_us)
{
	anchor_delta_last = delta_us;
	if (delta_us < anchor_delta_min) {
		anchor_delta_min = delta_us;
	}
	if (delta_us > anchor_delta_max) {
		anchor_delta_max = delta_us;
	}
	anchor_delta_sum += delta_us;
	anchor_delta_count++;
}
uint32_t sniffer_tap_anchor_delta_min(void) { return (anchor_delta_min == UINT32_MAX) ? 0U : anchor_delta_min; }
uint32_t sniffer_tap_anchor_delta_max(void) { return anchor_delta_max; }
uint32_t sniffer_tap_anchor_delta_last(void){ return anchor_delta_last; }
uint32_t sniffer_tap_anchor_delta_mean(void)
{
	if (anchor_delta_count == 0U) {
		return 0U;
	}
	return (uint32_t)(anchor_delta_sum / anchor_delta_count);
}
uint32_t sniffer_tap_anchor_delta_count(void) { return anchor_delta_count; }

void sniffer_tap_note_event_start(uint32_t widening_us)
{
	atomic_inc(&events_prepared);
	if (cur_event_slot0_seen) {
		atomic_inc(&events_with_slot0);
	}
	cur_event_slot0_seen = 0U;

	atomic_set(&widening_last_us, (atomic_val_t)widening_us);
	atomic_val_t cur = atomic_get(&widening_max_us);
	if ((atomic_val_t)widening_us > cur) {
		atomic_set(&widening_max_us, (atomic_val_t)widening_us);
	}
}
uint32_t sniffer_tap_events_prepared(void)   { return atomic_get(&events_prepared); }
uint32_t sniffer_tap_events_with_slot0(void) { return atomic_get(&events_with_slot0); }
uint32_t sniffer_tap_widening_last_us(void)  { return atomic_get(&widening_last_us); }
uint32_t sniffer_tap_widening_max_us(void)   { return atomic_get(&widening_max_us); }

void sniffer_tap_note_latency(uint16_t latency)
{
	atomic_inc(&latency_events);
	uint8_t bin = (latency >= LATENCY_HIST_BINS) ?
			(uint8_t)(LATENCY_HIST_BINS - 1U) : (uint8_t)latency;
	atomic_inc(&latency_histogram[bin]);

	/* Track max without a spinlock; a lost update is fine for a
	 * best-effort diagnostic. */
	atomic_val_t cur = atomic_get(&latency_max);
	if ((atomic_val_t)latency > cur) {
		atomic_set(&latency_max, (atomic_val_t)latency);
	}
}
uint32_t sniffer_tap_latency_events(void) { return atomic_get(&latency_events); }
uint32_t sniffer_tap_latency_max(void)    { return atomic_get(&latency_max); }
uint32_t sniffer_tap_latency_bin(uint8_t bin)
{
	if (bin >= LATENCY_HIST_BINS) {
		return 0U;
	}
	return (uint32_t)atomic_get(&latency_histogram[bin]);
}
uint8_t sniffer_tap_latency_bins(void) { return (uint8_t)LATENCY_HIST_BINS; }

uint32_t sniffer_tap_events_seen(void)         { return atomic_get(&events_seen); }
uint32_t sniffer_tap_events_full_data(void)    { return atomic_get(&events_full_data); }
uint32_t sniffer_tap_events_no_arm_miss(void)  { return atomic_get(&events_no_arm_miss); }
uint32_t sniffer_tap_payloads_captured(void)   { return atomic_get(&payloads_captured); }
uint32_t sniffer_tap_payloads_expected(void)   { return atomic_get(&payloads_expected); }

void sniffer_tap_ctrl_probe_set(bool on) { atomic_set(&ctrl_probe_on, on ? 1 : 0); }
bool sniffer_tap_ctrl_probe_get(void)    { return atomic_get(&ctrl_probe_on) != 0; }

void sniffer_tap_greedy_set(bool on)     { atomic_set(&greedy_on, on ? 1 : 0); }
bool sniffer_tap_greedy_get(void)        { return atomic_get(&greedy_on) != 0; }

void sniffer_tap_raw_enc_set(bool on)    { atomic_set(&raw_enc_on, on ? 1 : 0); }
bool sniffer_tap_raw_enc_get(void)       { return atomic_get(&raw_enc_on) != 0; }

void sniffer_tap_payload_omit_set(bool on) { atomic_set(&payload_omit_on, on ? 1 : 0); }
bool sniffer_tap_payload_omit_get(void)    { return atomic_get(&payload_omit_on) != 0; }

void sniffer_tap_chm_follow_set(bool on) { atomic_set(&chm_follow_on, on ? 1 : 0); }
bool sniffer_tap_chm_follow_get(void)    { return atomic_get(&chm_follow_on) != 0; }

/* Diagnostic: count BIG control PDUs observed on the wire (ISR context). */
void sniffer_tap_note_ctrl_seen(void)      { atomic_inc(&ctrl_seen_total); }
uint32_t sniffer_tap_ctrl_seen_total(void) { return atomic_get(&ctrl_seen_total); }

void sniffer_tap_note_chm_follow_applied(void) { atomic_inc(&chm_follow_applied); }
uint32_t sniffer_tap_chm_follow_applied(void)  { return atomic_get(&chm_follow_applied); }

void sniffer_tap_probe_isr_record(uint32_t cycles)
{
	if (cycles > probe_isr_max_cyc) {
		probe_isr_max_cyc = cycles;
	}
	probe_isr_sum_cyc += cycles;
	probe_isr_count++;
}

static void probe_tap_record(uint32_t cycles)
{
	if (cycles > probe_tap_max_cyc) {
		probe_tap_max_cyc = cycles;
	}
	probe_tap_sum_cyc += cycles;
	probe_tap_count++;
}

uint32_t sniffer_tap_probe_isr_max_us(void)
{
	return sniffer_dwt_cyc_to_us(probe_isr_max_cyc);
}

uint32_t sniffer_tap_probe_isr_mean_us(void)
{
	uint32_t count = probe_isr_count;

	if (count == 0U) {
		return 0U;
	}
	return sniffer_dwt_cyc_to_us((uint32_t)(probe_isr_sum_cyc / count));
}

uint32_t sniffer_tap_probe_isr_count(void)
{
	return probe_isr_count;
}

uint32_t sniffer_tap_probe_tap_max_us(void)
{
	return sniffer_dwt_cyc_to_us(probe_tap_max_cyc);
}

uint32_t sniffer_tap_probe_tap_mean_us(void)
{
	uint32_t count = probe_tap_count;

	if (count == 0U) {
		return 0U;
	}
	return sniffer_dwt_cyc_to_us((uint32_t)(probe_tap_sum_cyc / count));
}

uint32_t sniffer_tap_probe_a_mean_us(void)
{
	uint32_t count = probe_a_count;

	if (count == 0U) {
		return 0U;
	}
	return sniffer_dwt_cyc_to_us((uint32_t)(probe_a_sum_cyc / count));
}

uint32_t sniffer_tap_probe_b_mean_us(void)
{
	uint32_t count = probe_b_count;

	if (count == 0U) {
		return 0U;
	}
	return sniffer_dwt_cyc_to_us((uint32_t)(probe_b_sum_cyc / count));
}

uint32_t sniffer_tap_probe_c_mean_us(void)
{
	uint32_t count = probe_c_count;

	if (count == 0U) {
		return 0U;
	}
	return sniffer_dwt_cyc_to_us((uint32_t)(probe_c_sum_cyc / count));
}

void sniffer_tap_probe_reset(void)
{
	probe_isr_max_cyc = 0U;
	probe_isr_sum_cyc = 0U;
	probe_isr_count = 0U;
	probe_tap_max_cyc = 0U;
	probe_tap_sum_cyc = 0U;
	probe_tap_count = 0U;
	probe_a_sum_cyc = 0U;
	probe_b_sum_cyc = 0U;
	probe_c_sum_cyc = 0U;
	probe_a_count = 0U;
	probe_b_count = 0U;
	probe_c_count = 0U;
	atomic_clear(&events_seen);
	atomic_clear(&events_full_data);
	atomic_clear(&events_no_arm_miss);
	atomic_clear(&payloads_captured);
	atomic_clear(&payloads_expected);
	cur_event_arm_miss = 0U;
	last_tap_event_counter = 0xffffffffU;
	for (uint32_t i = 0; i < EVENT_WINDOW; i++) {
		payload_seen[i] = 0U;
	}
	atomic_clear(&latency_events);
	atomic_clear(&latency_max);
	for (uint32_t i = 0; i < LATENCY_HIST_BINS; i++) {
		atomic_clear(&latency_histogram[i]);
	}
	atomic_clear(&widening_max_us);
	atomic_clear(&widening_last_us);
	atomic_clear(&events_prepared);
	atomic_clear(&events_with_slot0);
	cur_event_slot0_seen = 0U;
	anchor_delta_min = UINT32_MAX;
	anchor_delta_max = 0U;
	anchor_delta_sum = 0U;
	anchor_delta_count = 0U;
	anchor_delta_last = 0U;
	bis_seq_ctr = 0U;
}

void sniffer_tap_chan_set(uint8_t chan)
{
	pending_chan = chan;
}

void sniffer_tap_rx_done(const struct lll_sync_iso *lll,
			 uint8_t crc_ok, uint8_t rssi_ready,
			 uint8_t bis_idx)
{
	struct sniffer_tap_pdu *rec;
	struct node_rx_pdu *node_rx;
	uint8_t aa[4];
	uint32_t tap_cyc_start;
	bool is_control_se;

	if (lll == NULL) {
		return;
	}
	if (bis_idx >= 32U) {
		return;
	}

	tap_cyc_start = sniffer_tap_dwt_cyc();

	atomic_inc(&bis_hook_calls);
	if (lll->bis_curr == lll->num_bis) {
		atomic_inc(&bis_max_at_hook);
	}
	if (lll->ctrl) {
		atomic_inc(&ctrl_flag_at_hook);
	}
	/* Mark slot-0 (nse=0 = BIS 1 first subevent, first bn, first
	 * irc, no PTC, no ctrl) capture */
	if (!lll->ctrl && lll->bis_curr == 1U && lll->bn_curr == 1U &&
	    lll->irc_curr == 1U && lll->ptc_curr == 0U) {
		cur_event_slot0_seen = 1U;
	}
	last_cssn_curr = lll->cssn_curr;
	last_cssn_next = lll->cssn_next;

	/* BIG Control Subevent: irc_curr==irc, walker's final round,
	 * bis_curr==num_bis, lll->ctrl. */
	is_control_se = (lll->bn_curr  == lll->bn)   &&
			(lll->irc_curr == lll->irc)  &&
			(lll->ptc_curr == lll->ptc)  &&
			(lll->bis_curr == lll->num_bis) &&
			lll->ctrl;

	rec = tap_hot_ring_alloc();
	if (rec == NULL) {
		atomic_inc(&drop_count);
		probe_tap_record(sniffer_tap_dwt_cyc() - tap_cyc_start);
		return;
	}

	rec->pdu_kind      = SNIFFER_TAP_KIND_BIS;
	rec->timestamp_us  = sniffer_tap_timestamp_us();
	rec->chan          = pending_chan;
	rec->phy           = lll->phy;
	rec->bis           = lll->bis_curr;
	rec->flags         = 0U;
	rec->derived       = 0U;
	rec->seq_ctr       = bis_seq_ctr++;
	rec->rssi_dbm      = 0;
	rec->pdu_len       = 0U;
	rec->event_counter = 0U;

	if (lll->bn > 0U && lll->payload_count >= lll->bn) {
		rec->event_counter = (uint16_t)((lll->payload_count / lll->bn) - 1U);
	}

	rec->subevent = (uint8_t)(((lll->irc_curr - 1U) * lll->bn)
				  + (lll->bn_curr - 1U)
				  + lll->ptc_curr);
	rec->bn_curr   = lll->bn_curr;
	rec->irc_curr  = lll->irc_curr;
	rec->ptc_curr  = lll->ptc_curr;
	rec->cssn_curr = lll->cssn_curr;
	rec->cssn_next = lll->cssn_next;

	if (lll->irc_curr > 1U) {
		rec->derived |= SNIFFER_TAP_DFLAG_RETRANSMISSION;
	}
	if (lll->ptc_curr > 0U) {
		rec->derived |= SNIFFER_TAP_DFLAG_PRETRANSMISSION;
	}
	if (lll->ctrl) {
		rec->derived |= SNIFFER_TAP_DFLAG_CONTROL;
	}
	if (lll->bis_spacing < (uint32_t)lll->sub_interval * lll->nse) {
		rec->derived |= SNIFFER_TAP_DFLAG_INTERLEAVED;
	}
	if ((uint32_t)rec->event_counter != last_tap_event_counter) {
		rec->derived |= SNIFFER_TAP_DFLAG_FIRST_EVENT_RX;

		if (last_tap_event_counter != 0xffffffffU &&
		    rec->event_counter >= EVENT_WINDOW) {
			uint32_t closing = (uint32_t)rec->event_counter - EVENT_WINDOW;
			uint32_t slot = closing & EVENT_WINDOW_MASK;
			uint32_t seen_bits = payload_seen[slot];
			uint32_t expected_mask = 0U;
			for (uint8_t b = 0; b < lll->num_bis; b++) {
				expected_mask |= ((1U << lll->bn) - 1U) << (b * lll->bn);
			}
			atomic_inc(&events_seen);
			if ((seen_bits & expected_mask) == expected_mask) {
				atomic_inc(&events_full_data);
			}
			if (cur_event_arm_miss == 0U) {
				atomic_inc(&events_no_arm_miss);
			}
			uint32_t captured_in_event =
				__builtin_popcount(seen_bits & expected_mask);
			atomic_add(&payloads_captured, captured_in_event);
			atomic_add(&payloads_expected,
				   __builtin_popcount(expected_mask));

			payload_seen[slot] = 0U;
		}
		cur_event_arm_miss = 0U;

		last_tap_event_counter = rec->event_counter;
	}

	if (!lll->ctrl && lll->bis_curr >= 1U && lll->bis_curr <= lll->num_bis &&
	    lll->bn_curr >= 1U && lll->bn_curr <= lll->bn && lll->bn > 0U) {
		uint32_t payload_offset =
			(uint32_t)(lll->bn_curr - 1U) +
			(uint32_t)lll->ptc_curr * (uint32_t)lll->pto;
		uint32_t payload_event =
			(uint32_t)rec->event_counter +
			(payload_offset / lll->bn);
		uint32_t target_bn_slot = payload_offset % lll->bn;
		uint32_t slot = payload_event & EVENT_WINDOW_MASK;
		uint32_t bit_idx = (lll->bis_curr - 1U) * lll->bn +
				   target_bn_slot;
		if (bit_idx < 32U) {
			payload_seen[slot] |= (1U << bit_idx);
		}
	}

	if (lll->bn > 0U && lll->payload_count >= lll->bn) {
		rec->payload_number = lll->payload_count +
				      (uint64_t)(lll->bn_curr - 1U) +
				      ((uint64_t)lll->ptc_curr * lll->pto) -
				      lll->bn;
	} else {
		rec->payload_number = 0U;
	}

	util_bis_aa_le32(lll->bis_curr, (uint8_t *)lll->seed_access_addr, aa);
	rec->access_addr = ((uint32_t)aa[0])
			   | ((uint32_t)aa[1] << 8)
			   | ((uint32_t)aa[2] << 16)
			   | ((uint32_t)aa[3] << 24);

	if (crc_ok) {
		rec->flags |= SNIFFER_TAP_FLAG_CRC_OK;
	}
	if (rssi_ready) {
		uint32_t mag = radio_rssi_get();
		if (mag > 127U) {
			mag = 127U;
		}
		rec->rssi_dbm = -(int8_t)mag;
		rec->flags |= SNIFFER_TAP_FLAG_RSSI_VAL;
	}
	if (IS_ENABLED(CONFIG_BT_CTLR_BROADCAST_ISO_ENC) && lll->enc) {
		rec->flags |= SNIFFER_TAP_FLAG_ENC;
	}
	/* Raw-encrypted sniff mode: the LLL configured the radio for
	 * unencrypted RX (no CCM) */
	const bool raw_enc = sniffer_tap_raw_enc_get();
	const bool payload_omit = sniffer_tap_payload_omit_get();
	if (raw_enc) {
		rec->flags |= SNIFFER_TAP_FLAG_ENC;
		rec->derived |= SNIFFER_TAP_DFLAG_CIPHERTEXT;
	}

	if (is_control_se) {
		atomic_inc(&ctrl_se_detected);
	}

	const uint8_t *raw = NULL;

	if (is_control_se) {
		raw = (const uint8_t *)radio_pkt_big_ctrl_get();
	} else {
		node_rx = ull_iso_pdu_rx_alloc_peek(1U);
		if (node_rx != NULL) {
			raw = (const uint8_t *)node_rx->pdu;
		}
	}

	uint32_t phase_a_end = sniffer_tap_dwt_cyc();
	probe_a_sum_cyc += (phase_a_end - tap_cyc_start);
	probe_a_count++;

	rec->_deferred_raw = NULL;
	rec->_deferred_len = 0U;

	if (raw != NULL) {
		const struct pdu_bis *pdu = (const struct pdu_bis *)raw;
		uint16_t payload_len = pdu->len;
		uint16_t hw_max;
		uint16_t copy_extra = 0U;

		if (is_control_se) {
			hw_max = (uint16_t)sizeof(struct pdu_big_ctrl);
		} else {
			hw_max = lll->max_pdu;
			if (IS_ENABLED(CONFIG_BT_CTLR_BROADCAST_ISO_ENC) &&
			    lll->enc) {
				hw_max += PDU_MIC_SIZE;
			} else if (raw_enc) {
				hw_max += PDU_MIC_SIZE;
				copy_extra = PDU_MIC_SIZE;
			}
		}
		if (hw_max > 0U && payload_len > hw_max) {
			payload_len = hw_max;
		}
		if (payload_len + copy_extra > SNIFFER_TAP_PDU_MAX - 2U) {
			payload_len = SNIFFER_TAP_PDU_MAX - 2U - copy_extra;
		}

		rec->pdu[0] = raw[0];
		rec->pdu[1] = (uint8_t)payload_len;
		rec->pdu_len = 2U + payload_len + copy_extra;

		/* Header-only capture mode (`sniff payload_omit on`):
		 * skip the payload copy entirely */
		if (payload_omit) {
			rec->flags |= SNIFFER_TAP_FLAG_PAYLOAD_OMITTED;
		} else {
			bool will_store = false;
			if (!is_control_se && payload_len > 0U && crc_ok &&
			    ull_iso_pdu_rx_alloc_peek(2U) != NULL) {
				uint32_t stream_curr = lll->stream_curr;
				uint32_t payload_index;

				if (lll->ptc_curr > 0U) {
					uint32_t ptx_idx = (uint32_t)lll->ptc_curr - 1U;
					uint32_t ptx_group_idx = ptx_idx / lll->bn;
					uint32_t ptx_payload_idx =
						ptx_idx - ptx_group_idx * lll->bn;
					uint32_t ptx_group_mult =
						(ptx_group_idx + 1U) * lll->pto;

					payload_index = ptx_payload_idx +
							ptx_group_mult * lll->bn;
				} else {
					payload_index = lll->bn_curr - 1U;
				}

				uint32_t payload_offset =
					((uint32_t)lll->latency_event * lll->bn) +
					payload_index;
				if (payload_offset < lll->payload_count_max &&
				    stream_curr < BT_CTLR_SYNC_ISO_STREAM_MAX) {
					uint32_t idx = lll->payload_tail + payload_offset;
					if (idx >= lll->payload_count_max) {
						idx -= lll->payload_count_max;
					}
					will_store = (lll->payload[stream_curr][idx] == NULL);
				}
			}

			if (will_store) {
				rec->_deferred_raw = raw;
				rec->_deferred_len = payload_len + copy_extra;
			} else if (payload_len + copy_extra > 0U) {
				memcpy(&rec->pdu[2],
				       raw + PDU_BIS_LL_HEADER_SIZE,
				       payload_len + copy_extra);
			}
		}
	}

	uint32_t phase_b_end = sniffer_tap_dwt_cyc();
	probe_b_sum_cyc += (phase_b_end - phase_a_end);
	probe_b_count++;

	if (is_control_se) {
		atomic_inc(&ctrl_se_forwarded);
	}
	tap_hot_ring_commit();

	uint32_t phase_c_end = sniffer_tap_dwt_cyc();
	probe_c_sum_cyc += (phase_c_end - phase_b_end);
	probe_c_count++;
	probe_tap_record(phase_c_end - tap_cyc_start);
}

void sniffer_tap_pa_rx_done(const struct lll_sync *lll,
			    uint8_t crc_ok, uint8_t rssi_ready)
{
	struct sniffer_tap_pdu rec;
	struct node_rx_pdu *node_rx;

	if (lll == NULL) {
		return;
	}

	memset(&rec, 0, sizeof(rec));

	rec.pdu_kind     = SNIFFER_TAP_KIND_PA;
	rec.timestamp_us = sniffer_tap_timestamp_us();
	rec.chan         = pending_chan;
	rec.phy          = lll->phy;
	/* Not BIS. */
	rec.bis          = 0U;
	rec.subevent     = 0U;

	rec.access_addr = ((uint32_t)lll->access_addr[0])
			  | ((uint32_t)lll->access_addr[1] << 8)
			  | ((uint32_t)lll->access_addr[2] << 16)
			  | ((uint32_t)lll->access_addr[3] << 24);

	if (crc_ok) {
		rec.flags |= SNIFFER_TAP_FLAG_CRC_OK;
	}
	if (rssi_ready) {
		uint32_t mag = radio_rssi_get();
		if (mag > 127U) {
			mag = 127U;
		}
		rec.rssi_dbm = -(int8_t)mag;
		rec.flags |= SNIFFER_TAP_FLAG_RSSI_VAL;
	}

	node_rx = ull_pdu_rx_alloc_peek(1U);
	if (node_rx != NULL) {
		const uint8_t *raw = (const uint8_t *)node_rx->pdu;
		const struct pdu_adv *pdu = (const struct pdu_adv *)raw;
		uint16_t payload_len = pdu->len;

		if (payload_len > PDU_AC_EXT_PAYLOAD_SIZE_MAX) {
			payload_len = PDU_AC_EXT_PAYLOAD_SIZE_MAX;
		}
		if (payload_len > SNIFFER_TAP_PDU_MAX - 2U) {
			payload_len = SNIFFER_TAP_PDU_MAX - 2U;
		}

		rec.pdu[0] = raw[0];
		rec.pdu[1] = (uint8_t)payload_len;
		if (payload_len > 0U) {
			memcpy(&rec.pdu[2],
			       raw + PDU_AC_LL_HEADER_SIZE,
			       payload_len);
		}
		rec.pdu_len = 2U + payload_len;
	}

	if (k_msgq_put(&tap_msgq, &rec, K_NO_WAIT) != 0) {
		atomic_inc(&drop_count);
		return;
	}
	k_work_submit(&drain_work);
}
