/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "util/util.h"
#include "lll_chan.h"

#include "bison_predict.h"
#include "bison_subevent_time.h"

bool bison_predict_subevent(const struct bison_snapshot *snap,
			    uint16_t event_counter,
			    uint8_t bis_index,
			    uint8_t intra_bis_se_idx,
			    struct bison_event_prediction *out)
{
	uint16_t chan_id;
	uint16_t prn_s;
	uint16_t remap_idx;
	uint8_t  chan_use;

	if (!snap || !out) {
		return false;
	}
	if (!snap->valid) {
		return false;
	}
	if (bis_index > snap->num_bis) {
		return false;
	}

	/* Access Address:
	 *  - Data sub-events: derived from BIS index (1..num_bis)
	 *  - Control sub-event: derived with bis_index=0
	 */
	util_bis_aa_le32(bis_index, (uint8_t *)snap->seed_access_addr,
			 out->access_addr);

	/* CRC init: [bis_index, base_crc_init[0..1]]
	 * (bis_index=0 for control sub-event; same LL convention.)
	 */
	out->crc_init[0] = bis_index;
	memcpy(&out->crc_init[1], snap->base_crc_init,
	       sizeof(snap->base_crc_init));

	/* CSA #2 - first sub-event of the BIS event (or, for the
	 * control sub-event, a fresh CSA #2 from BIS-0's chan_id).
	 */
	chan_id = lll_chan_id(out->access_addr);
	chan_use = lll_chan_iso_event(event_counter, chan_id,
				      (uint8_t *)snap->data_chan_map,
				      snap->data_chan_count,
				      &prn_s, &remap_idx);

	if (bis_index != 0U) {
		/* Data sub-event: CSA #2 - walk forward to the requested
		 * sub-event within the BIS event.
		 */
		for (uint8_t i = 0U; i < intra_bis_se_idx; i++) {
			chan_use = lll_chan_iso_subevent(chan_id,
							 snap->data_chan_map,
							 snap->data_chan_count,
							 &prn_s, &remap_idx);
		}
	}
	out->channel_index = chan_use;

	/* Time offset from the BIG event anchor.
	 *
	 * For a data sub-event at (bis_position, intra_bis_se_idx):
	 *   bis_position * bis_spacing + intra_bis_se_idx * sub_interval
	 *
	 * For the control sub-event (bis_index=0): position past the
	 * last data sub-event of the last BIS, i.e.
	 *   bison_subevent_time_us(_, _, num_bis-1, NSE_data).
	 */
	if (bis_index == 0U) {
		uint32_t ptc = snap->pto ? snap->bn : 0U;
		uint32_t nse_data = (uint32_t)snap->bn * snap->irc + ptc;

		out->time_offset_us = bison_subevent_time_us(
			snap->bis_spacing_us,
			snap->sub_interval_us,
			snap->num_bis - 1U,
			(uint8_t)nse_data);
	} else {
		out->time_offset_us = bison_subevent_time_us(
			snap->bis_spacing_us,
			snap->sub_interval_us,
			bis_index - 1U,
			intra_bis_se_idx);
	}

	/* The payload_count in the snapshot is the value seen at the
	 * sniffed event; advance it by the configured bursts per BIG
	 * event for the requested future event_counter. payload_count
	 * advances by bn per BIG event.
	 */
	{
		int16_t delta = (int16_t)(event_counter - snap->event_counter);

		out->payload_count = snap->payload_count +
				     (int64_t)delta * snap->bn;
	}

	out->event_counter = event_counter;
	out->bis_index = bis_index;
	out->intra_bis_se_idx = intra_bis_se_idx;

	return true;
}
