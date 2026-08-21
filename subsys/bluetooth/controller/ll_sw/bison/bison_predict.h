/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Per-sub-event prediction for the BISON attack: given the current
 * sniffer snapshot of an ongoing BIG and a target
 * (event_counter, bis_index, intra-BIS sub-event index), return the
 * radio parameters that the legitimate broadcaster will use for that
 * exact sub-event.
 */

#ifndef BISON_PREDICT_H_
#define BISON_PREDICT_H_

#include <stdbool.h>
#include <stdint.h>

#include "bison_sniff.h"

struct bison_event_prediction {
	/** Per-BIS access address (4 bytes, little-endian). */
	uint8_t access_addr[4];

	/** Per-BIS CRC init (3 bytes: bis_idx, base_crc_init[0..1]). */
	uint8_t crc_init[3];

	/** RF channel index, 0..36, output of CSA #2. */
	uint8_t channel_index;

	/** Sub-event start time, microseconds from BIG event anchor. */
	uint32_t time_offset_us;

	/** Payload counter value valid for this sub-event. */
	uint64_t payload_count;

	/** Echo of the inputs, for logging. */
	uint16_t event_counter;
	uint8_t  bis_index;          /* 1..num_bis */
	uint8_t  intra_bis_se_idx;   /* 0..NSE-1 */
};

/**
 * @brief Predict the radio parameters of a future BIS sub-event.
 *
 * @param snap                Snapshot from bison_sniff_snapshot(); must
 *                            be .valid.
 * @param event_counter       Target absolute event counter (16-bit
 *                            wrap-around per spec).
 * @param bis_index           1-indexed BIS, 1..snap->num_bis.
 * @param intra_bis_se_idx    0-indexed sub-event within the BIS event.
 * @param out                 Result.
 *
 * @return true on success, false on bad input (invalid snapshot, BIS
 *         out of range, etc.).
 */
bool bison_predict_subevent(const struct bison_snapshot *snap,
			    uint16_t event_counter,
			    uint8_t bis_index,
			    uint8_t intra_bis_se_idx,
			    struct bison_event_prediction *out);

#endif /* BISON_PREDICT_H_ */
