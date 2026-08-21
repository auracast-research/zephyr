/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Sub-event time offset within a BIG event.
 *
 * Used by bison_predict.c to compute the sub-event's time offset
 * from the BIG event anchor, which lll_sync_iso.c consumes when
 * hijacking that sub-event for TX injection.
 */

#ifndef BISON_SUBEVENT_TIME_H_
#define BISON_SUBEVENT_TIME_H_

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Microseconds from the BIG event anchor to the start of a
 *        specific sub-event.
 *
 * @param bis_spacing_us     BIGInfo BIS_Spacing, microseconds.
 * @param sub_interval_us    BIGInfo Sub_Interval, microseconds.
 * @param bis_position       0-indexed position of the BIS within the
 *                           BIG event (first = 0). NOT the BLE BIS
 *                           index (which is 1-indexed); compute as
 *                           (bis_index - 1).
 * @param intra_bis_se_idx   0-indexed sub-event within the BIS event,
 *                           range 0 .. (NSE - 1) where
 *                           NSE = bn*irc + ptc (+ 1 for ctrl subevent).
 *
 * @return Microseconds from the BIG event anchor.
 */
static inline uint32_t bison_subevent_time_us(uint32_t bis_spacing_us,
					      uint32_t sub_interval_us,
					      uint8_t bis_position,
					      uint8_t intra_bis_se_idx)
{
	return ((uint32_t)bis_position * bis_spacing_us) +
	       ((uint32_t)intra_bis_se_idx * sub_interval_us);
}

/**
 * @brief True if the BIG event uses sequential sub-event packing.
 *
 * Defined by the spec as BIS_Spacing >= Sub_Interval * NSE.
 */
static inline bool bison_is_sequential_packing(uint32_t bis_spacing_us,
					       uint32_t sub_interval_us,
					       uint8_t nse)
{
	return bis_spacing_us >= ((uint32_t)sub_interval_us * nse);
}

#endif /* BISON_SUBEVENT_TIME_H_ */
