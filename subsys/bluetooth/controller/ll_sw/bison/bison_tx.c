/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>

#define LOG_LEVEL CONFIG_BT_LOG_LEVEL
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(bison_tx);

#include "bison_sniff.h"
#include "bison_predict.h"
#include "bison_tx.h"
#include "bison_lll_hijack.h"

#define BISON_TX_PDU_MAX 251U

int bison_tx_schedule(uint16_t event_counter,
		      uint8_t bis_index,
		      uint8_t intra_bis_se_idx,
		      uint8_t llid,
		      uint8_t cssn,
		      uint8_t cstf,
		      const uint8_t *pdu_data,
		      uint8_t pdu_len)
{
	struct bison_snapshot snap;
	struct bison_event_prediction pred;
	struct bison_lll_hijack_req req;
	int err;

	if (pdu_len > 0U && !pdu_data) {
		return -EINVAL;
	}
	if (pdu_len > BISON_TX_PDU_MAX) {
		return -EMSGSIZE;
	}
	if (llid > BISON_TX_LLID_CTRL) {
		return -EINVAL;
	}
	if (cssn > 0x7U || cstf > 0x1U) {
		return -EINVAL;
	}

	if (!bison_sniff_snapshot(&snap)) {
		return -ENOENT;
	}
	if (bis_index > snap.num_bis) {
		return -ERANGE;
	}
	/* bis_index == 0 targets the control sub-event slot (see
	 * bison_predict.c); intra_bis_se_idx is ignored in that case.
	 */
	if (bis_index != 0U && intra_bis_se_idx >= snap.nse) {
		return -ERANGE;
	}

	if (!bison_predict_subevent(&snap, event_counter, bis_index,
				    intra_bis_se_idx, &pred)) {
		return -EINVAL;
	}

	memset(&req, 0, sizeof(req));
	req.event_counter  = event_counter;
	req.time_offset_us = pred.time_offset_us;
	memcpy(req.access_addr, pred.access_addr, sizeof(req.access_addr));
	memcpy(req.crc_init, pred.crc_init, sizeof(req.crc_init));
	req.channel_index  = pred.channel_index;
	req.phy            = snap.phy;
	req.llid           = llid;
	req.cssn           = cssn;
	req.cstf           = cstf;
	req.pdu_len        = pdu_len;
	if (pdu_len) {
		memcpy(req.pdu_data, pdu_data, pdu_len);
	}

	LOG_INF("TX enqueue: evt=%u bis=%u se=%u chan=%u t+%uus "
		"llid=%u cssn=%u cstf=%u",
		pred.event_counter, pred.bis_index, pred.intra_bis_se_idx,
		pred.channel_index, pred.time_offset_us,
		llid, cssn, cstf);

	err = bison_lll_hijack_enqueue(&req);
	if (err) {
		LOG_ERR("bison_lll_hijack_enqueue: %d", err);
		return err;
	}

	return 0;
}
