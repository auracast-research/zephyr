/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

int ull_sync_iso_init(void);
int ull_sync_iso_reset(void);
struct ll_sync_iso_set *ull_sync_iso_by_stream_get(uint16_t handle);
struct lll_sync_iso_stream *ull_sync_iso_stream_get(uint16_t handle);
void ull_sync_iso_stream_release(struct ll_sync_iso_set *sync_iso);
void ull_sync_iso_setup(struct ll_sync_iso_set *sync_iso,
			struct node_rx_pdu *node_rx,
			uint8_t *acad, uint8_t acad_len);

struct ll_sync_set;
struct pdu_big_info;
struct ll_sync_iso_set *ull_sync_iso_by_sync_get(struct ll_sync_set *sync);
void ull_sync_iso_chm_follow(struct ll_sync_set *sync, struct pdu_big_info *bi);
void ull_sync_iso_estab_done(struct node_rx_event_done *done);
void ull_sync_iso_done(struct node_rx_event_done *done);
void ull_sync_iso_done_terminate(struct node_rx_event_done *done);
