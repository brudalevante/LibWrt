// SPDX-License-Identifier: GPL-2.0-only
/*
 * rxown: loss-accounted ath11k RX-buffer ownership diagnostics.
 *
 * ath11k objects are deliberately opaque.  Saved ring and IDR pointers are
 * identities only; this module never includes or dereferences ath11k structs.
 * Unload rxown before unloading/reloading ath11k: kprobes in module text are
 * killed when ath11k goes away and are not rebound when it is loaded again.
 */

#include <linux/debugfs.h>
#include <linux/hashtable.h>
#include <linux/idr.h>
#include <linux/interrupt.h>
#include <linux/jiffies.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>

#define RXOWN_VERSION           2
#define RXOWN_RECORD_BITS       15
#define RXOWN_PAGE_BITS         12
#define RXOWN_SCOPE_BITS        6
#define RXOWN_MAX_RINGS         16
#define RXOWN_EVENT_CAP         512
#define RXOWN_MAX_RECORDS       32768
#define RXOWN_MAX_PAGES         8192
#define RXOWN_MAX_CALLERS       32

enum rxown_state {
	RXOWN_ALLOCATED,
	RXOWN_POSTED,
	RXOWN_REAPED,
	RXOWN_STATE_COUNT,
};

enum rxown_scope_kind {
	RXOWN_SCOPE_REGULAR = 1,
	RXOWN_SCOPE_MON_STATUS = 2,
	RXOWN_SCOPE_MON_PROCESS = 3,
};

enum rxown_event_type {
	RXOWN_EV_ALLOC = 1,
	RXOWN_EV_POST,
	RXOWN_EV_REAP,
	RXOWN_EV_SKB_RELEASE,
	RXOWN_EV_FRAGMENT_RELEASE,
};

struct rxown_record {
	struct hlist_node head_node;
	struct hlist_node skb_node;
	void *head;
	struct sk_buff *skb;
	struct page *page;
	u64 generation;
	unsigned long born;
	u32 requested;
	u32 aligned;
	s32 buf_id;
	s8 ring_slot;
	u8 state;
	u8 order;
	u8 skb_linked;
	u8 page_tracked;
	s8 caller_slot;
	unsigned long caller;
	void *pending_ring;
	s32 pending_mac_id;
	u32 pending_mgr;
	u8 pending_kind;
	u8 scope_candidate;
	u32 release_users;
	u32 release_dataref;
	u16 release_payload_refs;
	u16 release_nohdr_refs;
	u8 release_nohdr;
	u8 release_head_frag;
	u8 release_pp_recycle;
};

struct rxown_page {
	struct hlist_node node;
	struct page *page;
	u16 ring_state[RXOWN_MAX_RINGS][RXOWN_STATE_COUNT];
	u16 unscoped;
	u16 total;
	u16 history_ring_mask;
	u8 order;
	bool history_unscoped;
};

struct rxown_ring {
	bool used;
	bool actual_valid;
	bool resample;
	u8 kind;
	void *ring;
	struct idr *idr;
	s32 mac_id;
	u32 mgr;
	u32 bufs_max;
	s32 actual_idr;
	unsigned long last_idr_sample;
	u64 state_current[RXOWN_STATE_COUNT];
	u64 requested[RXOWN_STATE_COUNT];
	u64 aligned[RXOWN_STATE_COUNT];
	u64 unique_pages[RXOWN_STATE_COUNT];
	u64 backing_bytes[RXOWN_STATE_COUNT];
	u64 allocations;
	u64 posts;
	u64 reaps;
	u64 releases;
	u64 idr_alloc_failures;
	u64 untracked_removes;
	u64 release_while_posted;
	u64 reinject_allocations;
	u64 reinject_posts;
	u64 known_idr_alloc_unmatched;
};

struct rxown_scope {
	struct hlist_node node;
	struct task_struct *task;
	void *ring;
	s32 mac_id;
	u32 mgr;
	u8 kind;
	bool hardirq;
	bool softirq;
	bool nmi;
};

struct rxown_scope_call {
	struct rxown_scope *scope;
};

struct rxown_alloc_call {
	void *ring;
	unsigned long caller;
	u32 requested;
	s32 mac_id;
	u32 mgr;
	u8 kind;
	bool scoped;
};

struct rxown_idr_alloc_call {
	struct idr *idr;
	struct sk_buff *skb;
	u64 generation;
	u32 start;
	u32 end;
	s8 ring_slot;
	bool tracked;
	bool scoped;
	bool reinject;
};

struct rxown_idr_remove_call {
	struct idr *idr;
	u32 id;
	s8 ring_slot;
	bool tracked;
};

struct rxown_event {
	u64 sequence;
	u64 generation;
	unsigned long at;
	void *skb;
	void *head;
	void *ring;
	s32 mac_id;
	u32 mgr;
	s32 buf_id;
	u32 users;
	u32 dataref;
	u8 type;
	s8 ring_slot;
	u8 state;
	u8 nohdr;
	u8 head_frag;
	u8 pp_recycle;
};

struct rxown_global {
	u64 allocations;
	u64 scoped_allocations;
	u64 unscoped_allocations;
	u64 releases;
	u64 skb_releases;
	u64 record_alloc_failures;
	u64 record_capacity_failures;
	u64 page_alloc_failures;
	u64 page_capacity_failures;
	u64 scope_alloc_failures;
	u64 ring_capacity_failures;
	u64 head_collisions;
	u64 skb_collisions;
	u64 page_free_unmatched;
	u64 idr_remove_unmatched;
	u64 event_overwrites;
	u64 caller_capacity_failures;
	u64 scope_entries[4];
	u64 scope_returns;
	u64 scope_context_mismatches;
	u64 unscoped_current;
	u64 unscoped_requested;
	u64 unscoped_aligned;
};

struct rxown_caller {
	bool used;
	unsigned long addr;
	u64 allocations;
	u64 live_current;
	u64 releases;
	u64 requested;
	u64 aligned;
	u64 scoped_allocations;
};

static DEFINE_HASHTABLE(records_by_head, RXOWN_RECORD_BITS);
static DEFINE_HASHTABLE(records_by_skb, RXOWN_RECORD_BITS);
static DEFINE_HASHTABLE(pages, RXOWN_PAGE_BITS);
static DEFINE_HASHTABLE(scopes, RXOWN_SCOPE_BITS);
static DEFINE_SPINLOCK(rxown_lock);
static atomic64_t next_generation = ATOMIC64_INIT(0);
static atomic64_t next_event = ATOMIC64_INIT(0);
static struct rxown_ring rings[RXOWN_MAX_RINGS];
static struct rxown_event event_ring[RXOWN_EVENT_CAP];
static struct rxown_global global_stats;
static struct rxown_caller callers[RXOWN_MAX_CALLERS];
static struct dentry *debugfs_root;
static unsigned int record_count;
static unsigned int tracked_page_count;
static bool collecting;
static u8 monitor_process_ring_keys[256];

static struct kretprobe kp_replenish;
static struct kretprobe kp_mon_replenish;
static struct kretprobe kp_mon_process;
static struct kretprobe kp_netdev_alloc;
static struct kretprobe kp_idr_alloc;
static struct kretprobe kp_idr_remove;
static struct kprobe kp_skb_release;
static struct kprobe kp_page_free;

static const char *rxown_state_name(unsigned int state)
{
	static const char * const names[] = { "allocated", "posted", "reaped" };

	return state < ARRAY_SIZE(names) ? names[state] : "invalid";
}

static const char *rxown_event_name(unsigned int type)
{
	switch (type) {
	case RXOWN_EV_ALLOC:
		return "alloc";
	case RXOWN_EV_POST:
		return "post";
	case RXOWN_EV_REAP:
		return "reap";
	case RXOWN_EV_SKB_RELEASE:
		return "skb_release";
	case RXOWN_EV_FRAGMENT_RELEASE:
		return "head_fragment_release";
	default:
		return "invalid";
	}
}

static struct rxown_record *rxown_find_head_locked(void *head)
{
	struct rxown_record *rec;

	hash_for_each_possible(records_by_head, rec, head_node,
			       (unsigned long)head) {
		if (rec->head == head)
			return rec;
	}
	return NULL;
}

static struct rxown_record *rxown_find_skb_locked(struct sk_buff *skb)
{
	struct rxown_record *rec;

	hash_for_each_possible(records_by_skb, rec, skb_node,
			       (unsigned long)skb) {
		if (rec->skb == skb)
			return rec;
	}
	return NULL;
}

static struct rxown_page *rxown_find_page_locked(struct page *page)
{
	struct rxown_page *pg;

	hash_for_each_possible(pages, pg, node, (unsigned long)page) {
		if (pg->page == page)
			return pg;
	}
	return NULL;
}

static struct rxown_scope *rxown_find_scope_locked(struct task_struct *task)
{
	struct rxown_scope *scope;

	hash_for_each_possible(scopes, scope, node, (unsigned long)task) {
		if (scope->task == task)
			return scope;
	}
	return NULL;
}

static bool rxown_scope_context_matches(const struct rxown_scope *scope)
{
	return scope->hardirq == in_hardirq() &&
	       scope->softirq == in_serving_softirq() &&
	       scope->nmi == in_nmi();
}

static int rxown_find_ring_by_ptr_locked(void *ring)
{
	int i;

	for (i = 0; i < RXOWN_MAX_RINGS; i++)
		if (rings[i].used && rings[i].ring == ring)
			return i;
	return -1;
}

static int rxown_find_ring_by_idr_locked(struct idr *idr)
{
	int i;

	for (i = 0; i < RXOWN_MAX_RINGS; i++)
		if (rings[i].used && rings[i].idr == idr)
			return i;
	return -1;
}

static int rxown_get_ring_locked(void *ring, s32 mac_id, u32 mgr, u8 kind)
{
	int i = rxown_find_ring_by_ptr_locked(ring);

	if (i >= 0)
		return i;
	for (i = 0; i < RXOWN_MAX_RINGS; i++) {
		if (rings[i].used)
			continue;
		rings[i].used = true;
		rings[i].ring = ring;
		rings[i].mac_id = mac_id;
		rings[i].mgr = mgr;
		rings[i].kind = kind;
		return i;
	}
	global_stats.ring_capacity_failures++;
	return -1;
}

static int rxown_get_caller_locked(unsigned long addr)
{
	int i;

	for (i = 0; i < RXOWN_MAX_CALLERS; i++)
		if (callers[i].used && callers[i].addr == addr)
			return i;
	for (i = 0; i < RXOWN_MAX_CALLERS; i++) {
		if (callers[i].used)
			continue;
		callers[i].used = true;
		callers[i].addr = addr;
		return i;
	}
	global_stats.caller_capacity_failures++;
	return -1;
}

static void rxown_record_event_locked(u8 type, struct rxown_record *rec,
				      u32 users, u32 dataref)
{
	u64 seq = (u64)atomic64_inc_return(&next_event);
	struct rxown_event *event = &event_ring[(seq - 1) % RXOWN_EVENT_CAP];
	struct rxown_ring *ring = NULL;

	if (seq > RXOWN_EVENT_CAP)
		global_stats.event_overwrites++;
	if (rec->ring_slot >= 0)
		ring = &rings[rec->ring_slot];
	memset(event, 0, sizeof(*event));
	event->sequence = seq;
	event->generation = rec->generation;
	event->at = jiffies;
	event->skb = rec->skb;
	event->head = rec->head;
	event->buf_id = rec->buf_id;
	event->users = users;
	event->dataref = dataref;
	event->type = type;
	event->ring_slot = rec->ring_slot;
	event->state = rec->state;
	event->nohdr = rec->release_nohdr;
	event->head_frag = rec->release_head_frag;
	event->pp_recycle = rec->release_pp_recycle;
	if (ring) {
		event->ring = ring->ring;
		event->mac_id = ring->mac_id;
		event->mgr = ring->mgr;
	}
}

static void rxown_page_add_locked(struct rxown_record *rec,
				  struct rxown_page *pg)
{
	if (!pg)
		return;
	if (rec->ring_slot >= 0) {
		u16 *count = &pg->ring_state[rec->ring_slot][rec->state];

		if (!*count)
			rings[rec->ring_slot].unique_pages[rec->state]++;
		if (!*count)
			rings[rec->ring_slot].backing_bytes[rec->state] +=
				PAGE_SIZE << pg->order;
		(*count)++;
		pg->history_ring_mask |= BIT(rec->ring_slot);
	} else {
		pg->unscoped++;
		if (!rec->scope_candidate)
			pg->history_unscoped = true;
	}
	pg->total++;
}

static void rxown_page_remove_locked(struct rxown_record *rec)
{
	struct rxown_page *pg;

	if (!rec->page_tracked)
		return;
	pg = rxown_find_page_locked(rec->page);
	if (!pg)
		return;
	if (rec->ring_slot >= 0) {
		u16 *count = &pg->ring_state[rec->ring_slot][rec->state];

		if (WARN_ON_ONCE(!*count))
			return;
		(*count)--;
		if (!*count)
			rings[rec->ring_slot].unique_pages[rec->state]--;
		if (!*count)
			rings[rec->ring_slot].backing_bytes[rec->state] -=
				PAGE_SIZE << pg->order;
	} else if (pg->unscoped) {
		if (rec->scope_candidate)
			pg->history_unscoped = true;
		pg->unscoped--;
	}
	if (pg->total)
		pg->total--;
	if (!pg->total) {
		hash_del(&pg->node);
		if (tracked_page_count)
			tracked_page_count--;
		kfree(pg);
	}
}

static void rxown_account_add_locked(struct rxown_record *rec)
{
	if (rec->ring_slot >= 0) {
		struct rxown_ring *ring = &rings[rec->ring_slot];

		ring->state_current[rec->state]++;
		ring->requested[rec->state] += rec->requested;
		ring->aligned[rec->state] += rec->aligned;
	} else {
		global_stats.unscoped_current++;
		global_stats.unscoped_requested += rec->requested;
		global_stats.unscoped_aligned += rec->aligned;
	}
}

static void rxown_account_remove_locked(struct rxown_record *rec)
{
	if (rec->ring_slot >= 0) {
		struct rxown_ring *ring = &rings[rec->ring_slot];

		if (ring->state_current[rec->state])
			ring->state_current[rec->state]--;
		ring->requested[rec->state] -= rec->requested;
		ring->aligned[rec->state] -= rec->aligned;
	} else {
		if (global_stats.unscoped_current)
			global_stats.unscoped_current--;
		global_stats.unscoped_requested -= rec->requested;
		global_stats.unscoped_aligned -= rec->aligned;
	}
}

static void rxown_transition_locked(struct rxown_record *rec, u8 new_state)
{
	struct rxown_page *pg;
	u16 *old_count;
	u16 *new_count;

	if (rec->ring_slot < 0 || rec->state == new_state)
		return;
	pg = rec->page_tracked ? rxown_find_page_locked(rec->page) : NULL;
	if (pg) {
		old_count = &pg->ring_state[rec->ring_slot][rec->state];
		new_count = &pg->ring_state[rec->ring_slot][new_state];
		if (*old_count) {
			(*old_count)--;
			if (!*old_count)
				rings[rec->ring_slot].unique_pages[rec->state]--;
			if (!*old_count)
				rings[rec->ring_slot].backing_bytes[rec->state] -=
					PAGE_SIZE << pg->order;
		}
		if (!*new_count)
			rings[rec->ring_slot].unique_pages[new_state]++;
		if (!*new_count)
			rings[rec->ring_slot].backing_bytes[new_state] +=
				PAGE_SIZE << pg->order;
		(*new_count)++;
	}
	rxown_account_remove_locked(rec);
	rec->state = new_state;
	rxown_account_add_locked(rec);
}

static void rxown_promote_to_ring_locked(struct rxown_record *rec, int slot)
{
	struct rxown_page *pg;
	u16 *count;

	if (rec->ring_slot >= 0)
		return;
	pg = rec->page_tracked ? rxown_find_page_locked(rec->page) : NULL;
	if (pg) {
		if (pg->unscoped)
			pg->unscoped--;
		count = &pg->ring_state[slot][rec->state];
		if (!*count) {
			rings[slot].unique_pages[rec->state]++;
			rings[slot].backing_bytes[rec->state] +=
				PAGE_SIZE << pg->order;
		}
		(*count)++;
		pg->history_ring_mask |= BIT(slot);
	}
	rxown_account_remove_locked(rec);
	rec->ring_slot = slot;
	rxown_account_add_locked(rec);
	if (global_stats.unscoped_allocations)
		global_stats.unscoped_allocations--;
	global_stats.scoped_allocations++;
	rings[slot].allocations++;
	if (rec->caller_slot >= 0)
		callers[rec->caller_slot].scoped_allocations++;
}

static unsigned int rxown_count_idr_locked_by_caller(struct idr *idr)
{
	void *entry;
	int id;
	unsigned int count = 0;

	/* The filtered ath11k caller still holds its idr_lock here. */
	idr_for_each_entry(idr, entry, id)
		count++;
	return count;
}

static int rxown_scope_entry(struct kretprobe_instance *ri,
			     struct pt_regs *regs)
{
	struct rxown_scope_call *call = (void *)ri->data;
	struct rxown_scope *scope;
	struct kretprobe *rp = get_kretprobe(ri);
	unsigned long flags;

	if (!READ_ONCE(collecting))
		return 1;
	scope = kzalloc(sizeof(*scope), GFP_ATOMIC);
	if (!scope) {
		spin_lock_irqsave(&rxown_lock, flags);
		global_stats.scope_alloc_failures++;
		spin_unlock_irqrestore(&rxown_lock, flags);
		return 1;
	}
	scope->task = current;
	scope->mac_id = (s32)regs->regs[1];
	if (rp == &kp_mon_process) {
		scope->kind = RXOWN_SCOPE_MON_PROCESS;
		scope->ring = &monitor_process_ring_keys[(u8)scope->mac_id];
		scope->mgr = U32_MAX;
	} else {
		scope->ring = (void *)regs->regs[2];
		scope->mgr = (u32)regs->regs[4];
		scope->kind = rp == &kp_mon_replenish ?
			RXOWN_SCOPE_MON_STATUS : RXOWN_SCOPE_REGULAR;
	}
	scope->hardirq = in_hardirq();
	scope->softirq = in_serving_softirq();
	scope->nmi = in_nmi();
	call->scope = scope;
	spin_lock_irqsave(&rxown_lock, flags);
	hash_add(scopes, &scope->node, (unsigned long)scope->task);
	global_stats.scope_entries[scope->kind]++;
	spin_unlock_irqrestore(&rxown_lock, flags);
	return 0;
}

static int rxown_scope_return(struct kretprobe_instance *ri,
			      struct pt_regs *regs)
{
	struct rxown_scope_call *call = (void *)ri->data;
	unsigned long flags;

	(void)regs;
	if (!call->scope)
		return 0;
	spin_lock_irqsave(&rxown_lock, flags);
	if (!hlist_unhashed(&call->scope->node))
		hash_del(&call->scope->node);
	global_stats.scope_returns++;
	spin_unlock_irqrestore(&rxown_lock, flags);
	kfree(call->scope);
	call->scope = NULL;
	return 0;
}

static int rxown_netdev_alloc_entry(struct kretprobe_instance *ri,
				    struct pt_regs *regs)
{
	struct rxown_alloc_call *call = (void *)ri->data;
	struct rxown_scope *scope;
	unsigned long flags;

	if (!READ_ONCE(collecting))
		return 1;
	memset(call, 0, sizeof(*call));
	call->requested = (u32)regs->regs[1];
	call->caller = regs->regs[30];
	spin_lock_irqsave(&rxown_lock, flags);
	scope = rxown_find_scope_locked(current);
	if (scope) {
		call->ring = scope->ring;
		call->mac_id = scope->mac_id;
		call->mgr = scope->mgr;
		call->kind = scope->kind;
		call->scoped = true;
		if (!rxown_scope_context_matches(scope))
			global_stats.scope_context_mismatches++;
	}
	spin_unlock_irqrestore(&rxown_lock, flags);
	return 0;
}

static int rxown_netdev_alloc_return(struct kretprobe_instance *ri,
				     struct pt_regs *regs)
{
	struct rxown_alloc_call *call = (void *)ri->data;
	struct sk_buff *skb = (void *)regs_return_value(regs);
	struct rxown_record *rec, *collision;
	struct rxown_page *pg, *new_pg = NULL;
	unsigned long flags;

	if (!skb || !skb->head_frag || !skb->head)
		return 0;
	rec = kzalloc(sizeof(*rec), GFP_ATOMIC);
	if (!rec) {
		spin_lock_irqsave(&rxown_lock, flags);
		global_stats.record_alloc_failures++;
		spin_unlock_irqrestore(&rxown_lock, flags);
		return 0;
	}
	rec->skb = skb;
	rec->head = skb->head;
	rec->page = virt_to_head_page(skb->head);
	rec->generation = (u64)atomic64_inc_return(&next_generation);
	rec->born = jiffies;
	rec->requested = call->requested;
	rec->aligned = SKB_HEAD_ALIGN(call->requested + NET_SKB_PAD);
	rec->buf_id = -1;
	rec->state = RXOWN_ALLOCATED;
	rec->order = compound_order(rec->page);
	rec->skb_linked = true;
	rec->ring_slot = -1;
	rec->caller_slot = -1;
	rec->caller = call->caller;
	if (call->scoped) {
		rec->pending_ring = call->ring;
		rec->pending_mac_id = call->mac_id;
		rec->pending_mgr = call->mgr;
		rec->pending_kind = call->kind;
		rec->scope_candidate = true;
	}

	spin_lock_irqsave(&rxown_lock, flags);
	if (record_count >= RXOWN_MAX_RECORDS) {
		global_stats.record_capacity_failures++;
		goto collision_unlock;
	}
	collision = rxown_find_head_locked(rec->head);
	if (collision) {
		global_stats.head_collisions++;
		goto collision_unlock;
	}
	collision = rxown_find_skb_locked(rec->skb);
	if (collision) {
		global_stats.skb_collisions++;
		goto collision_unlock;
	}
	rec->caller_slot = rxown_get_caller_locked(rec->caller);
	pg = rxown_find_page_locked(rec->page);
	if (!pg && tracked_page_count < RXOWN_MAX_PAGES)
		new_pg = kzalloc(sizeof(*new_pg), GFP_ATOMIC);
	if (!pg && new_pg) {
		new_pg->page = rec->page;
		new_pg->order = rec->order;
		hash_add(pages, &new_pg->node, (unsigned long)new_pg->page);
		tracked_page_count++;
		pg = new_pg;
		new_pg = NULL;
	} else if (!pg) {
		if (tracked_page_count < RXOWN_MAX_PAGES)
			global_stats.page_alloc_failures++;
		else
			global_stats.page_capacity_failures++;
	}
	hash_add(records_by_head, &rec->head_node, (unsigned long)rec->head);
	hash_add(records_by_skb, &rec->skb_node, (unsigned long)rec->skb);
	record_count++;
	rxown_account_add_locked(rec);
	rxown_page_add_locked(rec, pg);
	rec->page_tracked = pg != NULL;
	global_stats.allocations++;
	if (rec->ring_slot >= 0) {
		global_stats.scoped_allocations++;
		rings[rec->ring_slot].allocations++;
	} else {
		global_stats.unscoped_allocations++;
	}
	if (rec->caller_slot >= 0) {
		struct rxown_caller *caller = &callers[rec->caller_slot];

		caller->allocations++;
		caller->live_current++;
		caller->requested += rec->requested;
		caller->aligned += rec->aligned;
		if (rec->ring_slot >= 0)
			caller->scoped_allocations++;
	}
	rxown_record_event_locked(RXOWN_EV_ALLOC, rec, 0, 0);
	spin_unlock_irqrestore(&rxown_lock, flags);
	kfree(new_pg);
	return 0;

collision_unlock:
	spin_unlock_irqrestore(&rxown_lock, flags);
	kfree(new_pg);
	kfree(rec);
	return 0;
}

static int rxown_idr_alloc_entry(struct kretprobe_instance *ri,
				 struct pt_regs *regs)
{
	struct rxown_idr_alloc_call *call = (void *)ri->data;
	struct sk_buff *skb = (void *)regs->regs[1];
	struct rxown_record *rec;
	struct rxown_scope *scope;
	struct idr *called_idr = (void *)regs->regs[0];
	unsigned long flags;
	int idr_slot, slot = -1;

	if (!READ_ONCE(collecting))
		return 1;
	memset(call, 0, sizeof(*call));
	call->ring_slot = -1;
	spin_lock_irqsave(&rxown_lock, flags);
	scope = rxown_find_scope_locked(current);
	rec = rxown_find_skb_locked(skb);
	idr_slot = rxown_find_ring_by_idr_locked(called_idr);
	if (scope && rec && rec->scope_candidate && rec->ring_slot < 0 &&
	    rec->pending_ring == scope->ring) {
		if (idr_slot >= 0) {
			slot = idr_slot;
		} else {
			slot = rxown_get_ring_locked(rec->pending_ring,
						     rec->pending_mac_id,
						     rec->pending_mgr,
						     rec->pending_kind);
			if (slot >= 0 && rings[slot].idr &&
			    rings[slot].idr != called_idr)
				slot = -1;
			if (slot >= 0)
				rings[slot].idr = called_idr;
		}
		if (slot >= 0)
			rxown_promote_to_ring_locked(rec, slot);
		call->scoped = true;
	} else {
		slot = idr_slot;
		call->reinject = slot >= 0;
	}
	if (slot < 0) {
		spin_unlock_irqrestore(&rxown_lock, flags);
		return 1;
	}
	call->idr = called_idr;
	call->skb = skb;
	if (rec && rec->ring_slot == slot)
		call->generation = rec->generation;
	call->start = (u32)regs->regs[2];
	call->end = (u32)regs->regs[3];
	call->ring_slot = slot;
	call->tracked = true;
	if (!rings[slot].idr)
		rings[slot].idr = called_idr;
	else if (rings[slot].idr != called_idr) {
		spin_unlock_irqrestore(&rxown_lock, flags);
		return 1;
	}
	spin_unlock_irqrestore(&rxown_lock, flags);
	return 0;
}

static int rxown_idr_alloc_return(struct kretprobe_instance *ri,
				  struct pt_regs *regs)
{
	struct rxown_idr_alloc_call *call = (void *)ri->data;
	int id = (int)regs_return_value(regs);
	struct rxown_record *rec;
	unsigned long flags;
	unsigned int exact = 0;
	bool sample = false;

	if (!call->tracked)
		return 0;
	if (id >= 0) {
		spin_lock_irqsave(&rxown_lock, flags);
		sample = !rings[call->ring_slot].actual_valid ||
			 rings[call->ring_slot].resample;
		spin_unlock_irqrestore(&rxown_lock, flags);
		if (sample)
			exact = rxown_count_idr_locked_by_caller(call->idr);
	}
	spin_lock_irqsave(&rxown_lock, flags);
	if (id < 0) {
		rings[call->ring_slot].idr_alloc_failures++;
		if (call->reinject)
			rings[call->ring_slot].reinject_allocations++;
		goto out;
	}
	rec = rxown_find_skb_locked(call->skb);
	if (call->reinject)
		rings[call->ring_slot].reinject_allocations++;
	if (call->generation && rec &&
	    rec->generation == call->generation &&
	    rec->ring_slot == call->ring_slot &&
	    (rec->state == RXOWN_ALLOCATED || rec->state == RXOWN_REAPED)) {
		rec->buf_id = id;
		rxown_transition_locked(rec, RXOWN_POSTED);
		rings[call->ring_slot].posts++;
		if (call->reinject)
			rings[call->ring_slot].reinject_posts++;
		rxown_record_event_locked(RXOWN_EV_POST, rec, 0, 0);
	} else if (call->reinject) {
		rings[call->ring_slot].known_idr_alloc_unmatched++;
	}
	if (sample) {
		rings[call->ring_slot].actual_idr = exact;
		rings[call->ring_slot].actual_valid = true;
		rings[call->ring_slot].resample = false;
	} else {
		rings[call->ring_slot].actual_idr++;
	}
	if (call->scoped) {
		if (call->start == 0)
			rings[call->ring_slot].bufs_max = call->end;
		else if (call->end > 1)
			rings[call->ring_slot].bufs_max =
				(call->end - 1) / 3;
		else
			rings[call->ring_slot].bufs_max = call->end;
	}
	rings[call->ring_slot].last_idr_sample = jiffies;
out:
	spin_unlock_irqrestore(&rxown_lock, flags);
	return 0;
}

static int rxown_idr_remove_entry(struct kretprobe_instance *ri,
				  struct pt_regs *regs)
{
	struct rxown_idr_remove_call *call = (void *)ri->data;
	struct idr *idr = (void *)regs->regs[0];
	unsigned long flags;
	int slot;

	if (!READ_ONCE(collecting))
		return 1;
	memset(call, 0, sizeof(*call));
	call->ring_slot = -1;
	spin_lock_irqsave(&rxown_lock, flags);
	slot = rxown_find_ring_by_idr_locked(idr);
	if (slot < 0) {
		spin_unlock_irqrestore(&rxown_lock, flags);
		return 1;
	}
	call->idr = idr;
	call->id = (u32)regs->regs[1];
	call->ring_slot = slot;
	call->tracked = true;
	spin_unlock_irqrestore(&rxown_lock, flags);
	return 0;
}

static int rxown_idr_remove_return(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct rxown_idr_remove_call *call = (void *)ri->data;
	struct sk_buff *skb = (void *)regs_return_value(regs);
	struct rxown_record *rec;
	unsigned long flags;
	unsigned int exact = 0;
	bool sample;

	if (!call->tracked)
		return 0;
	spin_lock_irqsave(&rxown_lock, flags);
	sample = !rings[call->ring_slot].actual_valid ||
		 rings[call->ring_slot].resample;
	spin_unlock_irqrestore(&rxown_lock, flags);
	if (sample)
		exact = rxown_count_idr_locked_by_caller(call->idr);

	spin_lock_irqsave(&rxown_lock, flags);
	if (sample) {
		rings[call->ring_slot].actual_idr = exact;
		rings[call->ring_slot].actual_valid = true;
		rings[call->ring_slot].resample = false;
	} else if (skb && rings[call->ring_slot].actual_idr > 0) {
		rings[call->ring_slot].actual_idr--;
	}
	rings[call->ring_slot].last_idr_sample = jiffies;
	if (!skb) {
		spin_unlock_irqrestore(&rxown_lock, flags);
		return 0;
	}
	rec = rxown_find_skb_locked(skb);
	if (!rec || rec->ring_slot != call->ring_slot) {
		rings[call->ring_slot].untracked_removes++;
		global_stats.idr_remove_unmatched++;
		spin_unlock_irqrestore(&rxown_lock, flags);
		return 0;
	}
	if (rec->state == RXOWN_POSTED) {
		rec->buf_id = call->id;
		rxown_transition_locked(rec, RXOWN_REAPED);
		rings[call->ring_slot].reaps++;
		rxown_record_event_locked(RXOWN_EV_REAP, rec, 0, 0);
	}
	spin_unlock_irqrestore(&rxown_lock, flags);
	return 0;
}

static int rxown_skb_release_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct sk_buff *skb = (void *)regs->regs[0];
	struct rxown_record *rec;
	void *head;
	u32 users, dataref;
	unsigned long flags;

	(void)p;
	if (!READ_ONCE(collecting))
		return 0;
	if (!skb || !skb->head)
		return 0;
	head = skb->head;
	users = refcount_read(&skb->users);
	dataref = (u32)atomic_read(&skb_shinfo(skb)->dataref);
	spin_lock_irqsave(&rxown_lock, flags);
	rec = rxown_find_head_locked(head);
	if (!rec) {
		spin_unlock_irqrestore(&rxown_lock, flags);
		return 0;
	}
	rec->release_users = users;
	rec->release_dataref = dataref;
	rec->release_payload_refs = dataref & SKB_DATAREF_MASK;
	rec->release_nohdr_refs = dataref >> SKB_DATAREF_SHIFT;
	rec->release_nohdr = skb->nohdr;
	rec->release_head_frag = skb->head_frag;
	rec->release_pp_recycle = skb->pp_recycle;
	global_stats.skb_releases++;
	if (rec->skb_linked && rec->skb == skb) {
		hash_del(&rec->skb_node);
		rec->skb_linked = false;
	}
	rxown_record_event_locked(RXOWN_EV_SKB_RELEASE, rec, users, dataref);
	spin_unlock_irqrestore(&rxown_lock, flags);
	return 0;
}

static int rxown_page_free_pre(struct kprobe *p, struct pt_regs *regs)
{
	void *head = (void *)regs->regs[0];
	struct rxown_record *rec;
	unsigned long flags;

	(void)p;
	if (!READ_ONCE(collecting))
		return 0;
	if (!head)
		return 0;
	spin_lock_irqsave(&rxown_lock, flags);
	rec = rxown_find_head_locked(head);
	if (!rec) {
		global_stats.page_free_unmatched++;
		spin_unlock_irqrestore(&rxown_lock, flags);
		return 0;
	}
	if (rec->ring_slot >= 0 && rec->state == RXOWN_POSTED) {
		rings[rec->ring_slot].release_while_posted++;
	}
	rxown_record_event_locked(RXOWN_EV_FRAGMENT_RELEASE, rec,
				  rec->release_users, rec->release_dataref);
	hash_del(&rec->head_node);
	if (record_count)
		record_count--;
	if (rec->skb_linked)
		hash_del(&rec->skb_node);
	rxown_page_remove_locked(rec);
	rxown_account_remove_locked(rec);
	global_stats.releases++;
	if (rec->ring_slot >= 0)
		rings[rec->ring_slot].releases++;
	if (rec->caller_slot >= 0) {
		struct rxown_caller *caller = &callers[rec->caller_slot];

		if (caller->live_current)
			caller->live_current--;
		caller->releases++;
		caller->requested -= rec->requested;
		caller->aligned -= rec->aligned;
	}
	spin_unlock_irqrestore(&rxown_lock, flags);
	kfree(rec);
	return 0;
}

struct rxown_snapshot {
	struct rxown_global global;
	struct rxown_ring rings[RXOWN_MAX_RINGS];
	struct rxown_caller callers[RXOWN_MAX_CALLERS];
	u64 tracked_pages;
	u64 tracked_backing;
	u64 tracked_aligned;
	u64 single_ring_pages;
	u64 cross_ring_pages;
	u64 ring_unscoped_pages;
	u64 unscoped_only_pages;
	u64 historical_cross_lifetime_pages;
	u64 same_ring_history_pages;
	u64 scoped_records;
	u64 total_records;
};

static void rxown_take_snapshot(struct rxown_snapshot *snap)
{
	struct rxown_page *pg;
	unsigned long flags;
	int bkt, i, state;

	memset(snap, 0, sizeof(*snap));
	spin_lock_irqsave(&rxown_lock, flags);
	snap->global = global_stats;
	memcpy(snap->rings, rings, sizeof(rings));
	memcpy(snap->callers, callers, sizeof(callers));
	snap->total_records = record_count;
	snap->tracked_aligned = global_stats.unscoped_aligned;
	for (i = 0; i < RXOWN_MAX_RINGS; i++) {
		for (state = 0; state < RXOWN_STATE_COUNT; state++) {
			snap->scoped_records += rings[i].state_current[state];
			snap->tracked_aligned += rings[i].aligned[state];
		}
	}
	hash_for_each(pages, bkt, pg, node) {
		unsigned int ring_origins = 0;
		bool has_unscoped = pg->unscoped != 0;
		u16 current_ring_mask = 0;

		snap->tracked_pages++;
		snap->tracked_backing += PAGE_SIZE << pg->order;
		for (i = 0; i < RXOWN_MAX_RINGS; i++) {
			bool present = false;

			for (state = 0; state < RXOWN_STATE_COUNT; state++)
				present |= pg->ring_state[i][state] != 0;
			if (present)
				current_ring_mask |= BIT(i);
			if (present)
				ring_origins++;
		}
		if (!ring_origins && has_unscoped)
			snap->unscoped_only_pages++;
		else if (ring_origins == 1 && !has_unscoped)
			snap->single_ring_pages++;
		else if (ring_origins > 1 && !has_unscoped)
			snap->cross_ring_pages++;
		if (ring_origins && has_unscoped)
			snap->ring_unscoped_pages++;
		if (ring_origins == 1 && !has_unscoped) {
			if (pg->history_unscoped ||
			    (pg->history_ring_mask & ~current_ring_mask))
				snap->historical_cross_lifetime_pages++;
			else
				snap->same_ring_history_pages++;
		}
	}
	spin_unlock_irqrestore(&rxown_lock, flags);
}

static int rxown_stats_show(struct seq_file *m, void *v)
{
	struct rxown_snapshot *snap;
	int i, state;

	(void)v;
	snap = kzalloc(sizeof(*snap), GFP_KERNEL);
	if (!snap)
		return -ENOMEM;
	rxown_take_snapshot(snap);
	seq_printf(m, "version=%u collecting=%u warning=unload_rxown_before_ath11k_reload\n",
		   RXOWN_VERSION, READ_ONCE(collecting));
	seq_printf(m, "records=%llu scoped_records=%llu records_capacity=%u pages_capacity=%u events_capacity=%u\n",
		   snap->total_records, snap->scoped_records,
		   RXOWN_MAX_RECORDS, RXOWN_MAX_PAGES, RXOWN_EVENT_CAP);
	seq_printf(m, "allocations=%llu scoped_allocations=%llu unscoped_allocations=%llu head_fragment_releases=%llu skb_release_checkpoints=%llu\n",
		   snap->global.allocations, snap->global.scoped_allocations,
		   snap->global.unscoped_allocations, snap->global.releases,
		   snap->global.skb_releases);
	seq_printf(m, "tracked_pages=%llu tracked_backing_bytes=%llu tracked_aligned_bytes=%llu tracked_slack_bytes=%llu\n",
		   snap->tracked_pages, snap->tracked_backing,
		   snap->tracked_aligned,
		   snap->tracked_backing > snap->tracked_aligned ?
		   snap->tracked_backing - snap->tracked_aligned : 0);
	seq_printf(m, "page_classes single_ring=%llu cross_ring=%llu ring_unscoped=%llu unscoped_only=%llu\n",
		   snap->single_ring_pages, snap->cross_ring_pages,
		   snap->ring_unscoped_pages, snap->unscoped_only_pages);
	seq_printf(m, "page_history lower_bound_cross_lifetime_stranded=%llu same_ring_only_in_tracking_window=%llu history_resets_when_tracked_page_empty=1\n",
		   snap->historical_cross_lifetime_pages,
		   snap->same_ring_history_pages);
	seq_printf(m, "unscoped current=%llu requested_bytes=%llu aligned_bytes=%llu\n",
		   snap->global.unscoped_current,
		   snap->global.unscoped_requested,
		   snap->global.unscoped_aligned);
	seq_printf(m, "failures record_alloc=%llu record_capacity=%llu page_alloc=%llu page_capacity=%llu scope_alloc=%llu ring_capacity=%llu caller_capacity=%llu head_collision=%llu skb_collision=%llu idr_remove_unmatched=%llu\n",
		   snap->global.record_alloc_failures,
		   snap->global.record_capacity_failures,
		   snap->global.page_alloc_failures,
		   snap->global.page_capacity_failures,
		   snap->global.scope_alloc_failures,
		   snap->global.ring_capacity_failures,
		   snap->global.caller_capacity_failures,
		   snap->global.head_collisions,
		   snap->global.skb_collisions,
		   snap->global.idr_remove_unmatched);
	seq_printf(m, "observations unmatched_fragment_release=%llu event_overwrites=%llu scope_regular=%llu scope_mon_replenish=%llu scope_mon_process=%llu scope_returns=%llu scope_context_mismatches=%llu\n",
		   snap->global.page_free_unmatched,
		   snap->global.event_overwrites,
		   snap->global.scope_entries[RXOWN_SCOPE_REGULAR],
		   snap->global.scope_entries[RXOWN_SCOPE_MON_STATUS],
		   snap->global.scope_entries[RXOWN_SCOPE_MON_PROCESS],
		   snap->global.scope_returns,
		   snap->global.scope_context_mismatches);
	seq_printf(m, "nmissed replenish=%d mon_replenish=%d mon_process=%d netdev_alloc=%d idr_alloc=%d idr_remove=%d skb_release=%lu fragment_release=%lu\n",
		   kp_replenish.nmissed, kp_mon_replenish.nmissed,
		   kp_mon_process.nmissed, kp_netdev_alloc.nmissed,
		   kp_idr_alloc.nmissed,
		   kp_idr_remove.nmissed, kp_skb_release.nmissed,
		   kp_page_free.nmissed);
	for (i = 0; i < RXOWN_MAX_RINGS; i++) {
		struct rxown_ring *ring = &snap->rings[i];

		if (!ring->used)
			continue;
		seq_printf(m, "ring slot=%d ptr=%px idr=%px kind=%u mac=%d mgr=%u bufs_max=%u actual_idr=%d actual_valid=%u sample_age_ms=%u allocations=%llu posts=%llu reaps=%llu fragment_releases=%llu idr_alloc_failures=%llu untracked_removes=%llu release_while_posted=%llu reinject_allocations=%llu reinject_posts=%llu known_idr_alloc_unmatched=%llu\n",
			   i, ring->ring, ring->idr, ring->kind, ring->mac_id,
			   ring->mgr, ring->bufs_max, ring->actual_idr,
			   ring->actual_valid,
			   ring->last_idr_sample ?
			   jiffies_to_msecs(jiffies - ring->last_idr_sample) : 0,
			   ring->allocations, ring->posts, ring->reaps,
			   ring->releases, ring->idr_alloc_failures,
			   ring->untracked_removes, ring->release_while_posted,
			   ring->reinject_allocations, ring->reinject_posts,
			   ring->known_idr_alloc_unmatched);
		for (state = 0; state < RXOWN_STATE_COUNT; state++)
			seq_printf(m, "ring_state slot=%d state=%s current=%llu requested_bytes=%llu aligned_bytes=%llu unique_pages=%llu backing_bytes=%llu\n",
				   i, rxown_state_name(state),
				   ring->state_current[state], ring->requested[state],
				   ring->aligned[state], ring->unique_pages[state],
				   ring->backing_bytes[state]);
	}
	for (i = 0; i < RXOWN_MAX_CALLERS; i++) {
		struct rxown_caller *caller = &snap->callers[i];

		if (!caller->used)
			continue;
		seq_printf(m, "caller slot=%d addr=%px symbol=%ps allocations=%llu scoped_allocations=%llu current=%llu releases=%llu requested_bytes=%llu aligned_bytes=%llu\n",
			   i, (void *)caller->addr, (void *)caller->addr,
			   caller->allocations, caller->scoped_allocations,
			   caller->live_current, caller->releases,
			   caller->requested, caller->aligned);
	}
	kfree(snap);
	return 0;
}

static int rxown_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, rxown_stats_show, inode->i_private);
}

static const struct file_operations rxown_stats_fops = {
	.owner = THIS_MODULE,
	.open = rxown_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int rxown_events_show(struct seq_file *m, void *v)
{
	struct rxown_event *snapshot;
	unsigned long flags;
	u64 total, first, seq;

	(void)v;
	snapshot = kcalloc(RXOWN_EVENT_CAP, sizeof(*snapshot), GFP_KERNEL);
	if (!snapshot)
		return -ENOMEM;
	spin_lock_irqsave(&rxown_lock, flags);
	memcpy(snapshot, event_ring, sizeof(event_ring));
	total = (u64)atomic64_read(&next_event);
	spin_unlock_irqrestore(&rxown_lock, flags);
	first = total > RXOWN_EVENT_CAP ? total - RXOWN_EVENT_CAP + 1 : 1;
	for (seq = first; seq <= total; seq++) {
		struct rxown_event *event = &snapshot[(seq - 1) % RXOWN_EVENT_CAP];

		if (event->sequence != seq)
			continue;
		seq_printf(m, "seq=%llu age_ms=%u event=%s gen=%llu skb=%px head=%px ring_slot=%d ring=%px mac=%d mgr=%u buf_id=%d state=%s users=%u dataref=%u payload_refs=%u nohdr_refs=%u nohdr=%u head_frag=%u pp_recycle=%u\n",
			   event->sequence,
			   jiffies_to_msecs(jiffies - event->at),
			   rxown_event_name(event->type), event->generation,
			   event->skb, event->head, event->ring_slot,
			   event->ring, event->mac_id, event->mgr,
			   event->buf_id, rxown_state_name(event->state),
			   event->users, event->dataref,
			   event->dataref & SKB_DATAREF_MASK,
			   event->dataref >> SKB_DATAREF_SHIFT, event->nohdr,
			   event->head_frag, event->pp_recycle);
	}
	kfree(snapshot);
	return 0;
}

static int rxown_events_open(struct inode *inode, struct file *file)
{
	return single_open(file, rxown_events_show, inode->i_private);
}

static const struct file_operations rxown_events_fops = {
	.owner = THIS_MODULE,
	.open = rxown_events_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static ssize_t rxown_control_write(struct file *file, const char __user *buf,
				   size_t len, loff_t *ppos)
{
	char command[16];
	unsigned long flags;
	size_t copy_len;
	int i;

	(void)file;
	(void)ppos;
	copy_len = min(len, sizeof(command) - 1);
	if (copy_from_user(command, buf, copy_len))
		return -EFAULT;
	command[copy_len] = '\0';
	if (strncmp(command, "resample", 8))
		return -EINVAL;
	spin_lock_irqsave(&rxown_lock, flags);
	for (i = 0; i < RXOWN_MAX_RINGS; i++)
		if (rings[i].used)
			rings[i].resample = true;
	spin_unlock_irqrestore(&rxown_lock, flags);
	return len;
}

static const struct file_operations rxown_control_fops = {
	.owner = THIS_MODULE,
	.write = rxown_control_write,
	.llseek = noop_llseek,
};

static struct kretprobe kp_replenish = {
	.kp.symbol_name = "ath11k_dp_rxbufs_replenish",
	.entry_handler = rxown_scope_entry,
	.handler = rxown_scope_return,
	.data_size = sizeof(struct rxown_scope_call),
	.maxactive = 64,
};

static struct kretprobe kp_mon_replenish = {
	.kp.symbol_name = "ath11k_dp_rx_mon_status_bufs_replenish",
	.entry_handler = rxown_scope_entry,
	.handler = rxown_scope_return,
	.data_size = sizeof(struct rxown_scope_call),
	.maxactive = 64,
};

static struct kretprobe kp_mon_process = {
	.kp.symbol_name = "ath11k_dp_rx_process_mon_status",
	.entry_handler = rxown_scope_entry,
	.handler = rxown_scope_return,
	.data_size = sizeof(struct rxown_scope_call),
	.maxactive = 64,
};

static struct kretprobe kp_netdev_alloc = {
	.kp.symbol_name = "__netdev_alloc_skb",
	.entry_handler = rxown_netdev_alloc_entry,
	.handler = rxown_netdev_alloc_return,
	.data_size = sizeof(struct rxown_alloc_call),
	.maxactive = 512,
};

static struct kretprobe kp_idr_alloc = {
	.kp.symbol_name = "idr_alloc",
	.entry_handler = rxown_idr_alloc_entry,
	.handler = rxown_idr_alloc_return,
	.data_size = sizeof(struct rxown_idr_alloc_call),
	.maxactive = 256,
};

static struct kretprobe kp_idr_remove = {
	.kp.symbol_name = "idr_remove",
	.entry_handler = rxown_idr_remove_entry,
	.handler = rxown_idr_remove_return,
	.data_size = sizeof(struct rxown_idr_remove_call),
	.maxactive = 256,
};

static struct kprobe kp_skb_release = {
	.symbol_name = "skb_release_data",
	.pre_handler = rxown_skb_release_pre,
};

static struct kprobe kp_page_free = {
	.symbol_name = "page_frag_free",
	.pre_handler = rxown_page_free_pre,
};

static void rxown_unregister_probes(unsigned int registered)
{
	if (registered >= 8)
		unregister_kprobe(&kp_page_free);
	if (registered >= 7)
		unregister_kprobe(&kp_skb_release);
	if (registered >= 6)
		unregister_kretprobe(&kp_idr_remove);
	if (registered >= 5)
		unregister_kretprobe(&kp_idr_alloc);
	if (registered >= 4)
		unregister_kretprobe(&kp_netdev_alloc);
	if (registered >= 3)
		unregister_kretprobe(&kp_mon_process);
	if (registered >= 2)
		unregister_kretprobe(&kp_mon_replenish);
	if (registered >= 1)
		unregister_kretprobe(&kp_replenish);
}

static int __init rxown_init(void)
{
	struct dentry *stats_file, *events_file, *control_file;
	int ret;
	unsigned int registered = 0;

	hash_init(records_by_head);
	hash_init(records_by_skb);
	hash_init(pages);
	hash_init(scopes);

	ret = register_kretprobe(&kp_replenish);
	if (ret)
		goto fail;
	registered++;
	ret = register_kretprobe(&kp_mon_replenish);
	if (ret)
		goto fail;
	registered++;
	ret = register_kretprobe(&kp_mon_process);
	if (ret)
		goto fail;
	registered++;
	ret = register_kretprobe(&kp_netdev_alloc);
	if (ret)
		goto fail;
	registered++;
	ret = register_kretprobe(&kp_idr_alloc);
	if (ret)
		goto fail;
	registered++;
	ret = register_kretprobe(&kp_idr_remove);
	if (ret)
		goto fail;
	registered++;
	ret = register_kprobe(&kp_skb_release);
	if (ret)
		goto fail;
	registered++;
	ret = register_kprobe(&kp_page_free);
	if (ret)
		goto fail;
	registered++;

	debugfs_root = debugfs_create_dir("rxown", NULL);
	if (IS_ERR(debugfs_root)) {
		ret = PTR_ERR(debugfs_root);
		debugfs_root = NULL;
		goto fail;
	}
	stats_file = debugfs_create_file("stats", 0444, debugfs_root, NULL,
				       &rxown_stats_fops);
	events_file = debugfs_create_file("events", 0444, debugfs_root, NULL,
					 &rxown_events_fops);
	control_file = debugfs_create_file("control", 0200, debugfs_root, NULL,
					  &rxown_control_fops);
	if (IS_ERR_OR_NULL(stats_file) || IS_ERR_OR_NULL(events_file) ||
	    IS_ERR_OR_NULL(control_file)) {
		ret = -ENOMEM;
		debugfs_remove_recursive(debugfs_root);
		debugfs_root = NULL;
		goto fail;
	}
	WRITE_ONCE(collecting, true);
	pr_info("rxown: loaded; unload before ath11k reload\n");
	return 0;

fail:
	WRITE_ONCE(collecting, false);
	rxown_unregister_probes(registered);
	pr_err("rxown: initialization failed: %d\n", ret);
	return ret;
}

static void __exit rxown_exit(void)
{
	struct rxown_record *rec;
	struct rxown_page *pg;
	struct rxown_scope *scope;
	struct hlist_node *tmp;
	unsigned long flags;
	int bkt;

	WRITE_ONCE(collecting, false);
	debugfs_remove_recursive(debugfs_root);
	debugfs_root = NULL;
	rxown_unregister_probes(8);

	spin_lock_irqsave(&rxown_lock, flags);
	hash_for_each_safe(records_by_head, bkt, tmp, rec, head_node) {
		hash_del(&rec->head_node);
		if (rec->skb_linked)
			hash_del(&rec->skb_node);
		kfree(rec);
	}
	hash_for_each_safe(pages, bkt, tmp, pg, node) {
		hash_del(&pg->node);
		kfree(pg);
	}
	hash_for_each_safe(scopes, bkt, tmp, scope, node) {
		hash_del(&scope->node);
		kfree(scope);
	}
	spin_unlock_irqrestore(&rxown_lock, flags);
	pr_info("rxown: unloaded\n");
}

module_init(rxown_init);
module_exit(rxown_exit);

MODULE_DESCRIPTION("loss-accounted ath11k RX-buffer ownership diagnostics");
MODULE_LICENSE("GPL");
