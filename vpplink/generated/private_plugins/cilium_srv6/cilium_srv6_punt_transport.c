/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — IF-3 punt transport (C7, D-76).
 *
 * design/detail/02-headend-dataplane.md §5.6 (the wire), §5.6.9 (this
 *   implementation: queue bounds, owner thread, reconnect, counters)
 * design/detail/00-overview.md §2.18 (the normative clauses), §4.1 (IF-3 is a
 *   Unix domain socket the agent owns; validate before use)
 *
 * This is the half of IF-3 that talks to the socket. cilium_srv6_punt.c owns
 * admission, tokens and reinjection; this file owns bytes and the connection.
 *
 * ------------------------------------------------------------------------
 * Threads
 * ------------------------------------------------------------------------
 *
 * `00` §2.18.7 fixes the split, and everything else here follows from it:
 *
 *   worker threads     csp_tx() only. It serialises the handoff into a frame
 *                      (cilium_srv6_if3_punt_encode), copies the frame and
 *                      the packet into the bounded queue under `t->lock`, and
 *                      returns. **No socket call is reachable from a worker.**
 *                      It also copies before returning because cilium-srv6-punt
 *                      frees the buffer as soon as the hook says SENT.
 *
 *   transport owner    the `cilium-srv6-punt-transport` process node, which
 *                      runs on the main thread. It is the only thread that
 *                      connects, writes, reads, reconnects and closes, and
 *                      the only one that touches `sock_fd`, `file_index`,
 *                      `send_off`, the receive buffer and the statistics
 *                      counters of `cspt_main_t`.
 *
 *   clib_file callbacks  they run on the main thread as part of the vlib
 *                      loop, and they do exactly one thing: signal the
 *                      process node. No I/O happens in them, so there is one
 *                      place — the process body — where the socket state
 *                      machine lives.
 *
 * The queue is the only shared object, and `t->lock` covers all of it:
 * `data`, `head`, `tail`, `n_bytes`, `n_entries`. The owner takes the same
 * lock for peek and pop, and drops it while it writes, which is safe because
 * a producer only ever writes at `tail` and the bytes under `head` stay
 * accounted as occupied until the owner pops them.
 *
 * There is no lock ordering to get wrong, and that is deliberate: `t->lock`
 * and the token store's `hm->punt_lock` are never held at the same time.
 * cilium_srv6_punt_one() releases `hm->punt_lock` before it calls the tx hook,
 * and cspt_disconnect() releases `t->lock` before it releases a token. The
 * only other cross-file call the owner makes, cilium_srv6_punt_reinject(),
 * takes the worker barrier and enqueues a frame; the classify node runs later
 * in the graph, so a reinject that punts again cannot re-enter this file from
 * inside the read loop.
 *
 * ------------------------------------------------------------------------
 * The queue
 * ------------------------------------------------------------------------
 *
 * One MPSC bounded variable-length byte ring under a spinlock, rather than a
 * lock-free SPSC ring per worker. The reasons are specific:
 *
 *   - `00` §2.18.7 asks for a *global* byte budget. Per-worker rings would
 *     have to split it N ways, and a budget that is 1/N per worker is not the
 *     bound the clause states: one busy worker would start dropping while
 *     most of the memory sat idle in the other rings.
 *   - the punt path is already serialised. cilium_srv6_punt_one() takes
 *     `hm->punt_lock` for admission on every punt, so a second short critical
 *     section on the same path adds a bounded amount of contention to a path
 *     that is bounded at 4096 outstanding punts to begin with — it is not the
 *     hot path.
 *   - draining N rings in punt order would need a merge, and the order punts
 *     reach the agent is not something to give up for a lock this path
 *     already pays elsewhere.
 *
 * Layout. `data` is a byte ring of `cap` bytes, `cap` a multiple of 4. A
 * record is a 4-byte length followed by the frame, padded to a multiple of 4,
 * and a record never wraps: if it does not fit before the end of the buffer, a
 * length of 0 is written as a skip marker and the record starts at 0. Records
 * are therefore contiguous, so the owner writes straight out of the ring and
 * the frame needs no second copy. Every record is at least 4 bytes and `cap`
 * is 4-aligned, so there is always room for a skip marker.
 *
 * Both bounds are checked on push and either one is a fail-closed drop with
 * its own counter (`n_drop_ring_full` on the queue the punt belongs to), and
 * cilium_srv6_punt_one() releases the token.
 *
 * ------------------------------------------------------------------------
 * Failure modes
 * ------------------------------------------------------------------------
 *
 *   no path configured   no transport is registered at all. Every punt is a
 *                        fail-closed drop counted in punt_no_transport, which
 *                        is exactly the disposition of the node before this
 *                        file existed.
 *   not connected        csp_tx() returns NO_TRANSPORT, so the same drop and
 *                        the same counter. The queue is not filled with
 *                        frames for an agent that is not there.
 *   queue full           QUEUE_FULL, counted in n_drop_ring_full. Separate
 *                        from the above so that "no agent" and "the agent is
 *                        too slow" are not one number.
 *   write interrupted    the frame is dropped and its token released locally;
 *                        it is **never resent** (`00` §2.18.8). There is no
 *                        ACK on IF-3, so a resend after a failure that
 *                        happened to be past the agent's read would produce a
 *                        second reinject of the same packet, which is worse
 *                        than losing it. See cspt_disconnect() for the exact
 *                        rule about what survives a reconnect.
 *   framing violation    close the connection and count
 *                        ipc_message_rejections_total (`00` §2.18.9).
 *   semantic violation   drop one frame, keep the connection, count
 *                        ipc_frame_drops_total. The asymmetry is the point:
 *                        one odd frame must not be able to disable the node's
 *                        slow path permanently.
 *
 * ------------------------------------------------------------------------
 * VPP facilities used
 * ------------------------------------------------------------------------
 *
 *   clib_file_add / clib_file_del / clib_file_set_data_available_to_write
 *                                     <vppinfra/file.h>, with the pool in
 *                                     `file_main` from <vlib/file.h>
 *   vlib_process_wait_for_event_or_clock, vlib_process_get_events,
 *   vlib_process_signal_event, vlib_process_signal_event_mt
 *                                     <vlib/node_funcs.h> (via <vlib/vlib.h>)
 *   clib_spinlock_*                   <vppinfra/lock.h>
 *   vlib_log_*                        <vlib/log.h>
 *
 * The socket itself is a plain AF_UNIX SOCK_STREAM fd rather than a
 * clib_socket_t: clib_socket_t carries its own tx buffering and write
 * semantics, and `00` §2.18.8 needs write_all with an owned remainder and a
 * no-resend rule on failure, which is easier to state against read(2) and
 * write(2) than to layer on top of another buffer.
 */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <vlib/vlib.h>
#include <vlib/file.h>
#include <vlib/log.h>
#include <vlib/threads.h>
#include <vnet/vnet.h>
#include <vppinfra/file.h>
#include <vppinfra/lock.h>

#include <cilium_srv6/cilium_srv6_guard.h>
#include <cilium_srv6/cilium_srv6_headend.h>
#include <cilium_srv6/cilium_srv6_punt_wire.h>

static vlib_log_class_t cspt_log_class;

#define CSPT_LOG_ERR(...)    vlib_log_err (cspt_log_class, __VA_ARGS__)
#define CSPT_LOG_WARN(...)   vlib_log_warn (cspt_log_class, __VA_ARGS__)
#define CSPT_LOG_NOTICE(...) vlib_log_notice (cspt_log_class, __VA_ARGS__)

/* The one event type. The process re-evaluates its whole state on any wake,
   so there is nothing to distinguish. */
#define CSPT_EVENT_WAKE 1

/* Bound on how many received frames one wake handles before yielding the main
   thread. Each reinject takes the worker barrier, so an agent that sends a
   burst must not be able to hold the graph still for the whole burst. */
#define CSPT_RX_FRAMES_PER_WAKE 64

/* Receive buffer. One maximum frame plus room to batch, so that a stream of
   36-byte releases is not one read() each. */
#define CSPT_RX_BUFFER_BYTES (64 << 10)

/* ------------------------------------------------------------------ */
/* state                                                               */
/* ------------------------------------------------------------------ */

typedef enum
{
  CSPT_DISCONNECTED = 0,
  CSPT_CONNECTING,
  CSPT_CONNECTED,
} cspt_state_t;

typedef struct
{
  /* ---- the queue: shared, all of it under `lock` ---- */
  clib_spinlock_t lock;
  u8 *data;
  u32 cap;	  /* bytes, a multiple of 4 */
  u32 head;	  /* first byte of the oldest record */
  u32 tail;	  /* where the next record goes */
  u32 n_bytes;	  /* occupied bytes, padding and headers included */
  u32 n_entries;  /* occupied records */
  u32 entry_cap;  /* 02 §5.2: 4096 */
  u32 high_water; /* largest n_bytes seen, for `show cilium srv6 headend` */
  /* Set by the owner while it is asleep, so that a producer only pays for
     vlib_process_signal_event_mt() when there is somebody to wake. */
  volatile u32 owner_idle;

  /* ---- owner only ---- */
  cspt_state_t state;
  int sock_fd;
  u32 file_index;
  u32 process_node_index;
  /* How much of the frame at the head of the queue has already been written.
     Non-zero means a frame is half-way out on the wire. */
  u32 send_off;
  u8 *rx;
  u32 rx_len;
  f64 backoff;
  f64 next_connect;
  u8 registered;

  /* ---- statistics, owner only except where noted ---- */
  u64 n_connects;
  u64 n_connect_failures;
  u64 n_disconnects;
  u64 n_frames_sent;
  u64 n_bytes_sent;
  u64 n_frames_received;
  u64 n_reinjects_received;
  u64 n_releases_received;
  u64 n_rejections[CILIUM_SRV6_IF3_N_RESULT];
  u64 n_release_reason[CILIUM_SRV6_IF3_N_DROP_REASON];
  u64 n_unknown_token;
  /* Frames refused by the encoder before they ever reached the queue. A
     non-zero value means the classifier produced a value the wire does not
     define, which is a plugin bug rather than an agent one. Written from
     workers, hence atomic. */
  u64 n_encode_refused;
} cspt_main_t;

static cspt_main_t cspt_main;

/* ------------------------------------------------------------------ */
/* the ring                                                            */
/* ------------------------------------------------------------------ */

#define CSPT_RECORD_HDR 4

static_always_inline u32
cspt_round4 (u32 n)
{
  return (n + 3) & ~((u32) 3);
}

static_always_inline void
cspt_put_len (u8 *p, u32 v)
{
  clib_memcpy_fast (p, &v, sizeof (v));
}

static_always_inline u32
cspt_get_len (const u8 *p)
{
  u32 v;

  clib_memcpy_fast (&v, p, sizeof (v));
  return v;
}

/*
 * Reserve room for one `frame_len`-byte frame and return where to write it.
 * `lock` held. Returns 0 when either bound is reached.
 *
 * Both bounds are checked before anything is written, so a refusal leaves the
 * queue exactly as it was: the caller releases the token and the packet is
 * dropped fail-closed (02 §5.2 never bypasses the miss).
 *
 * The record is committed here and filled by the caller, still under the
 * lock, so that the owner never sees a record whose bytes are not yet
 * written. Filling in place is what keeps the punt path at one copy of the
 * packet.
 */
static u8 *
cspt_ring_reserve (cspt_main_t *t, u32 frame_len)
{
  u32 rec = CSPT_RECORD_HDR + cspt_round4 (frame_len);
  u32 pad = 0;
  u8 *dst;

  if (t->n_entries >= t->entry_cap)
    return 0;

  /* A record never wraps, so if it does not fit before the end of the buffer
     the tail is skipped. The skipped bytes are occupancy like any other: not
     counting them would let the byte budget drift. */
  if (t->cap - t->tail < rec)
    pad = t->cap - t->tail;

  if (rec + pad > t->cap - t->n_bytes)
    return 0;

  if (pad)
    {
      /* `cap` is 4-aligned and every record is a multiple of 4, so `tail` is
	 too, and a non-zero remainder is at least the 4 bytes a marker
	 needs. A frame is never 0 bytes, so 0 is free to mean "skip". */
      cspt_put_len (t->data + t->tail, 0);
      t->n_bytes += pad;
      t->tail = 0;
    }

  cspt_put_len (t->data + t->tail, frame_len);
  dst = t->data + t->tail + CSPT_RECORD_HDR;

  t->tail += rec;
  if (t->tail == t->cap)
    t->tail = 0;
  t->n_bytes += rec;
  t->n_entries++;

  if (t->n_bytes > t->high_water)
    t->high_water = t->n_bytes;

  return dst;
}

/*
 * Point at the oldest frame without removing it. `lock` held.
 *
 * The returned pointer stays valid until the owner pops: producers only ever
 * write at `tail`, and the bytes under `head` are accounted as occupied, so
 * nothing can reach them. That is what lets the owner write straight out of
 * the ring with the lock released.
 *
 * Returns 0 when the queue is empty.
 */
static int
cspt_ring_peek (cspt_main_t *t, const u8 **frame, u32 *len)
{
  u32 l;

  if (t->n_entries == 0)
    return 0;

  l = cspt_get_len (t->data + t->head);
  if (l == 0)
    {
      /* Skip marker: the tail padding is released here rather than at push
	 time, so that the occupancy a producer sees is never lower than the
	 truth. */
      t->n_bytes -= t->cap - t->head;
      t->head = 0;
      l = cspt_get_len (t->data + t->head);
    }

  *frame = t->data + t->head + CSPT_RECORD_HDR;
  *len = l;
  return 1;
}

/* Remove the frame cspt_ring_peek() returned. `lock` held. */
static void
cspt_ring_pop (cspt_main_t *t, u32 len)
{
  u32 rec = CSPT_RECORD_HDR + cspt_round4 (len);

  t->head += rec;
  if (t->head == t->cap)
    t->head = 0;
  t->n_bytes -= rec;
  t->n_entries--;
}

/* ------------------------------------------------------------------ */
/* worker side: serialise and enqueue (00 §2.18.7)                     */
/* ------------------------------------------------------------------ */

/*
 * The registered tx hook. Runs on a worker with the buffer still owned by
 * cilium-srv6-punt, so it copies everything it needs and returns; the node
 * frees the buffer as soon as it sees SENT.
 *
 * It does no socket I/O, which is the clause `00` §2.18.7 states and the
 * reason the queue exists at all. The frame is built on the stack and copied
 * into the queue under the lock: one copy of the header, one of the packet.
 */

/*
 * Copy a buffer chain into `dst`, writing at most `cap` bytes. Returns how
 * many were written.
 *
 * It is bounded rather than using vlib_buffer_contents(), which takes no
 * destination size: the destination here is a queue record sized from
 * `meta->packet_length`, and a copy whose length is a different reading of
 * the same chain would write past it.
 */
static u32
cspt_copy_chain (vlib_main_t *vm, vlib_buffer_t *b, u8 *dst, u32 cap)
{
  u32 n = 0;

  while (b != 0 && n < cap)
    {
      u32 l = b->current_length;

      if (l > cap - n)
	l = cap - n;

      clib_memcpy_fast (dst + n, vlib_buffer_get_current (b), l);
      n += l;

      if (!(b->flags & VLIB_BUFFER_NEXT_PRESENT))
	break;
      b = vlib_get_buffer (vm, b->next_buffer);
    }

  return n;
}

static cilium_srv6_punt_tx_result_t
csp_tx (vlib_main_t *vm, vlib_buffer_t *b, const cilium_srv6_punt_meta_t *meta)
{
  cspt_main_t *t = &cspt_main;
  u8 hdr[CILIUM_SRV6_IF3_PUNT_HDR_LEN];
  u32 packet_len = meta->packet_length;
  u32 copied;
  u8 *dst;
  int was_idle;

  /*
   * `state` is written by the owner and read here without the lock. The race
   * is benign in both directions and there is nothing to serialise it with:
   * a punt enqueued just as the connection drops stays queued and goes out
   * after the reconnect, and a punt refused just as the connection comes up
   * is a fail-closed drop of one packet that the next one repeats. Taking the
   * queue lock around it would not remove the window either, only move it.
   */
  if (PREDICT_FALSE (t->state != CSPT_CONNECTED))
    return CILIUM_SRV6_PUNT_TX_NO_TRANSPORT;

  /*
   * 00 §4.1 bounds every declared length before it is used. A punt larger
   * than the wire allows is refused rather than truncated: a truncated packet
   * would be compiled against a header chain that is not the one that
   * arrived. cilium_srv6_if3_punt_encode() checks the same bound; the check
   * is here as well because `packet_len` also sizes the queue record.
   */
  if (PREDICT_FALSE (packet_len > CILIUM_SRV6_IF3_MAX_PACKET) ||
      PREDICT_FALSE (cilium_srv6_if3_punt_encode (hdr, &meta->w, packet_len) != CILIUM_SRV6_IF3_OK))
    {
      /*
       * Either the packet is over the wire bound, or the classifier produced
       * a value the wire does not define — an unknown cause, a discriminator
       * on a protocol that has none, fragment metadata that contradicts the
       * fragment kind. Sending it would have the agent drop the frame as a
       * field violation and the flow would punt for ever, so it is refused
       * here, where it is attributable to this plugin rather than to the
       * agent.
       */
      clib_atomic_fetch_add (&t->n_encode_refused, 1);
      return CILIUM_SRV6_PUNT_TX_QUEUE_FULL;
    }

  clib_spinlock_lock (&t->lock);

  dst = cspt_ring_reserve (t, CILIUM_SRV6_IF3_PUNT_HDR_LEN + packet_len);
  if (PREDICT_TRUE (dst != 0))
    {
      clib_memcpy_fast (dst, hdr, CILIUM_SRV6_IF3_PUNT_HDR_LEN);
      copied = cspt_copy_chain (vm, b, dst + CILIUM_SRV6_IF3_PUNT_HDR_LEN, packet_len);
      /*
       * The record is already committed, so a chain that turned out shorter
       * than `meta->packet_length` (which cannot happen — both come from the
       * same buffer at the same moment — but is cheap to make harmless) is
       * zero-filled rather than left holding whatever the ring had. The
       * frame's `length` and `packet_len` already describe the reserved size,
       * so the agent sees a well-framed frame either way.
       */
      if (PREDICT_FALSE (copied < packet_len))
	clib_memset (dst + CILIUM_SRV6_IF3_PUNT_HDR_LEN + copied, 0, packet_len - copied);
    }

  was_idle = (dst != 0) && t->owner_idle;
  if (was_idle)
    t->owner_idle = 0;

  clib_spinlock_unlock (&t->lock);

  if (PREDICT_FALSE (dst == 0))
    return CILIUM_SRV6_PUNT_TX_QUEUE_FULL;

  /*
   * Wake the owner only when it was asleep. vlib_process_signal_event_mt() is
   * the cross-thread signal (it goes through the main thread's remote-event
   * path); doing it per punt regardless would put that cost on every packet
   * of a burst, whereas the owner drains the whole queue per wake anyway.
   */
  if (was_idle)
    vlib_process_signal_event_mt (vlib_get_first_main (), t->process_node_index, CSPT_EVENT_WAKE,
				  0);

  return CILIUM_SRV6_PUNT_TX_SENT;
}

/* ------------------------------------------------------------------ */
/* owner side: connection                                              */
/* ------------------------------------------------------------------ */

/* All four callbacks do the same thing: hand the socket back to the process
   node, which owns the state machine. */
static clib_error_t *
cspt_file_event (clib_file_t *f)
{
  cspt_main_t *t = &cspt_main;

  (void) f;
  t->owner_idle = 0;
  vlib_process_signal_event (vlib_get_first_main (), t->process_node_index, CSPT_EVENT_WAKE, 0);
  return 0;
}

static void
cspt_file_register (cspt_main_t *t)
{
  clib_file_t template = { 0 };

  template.read_function = cspt_file_event;
  template.write_function = cspt_file_event;
  template.error_function = cspt_file_event;
  template.file_descriptor = t->sock_fd;
  template.description = format (0, "cilium-srv6 IF-3 punt socket");

  t->file_index = clib_file_add (&file_main, &template);
}

/*
 * Ask the poller to tell us when the socket becomes writable. Only used while
 * a write returned EAGAIN or while a connect is in flight; the rest of the
 * time an always-writable socket would wake the process on every loop.
 */
static void
cspt_want_write (cspt_main_t *t, int want)
{
  if (t->file_index != (u32) ~0)
    clib_file_set_data_available_to_write (&file_main, t->file_index, want != 0);
}

/*
 * Close the connection and decide what happens to the queue.
 *
 * The rule of `00` §2.18.8, made structural: a frame that was **partially
 * written** is dropped and its token released locally, because with no ACK on
 * IF-3 a resend risks a second reinject of a packet the agent already has.
 * Frames that were never written stay queued and survive the reconnect —
 * `send_off` is exactly the "was this one partially written" flag, and it is
 * non-zero for at most one frame, the one at the head.
 *
 * A queued frame's token keeps ageing while the transport is down, so a
 * reconnect that takes longer than the punt token timeout delivers frames
 * whose tokens have already expired. The agent's answer to those is refused
 * by cilium_srv6_punt_reinject() and counted in n_reinject_rejected; the
 * packet is lost either way, and dropping the queue instead would lose the
 * ones that are still good.
 */
static void
cspt_disconnect (cspt_main_t *t, const char *why)
{
  int was_connected = (t->state == CSPT_CONNECTED);

  if (t->send_off != 0)
    {
      const u8 *frame;
      u32 len;

      clib_spinlock_lock (&t->lock);
      if (cspt_ring_peek (t, &frame, &len))
	{
	  u8 token[CILIUM_SRV6_IF3_TOKEN_LEN];
	  u8 queue;

	  clib_memcpy_fast (token, cilium_srv6_if3_frame_token (frame), sizeof (token));
	  /* The opcode is the queue (02 §5.6.1), and it is the only place the
	     queue survives once the handoff is gone. */
	  queue = (u8) (frame[1] - CILIUM_SRV6_IF3_OP_PUNT_COMPILE);
	  cspt_ring_pop (t, len);
	  clib_spinlock_unlock (&t->lock);

	  if (queue < CILIUM_SRV6_PUNT_N_Q)
	    cilium_srv6_headend_main.punt_q[queue].n_drop_write_failed++;

	  /*
	   * Release the token locally. There is no drop reason from the agent
	   * — it never saw the frame — so the packet is charged to the same
	   * slow-path overflow reason the rest of this failure mode uses.
	   */
	  (void) cilium_srv6_punt_release (token, CILIUM_SRV6_IF3_DROP_SLOWPATH_OVERFLOW);
	}
      else
	{
	  clib_spinlock_unlock (&t->lock);
	}
      t->send_off = 0;
    }

  if (t->file_index != (u32) ~0)
    {
      /* clib_file_del closes the descriptor. */
      clib_file_del_by_index (&file_main, t->file_index);
      t->file_index = (u32) ~0;
      t->sock_fd = -1;
    }
  else if (t->sock_fd >= 0)
    {
      close (t->sock_fd);
      t->sock_fd = -1;
    }

  t->rx_len = 0;
  t->state = CSPT_DISCONNECTED;

  if (was_connected)
    {
      t->n_disconnects++;
      CSPT_LOG_WARN ("IF-3 punt transport disconnected: %s", why);
    }

  /* 02 §5.6.9: 200 ms, doubling to 5 s. An agent restart is routine, so the
     first retry is quick; an agent that is not coming back must not turn into
     a connect() storm. */
  t->backoff = (t->backoff <= 0.0) ? CILIUM_SRV6_IF3_BACKOFF_MIN : t->backoff * 2.0;
  if (t->backoff > CILIUM_SRV6_IF3_BACKOFF_MAX)
    t->backoff = CILIUM_SRV6_IF3_BACKOFF_MAX;
  t->next_connect = vlib_time_now (vlib_get_first_main ()) + t->backoff;
}

static void
cspt_connected (cspt_main_t *t)
{
  t->state = CSPT_CONNECTED;
  t->backoff = 0.0;
  t->n_connects++;
  cspt_want_write (t, 0);
  CSPT_LOG_NOTICE ("IF-3 punt transport connected to %s",
		   (char *) cilium_srv6_main.punt_socket_path);
}

/*
 * One connect attempt. Non-blocking: a Unix stream connect() usually
 * completes immediately, but it can return EINPROGRESS when the listener's
 * backlog is being drained, and blocking the main thread on that would stall
 * the whole graph.
 */
static void
cspt_connect (cspt_main_t *t, f64 now)
{
  struct sockaddr_un sun;
  const char *path = (const char *) cilium_srv6_main.punt_socket_path;
  size_t path_len;
  int fd, flags;

  if (now < t->next_connect)
    return;

  t->next_connect = now + CILIUM_SRV6_IF3_BACKOFF_MAX;

  if (path == 0)
    return;

  path_len = strlen (path);
  if (path_len >= sizeof (sun.sun_path))
    {
      t->n_connect_failures++;
      CSPT_LOG_ERR ("IF-3 punt socket path is %u bytes, the maximum is %u", (u32) path_len,
		    (u32) sizeof (sun.sun_path) - 1);
      return;
    }

  fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    {
      t->n_connect_failures++;
      return;
    }

  flags = fcntl (fd, F_GETFL, 0);
  if (flags < 0 || fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      close (fd);
      t->n_connect_failures++;
      return;
    }

  clib_memset (&sun, 0, sizeof (sun));
  sun.sun_family = AF_UNIX;
  clib_memcpy_fast (sun.sun_path, path, path_len);

  t->sock_fd = fd;
  cspt_file_register (t);

  if (connect (fd, (struct sockaddr *) &sun, sizeof (sun)) == 0)
    {
      cspt_connected (t);
      return;
    }

  if (errno == EINPROGRESS || errno == EALREADY)
    {
      t->state = CSPT_CONNECTING;
      cspt_want_write (t, 1);
      return;
    }

  t->n_connect_failures++;
  cspt_disconnect (t, "connect failed");
}

/* Finish a connect that returned EINPROGRESS. */
static void
cspt_connect_finish (cspt_main_t *t)
{
  int err = 0;
  socklen_t len = sizeof (err);

  if (getsockopt (t->sock_fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0)
    {
      t->n_connect_failures++;
      cspt_disconnect (t, "connect did not complete");
      return;
    }

  cspt_connected (t);
}

/* ------------------------------------------------------------------ */
/* owner side: writing                                                 */
/* ------------------------------------------------------------------ */

/*
 * Drain the queue onto the socket.
 *
 * write_all with an owned remainder: a frame is written from the queue, and
 * `send_off` records how much of it went out. A short write is normal on a
 * stream socket, so the remainder waits for writability rather than being
 * spun on, and the frame is popped only once all of it is out. Nothing is
 * ever resent (`00` §2.18.8); see cspt_disconnect().
 */
static void
cspt_write (cspt_main_t *t)
{
  while (t->state == CSPT_CONNECTED)
    {
      const u8 *frame;
      u32 len;
      ssize_t n;
      int have;

      clib_spinlock_lock (&t->lock);
      have = cspt_ring_peek (t, &frame, &len);
      clib_spinlock_unlock (&t->lock);

      if (!have)
	{
	  cspt_want_write (t, 0);
	  return;
	}

      n = write (t->sock_fd, frame + t->send_off, len - t->send_off);

      if (n < 0)
	{
	  if (errno == EINTR)
	    continue;
	  if (errno == EAGAIN || errno == EWOULDBLOCK)
	    {
	      cspt_want_write (t, 1);
	      return;
	    }
	  cspt_disconnect (t, "write failed");
	  return;
	}

      if (n == 0)
	{
	  cspt_want_write (t, 1);
	  return;
	}

      t->send_off += (u32) n;
      t->n_bytes_sent += (u64) n;

      if (t->send_off < len)
	{
	  /* Half a frame is on the wire. It is not resendable from here on:
	     cspt_disconnect() drops it if the connection fails. */
	  cspt_want_write (t, 1);
	  return;
	}

      clib_spinlock_lock (&t->lock);
      cspt_ring_pop (t, len);
      clib_spinlock_unlock (&t->lock);

      t->send_off = 0;
      t->n_frames_sent++;
    }
}

/* ------------------------------------------------------------------ */
/* owner side: reading                                                 */
/* ------------------------------------------------------------------ */

/*
 * Act on one decoded agent -> plugin frame.
 *
 * Neither branch trusts anything but the token. The reinject is re-classified
 * from its bytes (02 §5.1 step 8) and its echoed punt_id is checked against
 * what the dataplane recorded; the release carries no packet at all. A token
 * that is unknown or already consumed changes no state and is counted
 * (`00` §2.18.6).
 */
static void
cspt_deliver (cspt_main_t *t, const cilium_srv6_if3_reinject_t *m)
{
  int rv;

  if (m->drop_reason == CILIUM_SRV6_IF3_DROP_NONE)
    {
      t->n_reinjects_received++;
      rv = cilium_srv6_punt_reinject (m->token, m->punt_id, m->packet, m->packet_len);
    }
  else
    {
      t->n_releases_received++;
      t->n_release_reason[m->drop_reason]++;
      rv = cilium_srv6_punt_release (m->token, m->drop_reason);
    }

  if (rv != 0)
    t->n_unknown_token++;
}

/*
 * Read whatever is available and act on every complete frame in it.
 *
 * Framing is validated before anything is read out of a frame (`00` §4.1):
 * cilium_srv6_if3_frame_length() checks the version and the bound, and the
 * decoder checks that `length` describes the frame it is holding. A framing
 * violation closes the connection because the next byte's meaning is then
 * unknown; a field violation drops one frame and the stream continues
 * (`00` §2.18.9).
 */
static void
cspt_read (cspt_main_t *t)
{
  u32 handled = 0;

  while (t->state == CSPT_CONNECTED)
    {
      ssize_t n;
      u32 off = 0;

      if (t->rx_len < CSPT_RX_BUFFER_BYTES)
	{
	  n = read (t->sock_fd, t->rx + t->rx_len, CSPT_RX_BUFFER_BYTES - t->rx_len);
	  if (n < 0)
	    {
	      if (errno == EINTR)
		continue;
	      if (errno != EAGAIN && errno != EWOULDBLOCK)
		{
		  cspt_disconnect (t, "read failed");
		  return;
		}
	      n = 0;
	    }
	  else if (n == 0)
	    {
	      cspt_disconnect (t, "the agent closed the connection");
	      return;
	    }
	  t->rx_len += (u32) n;
	  if (n == 0 && t->rx_len == 0)
	    return;
	}

      /* Consume every complete frame in the buffer. */
      while (off < t->rx_len)
	{
	  cilium_srv6_if3_reinject_t m;
	  cilium_srv6_if3_result_t rv;
	  u32 total;

	  rv = cilium_srv6_if3_frame_length (t->rx + off, t->rx_len - off, &total);
	  if (rv == CILIUM_SRV6_IF3_ERR_TRUNCATED)
	    break; /* fewer than 4 header bytes: read more */
	  if (rv != CILIUM_SRV6_IF3_OK)
	    {
	      t->n_rejections[rv]++;
	      cspt_disconnect (t, cilium_srv6_if3_result_name (rv));
	      return;
	    }

	  if (t->rx_len - off < total)
	    break; /* the frame is not all here yet */

	  rv = cilium_srv6_if3_reinject_decode (t->rx + off, total, &m);
	  off += total;
	  t->n_frames_received++;
	  handled++;

	  if (rv == CILIUM_SRV6_IF3_OK)
	    {
	      cspt_deliver (t, &m);
	    }
	  else
	    {
	      t->n_rejections[rv]++;
	      if (cilium_srv6_if3_is_framing_error (rv))
		{
		  /* The frame's own boundary is not trustworthy, so neither is
		     the next one's. Everything still buffered is discarded
		     with the connection. */
		  cspt_disconnect (t, cilium_srv6_if3_result_name (rv));
		  return;
		}
	      /* Semantic: exactly this frame is discarded and the stream
		 continues. One odd frame must not take IF-3 down for the
		 node (00 §2.18.9). */
	    }

	  if (handled >= CSPT_RX_FRAMES_PER_WAKE)
	    break;
	}

      if (off)
	{
	  t->rx_len -= off;
	  if (t->rx_len)
	    memmove (t->rx, t->rx + off, t->rx_len);
	}

      if (handled >= CSPT_RX_FRAMES_PER_WAKE)
	{
	  /* Yield the main thread and come straight back: every reinject took
	     the worker barrier, so a burst must not hold the graph still. */
	  t->owner_idle = 0;
	  vlib_process_signal_event (vlib_get_first_main (), t->process_node_index, CSPT_EVENT_WAKE,
				     0);
	  return;
	}

      if (t->rx_len == CSPT_RX_BUFFER_BYTES)
	{
	  /* Nothing was consumed and the buffer is full. That cannot happen
	     with a peer that respects the frame bound, and continuing would
	     spin. */
	  t->n_rejections[CILIUM_SRV6_IF3_ERR_LENGTH]++;
	  cspt_disconnect (t, "the peer sent a frame larger than the IF-3 bound");
	  return;
	}

      if (off == 0)
	return; /* nothing more to read right now */
    }
}

/* ------------------------------------------------------------------ */
/* owner side: the process node                                        */
/* ------------------------------------------------------------------ */

static uword
cspt_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  cspt_main_t *t = &cspt_main;
  f64 now;

  (void) rt;
  (void) f;

  while (1)
    {
      f64 wait;
      int pending = 0;

      now = vlib_time_now (vm);

      if (t->state == CSPT_CONNECTED)
	wait = CILIUM_SRV6_IF3_BACKOFF_MAX;
      else
	{
	  wait = t->next_connect - now;
	  if (wait < CILIUM_SRV6_IF3_BACKOFF_MIN)
	    wait = CILIUM_SRV6_IF3_BACKOFF_MIN;
	}

      /*
       * The wake-up handshake, and the reason both halves of it are inside the
       * same critical section as the push.
       *
       * A producer signals only when it finds `owner_idle` set, so that a
       * burst does not pay a cross-thread signal per packet. The window that
       * has to be closed is the one where the owner has just drained the
       * queue, a producer pushes and sees `owner_idle` still 0, and the owner
       * then goes to sleep with work waiting — which would hold that frame
       * for a full clock period. Setting the flag and re-reading `n_entries`
       * under `lock` closes it: either the producer's push happens first, in
       * which case `pending` is true here, or the flag is set first, in which
       * case the producer sees it and signals.
       *
       * When there is work, the owner signals *itself* rather than skipping
       * the wait. The wait then returns immediately, but the process still
       * yields to the graph once, so a busy queue cannot starve the main
       * thread.
       */
      if (t->registered)
	{
	  clib_spinlock_lock (&t->lock);
	  t->owner_idle = 1;
	  pending = t->n_entries != 0;
	  clib_spinlock_unlock (&t->lock);
	}

      if (pending && t->state == CSPT_CONNECTED)
	vlib_process_signal_event (vm, t->process_node_index, CSPT_EVENT_WAKE, 0);

      vlib_process_wait_for_event_or_clock (vm, wait);
      (void) vlib_process_get_events (vm, 0);
      t->owner_idle = 0;

      if (!t->registered)
	continue; /* no punt socket configured: there is nothing to drive */

      now = vlib_time_now (vm);

      switch (t->state)
	{
	case CSPT_DISCONNECTED:
	  cspt_connect (t, now);
	  break;
	case CSPT_CONNECTING:
	  cspt_connect_finish (t);
	  break;
	case CSPT_CONNECTED:
	  break;
	}

      if (t->state == CSPT_CONNECTED)
	{
	  /* Read first: a reinject frees a token and therefore a quota slot,
	     and writing first would only widen the window in which the slot
	     is held. */
	  cspt_read (t);
	  cspt_write (t);
	}
    }

  return 0;
}

VLIB_REGISTER_NODE (cilium_srv6_punt_transport_process_node, static) = {
  .function = cspt_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "cilium-srv6-punt-transport",
  .process_log2_n_stack_bytes = 16,
};

/* ------------------------------------------------------------------ */
/* read-out                                                            */
/* ------------------------------------------------------------------ */

void
cilium_srv6_punt_transport_stats (cilium_srv6_punt_transport_stats_t *out)
{
  cspt_main_t *t = &cspt_main;
  u32 i;

  clib_memset (out, 0, sizeof (out[0]));

  if (!t->registered)
    return;

  out->configured = cilium_srv6_main.punt_socket_path != 0;
  out->connected = (t->state == CSPT_CONNECTED);
  out->n_connects = t->n_connects;
  out->n_connect_failures = t->n_connect_failures;
  out->n_disconnects = t->n_disconnects;
  out->n_frames_sent = t->n_frames_sent;
  out->n_bytes_sent = t->n_bytes_sent;
  out->n_frames_received = t->n_frames_received;
  out->n_reinjects_received = t->n_reinjects_received;
  out->n_releases_received = t->n_releases_received;
  out->n_unknown_token = t->n_unknown_token;
  out->n_encode_refused = t->n_encode_refused;

  for (i = 0; i < CILIUM_SRV6_IF3_N_RESULT; i++)
    out->n_rejections[i] = t->n_rejections[i];
  for (i = 0; i < CILIUM_SRV6_IF3_N_DROP_REASON; i++)
    out->n_release_reason[i] = t->n_release_reason[i];

  clib_spinlock_lock (&t->lock);
  out->queue_entries = t->n_entries;
  out->queue_bytes = t->n_bytes;
  out->queue_high_water_bytes = t->high_water;
  clib_spinlock_unlock (&t->lock);

  out->queue_entry_cap = t->entry_cap;
  out->queue_byte_cap = t->cap;
}

/* ------------------------------------------------------------------ */
/* init                                                                */
/* ------------------------------------------------------------------ */

/*
 * Registered after the headend, because csp_tx() reaches the token store and
 * the queue counters that cilium_srv6_punt_init() sets up. Until the hook is
 * registered every punt is a fail-closed drop counted in punt_no_transport,
 * which is also what happens for good when no socket path is configured.
 */
static clib_error_t *
cspt_init (vlib_main_t *vm)
{
  cspt_main_t *t = &cspt_main;
  cilium_srv6_main_t *cm = &cilium_srv6_main;
  u32 cap;

  cspt_log_class = vlib_log_register_class ("cilium-srv6", "if3");

  t->sock_fd = -1;
  t->file_index = (u32) ~0;
  t->state = CSPT_DISCONNECTED;
  t->process_node_index = cilium_srv6_punt_transport_process_node.index;
  t->entry_cap = CILIUM_SRV6_IF3_QUEUE_ENTRIES;

  if (cm->punt_socket_path == 0)
    {
      /*
       * No `cilium-srv6 { punt-socket <path> }`. There is no default path to
       * fall back to — D-27 puts the socket in a directory the agent creates
       * and owns — so the transport does not start. Every punt then fails
       * closed and is counted in punt_no_transport, which is observable in
       * `show cilium srv6 headend` and in srv6_headend_status_get.
       */
      CSPT_LOG_ERR ("no IF-3 punt socket configured: add `punt-socket <absolute "
		    "path>` to the cilium-srv6 startup stanza. Until then every "
		    "punt fails closed (DROP_SLOWPATH_OVERFLOW, punt_no_transport)");
      return 0;
    }

  cap = cm->punt_queue_bytes;
  if (cap < CILIUM_SRV6_IF3_QUEUE_BYTES_MIN)
    cap = CILIUM_SRV6_IF3_QUEUE_BYTES_MIN;
  /* A record never wraps, so the buffer is 4-aligned and one maximum-size
     record always fits. */
  cap = cap & ~((u32) 3);

  vec_validate (t->data, cap - 1);
  t->cap = cap;
  vec_validate (t->rx, CSPT_RX_BUFFER_BYTES - 1);

  clib_spinlock_init (&t->lock);

  t->registered = 1;
  cilium_srv6_punt_tx_register (csp_tx);

  CSPT_LOG_NOTICE ("IF-3 punt transport armed: socket %s, queue %u entries / %u bytes",
		   (char *) cm->punt_socket_path, t->entry_cap, t->cap);

  /*
   * No wake-up from here: a process node's runtime does not exist yet at
   * VLIB_INIT time. `next_connect` is 0, so the first scheduled run — one
   * backoff period, 200 ms, after the graph starts — dials the socket.
   */
  (void) vm;

  return 0;
}

VLIB_INIT_FUNCTION (cspt_init) = {
  .runs_after = VLIB_INITS ("cilium_srv6_headend_init"),
};
