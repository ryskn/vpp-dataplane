/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — cilium-srv6-classify (C7), dataplane.
 *
 * design/detail/02-headend-dataplane.md §3, in order:
 *
 *   endpoint = LocalEndpointTable[(rx_sw_if_index, rx_if_incarnation)]
 *   if (!endpoint)              -> drop (DROP_UNKNOWN_SOURCE_EP)
 *   if (link control packet)    -> drop (DROP_LINK_LOCAL_CONTROL)
 *   if (src_ip != endpoint.ip)  -> drop (DROP_SRC_IP_MISMATCH)
 *   meta.src_identity = endpoint.identity
 *   bounded inner EH / fragment parse (01 §3.1)
 *                               -> drop (DROP_MALFORMED_INNER)
 *   l4_discriminator (D-41)
 *   -> cilium-srv6-ct
 *
 * The source identity comes from the *interface*, never from the packet's
 * source address (02 §3): that is what stops a Pod from turning a source
 * address spoof into an identity spoof. The address is then compared against
 * the endpoint's own address so that a spoofed source cannot be used to
 * evade the destination side either.
 *
 * D-50 makes the acceptable input explicit as an architecture invariant:
 * forwarding traffic received on a Pod-facing interface is an L3 IPv6 packet
 * whose source is the Pod address bound to that interface. The Pod attachment
 * is an L3-only interface (TUN, or memif in IP mode) that the CNI configures
 * statically — address, route and MTU only, with link-local autoconfiguration
 * and RA/RS/SLAAC/DHCPv6 disabled — so no link-layer next hop is resolved and
 * the classify stage needs no exception for ND, MLD, RS or RA.
 *
 * The dataplane still counts what it cannot forward. A packet with a
 * link-local source or destination, or a multicast destination, is dropped as
 * DROP_LINK_LOCAL_CONTROL rather than as DROP_SRC_IP_MISMATCH: 06 §2 treats
 * the latter as a candidate security violation (a Pod using an address that
 * is not its own), while an IPv6 link control packet reaching an L3-only
 * attachment is a configuration or protocol event. Mixing them would make the
 * spoof counter unreadable. cilium/cilium#16261 is the failure mode this
 * design removes: a link-local sourced Neighbor Solicitation dropped by
 * policy stopped IPv6 forwarding entirely.
 *
 * D-31 is enforced inside cilium_srv6_local_ep_lookup(): the entry only
 * resolves while its stored incarnation still equals the live incarnation of
 * that sw_if_index, so a reused index cannot inherit a deleted Pod's
 * identity.
 *
 * Fragment rules (01 §3.1 / D-43), which this node also owns because
 * DROP_FRAGMENT_UNRESOLVED is a classify-stage reason (06 §2):
 *
 *   non-first fragment  FragmentVerdictCache hit with every D-20 binding
 *                       still valid -> same path as the first fragment,
 *                       bypassing conntrack and the ProgramCache;
 *                       anything else -> DROP_FRAGMENT_UNRESOLVED
 *   first fragment      a second one for the same (src, dst, id) received
 *                       from the network is DROP_FRAGMENT_UNRESOLVED (the
 *                       overlap proxy of D-43); otherwise evaluated normally
 *                       and recorded by cilium-srv6-program
 *   atomic fragment     treated as an ordinary packet
 *
 * No per-datagram offset state is kept and nothing is buffered, which is the
 * point of D-43: the ordering rule replaces the state that overlap detection
 * would need.
 *
 * The one-shot reinjection capability (Issue #90, decision of 2026-09-01)
 * -----------------------------------------------------------------------
 *
 * D-43 as written also drops the punted first fragment when the agent hands it
 * back: by then the FragmentVerdictCache holds the record the agent just
 * installed, the reinjected packet finds its own key present, and the datagram
 * is lost whichever order the agent uses (installing after reinjecting instead
 * makes the reinject punt again, i.e. a loop). The decision resolves this by
 * clarifying what D-43 counts, and by giving the record a capability rather
 * than a bare flag:
 *
 *   D-43's "second first fragment" means a first fragment newly received from
 *   network ingress. An authenticated reinjection, as the continuation of
 *   slow-path processing, is not a new network reception but the continued
 *   processing of the original packet.
 *
 * A bare "not forwarded yet" flag would not be enough, and this is the reason
 * the capability is bound to a punt_id: with a bare flag, an attacker that
 * sends a second first fragment for the same (src, dst, id) would spend the
 * flag, be forwarded, and leave the legitimate reinjection to be dropped —
 * which is precisely the "insert another first fragment into an already
 * decided datagram" that D-43 exists to prevent. So:
 *
 *   external first fragment (this node's normal input)
 *       record present -> DROP_FRAGMENT_UNRESOLVED, whatever the state of the
 *       capability, and the capability is *not* spent.
 *   reinjected first fragment of a fragment-class punt
 *       (CILIUM_SRV6_BUFFER_F_REINJECT and the redeemed token's queue is the
 *       fragment queue)
 *       record present, capability unspent and punt_id equal -> the
 *       capability is spent once and the packet continues to normal
 *       processing, where the D-20/D-51 checks apply exactly as they do to
 *       any other packet. The capability grants an exemption from D-43 and
 *       from nothing else.
 *   the same, anything else
 *       (no record, punt_id mismatch, capability already spent)
 *       -> DROP_FRAGMENT_STALE_REINJECT, and deliberately not a re-punt: a
 *       stale reinjection that punted again would be answered again and come
 *       back again.
 *
 * Continuation classes (the narrowing of 2026-09-01)
 * ---------------------------------------------------
 *
 *   The FragmentVerdictCache one-shot reinjection capability applies only to
 *   reinjections originating from a fragment-class punt. A fragment-class
 *   reinjection with no matching live capability is stale and MUST be dropped
 *   without re-punting. Reinjections originating from other authenticated
 *   punt classes, including D-38 conntrack reauthorization, follow their
 *   respective continuation semantics and do not require a
 *   FragmentVerdictCache capability.
 *
 * The capability is a mechanism local to the fragment class, not a general
 * exception to D-43, because only a fragment-class punt installs a
 * FragmentVerdictCache record. cilium-srv6-ct can punt a first fragment on the
 * D-38 re-authorisation queue, and that punt installs nothing, so "no record"
 * says nothing about it; its reinjection is classified exactly as it was
 * before Issue #90, D-43 included. Reading "reinjection with no record" as
 * stale would drop a reply the fragment path never touched.
 *
 *   reinject token
 *     +- fragment class (CILIUM_SRV6_PUNT_Q_FRAGMENT)
 *     |     requires a live FragmentVerdictCache capability
 *     +- any other class, D-38 re-authorisation included
 *           its own continuation semantics; no capability involved
 *
 * The class is taken from the token the reinjection redeemed, never from the
 * agent: an agent that could name its own continuation class could name the
 * one that requires no capability, and the capability would mean nothing.
 * That is why cilium_srv6_punt_reinject() copies t.queue into the buffer and
 * the classifier reads it from there.
 *
 * D-43 is not weakened by either class. Both are the continued processing of a
 * packet this node already received — network ingress, punt, authenticated
 * answer — and a first fragment newly received from the network is still
 * dropped, whichever class has a punt outstanding.
 *
 * non-first fragments do not consult the capability at all. They are gated on
 * the record and its bindings, so a slow reinjection delays the first fragment
 * of a datagram, not all of its other fragments.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/format.h>

#include <cilium_srv6/cilium_srv6_guard.h>
#include <cilium_srv6/cilium_srv6_headend.h>
#include <cilium_srv6/cilium_srv6_hparse.h>
#include <cilium_srv6/cilium_srv6.api_enum.h>

/*
 * The fragment classification this node records is also an IF-3 wire value
 * (`02` §5.6.5, D-76 §2.18.5): the punt frame reports what the bounded parser
 * found, and the validity of `fragment_id` / `frag_next_header` follows from
 * it. Asserting the equivalence here — in the file that produces the value,
 * and the one that includes the parser header — makes a renumbering of either
 * enum a build failure instead of a wrong byte on the wire.
 */
STATIC_ASSERT ((int) CILIUM_SRV6_FRAG_NONE == CILIUM_SRV6_IF3_FRAG_NONE &&
		 (int) CILIUM_SRV6_FRAG_ATOMIC == CILIUM_SRV6_IF3_FRAG_ATOMIC &&
		 (int) CILIUM_SRV6_FRAG_FIRST == CILIUM_SRV6_IF3_FRAG_FIRST &&
		 (int) CILIUM_SRV6_FRAG_NON_FIRST == CILIUM_SRV6_IF3_FRAG_NON_FIRST,
	       "the parser's fragment classification no longer matches the 02 §5.6.5 enum");

typedef enum
{
  CILIUM_SRV6_CLASSIFY_NEXT_DROP,
  CILIUM_SRV6_CLASSIFY_NEXT_CT,
  CILIUM_SRV6_CLASSIFY_NEXT_ENCAP,
  CILIUM_SRV6_CLASSIFY_N_NEXT,
} cilium_srv6_classify_next_t;

typedef enum
{
  CILIUM_SRV6_CLASSIFY_OK = 0,
  /* fragment resolved from the FragmentVerdictCache: straight to encap */
  CILIUM_SRV6_CLASSIFY_FRAG_ALLOW,
  CILIUM_SRV6_CLASSIFY_UNKNOWN_SOURCE_EP,
  CILIUM_SRV6_CLASSIFY_LINK_LOCAL_CONTROL,
  CILIUM_SRV6_CLASSIFY_SRC_IP_MISMATCH,
  CILIUM_SRV6_CLASSIFY_MALFORMED_INNER,
  CILIUM_SRV6_CLASSIFY_FRAGMENT_UNRESOLVED,
  /* Issue #90: a reinjected first fragment that no live capability admits. */
  CILIUM_SRV6_CLASSIFY_FRAGMENT_STALE_REINJECT,
  CILIUM_SRV6_CLASSIFY_POLICY_DENIED,
  CILIUM_SRV6_CLASSIFY_N_VERDICT,
} cilium_srv6_classify_verdict_t;

typedef struct
{
  u32 sw_if_index;
  u32 if_incarnation;
  u32 src_identity;
  u32 l4_discriminator;
  u32 path_cache_index;
  u8 verdict;
  u8 proto;
  u8 frag_kind;
  ip6_address_t src;
  ip6_address_t dst;
} cilium_srv6_classify_trace_t;

/* `static inline`: see the note in cilium_srv6_guard_node.c. */
static inline u8 *
format_cilium_srv6_classify_verdict (u8 *s, va_list *args)
{
  u32 v = va_arg (*args, u32);

  switch (v)
    {
    case CILIUM_SRV6_CLASSIFY_OK:
      return format (s, "classified");
    case CILIUM_SRV6_CLASSIFY_FRAG_ALLOW:
      return format (s, "fragment ALLOW from FragmentVerdictCache");
    case CILIUM_SRV6_CLASSIFY_UNKNOWN_SOURCE_EP:
      return format (s, "drop (DROP_UNKNOWN_SOURCE_EP)");
    case CILIUM_SRV6_CLASSIFY_LINK_LOCAL_CONTROL:
      return format (s, "drop (DROP_LINK_LOCAL_CONTROL)");
    case CILIUM_SRV6_CLASSIFY_SRC_IP_MISMATCH:
      return format (s, "drop (DROP_SRC_IP_MISMATCH)");
    case CILIUM_SRV6_CLASSIFY_MALFORMED_INNER:
      return format (s, "drop (DROP_MALFORMED_INNER)");
    case CILIUM_SRV6_CLASSIFY_FRAGMENT_UNRESOLVED:
      return format (s, "drop (DROP_FRAGMENT_UNRESOLVED)");
    case CILIUM_SRV6_CLASSIFY_FRAGMENT_STALE_REINJECT:
      return format (s, "drop (DROP_FRAGMENT_STALE_REINJECT)");
    case CILIUM_SRV6_CLASSIFY_POLICY_DENIED:
      return format (s, "drop (DROP_POLICY_DENIED, cached fragment verdict)");
    default:
      return format (s, "unknown(%u)", v);
    }
}

static inline u8 *
format_cilium_srv6_frag_kind (u8 *s, va_list *args)
{
  u32 v = va_arg (*args, u32);

  switch (v)
    {
    case CILIUM_SRV6_FRAG_NONE:
      return format (s, "none");
    case CILIUM_SRV6_FRAG_ATOMIC:
      return format (s, "atomic");
    case CILIUM_SRV6_FRAG_FIRST:
      return format (s, "first");
    case CILIUM_SRV6_FRAG_NON_FIRST:
      return format (s, "non-first");
    default:
      return format (s, "unknown(%u)", v);
    }
}

static inline u8 *
format_cilium_srv6_classify_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cilium_srv6_classify_trace_t *t = va_arg (*args, cilium_srv6_classify_trace_t *);

  s = format (s,
	      "cilium-srv6-classify: rx sw_if_index %u incarnation %u "
	      "identity %u\n"
	      "  src %U dst %U proto %u l4-disc %u fragment %U\n"
	      "  path %d verdict %U",
	      t->sw_if_index, t->if_incarnation, t->src_identity, format_ip6_address, &t->src,
	      format_ip6_address, &t->dst, (u32) t->proto, t->l4_discriminator,
	      format_cilium_srv6_frag_kind, (u32) t->frag_kind,
	      (t->path_cache_index == (u32) ~0) ? -1 : (int) t->path_cache_index,
	      format_cilium_srv6_classify_verdict, (u32) t->verdict);
  return s;
}

/*
 * D-20: a cached fragment verdict is only usable while every binding it was
 * created with still holds. This is deliberately the same set of checks
 * cilium-srv6-program applies to a ProgramCache entry, so the fragment path
 * cannot outlive a policy revoke or an endpoint incarnation change.
 */
static_always_inline int
cilium_srv6_frag_entry_usable (const cilium_srv6_headend_main_t *hm,
			       const cilium_srv6_frag_entry_t *f,
			       const cilium_srv6_headend_meta_t *meta, const ip6_address_t *src,
			       const ip6_address_t *dst, u32 frag_id, u8 next_header, f64 now)
{
  /* Defensive re-check of the key: an entry can be reclaimed by another
     worker between the bihash hit and this read. */
  if (PREDICT_FALSE (!f->in_use || f->frag_id != frag_id || f->next_header != next_header))
    return 0;

  if (PREDICT_FALSE (!ip6_address_is_equal (&f->src, src) || !ip6_address_is_equal (&f->dst, dst)))
    return 0;

  if (PREDICT_FALSE (f->expires_at <= now))
    return 0;

  /* Same endpoint lifetime and same identity (D-20). */
  if (PREDICT_FALSE (f->src_identity != meta->src_identity ||
		     f->local_context_id != meta->local_context_id ||
		     f->policy_rev_slot != meta->policy_rev_slot))
    return 0;

  if (PREDICT_FALSE (!cilium_srv6_revisions_match (hm, f->policy_rev_slot, f->policy_revision,
						   f->endpoint_rev_slot, f->endpoint_revision,
						   f->path_cache_index, f->path_revision)))
    return 0;

  return 1;
}

/*
 * Issue #90: spend the one-shot reinjection capability of `f`, if this packet
 * is the reinjection that capability was issued for.
 *
 * Returns 1 when the record admits this packet as the continuation of its own
 * punt, in which case the capability is spent here and cannot admit a second
 * packet. Returns 0 for everything else, which the caller turns into a drop —
 * D-43's for a packet received from the network, DROP_FRAGMENT_STALE_REINJECT
 * for a reinjection with no live capability behind it.
 *
 * Spending the capability is not conditional on the packet then being
 * forwarded. The D-20/D-51 checks run afterwards and may still drop it, and
 * that is deliberate: the capability records that the punt of this datagram
 * has been answered, which is true whether or not the answer still forwards.
 * A second attempt cannot arise in any case, because the punt token that
 * carried the punt_id is itself one-shot (00 §4.1).
 */
static_always_inline int
cilium_srv6_frag_capability_spend (cilium_srv6_frag_entry_t *f, int is_frag_reinject, u64 punt_id,
				   const ip6_address_t *src, const ip6_address_t *dst, u32 frag_id,
				   u8 next_header)
{
  /* An external first fragment never spends the capability, whatever its
     state: that is what stops an attacker from consuming the capability of a
     datagram it did not send and having the legitimate reinjection dropped
     in its place. */
  if (PREDICT_TRUE (!is_frag_reinject))
    return 0;

  /* The bihash hit is re-checked against the key, as everywhere else here: an
     entry can be reclaimed by another worker between the lookup and this
     read, and a reclaimed entry must not be able to admit a reinjection. */
  if (PREDICT_FALSE (!f->in_use || f->frag_id != frag_id || f->next_header != next_header))
    return 0;

  if (PREDICT_FALSE (!ip6_address_is_equal (&f->src, src) || !ip6_address_is_equal (&f->dst, dst)))
    return 0;

  /* punt_id 0 is "this record answers no punt" — what the dataplane writer
     installs for a first fragment it forwarded itself. No reinjection is
     coming for such a record and none is admitted. */
  if (PREDICT_FALSE (!f->reinject_pending || f->punt_id == 0 || f->punt_id != punt_id))
    return 0;

  f->reinject_pending = 0;
  return 1;
}

/*
 * One packet of 02 §3. Performs no allocation and does not modify the packet;
 * the metadata is written into the buffer's scratch area only.
 */
static_always_inline cilium_srv6_classify_verdict_t
cilium_srv6_classify_one (vlib_main_t *vm, const cilium_srv6_headend_main_t *hm,
			  const cilium_srv6_main_t *cm, vlib_buffer_t *b, f64 now,
			  cilium_srv6_hparse_t *hp)
{
  cilium_srv6_headend_meta_t *meta = cilium_srv6_headend_meta (b);
  cilium_srv6_path_meta_t *pm = cilium_srv6_path_meta (b);
  const u8 *p0 = (const u8 *) vlib_buffer_get_current (b);
  const ip6_header_t *ip = (const ip6_header_t *) p0;
  const cilium_srv6_local_ep_t *ep;
  u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
  u64 key[5];
  u32 index;
  u64 reinject_punt_id = 0;
  int is_frag_reinject = 0;

  /*
   * Issue #90. The reinject marking has to be read before the scratch areas
   * are initialised, because it lives in one of them
   * (cilium_srv6_reinject_meta_t overlays the path metadata). The flag, not
   * the value, is what makes this safe: a packet that arrived on an interface
   * has stale bytes in the scratch area but never the flag, so the value is
   * only ever read when cilium_srv6_punt_reinject() wrote it.
   *
   * The flag is cleared as it is consumed, so it cannot survive into a later
   * stage or, if the buffer is recirculated, into a second classification.
   *
   * Only a fragment-class punt is relevant here, and the queue is taken from
   * the redeemed token, not from the agent. cilium-srv6-ct can punt a first
   * fragment on the D-38 re-authorisation queue, and that punt installs no
   * FragmentVerdictCache record; treating its reinjection as a fragment
   * reinjection would make "no record" mean "stale" for a packet the fragment
   * path never took, and drop a reply that used to be forwarded. A
   * re-authorisation reinjection is therefore classified exactly as before
   * this change — including D-43, which still drops it if the datagram has
   * meanwhile acquired a record.
   */
  if (PREDICT_FALSE (0 != (b->flags & CILIUM_SRV6_BUFFER_F_REINJECT)))
    {
      const cilium_srv6_reinject_meta_t *rm = cilium_srv6_reinject_meta (b);

      if (rm->punt_queue == CILIUM_SRV6_PUNT_Q_FRAGMENT)
	{
	  is_frag_reinject = 1;
	  reinject_punt_id = rm->punt_id;
	}
      b->flags &= ~CILIUM_SRV6_BUFFER_F_REINJECT;
    }

  clib_memset (meta, 0, sizeof (*meta));
  clib_memset (pm, 0, sizeof (*pm));
  pm->path_cache_index = ~0;
  pm->program_index = ~0;

  /* Nothing is read from the header until it is known to be there. */
  if (PREDICT_FALSE (b->current_length < sizeof (ip6_header_t)))
    return CILIUM_SRV6_CLASSIFY_MALFORMED_INNER;

  /* 02 §3: one LocalEndpointTable lookup, keyed on (sw_if_index,
     if_incarnation) per D-31. */
  ep = cilium_srv6_local_ep_lookup (hm, cm, sw_if_index);
  if (PREDICT_FALSE (ep == NULL))
    return CILIUM_SRV6_CLASSIFY_UNKNOWN_SOURCE_EP;

  /*
   * D-50 / 02 §3: the Pod attachment is L3-only, so an IPv6 link control
   * packet is not forwardable input here. Counting it separately, and before
   * the spoof check, keeps DROP_SRC_IP_MISMATCH a candidate security
   * violation instead of a bucket that a link-local sourced Router
   * Solicitation or MLD report also lands in.
   */
  if (PREDICT_FALSE (ip6_address_is_link_local_unicast (&ip->src_address) ||
		     ip6_address_is_link_local_unicast (&ip->dst_address) ||
		     ip6_address_is_multicast (&ip->dst_address)))
    return CILIUM_SRV6_CLASSIFY_LINK_LOCAL_CONTROL;

  /* 02 §3: a Pod that spoofs its source address is dropped here rather than
     being classified with the interface's identity and a foreign address. */
  if (PREDICT_FALSE (!ip6_address_is_equal (&ip->src_address, &ep->ip)))
    return CILIUM_SRV6_CLASSIFY_SRC_IP_MISMATCH;

  meta->src_identity = ep->identity;
  meta->policy_rev_slot = ep->policy_rev_slot;
  meta->local_context_id = ep->local_context_id;
  meta->owner_quota_class = ep->owner_quota_class;

  /* 01 §3.1 bounded walk; every dereference inside is bound checked. */
  if (PREDICT_FALSE (CILIUM_SRV6_HPARSE_OK !=
		     cilium_srv6_hparse (p0, b->current_length,
					 vlib_buffer_length_in_chain (vm, b), hp)))
    return CILIUM_SRV6_CLASSIFY_MALFORMED_INNER;

  meta->proto = hp->proto;
  meta->l4_discriminator = hp->l4_discriminator;
  meta->frag_id = hp->frag_id;

  /* 01 §4: the flow entropy hash needs both ports, but only the destination
     one is part of the ProgramCache key, so the pair is carried separately. */
  pm->sport = hp->sport;
  pm->dport = hp->dport;
  pm->frag_next_header = hp->frag_next_header;
  /* 02 §7.2 (C10): the conntrack stage reads the TCP control bits from here
     rather than parsing the packet a second time. */
  pm->tcp_flags = hp->tcp_flags;

  switch (hp->frag_kind)
    {
    case CILIUM_SRV6_FRAG_NON_FIRST:
      {
	const cilium_srv6_frag_entry_t *f;
	const cilium_srv6_path_t *path;

	meta->flags |= CILIUM_SRV6_META_F_FRAG_NON_FIRST;

	cilium_srv6_frag_key (key, &ip->src_address, &ip->dst_address, hp->frag_id,
			      hp->frag_next_header);

	/*
	 * D-43: "first fragment より前に到着した non-first fragment は DROP".
	 * A miss is exactly that case (or an expired / evicted record), and
	 * nothing is buffered to wait for the first fragment.
	 */
	if (PREDICT_FALSE (!cilium_srv6_frag_lookup (hm, key, &index)))
	  return CILIUM_SRV6_CLASSIFY_FRAGMENT_UNRESOLVED;

	if (PREDICT_FALSE (index >= hm->frag_capacity))
	  return CILIUM_SRV6_CLASSIFY_FRAGMENT_UNRESOLVED;

	f = hm->frags + index;

	if (PREDICT_FALSE (!cilium_srv6_frag_entry_usable (hm, f, meta, &ip->src_address,
							  &ip->dst_address, hp->frag_id,
							  hp->frag_next_header, now)))
	  return CILIUM_SRV6_CLASSIFY_FRAGMENT_UNRESOLVED;

	if (f->verdict != CILIUM_SRV6_VERDICT_ALLOW)
	  return CILIUM_SRV6_CLASSIFY_POLICY_DENIED;

	/*
	 * D-49 / D-20 / D-51: the lease binds the fragment path too. It is
	 * read from the PolicyLeaseTable slot of the entry's dependency
	 * identity — the same slot the ProgramCache entry this verdict came
	 * from consults — so the fragment path cannot be the one route that
	 * survives a policy watcher outage.
	 */
	if (PREDICT_FALSE (!cilium_srv6_policy_lease_valid (hm, f->policy_rev_slot, f->src_identity,
							    f->policy_revision, now)))
	  return CILIUM_SRV6_CLASSIFY_FRAGMENT_UNRESOLVED;

	/* 01 §3.1: "non-first fragment は一致する ALLOW が存在する場合だけ
	   同じ path へ転送する". */
	path = cilium_srv6_path_get (hm, f->path_cache_index, f->path_generation);
	if (PREDICT_FALSE (path == NULL))
	  return CILIUM_SRV6_CLASSIFY_FRAGMENT_UNRESOLVED;

	pm->path_cache_index = f->path_cache_index;
	pm->path_generation = f->path_generation;
	meta->flags |= CILIUM_SRV6_META_F_FRAG_RESOLVED;

	return CILIUM_SRV6_CLASSIFY_FRAG_ALLOW;
      }

    case CILIUM_SRV6_FRAG_FIRST:
      meta->flags |= CILIUM_SRV6_META_F_FRAG_FIRST;

      cilium_srv6_frag_key (key, &ip->src_address, &ip->dst_address, hp->frag_id,
			    hp->frag_next_header);

      /*
       * D-43: "同一 (src, dst, fragment-id) に対する first fragment の
       * 再受信は DROP" — the proxy detection for an overlap attack, which
       * costs one lookup instead of per-datagram offset state. Issue #90
       * clarifies that "再受信" means a reception from network ingress, so
       * the rule is unchanged for every packet this node sees on an
       * interface. The reinjection of the punted first fragment is not an
       * exception to the rule but a different provenance: it continues the
       * processing of a packet already received, and within the fragment
       * class it is admitted only by the record's own capability.
       */
      if (PREDICT_FALSE (cilium_srv6_frag_lookup (hm, key, &index)))
	{
	  cilium_srv6_frag_entry_t *f;

	  if (PREDICT_FALSE (index >= hm->frag_capacity))
	    return is_frag_reinject ? CILIUM_SRV6_CLASSIFY_FRAGMENT_STALE_REINJECT
				    : CILIUM_SRV6_CLASSIFY_FRAGMENT_UNRESOLVED;

	  /*
	   * The write below is the only mutation cilium-srv6-classify makes to
	   * a FragmentVerdictCache entry, and it is made without frag_lock.
	   * That is safe rather than merely cheap: it is reached only on the
	   * reinject path, which runs on the main thread, and the only other
	   * writer of `reinject_pending` is srv6_fragment_verdict_add, which
	   * runs on the main thread too. A worker racing here can only recycle
	   * the pool slot through cilium_srv6_frag_record(), which always
	   * installs reinject_pending = 0, so the worst outcome of losing the
	   * race is clearing a byte that is already zero.
	   */
	  f = hm->frags + index;

	  if (!cilium_srv6_frag_capability_spend (f, is_frag_reinject, reinject_punt_id,
						  &ip->src_address, &ip->dst_address, hp->frag_id,
						  hp->frag_next_header))
	    return is_frag_reinject ? CILIUM_SRV6_CLASSIFY_FRAGMENT_STALE_REINJECT
				    : CILIUM_SRV6_CLASSIFY_FRAGMENT_UNRESOLVED;

	  /*
	   * The capability exempts this packet from D-43 and from nothing
	   * else. The record it was admitted by is policy-dependent state, so
	   * the D-20 bindings and the D-51 lease are checked here exactly as
	   * they are for a non-first fragment; a verdict that has stopped
	   * being usable between the punt and the reinjection fails closed.
	   */
	  if (PREDICT_FALSE (!cilium_srv6_frag_entry_usable (hm, f, meta, &ip->src_address,
							    &ip->dst_address, hp->frag_id,
							    hp->frag_next_header, now)))
	    return CILIUM_SRV6_CLASSIFY_FRAGMENT_UNRESOLVED;

	  if (f->verdict != CILIUM_SRV6_VERDICT_ALLOW)
	    return CILIUM_SRV6_CLASSIFY_POLICY_DENIED;

	  if (PREDICT_FALSE (!cilium_srv6_policy_lease_valid (hm, f->policy_rev_slot, f->src_identity,
							     f->policy_revision, now)))
	    return CILIUM_SRV6_CLASSIFY_FRAGMENT_UNRESOLVED;
	}
      else if (PREDICT_FALSE (is_frag_reinject))
	{
	  /*
	   * A reinjection whose record is gone — expired, evicted, or never
	   * installed. It is dropped and deliberately *not* punted again: the
	   * agent would compile the same answer and send the same packet back
	   * to the same absent record. 06 §2 keeps it apart from
	   * DROP_FRAGMENT_UNRESOLVED because it is a stale control-plane
	   * response, not a packet anomaly.
	   */
	  return CILIUM_SRV6_CLASSIFY_FRAGMENT_STALE_REINJECT;
	}

      /*
       * Normal processing from here, for the first reception and for the
       * admitted reinjection alike: conntrack, then the ProgramCache. The
       * reinjected packet is expected to hit the entry the agent installed
       * alongside the fragment verdict, and cilium-srv6-program's own call to
       * cilium_srv6_frag_record() finds the record already present and leaves
       * it — including its now spent capability — untouched.
       */
      break;

    case CILIUM_SRV6_FRAG_ATOMIC:
      /*
       * 01 §3.1: an atomic fragment is evaluated as an ordinary packet — no
       * FragmentVerdictCache entry, no D-43 re-reception rule — so nothing
       * about *forwarding* changes here.
       *
       * The flag is recorded because the IF-3 punt frame reports what the
       * parser found (02 §5.6.5, D-76 §2.18.2). Without it a punt of this
       * packet would say frag_kind = NONE while carrying the Fragment
       * header's Identification and Next Header, which is a frame that
       * contradicts itself, and the agent drops such a frame as a field
       * violation — so every atomically fragmented flow would punt for ever.
       */
      meta->flags |= CILIUM_SRV6_META_F_FRAG_ATOMIC;
      break;

    default:
      /* No Fragment header. */
      break;
    }

  return CILIUM_SRV6_CLASSIFY_OK;
}

static_always_inline u32
cilium_srv6_classify_error_of_verdict (cilium_srv6_classify_verdict_t v)
{
  switch (v)
    {
    case CILIUM_SRV6_CLASSIFY_UNKNOWN_SOURCE_EP:
      return CILIUM_SRV6_CLASSIFY_ERROR_UNKNOWN_SOURCE_EP;
    case CILIUM_SRV6_CLASSIFY_LINK_LOCAL_CONTROL:
      return CILIUM_SRV6_CLASSIFY_ERROR_LINK_LOCAL_CONTROL;
    case CILIUM_SRV6_CLASSIFY_SRC_IP_MISMATCH:
      return CILIUM_SRV6_CLASSIFY_ERROR_SRC_IP_MISMATCH;
    case CILIUM_SRV6_CLASSIFY_FRAGMENT_UNRESOLVED:
      return CILIUM_SRV6_CLASSIFY_ERROR_FRAGMENT_UNRESOLVED;
    case CILIUM_SRV6_CLASSIFY_FRAGMENT_STALE_REINJECT:
      return CILIUM_SRV6_CLASSIFY_ERROR_FRAGMENT_STALE_REINJECT;
    case CILIUM_SRV6_CLASSIFY_POLICY_DENIED:
      return CILIUM_SRV6_CLASSIFY_ERROR_POLICY_DENIED;
    default:
      return CILIUM_SRV6_CLASSIFY_ERROR_MALFORMED_INNER;
    }
}

VLIB_NODE_FN (cilium_srv6_classify_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  const cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  const cilium_srv6_main_t *cm = &cilium_srv6_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u8 verdicts[VLIB_FRAME_SIZE], *vd = verdicts;
  cilium_srv6_hparse_t parsed[VLIB_FRAME_SIZE], *hp = parsed;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 n_classified = 0, n_frag_bypass = 0;
  f64 now = vlib_time_now (vm);

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      cilium_srv6_classify_verdict_t v;

      v = cilium_srv6_classify_one (vm, hm, cm, b[0], now, hp);
      vd[0] = (u8) v;

      if (PREDICT_TRUE (v == CILIUM_SRV6_CLASSIFY_OK))
	{
	  next[0] = CILIUM_SRV6_CLASSIFY_NEXT_CT;
	  n_classified++;
	}
      else if (v == CILIUM_SRV6_CLASSIFY_FRAG_ALLOW)
	{
	  /* The verdict and the path are already resolved, so conntrack and
	     the ProgramCache have nothing to add (01 §3.1). */
	  next[0] = CILIUM_SRV6_CLASSIFY_NEXT_ENCAP;
	  n_frag_bypass++;
	}
      else
	{
	  b[0]->error = node->errors[cilium_srv6_classify_error_of_verdict (v)];
	  next[0] = CILIUM_SRV6_CLASSIFY_NEXT_DROP;
	}

      b += 1;
      next += 1;
      vd += 1;
      hp += 1;
      n_left -= 1;
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      u32 i;

      b = bufs;
      vd = verdicts;
      hp = parsed;

      for (i = 0; i < frame->n_vectors; i++, b++, vd++, hp++)
	{
	  const cilium_srv6_headend_meta_t *meta;
	  const cilium_srv6_path_meta_t *pm;
	  cilium_srv6_classify_trace_t *t;
	  u32 sw_if_index;

	  if (!(b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    continue;

	  meta = cilium_srv6_headend_meta (b[0]);
	  pm = cilium_srv6_path_meta (b[0]);
	  sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];

	  t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  clib_memset (t, 0, sizeof (*t));

	  t->sw_if_index = sw_if_index;
	  t->if_incarnation =
	    (sw_if_index < vec_len (cm->ifs)) ? cm->ifs[sw_if_index].incarnation : (u32) ~0;
	  t->src_identity = meta->src_identity;
	  t->l4_discriminator = meta->l4_discriminator;
	  t->path_cache_index = pm->path_cache_index;
	  t->verdict = vd[0];
	  t->proto = hp->proto;
	  t->frag_kind = hp->frag_kind;

	  if (b[0]->current_length >= sizeof (ip6_header_t))
	    {
	      const ip6_header_t *ip = (const ip6_header_t *) vlib_buffer_get_current (b[0]);

	      t->src = ip->src_address;
	      t->dst = ip->dst_address;
	    }
	}
    }

  vlib_node_increment_counter (vm, node->node_index, CILIUM_SRV6_CLASSIFY_ERROR_CLASSIFIED,
			       n_classified);
  vlib_node_increment_counter (vm, node->node_index, CILIUM_SRV6_CLASSIFY_ERROR_FRAGMENT_BYPASS,
			       n_frag_bypass);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (cilium_srv6_classify_node) = {
  .name = "cilium-srv6-classify",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_cilium_srv6_classify_trace,
  .format_buffer = format_ip6_header,
  .n_errors = CILIUM_SRV6_CLASSIFY_N_ERROR,
  .error_counters = cilium_srv6_classify_error_counters,
  .n_next_nodes = CILIUM_SRV6_CLASSIFY_N_NEXT,
  .next_nodes = {
    [CILIUM_SRV6_CLASSIFY_NEXT_DROP] = "ip6-drop",
    [CILIUM_SRV6_CLASSIFY_NEXT_CT] = "cilium-srv6-ct",
    [CILIUM_SRV6_CLASSIFY_NEXT_ENCAP] = "cilium-srv6-encap",
  },
};

/*
 * 02 §1: the headend chain starts at the Pod interface, immediately after the
 * ingress guard of 03 §1.1. Unlike the guard — which is permanent and on
 * every interface — classify is enabled per interface by
 * srv6_local_ep_add_del, because an interface with no local endpoint has no
 * source identity to resolve.
 *
 * Ordering: after cilium-srv6-guard (a packet must pass the injection guard
 * before it is classified) and before ip6-flow-classify, which is the head of
 * the built-in ip6-unicast chain, so that a classified packet leaves the arc
 * for the SRv6 headend graph instead of reaching ip6-lookup.
 */
VNET_FEATURE_INIT (cilium_srv6_classify_feature, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "cilium-srv6-classify",
  .runs_after = VNET_FEATURES ("cilium-srv6-guard"),
  .runs_before = VNET_FEATURES ("ip6-flow-classify"),
};
