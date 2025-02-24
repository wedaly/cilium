/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "jhash.h"

/* The daddr is explicitly excluded from the hash here in order to allow for
 * backend selection to choose the same backend even on different service VIPs.
 */
static __always_inline __u32
__hash_from_tuple_v4(const struct ipv4_ct_tuple *tuple, __be16 sport)
{
	return jhash_3words(tuple->saddr,
			    ((__u32)tuple->dport << 16) | sport,
			    tuple->nexthdr, HASH_INIT4_SEED);
}

static __always_inline __u32 hash_from_tuple_v4(const struct ipv4_ct_tuple *tuple)
{
	return __hash_from_tuple_v4(tuple, tuple->sport);
}

static __always_inline __u32
__hash_from_tuple_v6(const struct ipv6_ct_tuple *tuple, __be16 sport)
{
	__u32 a, b, c;

	a = tuple->saddr.p1;
	b = tuple->saddr.p2;
	c = tuple->saddr.p3;
	__jhash_mix(a, b, c);
	a += tuple->saddr.p4;
	b += ((__u32)tuple->dport << 16) | sport;
	c += tuple->nexthdr;
	__jhash_mix(a, b, c);
	a += HASH_INIT6_SEED;
	__jhash_final(a, b, c);
	return c;
}

static __always_inline __u32 hash_from_tuple_v6(const struct ipv6_ct_tuple *tuple)
{
	return __hash_from_tuple_v6(tuple, tuple->sport);
}
