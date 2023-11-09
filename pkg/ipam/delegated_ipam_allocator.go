// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"fmt"
	"net"
)

// delegatedIPAMAllocator implements ipam.Allocator that invokes a delegated IPAM CNI plugin.
// In most cases, the Cilium CNI will invoke the delegated IPAM plugin directly
// (for details see the CNI spec: https://www.cni.dev/docs/spec/#delegated-plugins-ipam)
// However, in some cases cilium-agent needs to allocate IPs for itself, bypassing the
// usual container runtime -> CNI -> IPAM plugin flow.
// In those cases, cilium-agent uses delegatedIPAMAllocator to invoke the delegated IPAM
// plugin directly.
type delegatedIPAMAllocator struct{}

func (d *delegatedIPAMAllocator) Allocate(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	// No difference between Allocate and AllocateWithoutSyncUpstream.
	return d.AllocateWithoutSyncUpstream(ip, owner, pool)
}

func (d *delegatedIPAMAllocator) AllocateWithoutSyncUpstream(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	return nil, fmt.Errorf("delegated IPAM does not support allocating a specific IP")
}

func (d *delegatedIPAMAllocator) Release(ip net.IP, pool Pool) error {
	// TODO: maybe validate that pool is default pool.
	// TODO: lookup the IP in the allocation database
	// TODO: if found, invoke CNI DEL (ignore errors)
	return nil
}

func (d *delegatedIPAMAllocator) AllocateNext(owner string, pool Pool) (*AllocationResult, error) {
	// No difference between AllocateNext and AllocateNextWithoutSyncUpstream.
	return d.AllocateNextWithoutSyncUpstream(owner, pool)
}

func (d *delegatedIPAMAllocator) AllocateNextWithoutSyncUpstream(owner string, pool Pool) (*AllocationResult, error) {
	// TODO: maybe validate that pool is default pool.
	// TODO: write to allocation DB that we're *about* to allocate an IP for some random netns ID
	// TODO: CNI ADD call
	// TODO: on success, write to allocation DB that we successfully did it.
	//            ... but if the write fails, try CNI DEL
	// TODO: on failure, remove the entry from the allocation DB.
	return nil, nil
}

func (d *delegatedIPAMAllocator) Dump() (map[Pool]map[string]string, string) {
	// Delegated IPAM does not support retrieving allocated IPs, so return a nil map.
	return nil, "delegated to plugin"
}

func (d *delegatedIPAMAllocator) Capacity() uint64 {
	// Delegated IPAM does not report capacity, so return zero.
	// This is used only for metrics, so doesn't impact IPAM allocation.
	return uint64(0)
}

func (d *delegatedIPAMAllocator) RestoreFinished() {
	// Delegated IPAM doesn't do anything on restore finished.
}
