// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"

	"github.com/lyft/cni-ipvlan-vpc-k8s/aws"
)

const (
	defaultPreAllocation = 4
)

func allocate(node *v2.CiliumNode) error {
	var alloc *aws.AllocationResult
	registry := &aws.Registry{}
	free, err := aws.FindFreeIPsAtIndex(node.Spec.ENI.FirstAllocationInterface, true)
	if err == nil && len(free) > 0 {
		registryFreeIPs, err := registry.TrackedBefore(time.Now().Add(time.Duration(-3600) * time.Second))
		if err == nil && len(registryFreeIPs) > 0 {
		loop:
			for _, freeAlloc := range free {
				for _, freeRegistry := range registryFreeIPs {
					if freeAlloc.IP.Equal(freeRegistry) {
						alloc = freeAlloc
						// update timestamp
						registry.TrackIP(freeRegistry)
						break loop
					}
				}
			}
		}
	}

	// No free IPs available for use, so let's allocate one
	if alloc == nil {
		// allocate an IP on an available interface
		alloc, err = aws.DefaultClient.AllocateIPFirstAvailableAtIndex(node.Spec.ENI.FirstAllocationInterface)
		if err != nil {
			// failed, so attempt to add an IP to a new interface
			newIf, err := aws.DefaultClient.NewInterface(node.Spec.ENI.SecurityGroups, node.Spec.ENI.SubnetTags)
			// If this interface has somehow gained more than one IP since being allocated,
			// abort this process and let a subsequent run find a valid IP.
			if err != nil || len(newIf.IPv4s) != 1 {
				return fmt.Errorf("unable to create a new elastic network interface due to %v",
					err)
			}
			// Freshly allocated interfaces will always have one valid IP - use
			// this IP address.
			alloc = &aws.AllocationResult{
				&newIf.IPv4s[0],
				*newIf,
			}
		}
	}

	node.Status.ENI.Available = append(node.Status.ENI.Available, alloc.IP.String())

	return nil
}

func refreshNode(node *v2.CiliumNode) error {
	requiredAddresses := node.Spec.ENI.PreAllocate
	if requiredAddresses == 0 {
		requiredAddresses = defaultPreAllocation
	}

	availableAddresses := len(node.Status.ENI.Available)

	if needed := requiredAddresses - availableAddresses; needed > 0 {
		log.Debugf("Need to allocate %d additional ENI addresses", needed)

		if err := allocate(node); err != nil {
			return err
		}

		_, err := ciliumK8sClient.CiliumV2().CiliumNodes("default").Update(node)
		if err != nil {
			log.WithError(err).Warning("Unable update CiliumNode")
		}

	}

	return nil
}

func startENIAllocator() {
	log.Info("Starting ENI allocator...")

	controller.NewManager().UpdateController("eni-allocator",
		controller.ControllerParams{
			RunInterval: time.Minute,
			DoFunc: func(_ context.Context) error {
				for _, obj := range ciliumNodeStore.List() {
					if node, ok := obj.(*v2.CiliumNode); ok {
						cpy := node.DeepCopy()
						refreshNode(cpy)
					}
				}

				return nil
			},
		})
}
