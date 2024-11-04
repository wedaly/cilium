#!/usr/bin/env bash

set -ex

createConflist() {
file=$1
ipv6Subnet=$2

ranges="[{\"subnet\": \"$ipv6Subnet\"}]"
cat <<EOF > $file
{
    "cniVersion": "0.3.1",
    "name": "cilium",
    "plugins": [
    {
        "type": "cilium-cni",
        "enable-debug": true,
        "log-file": "/var/log/cilium-cni.log",
        "ipam": {
        "type": "host-local",
        "ranges": [$ranges]
        }
    }
    ]
}
EOF
}

createConflist "kind-control-plane-delegated-ipam.conflist" "fd00:10:244:1::/64"
createConflist "kind-worker-delegated-ipam.conflist" "fd00:10:244:2::/64"
createConflist "kind-worker2-delegated-ipam.conflist" "fd00:10:244:3::/64"

ipFamily="ipv6"
podSubnet="fd00:10:244::/56"
serviceSubnet="fd00:10:96::/112"
cat <<EOF > kind-config-delegated-ipam.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    # Disable kube-controller-manager allocate-node-cidrs to avoid mismatch between
    # the node podCIDR assigned by KCM and the CIDR configured for the host-local IPAM plugin.
    kubeadmConfigPatches:
    - |
        apiVersion: kubeadm.k8s.io/v1beta3
        kind: ClusterConfiguration
        controllerManager:
        extraArgs:
            allocate-node-cidrs: "false"
    extraMounts:
    - hostPath: kind-control-plane-delegated-ipam.conflist
      containerPath: /etc/cni/net.d/05-cilium.conflist

  - role: worker
    extraMounts:
    - hostPath: kind-worker-delegated-ipam.conflist
      containerPath: /etc/cni/net.d/05-cilium.conflist

  - role: worker
    extraMounts:
    - hostPath: kind-worker2-delegated-ipam.conflist
      containerPath: /etc/cni/net.d/05-cilium.conflist

networking:
  disableDefaultCNI: true
  ipFamily: "$ipFamily"
  podSubnet: "$podSubnet"
  serviceSubnet: "$serviceSubnet"
EOF

kind create cluster --config kind-config-delegated-ipam.yaml --wait 10m

addPodCIDRRoutesToNode() {
    node=$1
    ipv6Subnet=$2
    nodeIPv6=$(kubectl get node $node -o json | jq -r '.status.addresses[] | select(.type=="InternalIP") | .address' | tail -n 1)
    echo "adding route from $ipv6Subnet via $nodeIPv6"
    sudo ip -6 route add $ipv6Subnet via $nodeIPv6
}

echo "Current routes:"
ip -6 route

echo "Configuring routes from podCIDR to node:"

addPodCIDRRoutesToNode kind-control-plane "fd00:10:244:1::/64"
addPodCIDRRoutesToNode kind-worker "fd00:10:244:2::/64"
addPodCIDRRoutesToNode kind-worker2 "fd00:10:244:3::/64"

echo "Updated routes:"
ip -6 route

cilium install \
    --helm-set=ipam.mode=delegated-plugin \
    --helm-set=cni.customConf=true \
    --helm-set=routingMode=native \
    --helm-set=ipv4.enabled=false \
    --helm-set=endpointRoutes.enabled=true \
    --helm-set=endpointHealthChecking.enabled=false \
    --helm-set=bpf.masquerade=true \
    --helm-set=ipMasqAgent.enabled=true \
    --helm-set=nodePort.enabled=true \
    --helm-set=ipv6.enabled=true \
    --helm-set=ipv6NativeRoutingCIDR=fd00:10:244::/56 \
    --helm-set=extraArgs[1]="--local-router-ipv6=fe80::" \
    --helm-set=enableIPv6Masquerade=true"

cilium status --wait