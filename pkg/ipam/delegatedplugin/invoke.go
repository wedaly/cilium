package delegatedplugin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	cniInvoke "github.com/containernetworking/cni/pkg/invoke"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesV1 "github.com/containernetworking/cni/pkg/types/100"
)

// Implements cniInvoke.CNIArgs interface.
type cniArgs struct {
	Command     string
	ContainerID string
	NetNS       string
	IfName      string
}

// Unlike cniInvoke.Args, this does NOT expose all environment variables,
// just the ones required by the plugin.
func (a *cniArgs) AsEnv() []string {
	return []string{
		fmt.Sprintf("CNI_COMMAND=%s", a.Command),
		fmt.Sprintf("CNI_CONTAINERID=%s", a.ContainerID),
		fmt.Sprintf("CNI_NETNS=%s", a.NetNS),
		fmt.Sprintf("CNI_IFNAME=%s", a.IfName),
	}
}

// Invoker is responsible for invoking a delegated IPAM plugin from cilium-agent.
// https://www.cni.dev/docs/spec/#delegated-plugin-protocol
// This is used only for cilium-agent to allocate IPs for itself.
// TODO: this should probably be an interface so we can mock it in tests.
type Invoker struct {
	cniBinaryPaths []string // Equivalent of CNI_PATH env var in CNI plugin
	netConf        *cniTypes.NetConf
}

func NewInvoker(cniConflistPath string, cniBinaryPaths []string) (*Invoker, error) {
	// TODO: add retries or watcher in case conflist doesn't yet exist.
	data, err := os.ReadFile(cniConflistPath)
	if err != nil {
		return nil, fmt.Errorf("Error reading CNI conflist from %q: %w", cniConflistPath, err)
	}

	// Parse it, so we fail fast if it's broken. And so we don't need to parse it again.
	var netConfList cniTypes.NetConfList
	if err := json.Unmarshal(data, &netConfList); err != nil {
		return nil, fmt.Errorf("Error parsing CNI conflist from %q: %w", cniConflistPath, err)
	}

	// Better find Cilium in the conflist.
	var netConf *cniTypes.NetConf
	for _, plugin := range netConfList.Plugins {
		if plugin.Name == "cilium-cni" {
			netConf = plugin
			break
		}
	}

	if netConf == nil {
		return nil, fmt.Errorf("Could not find Cilium plugin in CNI conflist %s", cniConflistPath)
	} else if netConf.IPAM.Type == "" {
		return nil, fmt.Errorf("Cilium CNI config does not have specify delegated IPAM plugin")
	}

	invoker := &Invoker{
		cniBinaryPaths: cniBinaryPaths,
		netConf:        netConf,
	}

	return invoker, nil
}

func (in *Invoker) DelegateAdd(ctx context.Context, containerId string) (*cniTypesV1.Result, error) {
	args := &cniArgs{
		Command:     "ADD",
		ContainerID: containerId,
		NetNS:       "host", // okay?
		IfName:      "eth0", // sure?
	}

	pluginPath, err := cniInvoke.FindInPath(in.netConf.IPAM.Type, in.cniBinaryPaths)
	if err != nil {
		return nil, err
	}

	netConfData, err := json.Marshal(in.netConf)
	if err != nil {
		return nil, err
	}

	result, err := cniInvoke.ExecPluginWithResult(ctx, pluginPath, netConfData, args, nil)
	if err != nil {
		return nil, err
	}

	versionedResult, err := cniTypesV1.NewResultFromResult(result)
	if err != nil {
		return nil, fmt.Errorf("could not interpret delegated IPAM result for CNI version %s: %w", cniTypesV1.ImplementedSpecVersion, err)
	}

	return versionedResult, nil
}

func (in *Invoker) DelegateDelete(ctx context.Context, containerId string) error {
	args := &cniArgs{
		Command:     "DEL",
		ContainerID: containerId,
		IfName:      "eth0", // sure?
	}

	pluginPath, err := cniInvoke.FindInPath(in.netConf.IPAM.Type, in.cniBinaryPaths)
	if err != nil {
		return err
	}

	netConfData, err := json.Marshal(in.netConf)
	if err != nil {
		return err
	}

	return cniInvoke.ExecPluginWithoutResult(ctx, pluginPath, netConfData, args, nil)
}

func (in *Invoker) DelegateCheck(ctx context.Context, containerId string) error {
	args := &cniArgs{
		Command:     "CHECK",
		ContainerID: containerId,
		NetNS:       "host", // okay?
		IfName:      "eth0", // sure?
	}

	pluginPath, err := cniInvoke.FindInPath(in.netConf.IPAM.Type, in.cniBinaryPaths)
	if err != nil {
		return err
	}

	netConfData, err := json.Marshal(in.netConf)
	if err != nil {
		return err
	}

	return cniInvoke.ExecPluginWithoutResult(ctx, pluginPath, netConfData, args, nil)
}
