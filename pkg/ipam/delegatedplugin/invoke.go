package delegatedplugin

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/containernetworking/cni/libcni"
	cniInvoke "github.com/containernetworking/cni/pkg/invoke"
	cniTypesV1 "github.com/containernetworking/cni/pkg/types/100"
)

// Implements cniInvoke.CNIArgs interface.
type cniArgs struct {
	Command     string
	ContainerID string
	NetNS       string
	IfName      string
	CNIPath     string
}

// Unlike cniInvoke.Args, this does NOT expose all environment variables,
// just the ones required by the plugin.
func (a *cniArgs) AsEnv() []string {
	return []string{
		fmt.Sprintf("CNI_COMMAND=%s", a.Command),
		fmt.Sprintf("CNI_CONTAINERID=%s", a.ContainerID),
		fmt.Sprintf("CNI_NETNS=%s", a.NetNS),
		fmt.Sprintf("CNI_IFNAME=%s", a.IfName),
		fmt.Sprintf("CNI_PATH=%s", a.CNIPath), // I think the spec says this isn't required, but reference implementation errors without it.
	}
}

// Invoker is responsible for invoking a delegated IPAM plugin from cilium-agent.
// https://www.cni.dev/docs/spec/#delegated-plugin-protocol
// This is used only for cilium-agent to allocate IPs for itself.
// TODO: this should probably be an interface so we can mock it in tests.
type Invoker struct {
	cniBinaryPaths []string // Equivalent of CNI_PATH env var in CNI plugin
	netConf        *libcni.NetworkConfig
}

func NewInvoker(cniConflistPath string, cniBinaryPaths []string) (*Invoker, error) {
	// TODO: add retries or watcher in case conflist doesn't yet exist.
	dir, name := path.Split(cniConflistPath)
	netConfList, err := libcni.LoadConfList(dir, name)
	if err != nil {
		return nil, fmt.Errorf("Error loading CNI conflist from %q: %w", cniConflistPath, err)
	}

	// Better find Cilium in the conflist.
	var netConf *libcni.NetworkConfig
	for _, plugin := range netConfList.Plugins {
		if plugin.Network.Type == "cilium-cni" {
			netConf = plugin
			break
		}
	}

	if netConf == nil {
		return nil, fmt.Errorf("Could not find Cilium plugin in CNI conflist %s", cniConflistPath)
	} else if netConf.Network.IPAM.Type == "" {
		return nil, fmt.Errorf("Cilium CNI config does not have specify delegated IPAM plugin")
	}

	// Need to copy some values from the conflist to the runtime config.
	// https://www.cni.dev/docs/spec/#deriving-runtimeconfig
	// We're doing the bare minimum here to get this working.
	inject := map[string]interface{}{
		"name":       netConfList.Name,
		"cniVersion": netConfList.CNIVersion,
	}
	netConf, err = libcni.InjectConf(netConf, inject)
	if err != nil {
		return nil, fmt.Errorf("Failed to inject params to CNI config: %w", err)
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
		CNIPath:     strings.Join(in.cniBinaryPaths, ":"),
	}

	pluginPath, err := cniInvoke.FindInPath(in.netConf.Network.IPAM.Type, in.cniBinaryPaths)
	if err != nil {
		return nil, err
	}

	result, err := cniInvoke.ExecPluginWithResult(ctx, pluginPath, in.netConf.Bytes, args, nil)
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
		CNIPath:     strings.Join(in.cniBinaryPaths, ":"),
	}

	pluginPath, err := cniInvoke.FindInPath(in.netConf.Network.IPAM.Type, in.cniBinaryPaths)
	if err != nil {
		return err
	}

	return cniInvoke.ExecPluginWithoutResult(ctx, pluginPath, in.netConf.Bytes, args, nil)
}

func (in *Invoker) DelegateCheck(ctx context.Context, containerId string) error {
	args := &cniArgs{
		Command:     "CHECK",
		ContainerID: containerId,
		NetNS:       "host", // okay?
		IfName:      "eth0", // sure?
		CNIPath:     strings.Join(in.cniBinaryPaths, ":"),
	}

	pluginPath, err := cniInvoke.FindInPath(in.netConf.Network.IPAM.Type, in.cniBinaryPaths)
	if err != nil {
		return err
	}

	return cniInvoke.ExecPluginWithoutResult(ctx, pluginPath, in.netConf.Bytes, args, nil)
}
