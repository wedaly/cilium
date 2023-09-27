// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/api/v1/models"
)

// DaemonInterface to help with testing.
type DaemonInterface interface {
	getStatus(bool) models.StatusResponse
}

// ServiceInterface to help with testing.
type ServiceInterface interface {
	GetLastUpdatedTs() time.Time
	GetCurrentTs() time.Time
}

type kubeproxyHealthzHandler struct {
	d   DaemonInterface
	svc ServiceInterface
}

// startKubeProxyHealthzHTTPService registers a handler function for the kube-proxy /healthz
// status HTTP endpoint exposed on addr.
// This endpoint reports the agent health status with the timestamp.
func (d *Daemon) startKubeProxyHealthzHTTPService(addr string) {
	lc := net.ListenConfig{Control: setsockoptReuseAddrAndPort}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	addrField := logrus.Fields{"address": addr}
	if errors.Is(err, unix.EADDRNOTAVAIL) {
		log.WithFields(addrField).Info("KubeProxy healthz server not available")
	} else if err != nil {
		log.WithFields(addrField).WithError(err).Fatal("hint: kube-proxy should not be running nor listening on the same healthz-bind-address.")
	}

	// Hack: wrap the listener to handle PLS PROXY protocol.
	plsLn := &plsCompatibleListener{ln}

	mux := http.NewServeMux()
	mux.Handle("/healthz", kubeproxyHealthzHandler{d: d, svc: d.svc})

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		err := srv.Serve(plsLn)
		if errors.Is(err, http.ErrServerClosed) {
			log.WithFields(addrField).Info("kube-proxy healthz status API server shutdown")
		} else if err != nil {
			log.WithFields(addrField).WithError(err).Fatal("Unable to start kube-proxy healthz server")
		}
	}()
	log.WithFields(addrField).Info("Started kube-proxy healthz server")
}

func (h kubeproxyHealthzHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	isUnhealthy := func(sr *models.StatusResponse) bool {
		if sr.Cilium != nil {
			state := sr.Cilium.State
			return state != models.StatusStateOk && state != models.StatusStateDisabled
		}
		return false
	}

	statusCode := http.StatusOK
	currentTs := h.svc.GetCurrentTs()
	var lastUpdateTs = currentTs
	// We piggy back here on Cilium daemon health. If Cilium is healthy, we can
	// reasonably assume that the node networking is ready.
	sr := h.d.getStatus(true)
	if isUnhealthy(&sr) {
		statusCode = http.StatusServiceUnavailable
		lastUpdateTs = h.svc.GetLastUpdatedTs()
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)
	fmt.Fprintf(w, `{"lastUpdated": %q,"currentTime": %q}`, lastUpdateTs, currentTs)
}

/* Everything below this line is a hack! */
const PROXY_PROTOCOL_HDR_LEN = 16

var PROXY_PROTOCOL_SIGNATURE = [...]byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

type plsCompatibleListener struct {
	ln net.Listener
}

func (l *plsCompatibleListener) Accept() (net.Conn, error) {
	conn, err := l.ln.Accept()
	if err != nil {
		return conn, err
	}

	r := bufio.NewReader(conn)

	// PROXY protocol header is 16 bytes, the first 12 of which are the signature.
	// https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
	maybeProxyHdr, err := r.Peek(PROXY_PROTOCOL_HDR_LEN)
	if err == nil && len(maybeProxyHdr) == PROXY_PROTOCOL_HDR_LEN && bytes.Equal(maybeProxyHdr[0:12], PROXY_PROTOCOL_SIGNATURE[:]) {
		// DEBUG to confirm we hit this branch
		log.Info("PROXY protocol detected")

		proxyHdr := maybeProxyHdr
		// Last 2 bytes of the header are the length in network endian order.
		proxyLen := binary.BigEndian.Uint16(proxyHdr[14:16])
		// Discard PROXY protocol (16 byte header + proxyLen).
		n, err := r.Discard(PROXY_PROTOCOL_HDR_LEN + int(proxyLen))
		if err != nil {
			return nil, err
		}

		// DEBUG logging to confirm we successfully discarded bytes.
		log.Infof("Discarded %d bytes for PROXY protocol", n)
	}

	return conn, nil
}

func (l *plsCompatibleListener) Close() error {
	return l.ln.Close()
}

func (l *plsCompatibleListener) Addr() net.Addr {
	return l.ln.Addr()
}
