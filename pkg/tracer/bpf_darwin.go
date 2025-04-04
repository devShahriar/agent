//go:build darwin

package tracer

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// bpfObjects contains a stub implementation for Darwin
type bpfObjects struct {
	TraceAccept4     *ebpf.Program
	TraceAccept4Exit *ebpf.Program
	TraceConnect     *ebpf.Program
	TraceWrite       *ebpf.Program
	TraceRead        *ebpf.Program
	TraceReadRet     *ebpf.Program
	TraceClose       *ebpf.Program

	// Maps
	Events        *ebpf.Map
	EventStorage  *ebpf.Map
	ConnState     *ebpf.Map
	ProcessInfo   *ebpf.Map
	ActiveFds     *ebpf.Map
	ActiveSockets *ebpf.Map
	SocketInfo    *ebpf.Map
	ReadArgsMap   *ebpf.Map
}

// loadBpfObjects is a stub for Darwin
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	return fmt.Errorf("BPF tracing is not supported on macOS")
}

// Close is a no-op on Darwin
func (o *bpfObjects) Close() error {
	return nil
}
