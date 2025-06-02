package bpf

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

var (
	packetCounter = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "xlbp",
			Name:      "interface_packets",
			Help:      "Counts packets for a given interface",
		},
		[]string{"name", "type", "direction"},
	)

	byteCounter = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "xlbp",
			Name:      "interface_bytes",
			Help:      "Counts bytes for a given interface",
		},
		[]string{"name", "type", "direction"},
	)
)

// TODO: question: can I create maps from user space even if they are not an inner map
// of an BPF_MAP_TYPE_ARRAY_OF_MAPS?
//
// In any case, this turned out to be a lot more complex than just scraping some per-cpu-array
// and I'm not sure if there are a lot of benefits. Theoretically, interfaces can be added and removed
// dynamically, or at least at config time.
//
// The caller uses an BPF_MAP_TYPE_ARRAY_OF_MAPS. While this
// seems to work, I'm not sure if this is what they are intended for.
// The docs here https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_ARRAY_OF_MAPS,
// mention that they are used for precise measurements.
// There is an example in the linux code which uses a map in map structure.
// The map is initialized upon declaration:
// https://github.com/torvalds/linux/blob/master/samples/bpf/map_perf_test.bpf.c
// https://github.com/torvalds/linux/blob/master/samples/bpf/map_perf_test_user.c
//
// In this case, the user space will dictate which interfaces are being monitored.
// So the outter map will have to be initialized from user space.
// Here is an example from cilium on how to initialize these maps from
// user space:
// https://github.com/cilium/ebpf/blob/main/examples/map_in_map/main.go
type interfaceCounters struct {
	logger *zap.Logger
	// interfacePacketCounters is an outter ebpf map, they key is the ifc index
	// the value is an inner per-cpu-array map.
	interfacePacketCounters *ebpf.Map
	// interfaceByteCounters is an outter ebpf map, they key is the ifc index
	// the value is an inner per-cpu-array map.
	interfaceByteCounters *ebpf.Map
}

// newInterfaceCounters takes the two outter maps for packets an bytes counters and
// creates and saves the inner maps which are per-cpu-arrays. These will be the
// ones which are being pegged in kernel space and scraped in user space.
func newInterfaceCounters(logger *zap.Logger, interfacePacketCounters, interfaceByteCounters *ebpf.Map, ifaces map[string]*net.Interface) (*interfaceCounters, error) {
	// https://github.com/cilium/ebpf/blob/main/examples/map_in_map/main.go
	for ifcName, ifc := range ifaces {
		if err := createInnerMap(ifcName, ifc.Index, interfacePacketCounters); err != nil {
			return nil, fmt.Errorf("error creating interface packet counters: %w", err)
		}

		if err := createInnerMap(ifcName, ifc.Index, interfaceByteCounters); err != nil {
			return nil, fmt.Errorf("error creating interface byte counters: %w", err)
		}
	}

	return &interfaceCounters{
		interfacePacketCounters: interfacePacketCounters,
		interfaceByteCounters:   interfaceByteCounters,
		logger:                  logger,
	}, nil
}

func (ic *interfaceCounters) close() {
	ic.closeEachInnerMap(ic.interfacePacketCounters)
	ic.closeEachInnerMap(ic.interfaceByteCounters)
}

func (ic *interfaceCounters) closeEachInnerMap(outterMap *ebpf.Map) {
	mapIter := outterMap.Iterate()
	var outerMapKey uint32
	var innerMapID ebpf.MapID
	for mapIter.Next(&outerMapKey, &innerMapID) {
		// With maps that contain maps, performing a lookup doesn't give
		// you the map directly, instead it gives you an ID, which you
		// can then use to get a full map pointer.
		innerMap, err := ebpf.NewMapFromID(innerMapID)
		if err != nil {
			ic.logger.Error("error getting map", zap.Error(err), zap.Uint32("ifc-idx", outerMapKey), zap.Uint32("map-id", uint32(innerMapID)))
			continue
		}

		if err := innerMap.Close(); err != nil {
			ic.logger.Error("error closing map", zap.Error(err), zap.Uint32("ifc-idx", outerMapKey), zap.Uint32("map-id", uint32(innerMapID)))
			continue
		}
	}
}

func createInnerMap(ifcName string, ifcIndex int, outterMap *ebpf.Map) error {
	innerSpec := &ebpf.MapSpec{
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: MaxInterfaces,
	}

	innerMap, err := ebpf.NewMap(innerSpec)
	if err != nil {
		return err
	}

	// In the following cilium/ebf example they first create the spec for the outter map.
	// After which they iteratively create the inner maps and load them in the outter map spec:
	// https://github.com/cilium/ebpf/blob/main/examples/map_in_map/main.go
	//
	// In our case the outter map is already defined in the kernel space and we want to populate
	// it from the user space.
	// In the kernel docs, https://docs.kernel.org/bpf/map_of_maps.html, they give the following example:
	// int add_devmap(int outer_fd, int index, const char *name) {
	//       int fd;
	//
	//       fd = bpf_map_create(BPF_MAP_TYPE_DEVMAP, name,
	//                           sizeof(__u32), sizeof(__u32), 256, NULL);
	//       if (fd < 0)
	//               return fd;
	//
	//       return bpf_map_update_elem(outer_fd, &index, &fd, BPF_ANY);
	// }
	// This makes sense considering the outter map declares the value as: __type(value, __u32);
	//
	// However this discussion in cilium/ebf says that for the ebf go library the value should be the inner map:
	// https://github.com/cilium/ebpf/discussions/1658
	//
	// AFAIU, in the cilium/ebpf library, if a pointer to a map is passed as a value, it will check the type and then marshal:
	// switch value := data.(type) {
	// case *Map:
	// 	if !m.typ.canStoreMap() {
	// 		return sys.Pointer{}, fmt.Errorf("can't store map in %s", m.typ)
	// 	}
	// 	buf, err = marshalMap(value, int(m.valueSize))
	// Which ultimetly calls:
	//	internal.NativeEndian.PutUint32(buf, m.fd.Uint())
	//
	// So it doesn't make a difference if we pass the map pointer or the map fd as in the linux kernel example

	if err := outterMap.Update(uint32(ifcIndex), innerMap, ebpf.UpdateAny); err != nil {
		// if err := outterMap.Update(uint32(ifcIndex), innerMap, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to initialize packet counters for interface %s with index %d: %w",
			ifcName, ifcIndex, err)
	}

	return nil
}

// TODO: this should be extended to use a WaitGroup and check for shutdown.
// the Dataplane object is duplicating this code in the Start() function.
func (ic *interfaceCounters) scrape() {
	ic.logger.Info("starting bpf metrics scraper")
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		<-ticker.C
		// read the interface counters
		ic.forEachInnerMap(ic.interfacePacketCounters, packetCounter)
		ic.forEachInnerMap(ic.interfaceByteCounters, byteCounter)
	}
}

// forEachInnerMap will iterate through the map and scrape the counters for all interfaces.
//
// An alternative implementation would be to get the inner maps for explicit interfaces.
//
//	func getInnerMap(ifcIndex uint32, outterMap *ebpf.Map) (*ebpf.Map, error) {
//		var innerMapID ebpf.MapID
//		if err := outterMap.Lookup(ifcIndex, &innerMapID); err != nil {
//			return nil, fmt.Errorf("error reading counters for interface index %d: %w", ifcIndex, err)
//		}
//
//		innerMap, err := ebpf.NewMapFromID(innerMapID)
//		if err != nil {
//			return nil, fmt.Errorf("error reading map for ID %d: %w", uint32(innerMapID), err)
//		}
//
//		return innerMap, nil
//	}
func (ic *interfaceCounters) forEachInnerMap(outterMap *ebpf.Map, gauge *prometheus.GaugeVec) {
	mapIter := outterMap.Iterate()
	var outerMapKey uint32
	var innerMapID ebpf.MapID
	for mapIter.Next(&outerMapKey, &innerMapID) {
		// With maps that contain maps, performing a lookup doesn't give
		// you the map directly, instead it gives you an ID, which you
		// can then use to get a full map pointer.
		innerMap, err := ebpf.NewMapFromID(innerMapID)
		if err != nil {
			ic.logger.Error("error getting map", zap.Error(err), zap.Uint32("ifc-idx", outerMapKey), zap.Uint32("map-id", uint32(innerMapID)))
			continue
		}

		setPrometheusGauge(ic.logger, outerMapKey, innerMap, gauge)
	}
}

func setPrometheusGauge(logger *zap.Logger, ifcIdx uint32, perCpuArray *ebpf.Map, gauge *prometheus.GaugeVec) {
	// TODO: I swear I did this in the past and know this was possible.
	// Providing -type counter_index for the bpf2go command should generate a counter part enum in go.
	// Instead I keep getting:
	// Error: collect C types: type name counter_index: not found
	// Until I figure out what's wrong this needs to be maintained by hand.
	counterIndexNameMapping := []string{
		0: "ingress",
		1: "egress",
		2: "passed",
		3: "dropped",
	}

	for idx, name := range counterIndexNameMapping {
		key := uint32(idx)

		var values []uint64
		err := perCpuArray.Lookup(&key, &values)
		if err != nil {
			logger.Error("Failed to read per-cpu-array", zap.Error(err))
			return
		}

		// Sum all per-CPU values
		var packetTotal uint64
		for _, value := range values {
			packetTotal += value
		}

		// TODO: I should implement a lookup here to get the ifc name instead of the index.
		// TODO: upstream is hardcoded. I should discern traffic somehow and peg the correct label.
		gauge.WithLabelValues("ifc-index-"+strconv.FormatUint(uint64(ifcIdx), 10), name, "upstream").Set(float64(packetTotal))
	}
}
