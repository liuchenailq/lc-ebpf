package main

import (
	"flag"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/emirpasic/gods/sets/hashset"
	"github.com/shirou/gopsutil/cpu"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 bpf trace_idle_with_sched_switch.c -- -I../headers

var (
	cpuCores              int
	samplePeriodNS        uint64
	lastIdleDurationTimes []uint64
	lastCalcTimes         []int64
	calcIter              int64
	cpuList               string
	coreSet               *hashset.Set
	cpuIdleHistorys       map[uint32][]string
)

func init() {
	cpuCores, _ = cpu.Counts(true)
	lastIdleDurationTimes = make([]uint64, cpuCores)
	lastCalcTimes = make([]int64, cpuCores)
	calcIter = int64(0)
	coreSet = hashset.New()
	cpuIdleHistorys = make(map[uint32][]string, 0)
	for i := 0; i < cpuCores; i++ {
		cpuIdleHistorys[uint32(i)] = make([]string, 0)
	}
}

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	flag.Uint64Var(&samplePeriodNS, "s", uint64(1000000000), "samplePeriodNS")
	flag.StringVar(&cpuList, "c", "0", "cpu list")
	flag.Parse()

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kp, err := link.Tracepoint("sched", "sched_switch", objs.SchedSwitch, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kp.Close()

	ticker := time.NewTicker(time.Duration(samplePeriodNS) * time.Nanosecond)
	defer ticker.Stop()
	for range ticker.C {
		s, err := calcCpuUsage(objs.IdleDurationTimeMap)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		if len(s) > 0 {
			fmt.Printf(fmt.Sprintf("\ntime\t\tCPU\t%sidle\n", "%"))
			fmt.Printf(s)
		}
	}
}

func calcCpuUsage(m *ebpf.Map) (string, error) {
	var (
		sb                    strings.Builder
		cpu                   uint32
		totalIdleDurationTime uint64
	)
	now := time.Now()
	iter := m.Iterate()
	for iter.Next(&cpu, &totalIdleDurationTime) {
		if int(cpu) >= cpuCores {
			continue
		}
		duration := time.Now().UnixNano() - lastCalcTimes[cpu]
		lastCalcTimes[cpu] = time.Now().UnixNano()
		idleDuration := totalIdleDurationTime - lastIdleDurationTimes[cpu]
		lastIdleDurationTimes[cpu] = totalIdleDurationTime
		if coreSet.Contains(cpu) && calcIter > 0 {
			cpuIdle := float64(idleDuration*100.0) / float64(duration)
			cpuIdleHistorys[cpu] = append(cpuIdleHistorys[cpu], fmt.Sprintf("%.2f", cpuIdle))
			sb.WriteString(fmt.Sprintf("%s\t%d\t%.2f\n", now.Format("2006-01-02 15:04:05"), cpu, cpuIdle))
		}
	}
	calcIter = calcIter + 1
	if calcIter > 100 {
		printCpuIdleHistorys()
	}
	return sb.String(), iter.Err()
}

func printCpuIdleHistorys() {
	for cpu := 0; cpu < cpuCores; cpu++ {
		if coreSet.Contains(uint32(cpu)) {
			fmt.Println(fmt.Sprintf("cpu %d, idle history: %s", cpu, strings.Join(cpuIdleHistorys[uint32(cpu)], ",")))
		}
	}
}
