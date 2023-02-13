// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/shirou/gopsutil/cpu"
	"log"
	"strings"
	"time"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 bpf trace_idle_with_hash_map.c -- -I../headers

const doIdleFunc = "do_idle"
const scheduleIdle = "schedule_idle"

var (
	cpuCores              int
	samplePeriodNS        uint64
	lastIdleDurationTimes []uint64
	calcIter              int64
)

func init() {
	cpuCores, _ = cpu.Counts(true)
	lastIdleDurationTimes = make([]uint64, cpuCores)
	samplePeriodNS = uint64(1000000000)
	calcIter = int64(0)
}

func main() {
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

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.
	kp, err := link.Kprobe(doIdleFunc, objs.KprobeDoIdle, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	kp1, err := link.Kprobe(scheduleIdle, objs.KprobeScheduleIdle, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp1.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := calcCpuUsage(objs.IdleDurationTimeMap)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Printf("%s", s)
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
		if int(cpu) < cpuCores {
			if calcIter > 0 {
				durationTime := totalIdleDurationTime - lastIdleDurationTimes[cpu]
				sb.WriteString(fmt.Sprintf("%s cpu %d, %.2f\n", now.Format("2006-01-02 15:04:05"), cpu, float64(durationTime*100.0/samplePeriodNS)))
			}
			lastIdleDurationTimes[cpu] = totalIdleDurationTime
		}
	}
	calcIter = calcIter + 1
	return sb.String(), iter.Err()
}
