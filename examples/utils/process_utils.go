package utils

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
)

// ExtendProcStat extend proc stat import from procfs.ProcStat struct
type ExtendProcStat struct {
	// The process ID.
	PID int
	// The filename of the executable.
	Comm string
	// The process state.
	State string
	// The PID of the parent of this process.
	PPID int
	// The process group ID of the process.
	PGRP int
	// The session ID of the process.
	Session int
	// The controlling terminal of the process.
	TTY int
	// The ID of the foreground process group of the controlling terminal of
	// the process.
	TPGID int
	// The kernel flags word of the process.
	Flags uint64
	// The number of minor faults the process has made which have not required
	// loading a memory page from disk.
	MinFlt uint
	// The number of minor faults that the process's waited-for children have
	// made.
	CMinFlt uint
	// The number of major faults the process has made which have required
	// loading a memory page from disk.
	MajFlt uint
	// The number of major faults that the process's waited-for children have
	// made.
	CMajFlt uint
	// Amount of time that this process has been scheduled in user mode,
	// measured in clock ticks.
	UTime uint
	// Amount of time that this process has been scheduled in kernel mode,
	// measured in clock ticks.
	STime uint
	// Amount of time that this process's waited-for children have been
	// scheduled in user mode, measured in clock ticks.
	CUTime uint
	// Amount of time that this process's waited-for children have been
	// scheduled in kernel mode, measured in clock ticks.
	CSTime uint
	// For processes running a real-time scheduling policy, this is the negated
	// scheduling priority, minus one.
	Priority int
	// The nice value, a value in the range 19 (low priority) to -20 (high
	// priority).
	Nice int
	// Number of threads in this process.
	NumThreads int
	// The time in jiffies before the next SIGALRM is sent
	ItrealValue int64
	// The time the process started after system boot, the value is expressed
	// in clock ticks.
	Starttime uint64
	// Virtual memory size in bytes.
	VSize uint
	// Resident set size in pages.
	RSS int
	// Soft limit in bytes on the rss of the process.
	RSSLimit uint64
	// the address above which program text can run
	StartCode uint64
	// the address below which program text can run
	EndCode uint64
	// StartsStack The address of the start (i.e., bottom) of the stack
	StartsStack uint64
	// The current value of ESP (stack pointer), as found in the kernel stack page for the process.
	KstkESP uint64
	// The current EIP (instruction pointer)
	KstkEIP uint64
	// The bitmap of pending signals
	Signal uint64
	// The bitmap of blocked signals
	Blocked uint64
	// SigIgnore The bitmap of ignored signals, displayed as a deci‐mal number
	SigIgnore uint64
	//The bitmap of caught signals, displayed as a decimal number
	SigCatch uint64
	// This is the "channel" in which the process is wait‐ing
	Wchan uint64
	// number of pages swapped
	NSwap uint64
	// Cumulative nswap for child processes
	CnSwap uint64
	// Signal to be sent to parent when we die
	ExitSignal int64
	// CPU number last executed on
	Processor int64
	// Real-time scheduling priority, a number in the range 1 to 99 for processes
	// scheduled under a real-time policy, or 0, for non-real-time processes.
	RTPriority uint
	// Scheduling policy.
	Policy uint
	// Aggregated block I/O delays, measured in clock ticks (centiseconds).
	DelayAcctBlkIOTicks uint64
	// Guest time of the process (time spent running a virtual cpu)
	GuestTime uint64
	// Guest time of the process's children
	CguestTime int64
	// Address above which program initialized
	StartData uint64
	// Address below which program initialized
	EndData uint64
	// Address above which program heap can be expanded with brk
	StartBrk uint64
	// Address above which program command-line arguments argv
	ArgStart uint64
	// Address below program command-line arguments are placed
	ArgEnd uint64
	// Address above which program environment is placed
	EnvStart uint64
	// Address below which program environment is placed
	EnvEnd uint64
	// The thread's exit status in the form reported by waitpid
	ExitCode int64

	proc fs.FS
}

func NewExtendProcStat(pid int) (ExtendProcStat, error) {
	data, err := ReadFileNoStat(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ExtendProcStat{}, err
	}
	var (
		//s = ExtendProcStat{PID: ep.PID, proc: ep.fs}
		s = ExtendProcStat{PID: pid}
		l = bytes.Index(data, []byte("("))
		r = bytes.LastIndex(data, []byte(")"))
	)

	if l < 0 || r < 0 {
		return ExtendProcStat{}, fmt.Errorf("unexpected format, couldn't extract comm %q", data)
	}

	s.Comm = string(data[l+1 : r])
	_, err = fmt.Fscan(
		bytes.NewBuffer(data[r+2:]),
		&s.State,
		&s.PPID,
		&s.PGRP,
		&s.Session,
		&s.TTY,
		&s.TPGID,
		&s.Flags,
		&s.MinFlt,
		&s.CMinFlt,
		&s.MajFlt,
		&s.CMajFlt,
		&s.UTime,
		&s.STime,
		&s.CUTime,
		&s.CSTime,
		&s.Priority,
		&s.Nice,
		&s.NumThreads,
		&s.ItrealValue,
		&s.Starttime,
		&s.VSize,
		&s.RSS,
		&s.RSSLimit,
		&s.StartCode,
		&s.EndCode,
		&s.StartsStack,
		&s.KstkESP,
		&s.KstkEIP,
		&s.Signal,
		&s.Blocked,
		&s.SigIgnore,
		&s.SigCatch,
		&s.Wchan,
		&s.NSwap,
		&s.CnSwap,
		&s.ExitSignal,
		&s.Processor,
		&s.RTPriority,
		&s.Policy,
		&s.DelayAcctBlkIOTicks,
		&s.GuestTime,
		&s.CguestTime,
		&s.StartData,
		&s.EndData,
		&s.StartBrk,
		&s.ArgStart,
		&s.ArgEnd,
		&s.EnvStart,
		&s.EnvEnd,
		&s.ExitCode,
	)
	if err != nil {
		return ExtendProcStat{}, err
	}
	return s, nil
}

func ReadFileNoStat(filename string) ([]byte, error) {
	const maxBufferSize = 256

	fd, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	reader := io.LimitReader(fd, maxBufferSize)
	return ioutil.ReadAll(reader)
}

func GetProcCmdLine(pid int) string {
	data, err := ReadFileNoStat(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	} else {
		return string(data)
	}
}
