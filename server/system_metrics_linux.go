//go:build linux

package server

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

func resourceFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	return strings.TrimSpace(string(data)), err
}

func resourceUint(path string) (uint64, error) {
	text, err := resourceFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(text, 10, 64)
}

func readResourceUsage() (resourceReading, error) {
	cgroups, _ := resourceFile("/proc/self/cgroup")
	container := false
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(marker); err == nil {
			container = true
		}
	}
	for _, marker := range []string{"docker", "containerd", "kubepods", "lxc"} {
		container = container || strings.Contains(cgroups, marker)
	}
	if container {
		return containerResourceUsage(cgroups)
	}
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return resourceReading{}, err
	}
	status, err := resourceFile("/proc/self/status")
	if err != nil {
		return resourceReading{}, err
	}
	for _, line := range strings.Split(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "VmRSS:" && fields[2] == "kB" {
			rss, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return resourceReading{}, err
			}
			seconds := float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1e6
			return resourceReading{scope: "process", source: "getrusage /proc/self/status", cpuSeconds: seconds, cores: float64(runtime.NumCPU()), memory: rss * 1024}, nil
		}
	}
	return resourceReading{}, fmt.Errorf("process resident memory is unavailable")
}

func containerResourceUsage(cgroups string) (resourceReading, error) {
	base := "/sys/fs/cgroup"
	for _, line := range strings.Split(cgroups, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[0] != "0" || parts[1] != "" {
			continue
		}
		relative := strings.TrimPrefix(filepath.Clean(parts[2]), "/")
		candidate := filepath.Join(base, relative)
		if _, err := os.Stat(filepath.Join(candidate, "cpu.stat")); err != nil {
			return resourceReading{}, fmt.Errorf("container cgroup path is unavailable: %w", err)
		}
		base = candidate
	}
	if _, err := os.Stat(filepath.Join(base, "cgroup.controllers")); err == nil {
		stat, err := resourceFile(filepath.Join(base, "cpu.stat"))
		if err != nil {
			return resourceReading{}, err
		}
		var cpu *float64
		for _, line := range strings.Split(stat, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "usage_usec" {
				value, err := strconv.ParseFloat(fields[1], 64)
				if err != nil {
					return resourceReading{}, err
				}
				seconds := value / 1e6
				cpu = &seconds
			}
		}
		if cpu == nil {
			return resourceReading{}, fmt.Errorf("cgroup CPU counter is unavailable")
		}
		memory, err := resourceUint(filepath.Join(base, "memory.current"))
		if err != nil {
			return resourceReading{}, err
		}
		reading := resourceReading{scope: "container", source: "cgroup v2", cpuSeconds: *cpu, cores: float64(runtime.NumCPU()), memory: memory}
		if limit, err := resourceUint(filepath.Join(base, "memory.max")); err == nil {
			reading.memoryLimit = &limit
		}
		if maximum, err := resourceFile(filepath.Join(base, "cpu.max")); err == nil {
			fields := strings.Fields(maximum)
			if len(fields) == 2 && fields[0] != "max" {
				quota, qerr := strconv.ParseFloat(fields[0], 64)
				period, perr := strconv.ParseFloat(fields[1], 64)
				if qerr == nil && perr == nil && quota > 0 && period > 0 && quota/period < reading.cores {
					reading.cores = quota / period
				}
			}
		}
		return reading, nil
	}
	// Cgroup v1 exposes counters in separate controller mounts. In a Docker
	// cgroup namespace these controller roots are already scoped to the container.
	cpuBase, err := resourceController(cgroups, "cpuacct", "cpuacct.usage")
	if err != nil {
		return resourceReading{}, err
	}
	cpu, err := resourceUint(filepath.Join(cpuBase, "cpuacct.usage"))
	if err != nil {
		return resourceReading{}, err
	}
	memoryBase, err := resourceController(cgroups, "memory", "memory.usage_in_bytes")
	if err != nil {
		return resourceReading{}, err
	}
	memory, err := resourceUint(filepath.Join(memoryBase, "memory.usage_in_bytes"))
	if err != nil {
		return resourceReading{}, err
	}
	reading := resourceReading{scope: "container", source: "cgroup v1", cpuSeconds: float64(cpu) / 1e9, cores: float64(runtime.NumCPU()), memory: memory}
	if limit, err := resourceUint(filepath.Join(memoryBase, "memory.limit_in_bytes")); err == nil && limit < 1<<60 {
		reading.memoryLimit = &limit
	}
	quotaBase, quotaErr := resourceController(cgroups, "cpu", "cpu.cfs_quota_us")
	quotaText, qerr := resourceFile(filepath.Join(quotaBase, "cpu.cfs_quota_us"))
	period, perr := resourceUint(filepath.Join(quotaBase, "cpu.cfs_period_us"))
	quota, err := strconv.ParseFloat(quotaText, 64)
	if quotaErr == nil && qerr == nil && perr == nil && err == nil && quota > 0 && period > 0 && quota/float64(period) < reading.cores {
		reading.cores = quota / float64(period)
	}
	return reading, nil
}

func resourceController(cgroups, controller, counter string) (string, error) {
	for _, line := range strings.Split(cgroups, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		for _, name := range strings.Split(parts[1], ",") {
			if name != controller {
				continue
			}
			for _, mount := range []string{controller, parts[1], "cpu,cpuacct", "cpuacct,cpu"} {
				base := filepath.Join("/sys/fs/cgroup", mount, strings.TrimPrefix(filepath.Clean(parts[2]), "/"))
				if _, err := os.Stat(filepath.Join(base, counter)); err == nil {
					return base, nil
				}
			}
		}
	}
	return "", fmt.Errorf("container %s controller is unavailable", controller)
}
