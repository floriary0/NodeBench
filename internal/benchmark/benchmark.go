package benchmark

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nodebench/nodebench/internal/model"
)

type Outcome struct {
	Status     string
	Confidence string
	Message    string
	Warnings   []model.Warning
}

type commandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
	Exists(string) bool
}

type execRunner struct{}

func (execRunner) Exists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func Run(ctx context.Context, workDir string, cpu *model.CPU, memory *model.Memory, disk *model.Disk) Outcome {
	return run(ctx, execRunner{}, workDir, cpu, memory, disk)
}

func run(ctx context.Context, commands commandRunner, workDir string, cpu *model.CPU, memory *model.Memory, disk *model.Disk) Outcome {
	outcome := Outcome{Status: "success", Confidence: "high"}
	completed := 0
	if commands.Exists("sysbench") {
		if runSysbench(ctx, commands, cpu, memory) {
			completed++
		} else {
			outcome.Warnings = append(outcome.Warnings, warning("sysbench_failed", "Sysbench 执行或解析失败"))
		}
	} else {
		outcome.Warnings = append(outcome.Warnings, warning("sysbench_missing", "未安装 sysbench，CPU 与内存性能未测"))
	}
	if commands.Exists("openssl") {
		runOpenSSL(ctx, commands, cpu)
	}

	if commands.Exists("fio") {
		if err := runFio(ctx, commands, workDir, disk); err == nil {
			completed++
		} else {
			outcome.Warnings = append(outcome.Warnings, warning("fio_failed", "Fio 执行失败："+err.Error()))
		}
	} else {
		outcome.Warnings = append(outcome.Warnings, warning("fio_missing", "未安装 fio，磁盘性能未测"))
	}

	switch completed {
	case 2:
		outcome.Message = "Sysbench 与 Fio 测试完成"
	case 0:
		outcome.Status = "skipped"
		outcome.Confidence = "low"
		outcome.Message = "缺少可用性能测试工具"
	default:
		outcome.Status = "partial"
		outcome.Confidence = "medium"
		outcome.Message = "部分性能测试完成"
	}
	return outcome
}

func runSysbench(ctx context.Context, commands commandRunner, cpu *model.CPU, memory *model.Memory) bool {
	ok := false
	singleCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	output, err := commands.Run(singleCtx, "sysbench", "cpu", "--threads=1", "--time=8", "--events=0", "--cpu-max-prime=10000", "run")
	cancel()
	if err == nil {
		if value, parseErr := parseEventsPerSecond(string(output)); parseErr == nil {
			cpu.SingleCoreScore = &value
			if runtime.NumCPU() == 1 {
				cpu.MultiCoreScore = &value
			}
			ok = true
		}
	}

	if runtime.NumCPU() > 1 {
		multiCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		output, err = commands.Run(multiCtx, "sysbench", "cpu", "--threads="+strconv.Itoa(runtime.NumCPU()), "--time=8", "--events=0", "--cpu-max-prime=10000", "run")
		cancel()
		if err == nil {
			if value, parseErr := parseEventsPerSecond(string(output)); parseErr == nil {
				cpu.MultiCoreScore = &value
				ok = true
			}
		}
	}

	for _, spec := range []struct {
		operation string
		target    **float64
	}{
		{"write", &memory.WriteBytesPerSecond},
		{"read", &memory.ReadBytesPerSecond},
	} {
		runCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		output, err = commands.Run(runCtx, "sysbench", "memory",
			"--memory-block-size=1M", "--memory-total-size=1000G",
			"--memory-oper="+spec.operation, "--memory-access-mode=seq", "--time=5", "run")
		cancel()
		if err == nil {
			if mib, parseErr := parseMemoryMiBPerSecond(string(output)); parseErr == nil {
				value := mib * 1024 * 1024
				*spec.target = &value
				ok = true
			}
		}
	}

	latencyCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	output, err = commands.Run(latencyCtx, "sysbench", "memory",
		"--memory-block-size=64", "--memory-total-size=1000G",
		"--memory-oper=read", "--memory-access-mode=rnd", "--time=5", "run")
	cancel()
	if err == nil {
		if value, parseErr := parseMemoryLatencyNS(string(output)); parseErr == nil {
			memory.LatencyNS = &value
			ok = true
		}
	}
	if ok {
		cpu.Confidence = "high"
		memory.Confidence = "high"
	}
	return ok
}

func runOpenSSL(ctx context.Context, commands commandRunner, cpu *model.CPU) {
	runCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	output, err := commands.Run(runCtx, "openssl", "speed",
		"-elapsed", "-seconds", "3", "-bytes", "16384", "-evp", "aes-256-gcm")
	if err != nil {
		return
	}
	if value, parseErr := parseOpenSSLAES(string(output)); parseErr == nil {
		cpu.AESBytesPerSecond = &value
	}
}

type fioSpec struct {
	name   string
	rw     string
	bs     string
	depth  int
	target **float64
}

func runFio(ctx context.Context, commands commandRunner, workDir string, disk *model.Disk) error {
	size, err := fioSize(workDir)
	if err != nil {
		return err
	}
	testFile := filepath.Join(workDir, ".nodebench-fio.tmp")
	defer os.Remove(testFile)

	preCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	_, err = commands.Run(preCtx, "fio", "--name=prealloc", "--filename="+testFile,
		"--rw=write", "--bs=1M", "--iodepth=1", "--numjobs=1", "--direct=1",
		"--size="+strconv.FormatInt(size, 10), "--fallocate=posix", "--overwrite=1",
		"--end_fsync=1", "--group_reporting")
	cancel()
	if err != nil {
		return fmt.Errorf("准备测试文件失败")
	}

	specs := []fioSpec{
		{"4K_q1", "randread", "4K", 1, nil},
		{"4K_q32", "randread", "4K", 32, &disk.Random4KReadIOPS},
		{"1M_q1", "read", "1M", 1, nil},
		{"1M_q8", "read", "1M", 8, &disk.SequentialReadBytesPerSecond},
		{"4K_q1", "randwrite", "4K", 1, nil},
		{"4K_q32", "randwrite", "4K", 32, &disk.Random4KWriteIOPS},
		{"1M_q1", "write", "1M", 1, nil},
		{"1M_q8", "write", "1M", 8, &disk.SequentialWriteBytesPerSecond},
	}
	success := 0
	for _, spec := range specs {
		args := []string{
			"--name=" + spec.name, "--filename=" + testFile, "--rw=" + spec.rw,
			"--bs=" + spec.bs, "--iodepth=" + strconv.Itoa(spec.depth),
			"--ioengine=libaio", "--direct=1", "--numjobs=1", "--runtime=10",
			"--size=" + strconv.FormatInt(size, 10), "--gtod_reduce=1",
			"--group_reporting", "--minimal",
		}
		if strings.Contains(spec.rw, "read") {
			args = append(args, "--time_based")
		} else {
			args = append(args, "--overwrite=1")
		}
		runCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		output, runErr := commands.Run(runCtx, "fio", args...)
		cancel()
		if runErr != nil {
			continue
		}
		bw, iops, parseErr := parseFioMinimal(string(output), strings.Contains(spec.rw, "write"))
		if parseErr != nil {
			continue
		}
		if spec.target != nil {
			if strings.Contains(spec.name, "4K") {
				*spec.target = &iops
			} else {
				bytesPerSecond := bw * 1024
				*spec.target = &bytesPerSecond
			}
		}
		success++
	}
	if success != len(specs) {
		return fmt.Errorf("仅完成 %d/%d 个子项", success, len(specs))
	}
	disk.CacheAffected = boolPointer(false)
	disk.Confidence = "high"
	return nil
}

func fioSize(workDir string) (int64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(workDir, &stat); err != nil {
		return 0, err
	}
	free := int64(stat.Bavail) * int64(stat.Bsize)
	size := free * 7 / 10
	const minimum = int64(256 * 1024 * 1024)
	const maximum = int64(2 * 1024 * 1024 * 1024)
	if size < minimum {
		return 0, errors.New("可用空间不足 256 MiB")
	}
	if size > maximum {
		size = maximum
	}
	return size, nil
}

var (
	eventsPattern    = regexp.MustCompile(`(?m)events per second:\s*([0-9.]+)`)
	memoryPattern    = regexp.MustCompile(`\(([0-9.]+)\s+MiB/sec\)`)
	totalPattern     = regexp.MustCompile(`(?m)total time:\s*([0-9.]+)s`)
	countPattern     = regexp.MustCompile(`(?m)total number of events:\s*([0-9]+)`)
	aesLinePattern   = regexp.MustCompile(`(?mi)^AES-256-GCM\s+(.+)$`)
	rateValuePattern = regexp.MustCompile(`([0-9]+(?:\.[0-9]+)?)([kKmMgG])`)
)

func parseEventsPerSecond(output string) (float64, error) {
	return parseFirstFloat(eventsPattern, output)
}

func parseMemoryMiBPerSecond(output string) (float64, error) {
	return parseFirstFloat(memoryPattern, output)
}

func parseMemoryLatencyNS(output string) (float64, error) {
	total, err := parseFirstFloat(totalPattern, output)
	if err != nil {
		return 0, err
	}
	count, err := parseFirstFloat(countPattern, output)
	if err != nil || count <= 0 {
		return 0, errors.New("缺少事件数")
	}
	return math.Round(total / count * 1e9), nil
}

func parseOpenSSLAES(output string) (float64, error) {
	line := aesLinePattern.FindStringSubmatch(output)
	if len(line) != 2 {
		return 0, errors.New("未找到 AES-256-GCM 吞吐")
	}
	values := rateValuePattern.FindAllStringSubmatch(line[1], -1)
	if len(values) == 0 {
		return 0, errors.New("未找到 AES 速率")
	}
	last := values[len(values)-1]
	value, err := strconv.ParseFloat(last[1], 64)
	if err != nil {
		return 0, err
	}
	switch strings.ToLower(last[2]) {
	case "k":
		value *= 1000
	case "m":
		value *= 1000 * 1000
	case "g":
		value *= 1000 * 1000 * 1000
	}
	return value, nil
}

func parseFirstFloat(pattern *regexp.Regexp, output string) (float64, error) {
	match := pattern.FindStringSubmatch(output)
	if len(match) != 2 {
		return 0, errors.New("未找到数值")
	}
	return strconv.ParseFloat(match[1], 64)
}

func parseFioMinimal(output string, write bool) (float64, float64, error) {
	line := strings.TrimSpace(strings.Split(strings.TrimSpace(output), "\n")[0])
	fields := strings.Split(line, ";")
	bwIndex, iopsIndex := 6, 7
	if write {
		bwIndex, iopsIndex = 47, 48
	}
	if len(fields) <= iopsIndex {
		return 0, 0, errors.New("Fio minimal 字段不足")
	}
	bw, err := strconv.ParseFloat(fields[bwIndex], 64)
	if err != nil {
		return 0, 0, err
	}
	iops, err := strconv.ParseFloat(fields[iopsIndex], 64)
	if err != nil {
		return 0, 0, err
	}
	return bw, iops, nil
}

func warning(code, message string) model.Warning {
	return model.Warning{Code: code, Severity: "warning", Message: message, Module: "performance"}
}

func boolPointer(value bool) *bool {
	return &value
}
