package benchmark

import (
	"math"
	"strings"
	"testing"
)

func TestParseSysbench(t *testing.T) {
	cpu := "events per second:  1386.42\n"
	if value, err := parseEventsPerSecond(cpu); err != nil || value != 1386.42 {
		t.Fatalf("CPU parse = %v, %v", value, err)
	}

	memory := "102400.00 MiB transferred (20479.64 MiB/sec)\n"
	if value, err := parseMemoryMiBPerSecond(memory); err != nil || value != 20479.64 {
		t.Fatalf("memory parse = %v, %v", value, err)
	}

	latency := "total time:                          5.0001s\ntotal number of events:              50001000\n"
	value, err := parseMemoryLatencyNS(latency)
	if err != nil || math.Abs(value-100) > 1 {
		t.Fatalf("latency parse = %v, %v", value, err)
	}
}

func TestParseFioMinimal(t *testing.T) {
	readFields := make([]string, 60)
	readFields[6], readFields[7] = "123456", "30140.5"
	bw, iops, err := parseFioMinimal(strings.Join(readFields, ";"), false)
	if err != nil || bw != 123456 || iops != 30140.5 {
		t.Fatalf("read fio parse = %v %v %v", bw, iops, err)
	}

	writeFields := make([]string, 60)
	writeFields[47], writeFields[48] = "654321", "44500"
	bw, iops, err = parseFioMinimal(strings.Join(writeFields, ";"), true)
	if err != nil || bw != 654321 || iops != 44500 {
		t.Fatalf("write fio parse = %v %v %v", bw, iops, err)
	}
}

func TestParseOpenSSLAES(t *testing.T) {
	output := "type             16384 bytes\nAES-256-GCM      1523456.78k\n"
	value, err := parseOpenSSLAES(output)
	if err != nil || value != 1523456780 {
		t.Fatalf("AES parse = %v, %v", value, err)
	}
}
