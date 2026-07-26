package scoring

import (
	"testing"

	"github.com/nodebench/nodebench/internal/model"
)

func TestApplyScoresAvailableDimensionsAndExcludesMissingIP(t *testing.T) {
	single, multi := 2300.0, 8200.0
	read, write := 900e6, 700e6
	iopsRead, iopsWrite := 50000.0, 32000.0
	report := model.Report{
		CPU: model.CPU{Cores: 4, SingleCoreScore: &single, MultiCoreScore: &multi, Confidence: "high"},
		Disk: model.Disk{
			SequentialReadBytesPerSecond: &read, SequentialWriteBytesPerSecond: &write,
			Random4KReadIOPS: &iopsRead, Random4KWriteIOPS: &iopsWrite, Confidence: "high",
		},
		Network: map[string]any{
			"province_tcp": []any{
				map[string]any{"latency_ms": 160.4, "retransmission_ratio": 0.0},
				map[string]any{"latency_ms": 180.6, "retransmission_ratio": 0.02},
			},
		},
		Routes: []any{
			map[string]any{"route_type": "CN2 GIA"},
			map[string]any{"route_type": "AS9929"},
		},
	}

	Apply(&report)

	overall := report.Scores["overall"].(map[string]any)
	if overall["value"].(int) <= 0 {
		t.Fatalf("overall score = %v, want positive", overall["value"])
	}
	dimensions := report.Scores["dimensions"].(map[string]any)
	ip := dimensions["ip"].(map[string]any)
	if ip["grade"] != "N/A" {
		t.Fatalf("ip grade = %v, want N/A", ip["grade"])
	}
	if overall["completeness"].(float64) >= 1 {
		t.Fatalf("overall completeness = %v, want less than 1", overall["completeness"])
	}
}

func TestApplyRoundsScoresToIntegers(t *testing.T) {
	single := 1400.4
	report := model.Report{
		CPU:     model.CPU{Cores: 1, SingleCoreScore: &single, Confidence: "medium"},
		Network: map[string]any{},
	}
	Apply(&report)
	dimensions := report.Scores["dimensions"].(map[string]any)
	compute := dimensions["compute"].(map[string]any)
	if _, ok := compute["value"].(int); !ok {
		t.Fatalf("compute value type = %T, want int", compute["value"])
	}
}
