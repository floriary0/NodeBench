package tcpquality

import (
	"strings"
	"testing"
)

func TestParseMatchingRTT(t *testing.T) {
	output := `SENT (0.0419s) TCP 29.35.1.2:28888 > 104.18.2.3:443 S ttl=64 id=1 iplen=40  seq=123 win=1480
RCVD (0.0434s) TCP 104.18.2.3:443 > 29.35.1.2:28888 SA ttl=57 id=2 iplen=44  seq=10 win=65535
Max rtt: 1.500ms | Min rtt: 1.500ms | Avg rtt: 1.500ms
Raw packets sent: 1 (40B) | Rcvd: 1 (44B) | Lost: 0 (0.00%)`
	value, err := parseMatchingRTT(output)
	if err != nil || value < 1.49 || value > 1.51 {
		t.Fatalf("RTT = %v, %v", value, err)
	}
}

func TestParseMatchingRTTRejectsUnrelatedPacket(t *testing.T) {
	output := `SENT (0.0419s) TCP 29.35.1.2:28888 > 104.18.2.3:443 S ttl=64
RCVD (0.0434s) TCP 104.18.2.3:80 > 29.35.1.2:28888 SA ttl=57`
	if _, err := parseMatchingRTT(output); err == nil {
		t.Fatal("expected mismatched source port to be rejected")
	}
}

func TestParseNodeTSVOnlyKeepsPublicIPv4CDN(t *testing.T) {
	data := `type	family	province	isp	host	ip	port	target
cdn	4	上海	电信	sh.example	1.1.1.1	80	x
cdn	4	北京	联通	bj.example	10.0.0.1	80	x
cdn	6	广东	移动	gd.example	2001:4860:4860::8888	80	x
`
	targets, err := parseNodeTSV(strings.NewReader(data), 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("targets = %d", len(targets))
	}
	if targets[0].Carrier != "telecom" || targets[0].Packets != 30 {
		t.Fatalf("unexpected target: %#v", targets[0])
	}
}

func TestAggregateSummary(t *testing.T) {
	latencyA, latencyB := 100.0, 200.0
	results := []Result{
		{Target: Target{China: true, Carrier: "telecom", Province: "上海"}, Sent: 10, Received: 10, AverageRTTMS: &latencyA},
		{Target: Target{China: true, Carrier: "telecom", Province: "北京"}, Sent: 10, Received: 8, LossRatio: .2, AverageRTTMS: &latencyB},
	}
	network := map[string]any{}
	applyResults(network, results, 2)
	summary := network["tcp_quality_summary"].(map[string]any)
	if summary["zero_retransmission_count"] != 1 || summary["light_retransmission_count"] != 1 {
		t.Fatalf("summary = %#v", summary)
	}
	if len(network["province_tcp"].([]any)) != 2 || len(network["china_carriers"].([]any)) != 1 {
		t.Fatalf("network aggregation failed: %#v", network)
	}
}
