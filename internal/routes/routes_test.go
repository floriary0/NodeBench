package routes

import (
	"strings"
	"testing"
)

func TestParseTraceroute(t *testing.T) {
	output := `traceroute to 1.1.1.1 (1.1.1.1), 30 hops max, 44 byte packets
 1  10.0.0.1  0.100 ms  0.200 ms  0.300 ms
 2  * * *
 3  59.43.247.1  10.100 ms  10.200 ms  10.300 ms
 4  202.97.12.1  11.100 ms  11.200 ms  11.300 ms`
	hops := parseTraceroute(output)
	if len(hops) != 3 || hops[1] != "59.43.247.1" {
		t.Fatalf("hops = %#v", hops)
	}
}

func TestParseCymru(t *testing.T) {
	output := `AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name
4809    | 59.43.247.1      | 59.43.0.0/16        | CN | apnic    | 2004-12-10 | CHINATELECOM-CN2
4134    | 202.97.12.1      | 202.97.0.0/16       | CN | apnic    | 1994-04-05 | CHINANET-BACKBONE`
	values, err := parseCymru(strings.NewReader(output))
	if err != nil || values["59.43.247.1"] != 4809 || values["202.97.12.1"] != 4134 {
		t.Fatalf("values = %#v, err = %v", values, err)
	}
}

func TestRouteClassification(t *testing.T) {
	tests := []struct {
		name    string
		hops    []string
		asns    map[string]int64
		carrier string
		want    string
	}{
		{
			name: "CN2 GIA", hops: []string{"8.8.8.8", "59.43.247.1"},
			asns: map[string]int64{"59.43.247.1": 4809}, carrier: "telecom", want: "CN2GIA",
		},
		{
			name: "CN2 GT", hops: []string{"59.43.247.1", "202.97.12.1"},
			asns: map[string]int64{"59.43.247.1": 4809, "202.97.12.1": 4134}, carrier: "telecom", want: "CN2GT",
		},
		{
			name: "10099 to 9929", hops: []string{"103.214.1.1", "218.105.1.1"},
			asns: map[string]int64{"103.214.1.1": 10099, "218.105.1.1": 9929}, carrier: "unicom", want: "10099->9929",
		},
		{
			name: "CMIN2", hops: []string{"1.1.1.1", "2.2.2.2"},
			asns: map[string]int64{"2.2.2.2": 58807}, carrier: "mobile", want: "CMIN2",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classify(test.hops, test.asns, test.carrier); got != test.want {
				t.Fatalf("classify() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestMaskedHopsNeverKeepFullIPv4(t *testing.T) {
	value, err := maskHop("59.43.247.1")
	if err != nil || value != "59.43.*.*" {
		t.Fatalf("mask = %q, %v", value, err)
	}
}

func TestEnrichProvinceRows(t *testing.T) {
	row := map[string]any{
		"carrier": "telecom", "province": "北京", "route": nil,
	}
	network := map[string]any{"province_tcp": []any{row}}
	routeOutput := []any{map[string]any{
		"carrier": "telecom", "target_city": "北京", "route_type": "CN2GIA",
	}}
	EnrichProvinceRows(network, routeOutput)
	if row["route"] != "CN2GIA" {
		t.Fatalf("route = %#v, want CN2GIA", row["route"])
	}
}
