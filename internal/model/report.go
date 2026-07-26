package model

import "time"

type Price struct {
	AmountMinor            int64  `json:"amount_minor"`
	Currency               string `json:"currency"`
	BillingPeriod          string `json:"billing_period"`
	MonthlyEquivalentMinor *int64 `json:"monthly_equivalent_minor"`
}

type UserSupplied struct {
	Provider            *string `json:"provider"`
	Plan                *string `json:"plan"`
	Price               *Price  `json:"price"`
	AdvertisedBandwidth *string `json:"advertised_bandwidth"`
	MonthlyTraffic      *string `json:"monthly_traffic"`
	Datacenter          *string `json:"datacenter"`
	PurchaseURL         *string `json:"purchase_url"`
	Note                *string `json:"note"`
	Unverified          bool    `json:"unverified"`
}

type Environment struct {
	MaskedIPv4     *string    `json:"masked_ipv4"`
	MaskedIPv6     *string    `json:"masked_ipv6"`
	CountryCode    string     `json:"country_code"`
	Country        string     `json:"country"`
	Region         string     `json:"region"`
	City           string     `json:"city"`
	Timezone       string     `json:"timezone"`
	ASN            *int64     `json:"asn"`
	Organization   *string    `json:"organization"`
	BGPPrefix      *string    `json:"bgp_prefix"`
	OSName         string     `json:"os_name"`
	OSVersion      string     `json:"os_version"`
	Kernel         string     `json:"kernel"`
	Architecture   string     `json:"architecture"`
	Virtualization string     `json:"virtualization"`
	Container      *string    `json:"container"`
	UptimeSeconds  int64      `json:"uptime_seconds"`
	LoadAverage    [3]float64 `json:"load_average"`
	ProcessCount   int        `json:"process_count"`
	ServiceCount   int        `json:"service_count"`
	Locale         *string    `json:"locale"`
	BIOSVendor     *string    `json:"bios_vendor"`
	Chipset        *string    `json:"chipset"`
	NICModel       *string    `json:"nic_model"`
	ClockSource    *string    `json:"clock_source"`
}

type Frequency struct {
	Current *float64 `json:"current"`
	Minimum *float64 `json:"minimum"`
	Maximum *float64 `json:"maximum"`
}

type Cache struct {
	L1Bytes *int64 `json:"l1_bytes"`
	L2Bytes *int64 `json:"l2_bytes"`
	L3Bytes *int64 `json:"l3_bytes"`
}

type CPU struct {
	Model             string    `json:"model"`
	Sockets           int       `json:"sockets"`
	Cores             int       `json:"cores"`
	Threads           int       `json:"threads"`
	FrequencyMHz      Frequency `json:"frequency_mhz"`
	Cache             Cache     `json:"cache"`
	Features          []string  `json:"features"`
	SingleCoreScore   *float64  `json:"single_core_score"`
	MultiCoreScore    *float64  `json:"multi_core_score"`
	AESBytesPerSecond *float64  `json:"aes_bytes_per_second"`
	WeightedScore     *float64  `json:"weighted_score"`
	PeerPercentile    *float64  `json:"peer_percentile"`
	Confidence        string    `json:"confidence"`
}

type Memory struct {
	TotalBytes          int64    `json:"total_bytes"`
	UsedBytes           int64    `json:"used_bytes"`
	AvailableBytes      int64    `json:"available_bytes"`
	SwapTotalBytes      int64    `json:"swap_total_bytes"`
	SwapUsedBytes       int64    `json:"swap_used_bytes"`
	ReadBytesPerSecond  *float64 `json:"read_bytes_per_second"`
	WriteBytesPerSecond *float64 `json:"write_bytes_per_second"`
	LatencyNS           *float64 `json:"latency_ns"`
	BalloonEnabled      *bool    `json:"balloon_enabled"`
	KSMEnabled          *bool    `json:"ksm_enabled"`
	Confidence          string   `json:"confidence"`
}

type Disk struct {
	Type                          string   `json:"type"`
	Filesystem                    *string  `json:"filesystem"`
	TotalBytes                    int64    `json:"total_bytes"`
	UsedBytes                     int64    `json:"used_bytes"`
	AvailableBytes                int64    `json:"available_bytes"`
	SequentialReadBytesPerSecond  *float64 `json:"sequential_read_bytes_per_second"`
	SequentialWriteBytesPerSecond *float64 `json:"sequential_write_bytes_per_second"`
	Random4KReadIOPS              *float64 `json:"random_4k_read_iops"`
	Random4KWriteIOPS             *float64 `json:"random_4k_write_iops"`
	WriteP95LatencyMS             *float64 `json:"write_p95_latency_ms"`
	SustainedWriteStability       *float64 `json:"sustained_write_stability"`
	CacheAffected                 *bool    `json:"cache_affected"`
	Confidence                    string   `json:"confidence"`
}

type Module struct {
	ID         string  `json:"id"`
	Status     string  `json:"status"`
	DurationMS int64   `json:"duration_ms"`
	Confidence string  `json:"confidence"`
	ErrorCode  *string `json:"error_code"`
	Message    *string `json:"message"`
}

type Completeness struct {
	Ratio             float64  `json:"ratio"`
	SuccessfulModules int      `json:"successful_modules"`
	PartialModules    int      `json:"partial_modules"`
	FailedModules     int      `json:"failed_modules"`
	MissingFields     []string `json:"missing_fields"`
}

type Warning struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Module   string `json:"module"`
}

type Report struct {
	SchemaVersion      string         `json:"schema_version"`
	ClientVersion      string         `json:"client_version"`
	ScoringVersion     string         `json:"scoring_version"`
	NodeCatalogVersion string         `json:"node_catalog_version"`
	ReportID           string         `json:"report_id"`
	Status             string         `json:"status"`
	Visibility         string         `json:"visibility"`
	StartedAt          time.Time      `json:"started_at"`
	CompletedAt        time.Time      `json:"completed_at"`
	DurationMS         int64          `json:"duration_ms"`
	UserSupplied       UserSupplied   `json:"user_supplied"`
	Environment        Environment    `json:"environment"`
	CPU                CPU            `json:"cpu"`
	Memory             Memory         `json:"memory"`
	Disk               Disk           `json:"disk"`
	Network            map[string]any `json:"network"`
	Routes             []any          `json:"routes"`
	IPQuality          map[string]any `json:"ip_quality"`
	Services           []any          `json:"services"`
	Scores             map[string]any `json:"scores"`
	SemanticEvaluation map[string]any `json:"semantic_evaluation"`
	Modules            []Module       `json:"modules"`
	Completeness       Completeness   `json:"completeness"`
	Warnings           []Warning      `json:"warnings"`
}

type Credentials struct {
	UploadSecret string `json:"upload_secret"`
}

type UploadEnvelope struct {
	Credentials
	Report Report `json:"report"`
}
