package ipservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nodebench/nodebench/internal/model"
	"github.com/nodebench/nodebench/internal/privacy"
)

const userAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126 Safari/537.36 NodeBench"

type Outcome struct {
	Status     string
	Confidence string
	Message    string
	Warnings   []model.Warning
}

type ipAPIResponse struct {
	IP           string `json:"ip"`
	IsProxy      *bool  `json:"is_proxy"`
	IsTor        *bool  `json:"is_tor"`
	IsVPN        *bool  `json:"is_vpn"`
	IsDatacenter *bool  `json:"is_datacenter"`
	IsAbuser     *bool  `json:"is_abuser"`
	IsCrawler    *bool  `json:"is_crawler"`
	ASN          struct {
		ASN   int64  `json:"asn"`
		Org   string `json:"org"`
		Route string `json:"route"`
		Type  string `json:"type"`
	} `json:"asn"`
	Company struct {
		Name        string          `json:"name"`
		Type        string          `json:"type"`
		AbuserScore json.RawMessage `json:"abuser_score"`
	} `json:"company"`
	Location struct {
		CountryCode string `json:"country_code"`
		Country     string `json:"country"`
		State       string `json:"state"`
		City        string `json:"city"`
		Timezone    string `json:"timezone"`
	} `json:"location"`
}

type nodeQualityGeoResponse struct {
	Country struct {
		ISOCode           string `json:"IsoCode"`
		RegisteredCountry struct {
			ISOCode string `json:"IsoCode"`
		} `json:"RegisteredCountry"`
	} `json:"Country"`
}

type serviceSpec struct {
	ID       string
	Name     string
	Category string
	Check    func(context.Context, *http.Client) serviceResult
}

type serviceResult struct {
	Available *bool
	Region    *string
	Level     string
}

// Run follows the public-IP, IP risk, media, AI and mail-port measurement
// methods used by NodeQuality. Full addresses are kept only in local variables.
func Run(ctx context.Context, environment *model.Environment, quality map[string]any, services *[]any, network map[string]any) Outcome {
	client := &http.Client{Timeout: 12 * time.Second}
	warnings := []model.Warning{}
	ipOK := false
	ip, err := publicIPv4(ctx, client)
	if err != nil {
		warnings = append(warnings, warning("public_ipv4_unavailable", "未取得公网 IPv4，IP 属性未测"))
	} else {
		masked, maskErr := privacy.MaskIP(ip)
		if maskErr != nil {
			warnings = append(warnings, warning("public_ipv4_mask_failed", "公网 IPv4 脱敏失败，IP 属性未落盘"))
		} else {
			environment.MaskedIPv4 = &masked
			network["ipv4_available"] = true
			ipOK = collectIPInfo(ctx, client, ip, environment, quality)
		}
	}

	network["ports"] = checkPorts(ctx)
	*services = checkServices(ctx, client)

	successfulServices := 0
	for _, raw := range *services {
		service, ok := raw.(map[string]any)
		if ok {
			if _, measured := service["available"].(bool); measured {
				successfulServices++
			}
		}
	}
	if err == nil && !ipOK {
		warnings = append(warnings, warning("ip_quality_unavailable", "IP 属性与风险源响应解析失败"))
	}
	if successfulServices == 0 {
		warnings = append(warnings, warning("services_unavailable", "服务解锁结果均未能判定"))
	}
	status, confidence := "success", "medium"
	if !ipOK || successfulServices < 3 {
		status, confidence = "partial", "low"
	}
	return Outcome{
		Status: status, Confidence: confidence,
		Message:  fmt.Sprintf("完成 IP 属性、%d 项服务和 5 个常用端口检测", successfulServices),
		Warnings: warnings,
	}
}

func publicIPv4(ctx context.Context, client *http.Client) (string, error) {
	endpoints := []string{
		"https://api.ipify.org", "https://ip.sb", "https://icanhazip.com",
	}
	for _, endpoint := range endpoints {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		request.Header.Set("User-Agent", userAgent)
		response, err := client.Do(request)
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 128))
		response.Body.Close()
		value := strings.TrimSpace(string(body))
		ip := net.ParseIP(value)
		if readErr == nil && response.StatusCode == http.StatusOK && ip != nil && ip.To4() != nil && publicIP(ip) {
			return ip.String(), nil
		}
	}
	return "", errors.New("public IPv4 unavailable")
}

func collectIPInfo(ctx context.Context, client *http.Client, ip string, environment *model.Environment, quality map[string]any) bool {
	endpoint := "https://api.ipapi.is/?q=" + url.QueryEscape(ip)
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	request.Header.Set("User-Agent", userAgent)
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false
	}
	var data ipAPIResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 256*1024)).Decode(&data); err != nil {
		return false
	}

	setString(&environment.Organization, firstNonEmpty(data.ASN.Org, data.Company.Name))
	if data.ASN.ASN > 0 {
		environment.ASN = &data.ASN.ASN
	}
	if data.ASN.Route != "" {
		environment.BGPPrefix = stringPointer(data.ASN.Route)
	}
	environment.CountryCode = upperCountry(data.Location.CountryCode)
	environment.Country = firstNonEmpty(data.Location.Country, environment.Country)
	environment.Region = firstNonEmpty(data.Location.State, environment.Region)
	environment.City = firstNonEmpty(data.Location.City, environment.City)
	environment.Timezone = firstNonEmpty(data.Location.Timezone, environment.Timezone)

	usageCountry := upperCountry(data.Location.CountryCode)
	registrationCountry := ""
	if geoUsage, geoRegistration, ok := collectNodeQualityGeo(ctx, client, ip); ok {
		usageCountry = geoUsage
		registrationCountry = geoRegistration
	}
	ipType, nativeIP := nativeIPType(usageCountry, registrationCountry)
	usageType := normalizeAttributeType(data.ASN.Type, data.IsDatacenter)
	companyType := normalizeAttributeType(data.Company.Type, nil)
	riskScore := parseRiskScore(data.Company.AbuserScore)
	quality["ip_type"] = ipType
	quality["native_ip"] = nativeIP
	quality["usage_type"] = usageType
	quality["company_type"] = companyType
	quality["usage_country_code"] = nullableCountry(usageCountry)
	quality["registration_country_code"] = nullableCountry(registrationCountry)
	quality["risk_score"] = riskScore
	quality["risk_level"] = riskLevel(riskScore)
	quality["proxy"] = data.IsProxy
	quality["vpn"] = data.IsVPN
	quality["tor"] = data.IsTor
	quality["server"] = data.IsDatacenter
	quality["abuse"] = data.IsAbuser
	quality["bot"] = data.IsCrawler
	quality["risk_sources"] = []any{map[string]any{
		"source": "ipapi.is", "score": riskScore, "status": "success",
		"collected_at": time.Now().UTC().Format(time.RFC3339),
	}}
	return true
}

func collectNodeQualityGeo(ctx context.Context, client *http.Client, ip string) (string, string, bool) {
	endpoint := "https://ipinfo.check.place/" + url.PathEscape(ip) + "?lang=en"
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	request.Header.Set("User-Agent", userAgent)
	response, err := client.Do(request)
	if err != nil {
		return "", "", false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", "", false
	}
	var data nodeQualityGeoResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 256*1024)).Decode(&data); err != nil {
		return "", "", false
	}
	usage := upperCountry(data.Country.ISOCode)
	registration := upperCountry(data.Country.RegisteredCountry.ISOCode)
	return usage, registration, usage != "" && registration != ""
}

func checkServices(ctx context.Context, client *http.Client) []any {
	specs := []serviceSpec{
		{ID: "netflix", Name: "Netflix", Category: "streaming", Check: checkNetflix},
		{ID: "youtube-premium", Name: "YouTube Premium", Category: "streaming", Check: checkYouTube},
		{ID: "amazon-prime-video", Name: "Amazon Prime Video", Category: "streaming", Check: checkPrimeVideo},
		{ID: "tiktok", Name: "TikTok", Category: "social", Check: checkTikTok},
		{ID: "reddit", Name: "Reddit", Category: "social", Check: checkReddit},
		{ID: "chatgpt", Name: "ChatGPT", Category: "ai", Check: checkChatGPT},
	}
	results := make([]any, len(specs))
	semaphore := make(chan struct{}, 3)
	var wait sync.WaitGroup
	for index, spec := range specs {
		wait.Add(1)
		go func(index int, spec serviceSpec) {
			defer wait.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				return
			}
			result := spec.Check(ctx, client)
			var available any
			if result.Available != nil {
				available = *result.Available
			}
			results[index] = map[string]any{
				"id": spec.ID, "name": spec.Name, "category": spec.Category,
				"available": available, "region": result.Region,
				"level": result.Level, "method": "native",
				"checked_at": time.Now().UTC().Format(time.RFC3339),
			}
		}(index, spec)
	}
	wait.Wait()
	for index, value := range results {
		if value == nil {
			spec := specs[index]
			results[index] = unknownService(spec)
		}
	}
	return results
}

func checkNetflix(ctx context.Context, client *http.Client) serviceResult {
	original, okOriginal := fetchText(ctx, client, "https://www.netflix.com/title/81280792", nil)
	catalog, okCatalog := fetchText(ctx, client, "https://www.netflix.com/title/70143836", nil)
	if !okOriginal || !okCatalog {
		return unknownResult()
	}
	originalBlocked := strings.Contains(original, "Oh no!")
	catalogBlocked := strings.Contains(catalog, "Oh no!")
	region := firstMatch(original+catalog, regexp.MustCompile(`"id":"([A-Z]{2})".{0,160}"countryName"`))
	switch {
	case originalBlocked && catalogBlocked:
		return serviceResult{Available: boolPointer(true), Region: region, Level: "partial"}
	case !originalBlocked || !catalogBlocked:
		return serviceResult{Available: boolPointer(true), Region: region, Level: "full"}
	default:
		return serviceResult{Available: boolPointer(false), Level: "blocked"}
	}
}

func checkYouTube(ctx context.Context, client *http.Client) serviceResult {
	body, ok := fetchText(ctx, client, "https://www.youtube.com/premium", map[string]string{"Accept-Language": "en"})
	if !ok {
		return unknownResult()
	}
	if strings.Contains(body, "Premium is not available in your country") || strings.Contains(body, "www.google.cn") {
		return serviceResult{Available: boolPointer(false), Level: "blocked"}
	}
	region := firstMatch(body, regexp.MustCompile(`"contentRegion":"([A-Z]{2})"`))
	if strings.Contains(body, "ad-free") {
		return serviceResult{Available: boolPointer(true), Region: region, Level: "full"}
	}
	return unknownResult()
}

func checkPrimeVideo(ctx context.Context, client *http.Client) serviceResult {
	body, ok := fetchText(ctx, client, "https://www.primevideo.com", nil)
	if !ok {
		return unknownResult()
	}
	region := firstMatch(body, regexp.MustCompile(`"currentTerritory":\s*"([A-Z]{2})"`))
	if region != nil {
		return serviceResult{Available: boolPointer(true), Region: region, Level: "full"}
	}
	return unknownResult()
}

func checkTikTok(ctx context.Context, client *http.Client) serviceResult {
	body, ok := fetchText(ctx, client, "https://www.tiktok.com/", map[string]string{"Accept-Language": "en"})
	if !ok {
		return unknownResult()
	}
	region := firstMatch(body, regexp.MustCompile(`"region":"([A-Z]{2})"`))
	if region != nil {
		return serviceResult{Available: boolPointer(true), Region: region, Level: "full"}
	}
	return unknownResult()
}

func checkReddit(ctx context.Context, client *http.Client) serviceResult {
	status, body := fetchStatus(ctx, client, "https://www.reddit.com/", nil)
	switch status {
	case http.StatusOK:
		region := firstMatch(body, regexp.MustCompile(`country="([A-Z]{2})"`))
		return serviceResult{Available: boolPointer(true), Region: region, Level: "full"}
	case http.StatusForbidden:
		return serviceResult{Available: boolPointer(false), Level: "blocked"}
	default:
		return unknownResult()
	}
}

func checkChatGPT(ctx context.Context, client *http.Client) serviceResult {
	api, apiOK := fetchText(ctx, client, "https://api.openai.com/compliance/cookie_requirements", map[string]string{"Authorization": "Bearer null"})
	web, webOK := fetchText(ctx, client, "https://ios.chat.openai.com/", nil)
	if !apiOK && !webOK {
		return unknownResult()
	}
	apiBlocked := strings.Contains(api, "unsupported_country")
	webBlocked := strings.Contains(strings.ToLower(web), "vpn")
	_, trace := fetchStatus(ctx, client, "https://chat.openai.com/cdn-cgi/trace", nil)
	region := firstMatch(trace, regexp.MustCompile(`(?m)^loc=([A-Z]{2})$`))
	switch {
	case !apiBlocked && !webBlocked:
		return serviceResult{Available: boolPointer(true), Region: region, Level: "full"}
	case apiBlocked && webBlocked:
		return serviceResult{Available: boolPointer(false), Level: "blocked"}
	default:
		return serviceResult{Available: boolPointer(true), Region: region, Level: "partial"}
	}
}

func checkPorts(ctx context.Context) []any {
	targets := []struct {
		Port int
		Host string
	}{
		{80, "one.one.one.one:80"}, {443, "one.one.one.one:443"},
		{25, "gmail-smtp-in.l.google.com:25"}, {465, "smtp.gmail.com:465"}, {587, "smtp.gmail.com:587"},
	}
	results := make([]any, len(targets))
	var wait sync.WaitGroup
	for index, target := range targets {
		wait.Add(1)
		go func(index int, target struct {
			Port int
			Host string
		}) {
			defer wait.Done()
			dialer := net.Dialer{Timeout: 5 * time.Second}
			connection, err := dialer.DialContext(ctx, "tcp", target.Host)
			if err == nil {
				connection.Close()
			}
			results[index] = map[string]any{
				"port": target.Port, "protocol": "tcp", "reachable": err == nil,
				"note": nil,
			}
		}(index, target)
	}
	wait.Wait()
	return results
}

func fetchText(ctx context.Context, client *http.Client, endpoint string, headers map[string]string) (string, bool) {
	status, body := fetchStatus(ctx, client, endpoint, headers)
	return body, status >= 200 && status < 400
}

func fetchStatus(ctx context.Context, client *http.Client, endpoint string, headers map[string]string) (int, string) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, ""
	}
	request.Header.Set("User-Agent", userAgent)
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, ""
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if err != nil {
		return response.StatusCode, ""
	}
	return response.StatusCode, string(body)
}

func publicIP(ip net.IP) bool {
	return !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsUnspecified()
}

func normalizeAttributeType(value string, datacenter *bool) string {
	if datacenter != nil && *datacenter {
		return "datacenter"
	}
	value = strings.ToLower(value)
	switch {
	case strings.Contains(value, "mobile"):
		return "mobile"
	case strings.Contains(value, "isp"), strings.Contains(value, "residential"), strings.Contains(value, "consumer"):
		return "residential"
	case strings.Contains(value, "hosting"), strings.Contains(value, "datacenter"), strings.Contains(value, "data center"):
		return "datacenter"
	case strings.Contains(value, "business"), strings.Contains(value, "commercial"):
		return "business"
	default:
		return "unknown"
	}
}

func nativeIPType(usageCountry, registrationCountry string) (string, any) {
	if usageCountry == "" || registrationCountry == "" {
		return "unknown", nil
	}
	native := strings.EqualFold(usageCountry, registrationCountry)
	if native {
		return "native", true
	}
	return "broadcast", false
}

func parseRiskScore(raw json.RawMessage) any {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var number float64
	if err := json.Unmarshal(raw, &number); err != nil {
		var text string
		if json.Unmarshal(raw, &text) != nil {
			return nil
		}
		fields := strings.Fields(text)
		if len(fields) == 0 {
			return nil
		}
		parsed, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return nil
		}
		number = parsed
	}
	if number < 0 || number > 1 {
		return nil
	}
	return float64(int(number*100 + .5))
}

func riskLevel(value any) string {
	score, ok := value.(float64)
	if !ok {
		return "unknown"
	}
	switch {
	case score <= 20:
		return "low"
	case score <= 40:
		return "medium_low"
	case score <= 70:
		return "medium"
	default:
		return "high"
	}
}

func nullableCountry(value string) any {
	value = upperCountry(value)
	if len(value) != 2 {
		return nil
	}
	return value
}

func upperCountry(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if len(value) != 2 {
		return ""
	}
	return value
}

func unknownResult() serviceResult {
	return serviceResult{Available: nil, Region: nil, Level: "unknown"}
}

func unknownService(spec serviceSpec) map[string]any {
	return map[string]any{
		"id": spec.ID, "name": spec.Name, "category": spec.Category,
		"available": nil, "region": nil, "level": "unknown", "method": "native",
		"checked_at": time.Now().UTC().Format(time.RFC3339),
	}
}

func firstMatch(value string, expression *regexp.Regexp) *string {
	match := expression.FindStringSubmatch(value)
	if len(match) < 2 || match[1] == "" {
		return nil
	}
	return stringPointer(match[1])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func setString(target **string, value string) {
	if value != "" {
		*target = stringPointer(value)
	}
}

func boolPointer(value bool) *bool {
	return &value
}

func stringPointer(value string) *string {
	return &value
}

func warning(code, message string) model.Warning {
	return model.Warning{Code: code, Severity: "warning", Message: message, Module: "ip_services"}
}
