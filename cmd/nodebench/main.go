package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nodebench/nodebench/internal/bandwidth"
	"github.com/nodebench/nodebench/internal/benchmark"
	"github.com/nodebench/nodebench/internal/builder"
	"github.com/nodebench/nodebench/internal/collector"
	"github.com/nodebench/nodebench/internal/identity"
	"github.com/nodebench/nodebench/internal/ipservice"
	"github.com/nodebench/nodebench/internal/model"
	"github.com/nodebench/nodebench/internal/netinfo"
	"github.com/nodebench/nodebench/internal/render"
	"github.com/nodebench/nodebench/internal/routes"
	"github.com/nodebench/nodebench/internal/scheduler"
	"github.com/nodebench/nodebench/internal/scoring"
	"github.com/nodebench/nodebench/internal/storage"
	"github.com/nodebench/nodebench/internal/tcpquality"
	"github.com/nodebench/nodebench/internal/upload"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "NodeBench 失败：%v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		workerURL       string
		publicBase      string
		outputRoot      string
		nonInteractive  bool
		skipPerformance bool
		skipTCPQuality  bool
		skipRoutes      bool
		skipBandwidth   bool
		tcpNodeURL      string
		tcpPackets      int
		internetPackets int
		tcpConcurrency  int
		statusReportID  string
	)
	defaultRoot, err := storage.DefaultRoot()
	if err != nil {
		return err
	}
	flag.StringVar(&workerURL, "worker-url", "", "Worker 基础地址；留空则只生成本地报告")
	flag.StringVar(&publicBase, "public-base-url", "http://localhost:3000", "报告网页基础地址")
	flag.StringVar(&outputRoot, "output-dir", defaultRoot, "本地任务根目录")
	flag.BoolVar(&nonInteractive, "yes", false, "跳过交互并接受标准模式")
	flag.BoolVar(&skipPerformance, "skip-performance", false, "跳过 Sysbench/Fio（开发与复测用）")
	flag.BoolVar(&skipTCPQuality, "skip-tcp-quality", false, "跳过 TCP SYN 质量探测（开发与复测用）")
	flag.BoolVar(&skipRoutes, "skip-routes", false, "跳过三网 TCP 回程线路（开发与复测用）")
	flag.BoolVar(&skipBandwidth, "skip-bandwidth", false, "跳过三网单线程带宽（开发与复测用）")
	flag.StringVar(&tcpNodeURL, "tcp-node-url", tcpquality.DefaultNodeURL, "三网 TCP 节点目录")
	flag.IntVar(&tcpPackets, "tcp-packets", 30, "每个三网节点 TCP SYN 包数（1-600）")
	flag.IntVar(&internetPackets, "international-packets", 15, "每个国际目标 TCP SYN 包数（1-600）")
	flag.IntVar(&tcpConcurrency, "tcp-concurrency", 16, "轻量 TCP SYN 目标并发数（最大 16；不影响带宽测速并发）")
	flag.StringVar(&statusReportID, "status", "", "查看任务状态；传入报告 ID 或 latest")
	flag.Parse()

	if statusReportID != "" {
		var state storage.State
		if statusReportID == "latest" {
			state, err = storage.LatestState(outputRoot)
		} else {
			state, err = storage.ReadState(outputRoot, statusReportID)
		}
		if err != nil {
			return err
		}
		current := "无"
		if state.CurrentModule != nil {
			current = moduleTitle(*state.CurrentModule)
		}
		fmt.Printf("报告：%s\n状态：%s\n阶段：%s\n进度：%d/%d\n更新：%s\n",
			state.ReportID, state.Status, current, state.Completed, state.Total,
			state.UpdatedAt.Local().Format("2006-01-02 15:04:05"))
		if state.LastError != nil {
			fmt.Printf("异常：%s\n", *state.LastError)
		}
		return nil
	}

	reader := bufio.NewReader(os.Stdin)
	user := model.UserSupplied{Unverified: true}
	if !nonInteractive {
		user, err = readUserSupplied(reader)
		if err != nil {
			return err
		}
	}

	reportID, credentials, err := identity.Generate()
	if err != nil {
		return err
	}
	reportURL := identity.ReportURL(strings.TrimRight(publicBase, "/"), reportID)

	fmt.Println()
	fmt.Println("NodeBench 标准模式")
	fmt.Println("模块：系统、CPU、内存、磁盘、三网、线路、IP、流媒体与常用服务")
	fmt.Println("预计：通常 5～10 分钟；带宽流量通常 2～8GB，12GB 为硬上限")
	fmt.Println("隐私：完整 IP、主机名、MAC、Machine ID、序列号和真实路径不会落盘或上传")
	fmt.Println("上传：测评期间不连接 Worker，结束后最多上传一份最终脱敏 JSON")
	fmt.Printf("预生成报告链接：%s\n", reportURL)
	fmt.Println("提示：报告默认公开，任何拿到链接的人都可以查看脱敏后的测评结果。")
	if !nonInteractive {
		confirmed, err := askYesNo(reader, "开始测评？[y/N] ")
		if err != nil {
			return err
		}
		if !confirmed {
			fmt.Println("已取消，未开始测评。")
			return nil
		}
	}

	startedAt := time.Now().UTC()
	if err := os.MkdirAll(outputRoot, 0o700); err != nil {
		return fmt.Errorf("创建任务根目录: %w", err)
	}
	totalModules := 7
	if err := storage.WriteState(outputRoot, storage.State{
		ReportID: reportID, Status: "starting", Total: totalModules,
	}); err != nil {
		return fmt.Errorf("写入初始状态: %w", err)
	}
	var report model.Report
	modules := scheduler.Run(context.Background(), []scheduler.Task{
		{
			ID: "environment",
			Run: func(context.Context) scheduler.Result {
				system := collector.Collect(outputRoot)
				report = builder.New(reportID, startedAt, user, system)
				return scheduler.Result{Status: "success", Confidence: "medium", Message: "基础环境采集完成"}
			},
		},
		{
			ID: "performance",
			Run: func(ctx context.Context) scheduler.Result {
				if skipPerformance {
					return scheduler.Result{Status: "skipped", Confidence: "low", Message: "按参数跳过性能测试"}
				}
				outcome := benchmark.Run(ctx, outputRoot, &report.CPU, &report.Memory, &report.Disk)
				report.Warnings = append(report.Warnings, outcome.Warnings...)
				return scheduler.Result{Status: outcome.Status, Confidence: outcome.Confidence, Message: outcome.Message}
			},
		},
		{
			ID: "network_stack",
			Run: func(context.Context) scheduler.Result {
				netinfo.Collect(report.Network)
				return scheduler.Result{Status: "success", Confidence: "medium", Message: "本机网络栈采集完成"}
			},
		},
		{
			ID: "china_network",
			Run: func(ctx context.Context) scheduler.Result {
				if skipTCPQuality {
					return scheduler.Result{Status: "skipped", Confidence: "low", Message: "按参数跳过 TCP 质量探测"}
				}
				outcome := tcpquality.Run(ctx, tcpquality.Config{
					NodeURL: tcpNodeURL, ChinaPackets: tcpPackets,
					InternationalPackets: internetPackets, Concurrency: tcpConcurrency,
				}, report.Network)
				report.Warnings = append(report.Warnings, outcome.Warnings...)
				return scheduler.Result{Status: outcome.Status, Confidence: outcome.Confidence, Message: outcome.Message}
			},
		},
		{
			ID: "routes",
			Run: func(ctx context.Context) scheduler.Result {
				if skipRoutes {
					return scheduler.Result{Status: "skipped", Confidence: "low", Message: "按参数跳过回程线路"}
				}
				outcome := routes.Run(ctx, routes.Config{
					NodeURL: tcpNodeURL, Concurrency: 16,
				}, &report.Routes)
				routes.EnrichProvinceRows(report.Network, report.Routes)
				report.Warnings = append(report.Warnings, outcome.Warnings...)
				return scheduler.Result{Status: outcome.Status, Confidence: outcome.Confidence, Message: outcome.Message}
			},
		},
		{
			ID: "bandwidth",
			Run: func(ctx context.Context) scheduler.Result {
				if skipBandwidth {
					return scheduler.Result{Status: "skipped", Confidence: "low", Message: "按参数跳过三网单线程带宽"}
				}
				outcome := bandwidth.Run(ctx, bandwidth.DefaultConfig(tcpNodeURL), report.Network, report.Routes)
				report.Warnings = append(report.Warnings, outcome.Warnings...)
				return scheduler.Result{Status: outcome.Status, Confidence: outcome.Confidence, Message: outcome.Message}
			},
		},
		{
			ID: "ip_services",
			Run: func(ctx context.Context) scheduler.Result {
				outcome := ipservice.Run(ctx, &report.Environment, report.IPQuality, &report.Services, report.Network)
				report.Warnings = append(report.Warnings, outcome.Warnings...)
				return scheduler.Result{Status: outcome.Status, Confidence: outcome.Confidence, Message: outcome.Message}
			},
		},
	}, func(index, total int, id string) {
		fmt.Printf("\n[%d/%d] %s\n", index, total, moduleTitle(id))
		current := id
		_ = storage.WriteState(outputRoot, storage.State{
			ReportID: reportID, Status: "running", CurrentModule: &current,
			Completed: index - 1, Total: total,
		})
	})
	report.Modules = modules
	scoring.Apply(&report)
	report.Modules = append(report.Modules,
		model.Module{ID: "scoring", Status: "success", Confidence: "medium", Message: pointer("已按可用测评维度生成评分")},
	)
	applyStage3Completeness(&report)
	if workerURL != "" {
		report.Status = "completed"
	}
	builder.Finalize(&report)
	_ = storage.WriteState(outputRoot, storage.State{
		ReportID: reportID, Status: "completed_local", Completed: totalModules, Total: totalModules,
	})
	textReport := render.Text(report, reportURL)
	paths, err := storage.Write(outputRoot, report, credentials, textReport)
	if err != nil {
		return err
	}

	fmt.Println(textReport)
	fmt.Printf("JSON：%s\n文本：%s\n", paths.ReportJSON, paths.ReportText)
	if workerURL == "" {
		fmt.Println("未配置 --worker-url，本次只生成本地报告。")
		return nil
	}

	fmt.Println("正在执行最终单次上传……")
	uploadModule := "upload"
	_ = storage.WriteState(outputRoot, storage.State{
		ReportID: reportID, Status: "uploading", CurrentModule: &uploadModule,
		Completed: totalModules, Total: totalModules,
	})
	result, err := uploadWithRetry(context.Background(), workerURL, model.UploadEnvelope{
		Credentials: credentials,
		Report:      report,
	})
	if err != nil {
		report.Status = "completed_local_only"
		report.Warnings = append(report.Warnings, model.Warning{
			Code: "worker_upload_failed", Severity: "warning",
			Message: "最终上传失败，本地报告不受影响", Module: "upload",
		})
		textReport = render.Text(report, reportURL)
		if _, writeErr := storage.Write(outputRoot, report, credentials, textReport); writeErr != nil {
			return fmt.Errorf("上传失败（%v），且更新本地状态失败: %w", err, writeErr)
		}
		message := "最终上传失败，本地报告已保留"
		_ = storage.WriteState(outputRoot, storage.State{
			ReportID: reportID, Status: "upload_failed", Completed: totalModules,
			Total: totalModules, LastError: &message,
		})
		return fmt.Errorf("最终上传失败，本地报告已保留: %w", err)
	}

	credentials.UploadSecret = ""
	if _, err := storage.Write(outputRoot, report, credentials, textReport); err != nil {
		return fmt.Errorf("上传成功，但清理本地上传凭证失败: %w", err)
	}
	fmt.Printf("上传成功：%s（%s，到期 %s）\n", result.ReportID, result.Status, result.ExpiresAt)
	fmt.Printf("报告链接：%s\n", reportURL)
	_ = storage.WriteState(outputRoot, storage.State{
		ReportID: reportID, Status: "uploaded", Completed: totalModules, Total: totalModules,
	})
	return nil
}

func moduleTitle(id string) string {
	switch id {
	case "environment":
		return "采集基础环境"
	case "performance":
		return "执行 Sysbench/Fio 性能测试"
	case "network_stack":
		return "采集网络栈参数"
	case "china_network":
		return "执行三网与国际 TCP SYN 质量探测"
	case "routes":
		return "执行三网 TCP 回程线路识别"
	case "bandwidth":
		return "执行三网单线程带宽与流量预算"
	case "ip_services":
		return "检测 IP 属性、风险、服务解锁与邮件端口"
	case "upload":
		return "上传最终脱敏报告"
	default:
		return id
	}
}

func applyStage3Completeness(report *model.Report) {
	success, partial, failed := 0, 0, 0
	statuses := make(map[string]string, len(report.Modules))
	for _, module := range report.Modules {
		statuses[module.ID] = module.Status
		switch module.Status {
		case "success":
			success++
		case "partial":
			partial++
		case "failed":
			failed++
		}
	}

	ratio := 0.0
	missing := make([]string, 0, 7)
	if statuses["environment"] == "success" {
		ratio += 0.10
	} else {
		missing = append(missing, "environment")
	}
	if statuses["network_stack"] == "success" {
		ratio += 0.10
	} else {
		missing = append(missing, "network.stack")
	}
	if statuses["performance"] == "success" {
		ratio += 0.20
	} else {
		missing = append(missing, "performance")
	}
	if statuses["china_network"] == "success" {
		ratio += 0.15
	} else {
		missing = append(missing, "network.province_tcp")
	}
	if statuses["routes"] == "success" || statuses["routes"] == "partial" {
		ratio += 0.15
	} else {
		missing = append(missing, "routes")
	}
	switch statuses["bandwidth"] {
	case "success":
		ratio += 0.10
	case "partial":
		ratio += 0.05
		missing = append(missing, "network.bandwidth.partial")
	default:
		missing = append(missing, "network.bandwidth")
	}

	if ipQualityMeasured(report.IPQuality) {
		ratio += 0.10
	} else {
		missing = append(missing, "ip_quality")
	}
	measuredServices, totalServices := serviceMeasurementCount(report.Services)
	if totalServices > 0 {
		ratio += 0.10 * float64(measuredServices) / float64(totalServices)
	}
	if totalServices == 0 || measuredServices < totalServices {
		missing = append(missing, "services")
	}

	ratio = math.Round(math.Min(math.Max(ratio, 0), 1)*100) / 100
	report.Completeness = model.Completeness{
		Ratio: ratio, SuccessfulModules: success, PartialModules: partial,
		FailedModules: failed, MissingFields: missing,
	}
}

func ipQualityMeasured(quality map[string]any) bool {
	if quality["risk_score"] != nil {
		return true
	}
	ipType, _ := quality["ip_type"].(string)
	return ipType != "" && ipType != "unknown"
}

func serviceMeasurementCount(services []any) (int, int) {
	measured := 0
	for _, raw := range services {
		service, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if _, ok := service["available"].(bool); ok {
			measured++
		}
	}
	return measured, len(services)
}

func pointer(value string) *string {
	return &value
}

func readUserSupplied(reader *bufio.Reader) (model.UserSupplied, error) {
	result := model.UserSupplied{Unverified: true}
	enabled, err := askYesNo(reader, "是否填写 VPS 厂商和套餐信息？[y/N] ")
	if err != nil || !enabled {
		return result, err
	}
	result.Provider = readOptional(reader, "VPS 提供商：", 160)
	result.Plan = readOptional(reader, "套餐名称：", 160)
	amount := readOptional(reader, "请将费用换算成人民币月付后输入（如 35.00，回车跳过）：", 32)
	if amount != nil {
		minor, err := parseMinor(*amount)
		if err != nil {
			return result, err
		}
		monthly := minor
		result.Price = &model.Price{
			AmountMinor: minor, Currency: "CNY",
			BillingPeriod: "month", MonthlyEquivalentMinor: &monthly,
		}
	}
	result.AdvertisedBandwidth = readOptional(reader, "标称带宽：", 160)
	result.MonthlyTraffic = readOptional(reader, "每月流量：", 160)
	result.Datacenter = readOptional(reader, "机房或地区：", 160)
	result.PurchaseURL = readOptional(reader, "购买链接：", 512)
	fmt.Println("备注中请勿填写订单号、账户、密码、完整 IP 或 API 密钥。")
	result.Note = readOptional(reader, "其他备注：", 500)
	return result, nil
}

func askYesNo(reader *bufio.Reader, prompt string) (bool, error) {
	fmt.Print(prompt)
	value, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "y" || value == "yes", nil
}

func readOptional(reader *bufio.Reader, prompt string, limit int) *string {
	fmt.Print(prompt)
	value, err := reader.ReadString('\n')
	if err != nil {
		return nil
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	runes := []rune(value)
	if len(runes) > limit {
		value = string(runes[:limit])
	}
	return &value
}

func parseMinor(value string) (int64, error) {
	parts := strings.Split(strings.TrimSpace(value), ".")
	if len(parts) > 2 || parts[0] == "" {
		return 0, fmt.Errorf("价格格式无效")
	}
	whole, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || whole < 0 {
		return 0, fmt.Errorf("价格格式无效")
	}
	fraction := "00"
	if len(parts) == 2 {
		fraction = parts[1] + "00"
		fraction = fraction[:2]
	}
	cents, err := strconv.ParseInt(fraction, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("价格格式无效")
	}
	return whole*100 + cents, nil
}

func uploadWithRetry(ctx context.Context, workerURL string, envelope model.UploadEnvelope) (upload.Result, error) {
	delays := []time.Duration{0, 30 * time.Second, 2 * time.Minute}
	var lastErr error
	for attempt, delay := range delays {
		if delay > 0 {
			fmt.Printf("上传失败，%s 后重试（%d/%d）……\n", delay, attempt+1, len(delays))
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return upload.Result{}, ctx.Err()
			case <-timer.C:
			}
		}
		result, err := upload.Send(ctx, workerURL, envelope)
		if err == nil {
			return result, nil
		}
		lastErr = err
	}
	return upload.Result{}, lastErr
}
