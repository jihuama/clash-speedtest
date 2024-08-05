package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/adapter/provider"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"gopkg.in/yaml.v3"
)

var (
	livenessObject     = flag.String("l", "https://speed.cloudflare.com/__down?bytes=%d", "liveness object, support http(s) url, support payload too")
	configPathConfig   = flag.String("c", "", "configuration file path, also support http(s) url")
	filterRegexConfig  = flag.String("f", ".*", "filter proxies by name, use regexp")
	downloadSizeConfig = flag.Int("size", 1024*1024*100, "download size for testing proxies")
	timeoutConfig      = flag.Duration("timeout", time.Second*5, "timeout for testing proxies")
	sortField          = flag.String("sort", "b", "sort field for testing proxies, b for bandwidth, t for TTFB")
	output             = flag.String("output", "newclash.yaml", "output clash config file")
	concurrent         = flag.Int("concurrent", 4, "download concurrent size")
	configMap          = make(map[string]any)
	effective          = 0
)

type CProxy struct {
	C.Proxy
	SecretConfig any
}

type Result struct {
	Name      string
	Bandwidth float64
	TTFB      time.Duration
}

var (
	red   = "\033[31m"
	green = "\033[32m"
)

type RawConfig struct {
	Providers map[string]map[string]any `yaml:"proxy-providers"`
	Proxies   []map[string]any          `yaml:"proxies"`
}

func main() {
	flag.Parse()

	C.UA = "clash.meta"

	if *configPathConfig == "" {
		log.Fatalln("Please specify the configuration file")
	}
	var body []byte
	var body1 []byte
	var allProxies = make(map[string]CProxy)
	for _, configPath := range strings.Split(*configPathConfig, ",") {

		var err error
		if strings.HasPrefix(configPath, "http") {
			var resp *http.Response
			resp, err = http.Get(configPath)
			if err != nil {
				log.Fatalln("failed to fetch config: %s", err)

			}
			body1, err = io.ReadAll(resp.Body)
		} else {
			body1, err = os.ReadFile(configPath)
		}
		if err != nil {
			log.Fatalln("failed to read config: %s", err)

		}

		if err := yaml.Unmarshal(body1, &configMap); err != nil {
			log.Fatalln("fail to Unmarshal: %s", err)
		}
		body, err = yaml.Marshal(&configMap)

		if err != nil {
			log.Fatalln("Failed to Marshal : %s", err)
		}
		lps, err := loadProxies(body)
		if err != nil {
			log.Fatalln("Failed to convert : %s", err)
		}

		for k, p := range lps {
			if _, ok := allProxies[k]; !ok {
				allProxies[k] = p
			}
		}
	}

	heads := getHead(body)
	groups := getGroups(body)
	tails := getTail(body)

	filteredProxies := filterProxies(*filterRegexConfig, allProxies)
	results := make([]Result, 0, len(filteredProxies))

	format := "%s%-42s\t%-12s\t%-12s\033[0m\n"

	fmt.Printf(format, "", "节点", "带宽", "延迟")
	for _, name := range filteredProxies {
		proxy := allProxies[name]
		switch proxy.Type() {
		case C.Shadowsocks, C.ShadowsocksR, C.Snell, C.Socks5, C.Http, C.Vmess, C.Vless, C.Trojan, C.Hysteria, C.Hysteria2, C.WireGuard, C.Tuic:
			result := TestProxyConcurrent(name, proxy, *downloadSizeConfig, *timeoutConfig, *concurrent)
			result.Printf(format)
			results = append(results, *result)
		case C.Direct, C.Reject, C.Relay, C.Selector, C.Fallback, C.URLTest, C.LoadBalance:
			continue
		default:
			log.Fatalln("Unsupported proxy type: %s", proxy.Type())
		}
	}

	if *sortField != "" {
		switch *sortField {
		case "b", "bandwidth":
			sort.Slice(results, func(i, j int) bool {
				return results[i].Bandwidth > results[j].Bandwidth
			})
			fmt.Println("\n\n------------------------结果按照带宽排序------------------------")
		case "t", "ttfb":
			sort.Slice(results, func(i, j int) bool {
				return results[i].TTFB < results[j].TTFB
			})
			fmt.Println("\n\n------------------------结果按照延迟排序------------------------")
		default:
			log.Fatalln("Unsupported sort field: %s", *sortField)
		}
		fmt.Printf(format, "", "节点", "带宽", "延迟")
		for _, result := range results {
			result.Printf(format)
		}
	}

	Sorts, Unsorts, err := writeNodeConfigurationToYAML(results, allProxies)
	if err != nil {
		log.Fatalln("Failed to analyse yaml: %s", err)
	}

	naproxys := b2s(Unsorts)
	newgroups := delDuplicate(groups, naproxys)
	newgroups1 := addReject(newgroups)
	genNewfile(*output, heads, Sorts, newgroups1, tails)
	fmt.Printf("\nTest finished, there are %d effective nodes!\n", effective)
	fmt.Printf("Output clash config file is %s.\n", *output)
}

func filterProxies(filter string, proxies map[string]CProxy) []string {
	filterRegexp := regexp.MustCompile(filter)
	filteredProxies := make([]string, 0, len(proxies))
	for name := range proxies {
		if filterRegexp.MatchString(name) {
			filteredProxies = append(filteredProxies, name)
		}
	}
	sort.Strings(filteredProxies)
	return filteredProxies
}

func loadProxies(buf []byte) (map[string]CProxy, error) {
	rawCfg := &RawConfig{
		Proxies: []map[string]any{},
	}
	if err := yaml.Unmarshal(buf, rawCfg); err != nil {
		return nil, err
	}
	proxies := make(map[string]CProxy)
	proxiesConfig := rawCfg.Proxies
	providersConfig := rawCfg.Providers

	for i, config := range proxiesConfig {
		proxy, err := adapter.ParseProxy(config)
		if err != nil {
			return nil, fmt.Errorf("proxy %d: %w", i, err)
		}

		if _, exist := proxies[proxy.Name()]; exist {
			return nil, fmt.Errorf("proxy %s is the duplicate name", proxy.Name())
		}
		proxies[proxy.Name()] = CProxy{Proxy: proxy, SecretConfig: config}
	}
	for name, config := range providersConfig {
		if name == provider.ReservedName {
			return nil, fmt.Errorf("can not defined a provider called `%s`", provider.ReservedName)
		}
		pd, err := provider.ParseProxyProvider(name, config)
		if err != nil {
			return nil, fmt.Errorf("parse proxy provider %s error: %w", name, err)
		}
		if err := pd.Initial(); err != nil {
			return nil, fmt.Errorf("initial proxy provider %s error: %w", pd.Name(), err)
		}
		for _, proxy := range pd.Proxies() {
			proxies[fmt.Sprintf("[%s] %s", name, proxy.Name())] = CProxy{Proxy: proxy}
		}
	}
	return proxies, nil
}

func (r *Result) Printf(format string) {
	color := ""
	if r.Bandwidth < 1024*1024 {
		color = red
	} else if r.Bandwidth > 1024*1024*10 {
		color = green
	}
	fmt.Printf(format, color, r.Name, formatBandwidth(r.Bandwidth), formatMilliseconds(r.TTFB))
}

func TestProxyConcurrent(name string, proxy C.Proxy, downloadSize int, timeout time.Duration, concurrentCount int) *Result {
	if concurrentCount <= 0 {
		concurrentCount = 1
	}

	chunkSize := downloadSize / concurrentCount
	totalTTFB := int64(0)
	downloaded := int64(0)

	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < concurrentCount; i++ {
		wg.Add(1)
		go func(i int) {
			result, w := TestProxy(name, proxy, chunkSize, timeout)
			if w != 0 {
				atomic.AddInt64(&downloaded, w)
				atomic.AddInt64(&totalTTFB, int64(result.TTFB))
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
	downloadTime := time.Since(start)

	result := &Result{
		Name:      name,
		Bandwidth: float64(downloaded) / downloadTime.Seconds(),
		TTFB:      time.Duration(totalTTFB / int64(concurrentCount)),
	}

	return result
}

func TestProxy(name string, proxy C.Proxy, downloadSize int, timeout time.Duration) (*Result, int64) {
	client := http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				var u16Port uint16
				if port, err := strconv.ParseUint(port, 10, 16); err == nil {
					u16Port = uint16(port)
				}
				return proxy.DialContext(ctx, &C.Metadata{
					Host:    host,
					DstPort: u16Port,
				})
			},
		},
	}

	start := time.Now()
	resp, err := client.Get(fmt.Sprintf(*livenessObject, downloadSize))
	if err != nil {
		return &Result{name, -1, -1}, 0
	}
	defer resp.Body.Close()
	if resp.StatusCode-http.StatusOK > 100 {
		return &Result{name, -1, -1}, 0
	}
	ttfb := time.Since(start)

	written, _ := io.Copy(io.Discard, resp.Body)
	if written == 0 {
		return &Result{name, -1, -1}, 0
	}
	downloadTime := time.Since(start) - ttfb
	bandwidth := float64(written) / downloadTime.Seconds()

	return &Result{name, bandwidth, ttfb}, written
}

func formatBandwidth(v float64) string {
	if v <= 0 {
		return "N/A"
	}
	if v < 1024 {
		return fmt.Sprintf("%.02fB/s", v)
	}
	v /= 1024
	if v < 1024 {
		return fmt.Sprintf("%.02fKB/s", v)
	}
	v /= 1024
	if v < 1024 {
		return fmt.Sprintf("%.02fMB/s", v)
	}
	v /= 1024
	if v < 1024 {
		return fmt.Sprintf("%.02fGB/s", v)
	}
	v /= 1024
	return fmt.Sprintf("%.02fTB/s", v)
}

func formatMilliseconds(v time.Duration) string {
	if v <= 0 {
		return "N/A"
	}
	return fmt.Sprintf("%.02fms", float64(v.Milliseconds()))
}

func writeNodeConfigurationToYAML(results []Result, proxies map[string]CProxy) ([]byte, []byte, error) {

	var sortedProxies []any
	var unsortedProxies []any

	for _, result := range results {
		if v, ok := proxies[result.Name]; ok {
			if result.TTFB > 0 {
				sortedProxies = append(sortedProxies, v.SecretConfig)
				effective++
			} else {
				unsortedProxies = append(unsortedProxies, result.Name)
			}
		}
	}

	bytes, _ := yaml.Marshal(sortedProxies)

	bytes1, err := yaml.Marshal(unsortedProxies)

	return bytes, bytes1, err
}

func delDuplicate(buf1 []string, buf2 []string) []string {

	filteredLines := make([]string, 0, len(buf1))
	for _, line1 := range buf1 {
		if !stringInSlice(line1, buf2) {
			filteredLines = append(filteredLines, line1)
		}
	}
	return filteredLines

}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if strings.TrimSpace(a) == strings.TrimSpace(b) {
			return true
		}
	}
	return false
}
func addReject(buf []string) []string {

	filteredLines := make([]string, 0, len(buf)+10)
	for i, line1 := range buf {
		filteredLines = append(filteredLines, line1)
		if strings.TrimSpace(line1) == "proxies:" {
			if strings.TrimSpace(buf[i+1]) == "tolerance: 20" || strings.TrimSpace(buf[i+1]) == "type: select" {
				filteredLines = append(filteredLines, "        - REJECT")
			}
		}
	}
	return filteredLines
}

func getHead(buf []byte) []string {
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(string(buf)))
	// 设置扫描器的分隔函数为ScanLines（按行扫描）
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if strings.TrimSpace(string(scanner.Text())) == "proxies:" {
			break
		}
	}
	return lines
}
func getGroups(buf []byte) []string {
	var lines []string
	flag := 0
	scanner := bufio.NewScanner(strings.NewReader(string(buf)))
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {

		if strings.TrimSpace(string(scanner.Text())) == "proxy-groups:" {
			flag = 1
			lines = append(lines, scanner.Text())
			continue
		}
		if flag == 1 {
			if strings.TrimSpace(string(scanner.Text())) == "rules:" {
				break
			}
			lines = append(lines, scanner.Text())
		}

	}
	return lines
}
func getTail(buf []byte) []string {
	var lines []string
	flag := false
	scanner := bufio.NewScanner(strings.NewReader(string(buf)))
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {

		if strings.TrimSpace(string(scanner.Text())) == "rules:" {
			flag = true
		}
		if flag {
			lines = append(lines, scanner.Text())
		}

	}
	return lines
}

// []byte转string
func b2s(b []byte) []string {
	str := string(b)
	strSlice := strings.Split(str, "\n")
	return strSlice

}
func genNewfile(file string, heads []string, Sorts []byte, newgroups1 []string, tails []string) error {
	fp, err := os.Create(file)
	if err != nil {
		return err
	}
	defer fp.Close()

	err = strWritefile(fp, heads)
	if err != nil {
		return err
	}

	_, err = fp.Write(Sorts)
	if err != nil {
		return err
	}
	err = strWritefile(fp, newgroups1)
	if err != nil {
		return err
	}

	err = strWritefile(fp, tails)
	if err != nil {
		return err
	}

	return nil
}
func strWritefile(fp *os.File, buf []string) error {
	for _, str := range buf {
		_, err := fp.WriteString(str + "\n")
		if err != nil {
			return err
		}
	}
	return nil
}
