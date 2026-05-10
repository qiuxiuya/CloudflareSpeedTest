package task

import (
	"bufio"
	"encoding/json"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const defaultInputFile = "ip.txt"

var (
	// TestAll test all ip
	TestAll = false
	// IPFile is the filename of IP Rangs
	IPFile = defaultInputFile
	IPText string
	// MasscanFile is the filename of masscan JSON output
	MasscanFile string
	// TCPPortSet 标记用户是否显式指定了 -tp 参数
	TCPPortSet = false
	// IPPortMap 存储每个 IPAddr 指针对应的端口（masscan 模式下使用）
	IPPortMap = make(map[*net.IPAddr]int)
)

// masscan JSON 输出的数据结构
type masscanEntry struct {
	IP    string `json:"ip"`
	Ports []struct {
		Port   int    `json:"port"`
		Proto  string `json:"proto"`
		Status string `json:"status"`
	} `json:"ports"`
}

// GetPort 获取指定 IP 对应的端口，优先从 IPPortMap 中查找，找不到则返回全局 TCPPort
func GetPort(ip *net.IPAddr) int {
	if port, ok := IPPortMap[ip]; ok {
		return port
	}
	return TCPPort
}

func InitRandSeed() {
	rand.Seed(time.Now().UnixNano())
}

func isIPv4(ip string) bool {
	return strings.Contains(ip, ".")
}

func randIPEndWith(num byte) byte {
	if num == 0 { // 对于 /32 这种单独的 IP
		return byte(0)
	}
	return byte(rand.Intn(int(num)))
}

type IPRanges struct {
	ips     []*net.IPAddr
	mask    string
	firstIP net.IP
	ipNet   *net.IPNet
}

func newIPRanges() *IPRanges {
	return &IPRanges{
		ips: make([]*net.IPAddr, 0),
	}
}

// 如果是单独 IP 则加上子网掩码，反之则获取子网掩码(r.mask)
func (r *IPRanges) fixIP(ip string) string {
	// 如果不含有 '/' 则代表不是 IP 段，而是一个单独的 IP，因此需要加上 /32 /128 子网掩码
	if i := strings.IndexByte(ip, '/'); i < 0 {
		if isIPv4(ip) {
			r.mask = "/32"
		} else {
			r.mask = "/128"
		}
		ip += r.mask
	} else {
		r.mask = ip[i:]
	}
	return ip
}

// 解析 IP 段，获得 IP、IP 范围、子网掩码
func (r *IPRanges) parseCIDR(ip string) {
	var err error
	if r.firstIP, r.ipNet, err = net.ParseCIDR(r.fixIP(ip)); err != nil {
		log.Fatalln("ParseCIDR err", err)
	}
}

func (r *IPRanges) appendIPv4(d byte) {
	r.appendIP(net.IPv4(r.firstIP[12], r.firstIP[13], r.firstIP[14], d))
}

func (r *IPRanges) appendIP(ip net.IP) {
	r.ips = append(r.ips, &net.IPAddr{IP: ip})
}

// 返回第四段 ip 的最小值及可用数目
func (r *IPRanges) getIPRange() (minIP, hosts byte) {
	minIP = r.firstIP[15] & r.ipNet.Mask[3] // IP 第四段最小值

	// 根据子网掩码获取主机数量
	m := net.IPv4Mask(255, 255, 255, 255)
	for i, v := range r.ipNet.Mask {
		m[i] ^= v
	}
	total, _ := strconv.ParseInt(m.String(), 16, 32) // 总可用 IP 数
	if total > 255 {                                 // 矫正 第四段 可用 IP 数
		hosts = 255
		return
	}
	hosts = byte(total)
	return
}

func (r *IPRanges) chooseIPv4() {
	if r.mask == "/32" { // 单个 IP 则无需随机，直接加入自身即可
		r.appendIP(r.firstIP)
	} else {
		minIP, hosts := r.getIPRange()    // 返回第四段 IP 的最小值及可用数目
		for r.ipNet.Contains(r.firstIP) { // 只要该 IP 没有超出 IP 网段范围，就继续循环随机
			if TestAll { // 如果是测速全部 IP
				for i := 0; i <= int(hosts); i++ { // 遍历 IP 最后一段最小值到最大值
					r.appendIPv4(byte(i) + minIP)
				}
			} else { // 随机 IP 的最后一段 0.0.0.X
				r.appendIPv4(minIP + randIPEndWith(hosts))
			}
			r.firstIP[14]++ // 0.0.(X+1).X
			if r.firstIP[14] == 0 {
				r.firstIP[13]++ // 0.(X+1).X.X
				if r.firstIP[13] == 0 {
					r.firstIP[12]++ // (X+1).X.X.X
				}
			}
		}
	}
}

func (r *IPRanges) chooseIPv6() {
	if r.mask == "/128" { // 单个 IP 则无需随机，直接加入自身即可
		r.appendIP(r.firstIP)
	} else {
		var tempIP uint8                  // 临时变量，用于记录前一位的值
		for r.ipNet.Contains(r.firstIP) { // 只要该 IP 没有超出 IP 网段范围，就继续循环随机
			r.firstIP[15] = randIPEndWith(255) // 随机 IP 的最后一段
			r.firstIP[14] = randIPEndWith(255) // 随机 IP 的最后一段

			targetIP := make([]byte, len(r.firstIP))
			copy(targetIP, r.firstIP)
			r.appendIP(targetIP) // 加入 IP 地址池

			for i := 13; i >= 0; i-- { // 从倒数第三位开始往前随机
				tempIP = r.firstIP[i]              // 保存前一位的值
				r.firstIP[i] += randIPEndWith(255) // 随机 0~255，加到当前位上
				if r.firstIP[i] >= tempIP {        // 如果当前位的值大于等于前一位的值，说明随机成功了，可以退出该循环
					break
				}
			}
		}
	}
}

// loadMasscanJSON 从 masscan JSON 文件加载 IP 和端口数据
func loadMasscanJSON() []*net.IPAddr {
	file, err := os.ReadFile(MasscanFile)
	if err != nil {
		log.Fatalf("读取 masscan JSON 文件 [%s] 失败：%v", MasscanFile, err)
	}

	// masscan -oJ 输出的 JSON 可能末尾带有 "finished" 行，需要清理
	content := strings.TrimSpace(string(file))
	// 移除可能存在的结尾 "finished" 行（masscan -oJ 的标准输出格式）
	if idx := strings.LastIndex(content, "\n{"); idx != -1 {
		lastLine := strings.TrimSpace(content[idx:])
		if strings.Contains(lastLine, "\"finished\"") {
			content = strings.TrimSpace(content[:idx])
		}
	}
	// 确保内容被 [] 包裹
	if !strings.HasPrefix(content, "[") {
		content = "[" + content + "]"
	}
	// 移除末尾多余的逗号（JSON 不允许 trailing comma）
	content = strings.TrimRight(strings.TrimSpace(content), ",")
	// 如果移除逗号后不是以 ] 结尾，补上
	if !strings.HasSuffix(strings.TrimSpace(content), "]") {
		content = content + "]"
	}

	var entries []masscanEntry
	if err := json.Unmarshal([]byte(content), &entries); err != nil {
		log.Fatalf("解析 masscan JSON 文件 [%s] 失败：%v", MasscanFile, err)
	}

	if TCPPortSet {
		// 用户指定了 -tp 端口，对 IP 去重后使用全局端口
		seen := make(map[string]bool)
		ips := make([]*net.IPAddr, 0)
		for _, entry := range entries {
			ip := strings.TrimSpace(entry.IP)
			if ip == "" || seen[ip] {
				continue
			}
			seen[ip] = true
			parsedIP := net.ParseIP(ip)
			if parsedIP == nil {
				log.Printf("[警告] 无法解析 IP: %s，跳过", ip)
				continue
			}
			ips = append(ips, &net.IPAddr{IP: parsedIP})
		}
		return ips
	}

	// 未指定 -tp，使用 JSON 中每个 IP:端口 组合，同一 IP 不同端口视为不同测试目标
	seen := make(map[string]bool) // 用 "ip:port" 去重
	ips := make([]*net.IPAddr, 0)
	for _, entry := range entries {
		ip := strings.TrimSpace(entry.IP)
		if ip == "" {
			continue
		}
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			log.Printf("[警告] 无法解析 IP: %s，跳过", ip)
			continue
		}
		for _, port := range entry.Ports {
			key := ip + ":" + strconv.Itoa(port.Port)
			if seen[key] {
				continue // 跳过重复的 IP:端口 组合
			}
			seen[key] = true
			// 每个 IP:端口 组合创建独立的 IPAddr 实例
			targetIP := make(net.IP, len(parsedIP))
			copy(targetIP, parsedIP)
			ipAddr := &net.IPAddr{IP: targetIP}
			IPPortMap[ipAddr] = port.Port // 通过指针地址映射端口
			ips = append(ips, ipAddr)
		}
	}
	return ips
}

func loadIPRanges() []*net.IPAddr {
	// 优先处理 masscan JSON 文件
	if MasscanFile != "" {
		return loadMasscanJSON()
	}

	ranges := newIPRanges()
	if IPText != "" { // 从参数中获取 IP 段数据
		IPs := strings.Split(IPText, ",") // 以逗号分隔为数组并循环遍历
		for _, IP := range IPs {
			IP = strings.TrimSpace(IP) // 去除首尾的空白字符（空格、制表符、换行符等）
			if IP == "" {              // 跳过空的（即开头、结尾或连续多个 ,, 的情况）
				continue
			}
			ranges.parseCIDR(IP) // 解析 IP 段，获得 IP、IP 范围、子网掩码
			if isIPv4(IP) {      // 生成要测速的所有 IPv4 / IPv6 地址（单个/随机/全部）
				ranges.chooseIPv4()
			} else {
				ranges.chooseIPv6()
			}
		}
	} else { // 从文件中获取 IP 段数据
		if IPFile == "" {
			IPFile = defaultInputFile
		}
		file, err := os.Open(IPFile)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() { // 循环遍历文件每一行
			line := strings.TrimSpace(scanner.Text()) // 去除首尾的空白字符（空格、制表符、换行符等）
			if line == "" {                           // 跳过空行
				continue
			}
			ranges.parseCIDR(line) // 解析 IP 段，获得 IP、IP 范围、子网掩码
			if isIPv4(line) {      // 生成要测速的所有 IPv4 / IPv6 地址（单个/随机/全部）
				ranges.chooseIPv4()
			} else {
				ranges.chooseIPv6()
			}
		}
	}
	return ranges.ips
}
