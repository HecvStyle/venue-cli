package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// --------------- 配置 ---------------

const defaultAPIBase = "https://wangcheng.culturalcloud.net"

var (
	apiBase  string
	token    string // 生效 token, authGet/authPost 读取
	envToken string // 启动时捕获的 VENUE_TOKEN; 非空则整会话覆盖
	cfg      *Config
	client   = &http.Client{Timeout: 15 * time.Second}
	reader   = bufio.NewReader(os.Stdin)
)

// --------------- 数据结构 ---------------

type PageResp[T any] struct {
	Code int `json:"code"`
	Data struct {
		Records []T   `json:"records"`
		Total   int64 `json:"total"`
	} `json:"data"`
	Msg string `json:"msg"`
}

type SingleResp[T any] struct {
	Code int    `json:"code"`
	Data T      `json:"data"`
	Msg  string `json:"msg"`
}

type Venue struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Address  string `json:"address"`
	Type     int    `json:"type"`
	Category string `json:"category"`
}

type VenueSpaceGroup struct {
	ID             string       `json:"id"`
	Name           string       `json:"name"`
	VenueSpaceList []VenueSpace `json:"venueSpaceList"`
}

type VenueSpace struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type VenueSpaceDetail struct {
	ID              string        `json:"id"`
	Name            string        `json:"name"`
	BookingDateList []BookingDate `json:"bookingDateList"`
}

type BookingDate struct {
	Date         string     `json:"date"`
	TimeSlotList []TimeSlot `json:"timeSlotList"`
}

type TimeSlot struct {
	ID               string `json:"id"`
	StartTime        string `json:"startTime"`
	EndTime          string `json:"endTime"`
	Quota            int    `json:"quota"`
	TotalQuota       int    `json:"totalQuota"`
	BookingStatus    int    `json:"bookingStatus"`
	UnbookableReason string `json:"unbookableReason"`
}

type BookingResult struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

type DictItem struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// Account 一个已保存的登录账号, Phone 为唯一键
type Account struct {
	Phone      string `json:"phone"` // 11 位手机号, 或 legacyPhoneKey
	Token      string `json:"token"`
	CreatedAt  string `json:"created_at"`             // time.RFC3339
	LastUsedAt string `json:"last_used_at,omitempty"` // time.RFC3339, 登录/切换时更新
}

// Config ~/.venue-cli/config.json 的根结构
type Config struct {
	Current  string    `json:"current"` // 当前账号的 Phone; "" = 无
	Accounts []Account `json:"accounts"`
}

// --------------- 账号配置持久化 ---------------

const (
	legacyPhoneKey  = "__legacy__"       // 迁移导入的旧 token 无手机号
	legacyTokenName = ".venue-cli-token" // 旧版文件名 (cwd 与 home 同名)
)

func tokenFilePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, legacyTokenName)
}

func configFilePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".venue-cli", "config.json")
}

func nowRFC3339() string {
	return time.Now().Format(time.RFC3339)
}

func formatTimeRFC3339(s string) string {
	if s == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.Format("2006-01-02 15:04")
}

func maskPhone(phone string) string {
	if len(phone) != 11 {
		return phone
	}
	return phone[:3] + "****" + phone[7:]
}

func accountLabel(phone string) string {
	switch phone {
	case legacyPhoneKey:
		return "默认账号(旧token迁移)"
	case "":
		return "无"
	}
	return maskPhone(phone)
}

// readLegacyToken 读取旧版单 token 文件, cwd 优先 (与旧 loadToken 顺序一致)
func readLegacyToken() string {
	for _, p := range []string{legacyTokenName, tokenFilePath()} {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if t := strings.TrimSpace(string(data)); t != "" {
			return t
		}
	}
	return ""
}

func saveConfig(c *Config) error {
	if err := os.MkdirAll(filepath.Dir(configFilePath()), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFilePath(), data, 0600)
}

// loadConfig 加载多账号配置; 仅当配置文件不存在时执行一次性旧 token 迁移
func loadConfig() *Config {
	c := &Config{}
	path := configFilePath()

	data, err := os.ReadFile(path)
	if err == nil {
		if json.Unmarshal(data, c) == nil {
			return c
		}
		// 损坏: 备份后从零开始 (文件存在过, 不再迁移)
		fmt.Printf("  ⚠ 配置文件损坏, 已备份为 %s.bak\n", path)
		if renErr := os.Rename(path, path+".bak"); renErr != nil {
			fmt.Printf("  ⚠ 备份失败: %v\n", renErr)
		}
		return c
	}
	if !os.IsNotExist(err) {
		fmt.Printf("  ⚠ 读取配置失败: %v\n", err)
		return c
	}

	// 配置文件不存在 → 尝试一次性迁移旧版单 token 文件
	tok := readLegacyToken()
	if tok == "" {
		return c
	}
	c.Accounts = []Account{{Phone: legacyPhoneKey, Token: tok, CreatedAt: nowRFC3339()}}
	c.Current = legacyPhoneKey
	if err := saveConfig(c); err != nil {
		fmt.Printf("  ⚠ 迁移保存失败(本会话仍可用): %v\n", err)
	} else {
		fmt.Println("  ✓ 已迁移旧版 token 为「默认账号」，原文件已保留")
	}
	return c
}

func currentAccount(c *Config) *Account {
	for i := range c.Accounts {
		if c.Accounts[i].Phone == c.Current {
			return &c.Accounts[i]
		}
	}
	return nil
}

// upsertAccount 保存账号; 同手机号已存在则原地刷新 token (保留 CreatedAt)
func upsertAccount(c *Config, phone, tok string) {
	for i := range c.Accounts {
		if c.Accounts[i].Phone == phone {
			c.Accounts[i].Token = tok
			return
		}
	}
	c.Accounts = append(c.Accounts, Account{Phone: phone, Token: tok, CreatedAt: nowRFC3339()})
}

func removeAccount(c *Config, phone string) {
	for i := range c.Accounts {
		if c.Accounts[i].Phone == phone {
			c.Accounts = append(c.Accounts[:i], c.Accounts[i+1:]...)
			return
		}
	}
}

// --------------- HTTP 工具 ---------------

// publicGet 请求公开接口（不带 Authorization）
func publicGet(path string, result any) error {
	req, err := http.NewRequest("GET", apiBase+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, result)
}

// authGet 请求需认证接口
func authGet(path string, result any) error {
	req, err := http.NewRequest("GET", apiBase+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, result)
}

// authPost 请求需认证的 POST 接口（支持加密）
func authPost(path string, payload any, result any, encrypted bool) error {
	var bodyData []byte
	var err error

	if encrypted {
		enc, encErr := encryptBody(payload)
		if encErr != nil {
			return fmt.Errorf("加密失败: %w", encErr)
		}
		bodyData, err = json.Marshal(enc)
	} else {
		bodyData, err = json.Marshal(payload)
	}
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", apiBase+path, bytes.NewReader(bodyData))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, result)
}

func apiPostForm(path string, headers map[string]string, result any) error {
	req, err := http.NewRequest("POST", apiBase+path, strings.NewReader(""))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, result)
}

// --------------- 加密工具 ---------------

const (
	aesKey  = "5g2DrdihwadUI5Ee"
	hmacKey = "27a4262999804b733bd5b338ac0879485e64a2e90c511052fd20508e5575d2a5"
)

// aesCfbEncryptBase64 使用 AES-128-CFB 加密并返回 base64
func aesCfbEncryptBase64(plaintext []byte, key string) string {
	keyBytes := []byte(key)
	block, _ := aes.NewCipher(keyBytes)
	iv := make([]byte, aes.BlockSize)
	copy(iv, keyBytes)

	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)

	return base64.StdEncoding.EncodeToString(ciphertext)
}

// hmacSha256Hex 计算 HMAC-SHA256 并返回 hex 字符串
func hmacSha256Hex(message, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

// encryptBody 加密请求体，返回加密后的结构
func encryptBody(data any) (map[string]any, error) {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	encrypted := aesCfbEncryptBase64(jsonBytes, aesKey)
	timestamp := time.Now().UnixMilli()
	nonce := fmt.Sprintf("%s%s%s",
		strconv.FormatInt(time.Now().UnixMilli(), 36),
		randString(8),
		randString(8))
	sign := hmacSha256Hex(fmt.Sprintf("%d.%s.%s", timestamp, nonce, encrypted), hmacKey)

	return map[string]any{
		"data":      encrypted,
		"timestamp": timestamp,
		"nonce":     nonce,
		"sign":      sign,
	}, nil
}

func randString(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

// --------------- 交互工具 ---------------

func prompt(msg string) string {
	fmt.Print(msg)
	text, err := reader.ReadString('\n')
	text = strings.TrimSpace(text)
	if err != nil && text == "" {
		// stdin 关闭/输入结束: 直接退出, 避免菜单循环空转
		fmt.Println("\n输入结束，退出")
		os.Exit(0)
	}
	return text
}

func promptInt(msg string) (int, error) {
	s := prompt(msg)
	return strconv.Atoi(s)
}

func printLine() {
	fmt.Println(strings.Repeat("─", 50))
}

// --------------- 登录 ---------------

func sendSmsCode(phone string) error {
	var resp struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	req, err := http.NewRequest("GET", apiBase+"/admin/mobile/"+phone, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Basic YXBwOmFwcA==")

	r, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("请求失败: %w", err)
	}
	defer r.Body.Close()

	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("响应解析失败: %s", string(body))
	}
	if resp.Code != 0 {
		return fmt.Errorf("%s", resp.Msg)
	}
	return nil
}

func loginByMobile(phone, smsCode string) (string, error) {
	params := url.Values{
		"code":       {smsCode},
		"grant_type": {"mobile"},
		"scope":      {"server"},
		"mobile":     {phone},
	}

	var resp struct {
		Code        int    `json:"code"`
		AccessToken string `json:"access_token"`
		Msg         string `json:"msg"`
	}

	err := apiPostForm("/admin/oauth2/token?"+params.Encode(),
		map[string]string{
			"Authorization": "Basic YXBwOmFwcA==",
		}, &resp)
	if err != nil {
		return "", err
	}
	if resp.Code == 1 {
		return "", fmt.Errorf("%s", resp.Msg)
	}
	if resp.AccessToken == "" {
		return "", fmt.Errorf("登录失败: 未返回 token (msg: %s)", resp.Msg)
	}
	return resp.AccessToken, nil
}

func doLogin() {
	fmt.Println("\n── 手机号登录 ──")

	phone := prompt("  手机号: ")
	if len(phone) != 11 {
		fmt.Println("  ✗ 手机号格式错误")
		return
	}

	fmt.Printf("  正在发送验证码到 %s ...\n", phone)
	if err := sendSmsCode(phone); err != nil {
		fmt.Printf("  ✗ 发送失败: %v\n", err)
		return
	}
	fmt.Println("  ✓ 验证码已发送")

	smsCode := prompt("  输入验证码: ")
	if smsCode == "" {
		fmt.Println("  ✗ 验证码不能为空")
		return
	}

	fmt.Println("  登录中...")
	t, err := loginByMobile(phone, smsCode)
	if err != nil {
		fmt.Printf("  ✗ 登录失败: %v\n", err)
		return
	}

	upsertAccount(cfg, phone, t)
	cfg.Current = phone
	if err := saveConfig(cfg); err != nil {
		fmt.Printf("  ⚠ 保存配置失败: %v\n", err)
	}
	if envToken != "" {
		fmt.Println("  ✓ 登录成功! 账号已保存; VENUE_TOKEN 覆盖中，本会话仍使用环境变量 token")
		return
	}
	token = t
	fmt.Printf("  ✓ 登录成功! 当前账号: %s\n", accountLabel(phone))
}

// --------------- 业务逻辑 ---------------

func selectCategory() string {
	var resp struct {
		Code int        `json:"code"`
		Data []DictItem `json:"data"`
	}
	if err := publicGet("/admin/api/front/dict/details?dictType=venue_category", &resp); err != nil {
		fmt.Printf("  获取分类失败: %v\n", err)
		return ""
	}
	if len(resp.Data) == 0 {
		return ""
	}

	fmt.Println("\n  场馆类型:")
	fmt.Println("  0. 全部")
	for i, item := range resp.Data {
		fmt.Printf("  %d. %s\n", i+1, item.Label)
	}

	choice, err := promptInt("\n  选择类型 [0]: ")
	if err != nil || choice < 0 || choice > len(resp.Data) {
		choice = 0
	}
	if choice == 0 {
		return ""
	}
	return resp.Data[choice-1].Value
}

func selectVenue(category string) *Venue {
	page := 1
	for {
		path := fmt.Sprintf("/admin/api/front/venue/page?current=%d&size=20&type=1", page)
		if category != "" {
			path += "&category=" + category
		}

		var resp PageResp[Venue]
		if err := publicGet(path, &resp); err != nil {
			fmt.Printf("  获取场馆列表失败: %v\n", err)
			return nil
		}

		venues := resp.Data.Records
		if len(venues) == 0 {
			if page == 1 {
				fmt.Println("  没有找到可预约的场馆")
			}
			return nil
		}

		fmt.Println("\n  可预约场馆:")
		for i, v := range venues {
			mark := " "
			if v.Type == 2 {
				mark = "○"
			}
			fmt.Printf("  %d. [%s] %s\n     %s\n", i+1, mark, v.Name, v.Address)
		}
		totalPages := int(resp.Data.Total+19) / 20
		fmt.Printf("\n  第 %d/%d 页, 共 %d 个场馆\n", page, totalPages, resp.Data.Total)

		input := prompt("  选择场馆编号 (n=下一页, p=上一页, q=退出): ")
		switch input {
		case "q", "Q":
			return nil
		case "n", "N":
			if page < totalPages {
				page++
			} else {
				fmt.Println("  已经是最后一页")
			}
		case "p", "P":
			if page > 1 {
				page--
			}
		default:
			choice, err := strconv.Atoi(input)
			if err == nil && choice >= 1 && choice <= len(venues) {
				return &venues[choice-1]
			}
			fmt.Println("  无效输入")
		}
	}
}

func selectSpace(venueID string) *VenueSpaceDetail {
	path := fmt.Sprintf("/admin/api/front/venueSpace/group/list?venueId=%s", venueID)
	var resp struct {
		Code int               `json:"code"`
		Data []VenueSpaceGroup `json:"data"`
	}
	if err := publicGet(path, &resp); err != nil {
		fmt.Printf("  获取场地列表失败: %v\n", err)
		return nil
	}

	var spaces []VenueSpace
	var labels []string
	for _, g := range resp.Data {
		for _, s := range g.VenueSpaceList {
			spaces = append(spaces, s)
			labels = append(labels, g.Name+" - "+s.Name)
		}
	}

	if len(spaces) == 0 {
		fmt.Println("  该场馆下没有可用场地")
		return nil
	}

	fmt.Println("\n  可用场地:")
	for i, l := range labels {
		fmt.Printf("  %d. %s\n", i+1, l)
	}

	choice, err := promptInt("\n  选择场地: ")
	if err != nil || choice < 1 || choice > len(spaces) {
		fmt.Println("  无效选择")
		return nil
	}

	selected := spaces[choice-1]

	var detailResp SingleResp[VenueSpaceDetail]
	detailPath := fmt.Sprintf("/admin/api/front/venueSpace/detail/%s", selected.ID)
	if err := publicGet(detailPath, &detailResp); err != nil {
		fmt.Printf("  获取场地详情失败: %v\n", err)
		return nil
	}
	return &detailResp.Data
}

func weekDay(dateStr string) string {
	t, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return ""
	}
	weekdays := []string{"周日", "周一", "周二", "周三", "周四", "周五", "周六"}
	wd := weekdays[t.Weekday()]

	now := time.Now()
	today := now.Format("2006-01-02")
	tomorrow := now.AddDate(0, 0, 1).Format("2006-01-02")
	if dateStr == today {
		return "今天"
	}
	if dateStr == tomorrow {
		return "明天"
	}
	return wd
}

func selectDateAndSlots(detail *VenueSpaceDetail) ([]string, string, string, error) {
	if len(detail.BookingDateList) == 0 {
		return nil, "", "", fmt.Errorf("没有可预约的日期")
	}

	fmt.Println("\n  可预约日期:")
	for i, d := range detail.BookingDateList {
		t, _ := time.Parse("2006-01-02", d.Date)
		avail := 0
		for _, ts := range d.TimeSlotList {
			if ts.BookingStatus == 1 && ts.Quota > 0 {
				avail++
			}
		}
		fmt.Printf("  %d. %s (%s) [%d个可选时段]\n", i+1, t.Format("01-02"), weekDay(d.Date), avail)
	}

	dateIdx, err := promptInt("\n  选择日期: ")
	if err != nil || dateIdx < 1 || dateIdx > len(detail.BookingDateList) {
		return nil, "", "", fmt.Errorf("无效的日期选择")
	}
	selectedDate := detail.BookingDateList[dateIdx-1]

	fmt.Printf("\n  %s 可预约时段:\n", selectedDate.Date)
	for i, ts := range selectedDate.TimeSlotList {
		status := ""
		switch {
		case ts.BookingStatus == 2:
			reason := ts.UnbookableReason
			if reason == "" {
				reason = "不可预约"
			}
			status = fmt.Sprintf("  ✗ %s", reason)
		case ts.Quota == 0:
			status = "  ✗ 已满"
		default:
			status = fmt.Sprintf("  剩余 %d/%d", ts.Quota, ts.TotalQuota)
		}
		timeRange := fmt.Sprintf("%s-%s", ts.StartTime[:5], ts.EndTime[:5])
		fmt.Printf("  %d. %-16s %s\n", i+1, timeRange, status)
	}

	slotInput := prompt("\n  选择时段 (范围如 1-3, 或逗号分隔如 1,3,5): ")
	slotIndices := parseSlotRange(slotInput, len(selectedDate.TimeSlotList))

	var validIDs []string
	var firstStart, lastEnd string
	for _, idx := range slotIndices {
		ts := selectedDate.TimeSlotList[idx]
		if ts.BookingStatus == 2 || ts.Quota == 0 {
			fmt.Printf("  ⚠ 时段 %s-%s 不可预约，已跳过\n", ts.StartTime[:5], ts.EndTime[:5])
			continue
		}
		validIDs = append(validIDs, ts.ID)
		if firstStart == "" {
			firstStart = ts.StartTime[:5]
		}
		lastEnd = ts.EndTime[:5]
	}

	if len(validIDs) == 0 {
		return nil, "", "", fmt.Errorf("没有选择有效的时段")
	}

	timeRange := fmt.Sprintf("%s %s-%s", selectedDate.Date, firstStart, lastEnd)
	duration := calcDuration(firstStart, lastEnd)
	return validIDs, timeRange, duration, nil
}

func parseSlotRange(input string, max int) []int {
	var indices []int
	parts := strings.Split(input, "-")
	if len(parts) == 2 {
		start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err1 == nil && err2 == nil {
			for i := start; i <= end && i <= max; i++ {
				if i >= 1 {
					indices = append(indices, i-1)
				}
			}
		}
	} else {
		for _, s := range strings.Split(input, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(s))
			if err == nil && n >= 1 && n <= max {
				indices = append(indices, n-1)
			}
		}
	}
	return indices
}

func calcDuration(start, end string) string {
	parts1 := strings.Split(start, ":")
	parts2 := strings.Split(end, ":")
	h1, _ := strconv.Atoi(parts1[0])
	m1, _ := strconv.Atoi(parts1[1])
	h2, _ := strconv.Atoi(parts2[0])
	m2, _ := strconv.Atoi(parts2[1])
	minutes := (h2*60 + m2) - (h1*60 + m1)
	if minutes%60 == 0 {
		return fmt.Sprintf("%d小时", minutes/60)
	}
	return fmt.Sprintf("%d分钟", minutes)
}

// getCaptchaToken 启动本地 Web 服务器，让用户在浏览器中完成阿里云滑块验证
func getCaptchaToken() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("无法启动本地服务器: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	resultCh := make(chan string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, captchaHTML)
	})
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", 405)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			CaptchaVerifyParam string `json:"captchaVerifyParam"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			w.WriteHeader(400)
			fmt.Fprint(w, `{"status":"error","message":"invalid json"}`)
			return
		}
		if req.CaptchaVerifyParam == "" {
			w.WriteHeader(400)
			fmt.Fprint(w, `{"status":"error","message":"empty param"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
		resultCh <- req.CaptchaVerifyParam
	})

	server := &http.Server{Handler: mux}

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	fmt.Printf("\n  请在浏览器中打开以下地址完成验证码:\n")
	fmt.Printf("  \033[36mhttp://127.0.0.1:%d\033[0m\n\n", port)
	fmt.Println("  等待验证完成...")

	select {
	case result := <-resultCh:
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		server.Shutdown(ctx)
		return result, nil
	case err := <-errCh:
		return "", err
	case <-time.After(5 * time.Minute):
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		server.Shutdown(ctx)
		return "", fmt.Errorf("验证超时")
	}
}

var captchaHTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>验证码</title>
<style>
  body { font-family: -apple-system, sans-serif; display:flex; justify-content:center; align-items:center; min-height:100vh; margin:0; background:#f5f5f5; }
  .card { background:#fff; border-radius:12px; padding:40px; box-shadow:0 2px 12px rgba(0,0,0,.1); text-align:center; max-width:400px; }
  h2 { margin:0 0 8px; font-size:20px; }
  p { color:#666; margin:0 0 24px; font-size:14px; }
  #captcha { display:inline-block; }
  .success { color:#52c41a; font-size:16px; font-weight:500; }
  .error { color:#ff4d4f; font-size:14px; }
</style>
</head>
<body>
<div class="card">
  <h2>请完成验证</h2>
  <p>滑动滑块完成拼图后自动提交</p>
  <div id="captcha"></div>
  <div id="msg"></div>
</div>
<script>
  window.__sc_option = { captchaLanguage: "cn" };
</script>
<script src="https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js" async></script>
<script>
  function init() {
    if (typeof AWSC === "undefined") { setTimeout(init, 300); return; }
    AWSC.use("captcha", function(state, module) {
      var captcha = module.init({
        SceneId: "el91fged",
        mode: "popup",
        element: "#captcha",
        success: function(data) {
          fetch("/callback", {
            method: "POST",
            headers: {"Content-Type":"application/json"},
            body: JSON.stringify({captchaVerifyParam: data})
          }).then(function(r) { return r.json(); }).then(function(d) {
            if (d.status === "ok") {
              document.getElementById("msg").innerHTML = '<p class="success">验证成功！可以关闭此页面</p>';
              document.getElementById("captcha").style.display = "none";
            } else {
              document.getElementById("msg").innerHTML = '<p class="error">提交失败，请重试</p>';
              captcha.refresh();
            }
          }).catch(function() {
            document.getElementById("msg").innerHTML = '<p class="error">网络错误，请重试</p>';
            captcha.refresh();
          });
        },
        fail: function() {
          document.getElementById("msg").innerHTML = '<p class="error">验证失败，请重试</p>';
          captcha.refresh();
        }
      });
      captcha.show();
    });
  }
  setTimeout(init, 500);
</script>
</body>
</html>`

func submitBooking(timeSlotIDs []string, captchaVerifyParam string) (*BookingResult, error) {
	payload := map[string]any{
		"timeSlotIds":        timeSlotIDs,
		"forms":              []any{},
		"captchaVerifyParam": captchaVerifyParam,
	}

	var result BookingResult
	if err := authPost("/admin/api/member/venueSpace/booking", payload, &result, true); err != nil {
		return nil, err
	}
	return &result, nil
}

func doBooking() {
	fmt.Println("\n── 第1步: 选择场馆类型 ──")
	category := selectCategory()

	fmt.Println("\n── 第2步: 选择场馆 ──")
	venue := selectVenue(category)
	if venue == nil {
		return
	}
	fmt.Printf("\n  ✓ 已选择: %s\n", venue.Name)

	fmt.Println("\n── 第3步: 选择场地 ──")
	spaceDetail := selectSpace(venue.ID)
	if spaceDetail == nil {
		return
	}
	fmt.Printf("\n  ✓ 已选择: %s\n", spaceDetail.Name)

	fmt.Println("\n── 第4步: 选择预约时段 ──")
	slotIDs, timeRange, duration, err := selectDateAndSlots(spaceDetail)
	if err != nil {
		fmt.Printf("  ✗ %v\n", err)
		return
	}

	printLine()
	fmt.Println("\n  预约确认:")
	fmt.Printf("  场馆: %s\n", venue.Name)
	fmt.Printf("  场地: %s\n", spaceDetail.Name)
	fmt.Printf("  时间: %s\n", timeRange)
	fmt.Printf("  时长: %s\n", duration)
	fmt.Printf("  时段数: %d\n", len(slotIDs))

	confirm := prompt("\n  确认提交? (y/n) [y]: ")
	if confirm == "n" || confirm == "N" {
		fmt.Println("  已取消")
		return
	}

	fmt.Println("\n── 第5步: 完成验证码 ──")
	captchaParam, err := getCaptchaToken()
	if err != nil {
		fmt.Printf("  ✗ 验证失败: %v\n", err)
		return
	}

	fmt.Println("\n── 第6步: 提交预约 ──")
	result, err := submitBooking(slotIDs, captchaParam)
	if err != nil {
		fmt.Printf("  ✗ 提交失败: %v\n", err)
		return
	}

	if result.Code == 0 {
		fmt.Println("\n  ✓ 预约成功!")
		var data any
		if json.Unmarshal(result.Data, &data) == nil {
			switch v := data.(type) {
			case map[string]any:
				if id, ok := v["id"]; ok {
					fmt.Printf("  预约记录ID: %v\n", id)
				}
			case string:
				fmt.Printf("  预约记录ID: %s\n", v)
			}
		}
	} else {
		fmt.Printf("  ✗ 预约失败: %s\n", result.Msg)
	}
}

type BookingRecord struct {
	ID             string `json:"id"`
	VenueName      string `json:"venueName"`
	VenueSpaceName string `json:"venueSpaceName"`
	BookingDate    string `json:"bookingDate"`
	StartTime      string `json:"startTime"`
	EndTime        string `json:"endTime"`
	Status         int    `json:"status"`
}

var statusMap = map[int]string{
	0: "待审核", 1: "已审核", 2: "已取消",
	3: "已驳回", 4: "已完成", 5: "已过期",
}

func statusText(s int) string {
	if t, ok := statusMap[s]; ok {
		return t
	}
	return "未知"
}

func fetchRecords() ([]BookingRecord, int64, error) {
	path := "/admin/api/member/venueSpace/page?current=1&size=20"
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Records []BookingRecord `json:"records"`
			Total   int64           `json:"total"`
		} `json:"data"`
		Msg string `json:"msg"`
	}
	if err := authGet(path, &resp); err != nil {
		return nil, 0, err
	}
	return resp.Data.Records, resp.Data.Total, nil
}

func viewRecords() {
	fmt.Println("\n── 预约记录 ──")
	fmt.Println()

	records, total, err := fetchRecords()
	if err != nil {
		fmt.Printf("  获取记录失败: %v\n", err)
		return
	}

	if len(records) == 0 {
		fmt.Println("  暂无预约记录")
		return
	}

	for i, r := range records {
		fmt.Printf("  %d. [%s] %s - %s\n", i+1, statusText(r.Status), r.VenueName, r.VenueSpaceName)
		fmt.Printf("     %s %s-%s\n", r.BookingDate, r.StartTime[:5], r.EndTime[:5])
	}
	fmt.Printf("\n  共 %d 条记录\n", total)
}

// --------------- 签到（核销） ---------------

func getBookingDetail(recordID string) (*BookingRecord, error) {
	path := fmt.Sprintf("/admin/api/member/venueSpace/bookingDetail?recordId=%s", recordID)
	var resp struct {
		Code int            `json:"code"`
		Data *BookingRecord `json:"data"`
		Msg  string         `json:"msg"`
	}
	if err := authGet(path, &resp); err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, fmt.Errorf("%s", resp.Msg)
	}
	return resp.Data, nil
}

func doCheckIn() {
	fmt.Println("\n── 签到（核销） ──")
	fmt.Println()

	records, _, err := fetchRecords()
	if err != nil {
		fmt.Printf("  获取记录失败: %v\n", err)
		return
	}

	// 只显示可核销的记录（status=1 已审核）
	var checkable []BookingRecord
	for _, r := range records {
		if r.Status == 1 {
			checkable = append(checkable, r)
		}
	}

	if len(checkable) == 0 {
		fmt.Println("  没有可签到的预约记录（需要状态为「已审核」的记录）")
		return
	}

	fmt.Println("  可签到记录:")
	for i, r := range checkable {
		fmt.Printf("  %d. %s - %s\n", i+1, r.VenueName, r.VenueSpaceName)
		fmt.Printf("     %s %s-%s\n", r.BookingDate, r.StartTime[:5], r.EndTime[:5])
	}

	choice, err := promptInt("\n  选择记录编号: ")
	if err != nil || choice < 1 || choice > len(checkable) {
		fmt.Println("  无效选择")
		return
	}
	selected := checkable[choice-1]

	// 获取详情
	detail, err := getBookingDetail(selected.ID)
	if err != nil {
		fmt.Printf("  获取详情失败: %v\n", err)
		return
	}

	printLine()
	fmt.Println("\n  预约详情:")
	fmt.Printf("  场馆: %s\n", detail.VenueName)
	fmt.Printf("  场地: %s\n", detail.VenueSpaceName)
	fmt.Printf("  日期: %s\n", detail.BookingDate)
	fmt.Printf("  时间: %s-%s\n", detail.StartTime[:5], detail.EndTime[:5])

	// 获取经纬度 (默认签到位置，可通过环境变量覆盖)
	lat := 28.275529
	lng := 112.909235

	if v := os.Getenv("VENUE_LAT"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			lat = n
		}
	}
	if v := os.Getenv("VENUE_LNG"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			lng = n
		}
	}

	confirm := prompt(fmt.Sprintf("\n  确认签到? (位置: %.6f, %.6f) (y/n) [y]: ", lat, lng))
	if confirm == "n" || confirm == "N" {
		fmt.Println("  已取消")
		return
	}

	// 提交核销
	payload := map[string]any{
		"recordId":  selected.ID,
		"latitude":  lat,
		"longitude": lng,
	}

	var result struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := authPost("/admin/api/member/venueSpace/verify", payload, &result, true); err != nil {
		fmt.Printf("  ✗ 签到失败: %v\n", err)
		return
	}

	if result.Code == 0 {
		fmt.Println("\n  ✓ 签到成功!")
	} else {
		fmt.Printf("  ✗ 签到失败: %s\n", result.Msg)
	}
}

// --------------- 账号管理 ---------------

func accountMenu() {
	for {
		fmt.Println("\n── 账号管理 ──")
		if envToken != "" {
			fmt.Println("  ⚠ VENUE_TOKEN 环境变量生效中: API 使用环境变量 token，切换/登录仅保存，下次启动生效")
		}
		if len(cfg.Accounts) == 0 {
			fmt.Println("  (暂无账号)")
		} else {
			for i, a := range cfg.Accounts {
				mark := " "
				if a.Phone == cfg.Current {
					mark = "*"
				}
				line := fmt.Sprintf("  %d. [%s] %s", i+1, mark, accountLabel(a.Phone))
				if a.LastUsedAt != "" {
					line += "  最近使用 " + formatTimeRFC3339(a.LastUsedAt)
				}
				fmt.Println(line)
			}
		}

		fmt.Println("\n  [l] 登录新账号")
		fmt.Println("  [d] 删除账号")
		fmt.Println("  [q] 返回")
		fmt.Println()

		choice := prompt("  请选择: ")
		switch choice {
		case "q", "Q":
			return
		case "l", "L":
			doLogin()
		case "d", "D":
			deleteAccount()
		default:
			idx, err := strconv.Atoi(choice)
			if err != nil || idx < 1 || idx > len(cfg.Accounts) {
				fmt.Println("  无效输入")
				continue
			}
			switchAccount(&cfg.Accounts[idx-1])
		}
	}
}

func switchAccount(a *Account) {
	if a.Phone == cfg.Current {
		fmt.Println("  当前已是该账号")
		return
	}
	cfg.Current = a.Phone
	a.LastUsedAt = nowRFC3339()
	if err := saveConfig(cfg); err != nil {
		fmt.Printf("  ⚠ 保存配置失败: %v\n", err)
	}
	if envToken != "" {
		fmt.Printf("  ✓ 已保存切换至 %s（VENUE_TOKEN 覆盖中，本会话 token 不变）\n", accountLabel(a.Phone))
		return
	}
	token = a.Token
	fmt.Printf("  ✓ 已切换至 %s\n", accountLabel(a.Phone))
}

func deleteAccount() {
	if len(cfg.Accounts) == 0 {
		fmt.Println("  暂无账号")
		return
	}
	idx, err := promptInt("\n  输入要删除的编号: ")
	if err != nil || idx < 1 || idx > len(cfg.Accounts) {
		fmt.Println("  无效输入")
		return
	}
	acct := cfg.Accounts[idx-1]
	confirm := prompt(fmt.Sprintf("  确认删除 %s? (y/n): ", accountLabel(acct.Phone)))
	if confirm != "y" && confirm != "Y" {
		fmt.Println("  已取消")
		return
	}
	removeAccount(cfg, acct.Phone)
	if cfg.Current == acct.Phone {
		cfg.Current = ""
		if envToken == "" {
			token = ""
		}
	}
	if err := saveConfig(cfg); err != nil {
		fmt.Printf("  ⚠ 保存配置失败: %v\n", err)
	}
	fmt.Printf("  ✓ 已删除 %s\n", accountLabel(acct.Phone))
}

// --------------- 主流程 ---------------

func main() {
	apiBase = os.Getenv("VENUE_API_BASE")
	if apiBase == "" {
		apiBase = defaultAPIBase
	}
	apiBase = strings.TrimRight(apiBase, "/")

	fmt.Println("╔══════════════════════════════════════╗")
	fmt.Println("║         场 馆 预 约 工 具            ║")
	fmt.Println("╚══════════════════════════════════════╝")

	envToken = os.Getenv("VENUE_TOKEN")
	cfg = loadConfig()
	if envToken != "" {
		token = envToken
	} else if a := currentAccount(cfg); a != nil {
		token = a.Token
	}

	fmt.Printf("  API: %s\n", apiBase)
	label := "无"
	if a := currentAccount(cfg); a != nil {
		label = accountLabel(a.Phone)
	}
	if envToken != "" {
		fmt.Printf("  账号: %s (VENUE_TOKEN 覆盖中)\n", label)
	} else {
		fmt.Printf("  账号: %s\n", label)
	}
	if token != "" {
		fmt.Println("  状态: 已登录")
	} else {
		fmt.Println("  状态: 未登录 (请先登录)")
	}

	for {
		printLine()
		if a := currentAccount(cfg); a != nil {
			fmt.Printf("  当前账号: %s\n", accountLabel(a.Phone))
		}
		fmt.Println("\n[1] 预约场馆")
		fmt.Println("[2] 查看预约记录")
		fmt.Println("[3] 签到（核销）")
		fmt.Println("[4] 登录 (手机号+验证码)")
		fmt.Println("[5] 账号管理")
		fmt.Println("[q] 退出")
		fmt.Println()

		choice := prompt("  请选择: ")
		switch choice {
		case "1":
			if token == "" {
				fmt.Println("  ✗ 请先登录")
				continue
			}
			doBooking()
		case "2":
			if token == "" {
				fmt.Println("  ✗ 请先登录")
				continue
			}
			viewRecords()
		case "3":
			if token == "" {
				fmt.Println("  ✗ 请先登录")
				continue
			}
			doCheckIn()
		case "4":
			doLogin()
		case "5":
			accountMenu()
		case "q", "Q":
			fmt.Println("再见!")
			return
		}
	}
}
