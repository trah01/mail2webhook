package main

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-message/mail"
	"github.com/gin-gonic/gin"
	_ "modernc.org/sqlite"
)

//go:embed templates/*
var templatesFS embed.FS

// ===================== 数据模型 =====================

// EmailAccount 邮箱账号配置
type EmailAccount struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	ImapServer    string   `json:"imap_server"`
	EmailUser     string   `json:"email_user"`
	EmailPass     string   `json:"email_pass"`
	Enabled       bool     `json:"enabled"`
	CheckInterval int      `json:"check_interval"` // 秒
	Folders       []string `json:"folders"`
	FilterMode    string   `json:"filter_mode"` // "none", "whitelist", "blacklist"
	Whitelist     []string `json:"whitelist"`
	Blacklist     []string `json:"blacklist"`
}

// WebhookTarget Webhook 目标配置
type WebhookTarget struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"` // "feishu", "slack", "discord", "custom", "email"
	URL      string `json:"url"`
	Enabled  bool   `json:"enabled"`
	Template string `json:"template"` // 自定义模板
}

// ForwardRule 转发规则
type ForwardRule struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	SourceAccount string   `json:"source_account"` // 邮箱账号ID，"all" 表示所有
	TargetWebhook string   `json:"target_webhook"` // Webhook目标ID
	Filters       []string `json:"filters"`        // 主题关键词过滤
	Enabled       bool     `json:"enabled"`
}

// Message 存储的消息
type Message struct {
	ID           string     `json:"id"`
	SourceEmail  string     `json:"source_email"`
	AccountID    string     `json:"account_id"`
	Subject      string     `json:"subject"`
	From         string     `json:"from"`
	To           string     `json:"to"`
	Date         time.Time  `json:"date"`
	Body         string     `json:"body"`
	BodyHTML     string     `json:"body_html"`
	Status       string     `json:"status"` // "pending", "sent", "failed"
	TargetType   string     `json:"target_type"`
	TargetName   string     `json:"target_name"`
	RetryCount   int        `json:"retry_count"`
	ErrorMessage string     `json:"error_message"`
	CreatedAt    time.Time  `json:"created_at"`
	SentAt       *time.Time `json:"sent_at"`
}

// LogEntry 日志条目
type LogEntry struct {
	Time    string `json:"time"`
	Message string `json:"message"`
	Type    string `json:"type"` // "info", "success", "error", "warning"
}

// Config 全局配置
type Config struct {
	Accounts        []EmailAccount  `json:"accounts"`
	Webhooks        []WebhookTarget `json:"webhooks"`
	Rules           []ForwardRule   `json:"rules"`
	DefaultInterval int             `json:"default_interval"`
	MaxRetries      int             `json:"max_retries"`
}

// ===================== 全局变量 =====================

var (
	config           Config
	configLock       sync.RWMutex
	db               *sql.DB
	logs             []LogEntry
	logsMutex        sync.Mutex
	urlRegex         = regexp.MustCompile(`https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+`)
	codeRegex        = regexp.MustCompile(`(?i)(?:验证码|校验码|动态码|验证|确认码|verification code|security code|auth code|\bcode\b)[\s:：\-\[【]*([a-zA-Z0-9]{4,8})\b`)
	accountLastCheck sync.Map                                  // 记录每个账号最后的检查时间
	accountChecking  sync.Map                                  // 防止同一个账号的 IMAP 检查并发
	processingMutex  sync.Mutex                                // 防止并发处理待发送消息
	httpClient       = &http.Client{Timeout: 15 * time.Second} // 全局 Webhook 请求带超时的客户端
)

const (
	ConfigFile = "data/config.json"
	DBFile     = "data/messages.db"
)

// ===================== 数据库操作 =====================

func initDB() {
	if err := os.MkdirAll("data", 0755); err != nil {
		log.Fatal("Failed to create user data directory:", err)
	}

	var err error
	db, err = sql.Open("sqlite", DBFile)
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}

	// 开启 WAL 模式和设置 busy_timeout ，避免并发写入锁定和提升性能
	db.Exec("PRAGMA journal_mode=WAL;")
	db.Exec("PRAGMA busy_timeout=5000;")

	// 创建消息表
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS messages (
			id TEXT PRIMARY KEY,
			source_email TEXT,
			account_id TEXT,
			subject TEXT,
			from_addr TEXT,
			to_addr TEXT,
			date DATETIME,
			body TEXT,
			body_html TEXT,
			status TEXT DEFAULT 'pending',
			target_type TEXT,
			target_name TEXT,
			retry_count INTEGER DEFAULT 0,
			error_message TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			sent_at DATETIME
		);
		CREATE INDEX IF NOT EXISTS idx_status ON messages(status);
		CREATE INDEX IF NOT EXISTS idx_created ON messages(created_at DESC);
		CREATE INDEX IF NOT EXISTS idx_account ON messages(account_id);
	`)
	if err != nil {
		log.Fatal("Failed to create tables:", err)
	}
}

func saveMessage(msg *Message) error {
	_, err := db.Exec(`
		INSERT OR REPLACE INTO messages 
		(id, source_email, account_id, subject, from_addr, to_addr, date, body, body_html, 
		 status, target_type, target_name, retry_count, error_message, created_at, sent_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, msg.ID, msg.SourceEmail, msg.AccountID, msg.Subject, msg.From, msg.To, msg.Date,
		msg.Body, msg.BodyHTML, msg.Status, msg.TargetType, msg.TargetName,
		msg.RetryCount, msg.ErrorMessage, msg.CreatedAt, msg.SentAt)
	return err
}

func getMessages(status string, limit int, offset int) ([]Message, error) {
	query := `SELECT id, source_email, account_id, subject, from_addr, to_addr, date, body, 
		status, target_type, target_name, retry_count, error_message, created_at, sent_at 
		FROM messages`
	args := []interface{}{}

	if status != "" {
		query += " WHERE status = ?"
		args = append(args, status)
	}

	query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []Message
	for rows.Next() {
		var msg Message
		var nsSubject, nsFrom, nsTo, nsBody, nsTargetType, nsTargetName, nsErrorMsg, nsSourceEmail sql.NullString
		var niRetryCount sql.NullInt64
		var dateStr, createdAtStr string
		var nsDate, nsCreatedAt, sentAtStr sql.NullString

		err := rows.Scan(&msg.ID, &nsSourceEmail, &msg.AccountID, &nsSubject, &nsFrom,
			&nsTo, &nsDate, &nsBody, &msg.Status, &nsTargetType, &nsTargetName,
			&niRetryCount, &nsErrorMsg, &nsCreatedAt, &sentAtStr)
		if err != nil {
			return nil, err
		}

		msg.SourceEmail = nsSourceEmail.String
		msg.Subject = nsSubject.String
		msg.From = nsFrom.String
		msg.To = nsTo.String
		msg.Body = nsBody.String
		msg.TargetType = nsTargetType.String
		msg.TargetName = nsTargetName.String
		msg.ErrorMessage = nsErrorMsg.String
		msg.RetryCount = int(niRetryCount.Int64)

		if nsDate.Valid {
			dateStr = nsDate.String
		}
		if nsCreatedAt.Valid {
			createdAtStr = nsCreatedAt.String
		}

		msg.Date = tryParseTime(dateStr)
		msg.CreatedAt = tryParseTime(createdAtStr)
		if sentAtStr.Valid && sentAtStr.String != "" {
			t := tryParseTime(sentAtStr.String)
			msg.SentAt = &t
		}

		messages = append(messages, msg)
	}
	return messages, nil
}

func tryParseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	// 尝试常见的 SQLite 时间格式
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05Z",
		"2006-01-02T15:04:05Z",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func getMessageStats() (map[string]int, error) {
	stats := make(map[string]int)
	rows, err := db.Query(`SELECT status, COUNT(*) FROM messages GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		stats[status] = count
	}
	return stats, nil
}

func deleteOldMessages(days int) error {
	_, err := db.Exec(`DELETE FROM messages WHERE created_at < datetime('now', ?)`,
		fmt.Sprintf("-%d days", days))
	return err
}

// ===================== 配置管理 =====================

func loadConfig() {
	configLock.Lock()
	defer configLock.Unlock()

	// 默认配置
	config = Config{
		DefaultInterval: 60,
		MaxRetries:      3,
	}

	data, err := os.ReadFile(ConfigFile)
	if err == nil {
		json.Unmarshal(data, &config)
	} else {
		saveConfigNoLock()
	}
}

func saveConfigNoLock() {
	data, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(ConfigFile, data, 0644)
}

func saveConfig() {
	configLock.Lock()
	defer configLock.Unlock()
	saveConfigNoLock()
}

// ===================== 日志管理 =====================

func addLog(msg string, logType string) {
	logsMutex.Lock()
	defer logsMutex.Unlock()

	entry := LogEntry{
		Time:    time.Now().Format("15:04:05"),
		Message: msg,
		Type:    logType,
	}
	logs = append([]LogEntry{entry}, logs...)
	if len(logs) > 200 {
		logs = logs[:200]
	}

	// 同时输出到控制台
	prefix := map[string]string{
		"info":    "ℹ️",
		"success": "✅",
		"error":   "❌",
		"warning": "⚠️",
	}[logType]
	log.Printf("%s %s", prefix, msg)
}

// ===================== 邮件处理 =====================

func cleanHTML(htmlStr string) string {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlStr))
	if err != nil {
		return htmlStr
	}
	doc.Find("script, style, head, title, meta").Each(func(i int, s *goquery.Selection) {
		s.Remove()
	})
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		href, _ := s.Attr("href")
		text := strings.TrimSpace(s.Text())
		if href != "" {
			if text == "" {
				text = "链接"
			} else if len(text) > 80 {
				text = text[:77] + "..."
			}

			if len(href) > 600 {
				s.SetText(fmt.Sprintf("[%s](长链接由于超长已被过滤)", text))
			} else {
				s.SetText(fmt.Sprintf("[%s](%s)", text, href))
			}
		}
	})

	text := strings.TrimSpace(doc.Text())
	text = urlRegex.ReplaceAllStringFunc(text, func(u string) string {
		if len(u) > 600 {
			return u[:80] + "...(该段长链接由于超长已被过滤)"
		}
		return u
	})
	return text
}

func shouldProcessEmail(account *EmailAccount, fromAddr string, fromName string) bool {
	switch account.FilterMode {
	case "whitelist":
		for _, w := range account.Whitelist {
			wLow := strings.ToLower(w)
			if strings.Contains(strings.ToLower(fromAddr), wLow) || strings.Contains(strings.ToLower(fromName), wLow) {
				return true
			}
		}
		return false
	case "blacklist":
		for _, b := range account.Blacklist {
			bLow := strings.ToLower(b)
			if strings.Contains(strings.ToLower(fromAddr), bLow) || strings.Contains(strings.ToLower(fromName), bLow) {
				return false
			}
		}
		return true
	default:
		return true
	}
}

func checkMailForAccount(account *EmailAccount) {
	if !account.Enabled {
		return
	}

	// 防并发：如果当前账号的上一轮检查卡住未完成，则放弃本次调度
	if _, loaded := accountChecking.LoadOrStore(account.ID, true); loaded {
		return
	}
	defer accountChecking.Delete(account.ID)

	// 记录最后检查时间而不是频繁刷屏日志
	accountLastCheck.Store(account.ID, time.Now().Format("2006-01-02 15:04:05"))

	// 自动添加默认端口993
	imapServer := account.ImapServer
	if !strings.Contains(imapServer, ":") {
		imapServer = imapServer + ":993"
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	c, err := client.DialWithDialerTLS(dialer, imapServer, nil)
	if err != nil {
		addLog(fmt.Sprintf("IMAP连接失败 [%s]: %v", account.Name, err), "error")
		return
	}
	defer c.Logout()

	if err := c.Login(account.EmailUser, account.EmailPass); err != nil {
		addLog(fmt.Sprintf("IMAP登录失败 [%s]: %v", account.Name, err), "error")
		return
	}

	folders := account.Folders
	if len(folders) == 0 {
		folders = []string{"INBOX"}
	}

	for _, folder := range folders {
		_, err := c.Select(folder, false)
		if err != nil {
			continue
		}

		criteria := imap.NewSearchCriteria()
		criteria.WithoutFlags = []string{imap.SeenFlag}
		uids, _ := c.UidSearch(criteria)

		limit := 10
		if len(uids) > limit {
			uids = uids[len(uids)-limit:]
		}

		for _, uid := range uids {
			// 检查是否已处理
			var count int
			db.QueryRow(`SELECT COUNT(*) FROM messages WHERE id = ?`,
				fmt.Sprintf("%s-%d", account.ID, uid)).Scan(&count)
			if count > 0 {
				continue
			}

			seqSet := new(imap.SeqSet)
			seqSet.AddNum(uid)

			var section imap.BodySectionName
			items := []imap.FetchItem{section.FetchItem(), imap.FetchEnvelope}
			messages := make(chan *imap.Message, 1)

			go func() {
				c.UidFetch(seqSet, items, messages)
			}()

			var msg *imap.Message
			for m := range messages {
				if msg == nil {
					msg = m // 获取第一个拿去处理，剩下的强行消费完（防止 IMAP Server 返回多个对象导致 Channel 卡死 goroutine 泄露）
				}
			}

			if msg == nil || msg.Envelope == nil {
				continue
			}

			// 只处理最近 3 分钟内的邮件，防止一堆很久以前的未读邮件突然发过来
			if time.Since(msg.Envelope.Date) > 3*time.Minute {
				// 写入数据库标记为 ignored，防止下次循环重新 fetch envelope
				msgID := fmt.Sprintf("%s-%d", account.ID, uid)
				db.Exec(`INSERT OR IGNORE INTO messages (id, account_id, status, created_at) VALUES (?, ?, 'ignored', ?)`, msgID, account.ID, time.Now())
				continue
			}

			from := ""
			fromName := ""
			if len(msg.Envelope.From) > 0 {
				from = msg.Envelope.From[0].Address()
				fromName = msg.Envelope.From[0].PersonalName
			}

			// 过滤检查
			if !shouldProcessEmail(account, from, fromName) {
				// 不匹配白名单/黑名单的邮件也标记为 ignored，防止反复被拉回来查
				msgID := fmt.Sprintf("%s-%d", account.ID, uid)
				db.Exec(`INSERT OR IGNORE INTO messages (id, account_id, status, created_at) VALUES (?, ?, 'ignored', ?)`, msgID, account.ID, time.Now())
				continue
			}

			r := msg.GetBody(&section)
			if r == nil {
				continue
			}
			mr, err := mail.CreateReader(r)
			if err != nil {
				continue
			}

			var body, bodyHTML string
			for {
				p, err := mr.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					break
				}

				switch h := p.Header.(type) {
				case *mail.InlineHeader:
					contentType, _, _ := h.ContentType()
					b, _ := io.ReadAll(p.Body)
					if contentType == "text/html" {
						bodyHTML = string(b)
						body = cleanHTML(string(b))
					} else if contentType == "text/plain" && body == "" {
						body = urlRegex.ReplaceAllStringFunc(string(b), func(u string) string {
							disp := u
							if len(disp) > 80 {
								disp = disp[:77] + "..."
							}
							if len(u) > 600 {
								return fmt.Sprintf("[%s](长链接由于超长已被过滤)", disp)
							}
							return fmt.Sprintf("[%s](%s)", disp, u)
						})
					}
				}
			}

			// 存储消息
			msgID := fmt.Sprintf("%s-%d", account.ID, uid)
			newMsg := &Message{
				ID:          msgID,
				SourceEmail: account.EmailUser,
				AccountID:   account.ID,
				Subject:     msg.Envelope.Subject,
				From:        from,
				To:          account.EmailUser,
				Date:        msg.Envelope.Date,
				Body:        body,
				BodyHTML:    bodyHTML,
				Status:      "pending",
				CreatedAt:   time.Now(),
			}

			if err := saveMessage(newMsg); err != nil {
				addLog(fmt.Sprintf("保存消息失败: %v", err), "error")
				continue
			}

			addLog(fmt.Sprintf("收到新邮件 [%s]: %s", account.Name, msg.Envelope.Subject), "success")

			// 标记已读
			c.UidStore(seqSet, imap.AddFlags, []interface{}{imap.SeenFlag}, nil)
		}
	}
}

// ===================== 消息转发 =====================

func sendToFeishu(webhookURL, subject, from, date, body string) error {
	runes := []rune(body)
	chunkSize := 1800
	var chunks []string
	for i := 0; i < len(runes); i += chunkSize {
		end := i + chunkSize
		if end > len(runes) {
			end = len(runes)
		}
		chunks = append(chunks, string(runes[i:end]))
	}

	totalBatches := (len(chunks) + 9) / 10
	for i := 0; i < len(chunks); i += 10 {
		end := i + 10
		if end > len(chunks) {
			end = len(chunks)
		}
		batch := chunks[i:end]
		idx := i/10 + 1
		isFirst := (i == 0)

		elements := []interface{}{}
		if isFirst {
			elements = append(elements, map[string]interface{}{
				"tag":  "div",
				"text": map[string]interface{}{"tag": "lark_md", "content": fmt.Sprintf("**主题：** %s\n**发件人：** %s\n**时间：** %s", subject, from, date)},
			})
			elements = append(elements, map[string]interface{}{"tag": "hr"})
		}

		for _, txt := range batch {
			if strings.TrimSpace(txt) != "" {
				elements = append(elements, map[string]interface{}{
					"tag":  "div",
					"text": map[string]interface{}{"tag": "lark_md", "content": txt},
				})
			}
		}

		elements = append(elements, map[string]interface{}{
			"tag":      "note",
			"elements": []map[string]interface{}{{"tag": "plain_text", "content": fmt.Sprintf("[Mail2Webhook] Part %d / %d", idx, totalBatches)}},
		})

		card := map[string]interface{}{
			"config": map[string]interface{}{"wide_screen_mode": true},
			"header": map[string]interface{}{
				"template": "turquoise",
				"title":    map[string]interface{}{"tag": "plain_text", "content": subject},
			},
			"elements": elements,
		}
		if !isFirst {
			card["header"].(map[string]interface{})["template"] = "grey"
			card["header"].(map[string]interface{})["title"].(map[string]interface{})["content"] = "[邮件正文续接]"
		}

		payload := map[string]interface{}{"msg_type": "interactive", "card": card}
		jsonBody, _ := json.Marshal(payload)
		resp, err := httpClient.Post(webhookURL, "application/json", bytes.NewBuffer(jsonBody))
		if err != nil {
			return err
		}

		if resp.StatusCode >= 400 {
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
		}
		resp.Body.Close()
		time.Sleep(600 * time.Millisecond)
	}
	return nil
}

func sendToSlack(webhookURL, subject, from, date, body string) error {
	payload := map[string]interface{}{
		"blocks": []map[string]interface{}{
			{
				"type": "header",
				"text": map[string]interface{}{
					"type": "plain_text",
					"text": subject,
				},
			},
			{
				"type": "section",
				"fields": []map[string]interface{}{
					{"type": "mrkdwn", "text": fmt.Sprintf("*发件人:*\n%s", from)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*时间:*\n%s", date)},
				},
			},
			{
				"type": "divider",
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": body,
				},
			},
		},
	}
	jsonBody, _ := json.Marshal(payload)
	resp, err := httpClient.Post(webhookURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}
	return nil
}

func sendToDiscord(webhookURL, subject, from, date, body string) error {
	// Discord 限制 2000 字符
	if len(body) > 1900 {
		body = body[:1900] + "..."
	}
	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       subject,
				"description": body,
				"color":       3447003,
				"fields": []map[string]interface{}{
					{"name": "发件人", "value": from, "inline": true},
					{"name": "时间", "value": date, "inline": true},
				},
				"footer": map[string]interface{}{
					"text": "Mail2Webhook",
				},
			},
		},
	}
	jsonBody, _ := json.Marshal(payload)
	resp, err := httpClient.Post(webhookURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}
	return nil
}

func sendToCustomWebhook(webhookURL, subject, from, date, body string) error {
	payload := map[string]interface{}{
		"subject": subject,
		"from":    from,
		"date":    date,
		"body":    body,
	}
	jsonBody, _ := json.Marshal(payload)
	resp, err := httpClient.Post(webhookURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}
	return nil
}

func sendToDingTalk(webhookURL, subject, from, date, body string) error {
	if len(body) > 15000 {
		body = body[:15000] + "..."
	}
	payload := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]interface{}{
			"title": subject,
			"text":  fmt.Sprintf("### %s\n**发件人:** %s\n**时间:** %s\n\n%s", subject, from, date, body),
		},
	}
	jsonBody, _ := json.Marshal(payload)
	resp, err := httpClient.Post(webhookURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}
	return nil
}

func sendToWeCom(webhookURL, subject, from, date, body string) error {
	fullText := fmt.Sprintf("### %s\n**发件人:** %s\n**时间:** %s\n\n%s", subject, from, date, body)
	runes := []rune(fullText)
	if len(runes) > 1300 {
		fullText = string(runes[:1300]) + "..."
	}
	payload := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]interface{}{
			"content": fullText,
		},
	}
	jsonBody, _ := json.Marshal(payload)
	resp, err := httpClient.Post(webhookURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}
	return nil
}

func processPendingMessages() {
	// 防止消息发送队列重叠并发引发重复发送通知
	if !processingMutex.TryLock() {
		return
	}
	defer processingMutex.Unlock()

	// 获取所有启用的规则
	configLock.RLock()
	rules := make([]ForwardRule, 0)
	webhooks := make(map[string]WebhookTarget)
	accounts := make(map[string]EmailAccount)

	for _, w := range config.Webhooks {
		webhooks[w.ID] = w
	}
	for _, a := range config.Accounts {
		accounts[a.ID] = a
	}
	for _, r := range config.Rules {
		if r.Enabled {
			rules = append(rules, r)
		}
	}
	maxRetries := config.MaxRetries
	configLock.RUnlock()

	// 获取待发送消息
	messages, err := getMessages("pending", 100, 0)
	if err != nil {
		addLog(fmt.Sprintf("获取待发送消息失败: %v", err), "error")
		return
	}

	for _, msg := range messages {
		if msg.RetryCount >= maxRetries {
			msg.Status = "failed"
			msg.ErrorMessage = "超过最大重试次数"
			saveMessage(&msg)
			continue
		}

		// 匹配规则
		for _, rule := range rules {
			// 检查源账号匹配
			if rule.SourceAccount != "all" && rule.SourceAccount != msg.AccountID {
				continue
			}

			// 检查关键词过滤
			if len(rule.Filters) > 0 {
				matched := false
				for _, f := range rule.Filters {
					if strings.Contains(strings.ToLower(msg.Subject), strings.ToLower(f)) {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
			}

			// 获取目标 Webhook
			webhook, ok := webhooks[rule.TargetWebhook]
			if !ok || !webhook.Enabled {
				continue
			}

			// 发送
			var sendErr error
			dateStr := msg.Date.Format("2006-01-02 15:04:05")

			// 智能提取验证码并高亮前置
			displayBody := msg.Body
			var verificationCode string
			if matches := codeRegex.FindStringSubmatch(msg.Subject); len(matches) > 1 {
				verificationCode = matches[1]
			} else if matches := codeRegex.FindStringSubmatch(msg.Body); len(matches) > 1 {
				verificationCode = matches[1]
			}

			if verificationCode != "" {
				displayBody = fmt.Sprintf("**[智能提取验证码] %s**\n\n%s", verificationCode, msg.Body)
			}

			switch webhook.Type {
			case "feishu":
				sendErr = sendToFeishu(webhook.URL, msg.Subject, msg.From, dateStr, displayBody)
			case "dingtalk":
				sendErr = sendToDingTalk(webhook.URL, msg.Subject, msg.From, dateStr, displayBody)
			case "wecom":
				sendErr = sendToWeCom(webhook.URL, msg.Subject, msg.From, dateStr, displayBody)
			case "slack":
				sendErr = sendToSlack(webhook.URL, msg.Subject, msg.From, dateStr, displayBody)
			case "discord":
				sendErr = sendToDiscord(webhook.URL, msg.Subject, msg.From, dateStr, displayBody)
			case "custom":
				sendErr = sendToCustomWebhook(webhook.URL, msg.Subject, msg.From, dateStr, displayBody)
			}

			if sendErr != nil {
				msg.RetryCount++
				msg.ErrorMessage = sendErr.Error()
				saveMessage(&msg)
				addLog(fmt.Sprintf("发送失败 [%s -> %s]: %v", msg.Subject, webhook.Name, sendErr), "error")
			} else {
				msg.Status = "sent"
				msg.TargetType = webhook.Type
				msg.TargetName = webhook.Name
				now := time.Now()
				msg.SentAt = &now
				saveMessage(&msg)
				addLog(fmt.Sprintf("转发成功 [%s -> %s]", msg.Subject, webhook.Name), "success")
			}
		}
	}
}

// ===================== 后台任务 =====================

func startBackgroundTasks() {
	// 消息处理循环
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		for range ticker.C {
			processPendingMessages()
		}
	}()

	// 清理旧消息
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		for range ticker.C {
			deleteOldMessages(30) // 保留30天
		}
	}()

	// 为保护隐私，定期清理已处理完毕消息的邮件正文内容 (1分钟清理一次)
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		for range ticker.C {
			db.Exec(`UPDATE messages SET body = '', body_html = '' WHERE status IN ('sent', 'failed') AND body != ''`)
		}
	}()

	// 邮箱检查调度
	go func() {
		accountLastRun := make(map[string]time.Time)
		ticker := time.NewTicker(5 * time.Second)
		for range ticker.C {
			configLock.RLock()
			accounts := config.Accounts
			configLock.RUnlock()

			now := time.Now()
			for i := range accounts {
				acc := accounts[i]
				if !acc.Enabled {
					continue
				}

				interval := acc.CheckInterval
				if interval < 15 {
					// 若账号未配置有效间隔，回退使用全局默认
					configLock.RLock()
					interval = config.DefaultInterval
					configLock.RUnlock()
					if interval < 15 {
						interval = 60
					}
				}

				lastRun, exists := accountLastRun[acc.ID]
				if !exists || now.Sub(lastRun) >= time.Duration(interval)*time.Second {
					accountLastRun[acc.ID] = now
					// 启动独立协程去收件，不阻塞其他账号的调度
					go checkMailForAccount(&acc)
				}
			}
		}
	}()
}

// ===================== HTTP API =====================

func setupAPI(r *gin.Engine) {
	// 静态页面
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	// ===== 账号管理 =====
	r.GET("/api/accounts", func(c *gin.Context) {
		configLock.RLock()
		defer configLock.RUnlock()
		safeAccounts := make([]EmailAccount, len(config.Accounts))
		for i, acc := range config.Accounts {
			safeAccounts[i] = acc
			if safeAccounts[i].EmailPass != "" {
				safeAccounts[i].EmailPass = "********"
			}
		}
		c.JSON(http.StatusOK, safeAccounts)
	})

	r.POST("/api/accounts", func(c *gin.Context) {
		var account EmailAccount
		if err := c.ShouldBindJSON(&account); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if account.ID == "" {
			account.ID = fmt.Sprintf("acc_%d", time.Now().UnixNano())
		}
		configLock.Lock()
		// 如果有假掩码，还原数据：通常新添加不该有，防御性操作
		if account.EmailPass == "********" {
			account.EmailPass = ""
		}
		config.Accounts = append(config.Accounts, account)
		saveConfigNoLock()
		configLock.Unlock()
		c.JSON(http.StatusOK, account)
	})

	// 测试连接和获取文件夹
	r.POST("/api/test-imap", func(c *gin.Context) {
		var account EmailAccount
		if err := c.ShouldBindJSON(&account); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 恢复密码掩码（用户直接在编辑界面点测试的时候传过来的是 ********）
		if account.EmailPass == "********" && account.ID != "" {
			configLock.RLock()
			for _, acc := range config.Accounts {
				if acc.ID == account.ID {
					account.EmailPass = acc.EmailPass
					break
				}
			}
			configLock.RUnlock()
		}

		imapServer := account.ImapServer
		if !strings.Contains(imapServer, ":") {
			imapServer = imapServer + ":993"
		}

		dialer := &net.Dialer{Timeout: 10 * time.Second}
		clientImap, err := client.DialWithDialerTLS(dialer, imapServer, nil)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("连接服务器失败: %v", err)})
			return
		}
		defer clientImap.Logout()

		if err := clientImap.Login(account.EmailUser, account.EmailPass); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("登录验证失败: %v", err)})
			return
		}

		// 获取文件夹列表
		mailboxes := make(chan *imap.MailboxInfo, 10)
		done := make(chan error, 1)
		go func() {
			done <- clientImap.List("", "*", mailboxes)
		}()

		var folders []string
		for m := range mailboxes {
			folders = append(folders, m.Name)
		}

		if err := <-done; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("获取文件夹失败: %v", err)})
			return
		}

		c.JSON(http.StatusOK, gin.H{"folders": folders})
	})

	r.PUT("/api/accounts/:id", func(c *gin.Context) {
		id := c.Param("id")
		var account EmailAccount
		if err := c.ShouldBindJSON(&account); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		configLock.Lock()
		for i, acc := range config.Accounts {
			if acc.ID == id {
				account.ID = id
				// 恢复密码占位符
				if account.EmailPass == "********" {
					account.EmailPass = acc.EmailPass
				}
				config.Accounts[i] = account
				break
			}
		}
		saveConfigNoLock()
		configLock.Unlock()
		c.JSON(http.StatusOK, account)
	})

	r.DELETE("/api/accounts/:id", func(c *gin.Context) {
		id := c.Param("id")
		configLock.Lock()
		newAccounts := make([]EmailAccount, 0)
		for _, acc := range config.Accounts {
			if acc.ID != id {
				newAccounts = append(newAccounts, acc)
			}
		}
		config.Accounts = newAccounts
		saveConfigNoLock()
		configLock.Unlock()
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	// ===== Webhook 管理 =====
	r.GET("/api/webhooks", func(c *gin.Context) {
		configLock.RLock()
		defer configLock.RUnlock()
		safeWebhooks := make([]WebhookTarget, len(config.Webhooks))
		for i, wh := range config.Webhooks {
			safeWebhooks[i] = wh
			if wh.URL != "" {
				l := len(wh.URL)
				if l > 35 {
					safeWebhooks[i].URL = wh.URL[:30] + "...********..." + wh.URL[l-5:]
				} else {
					safeWebhooks[i].URL = "********"
				}
			}
		}
		c.JSON(http.StatusOK, safeWebhooks)
	})

	r.POST("/api/webhooks", func(c *gin.Context) {
		var webhook WebhookTarget
		if err := c.ShouldBindJSON(&webhook); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if webhook.ID == "" {
			webhook.ID = fmt.Sprintf("wh_%d", time.Now().UnixNano())
		}
		configLock.Lock()
		if strings.Contains(webhook.URL, "********") {
			webhook.URL = ""
		}
		config.Webhooks = append(config.Webhooks, webhook)
		saveConfigNoLock()
		configLock.Unlock()
		c.JSON(http.StatusOK, webhook)
	})

	r.PUT("/api/webhooks/:id", func(c *gin.Context) {
		id := c.Param("id")
		var webhook WebhookTarget
		if err := c.ShouldBindJSON(&webhook); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		configLock.Lock()
		for i, wh := range config.Webhooks {
			if wh.ID == id {
				webhook.ID = id
				// 恢复脱敏数据占位符
				if strings.Contains(webhook.URL, "********") {
					webhook.URL = wh.URL
				}
				config.Webhooks[i] = webhook
				break
			}
		}
		saveConfigNoLock()
		configLock.Unlock()
		c.JSON(http.StatusOK, webhook)
	})

	r.DELETE("/api/webhooks/:id", func(c *gin.Context) {
		id := c.Param("id")
		configLock.Lock()
		newWebhooks := make([]WebhookTarget, 0)
		for _, wh := range config.Webhooks {
			if wh.ID != id {
				newWebhooks = append(newWebhooks, wh)
			}
		}
		config.Webhooks = newWebhooks
		saveConfigNoLock()
		configLock.Unlock()
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	// ===== 规则管理 =====
	r.GET("/api/rules", func(c *gin.Context) {
		configLock.RLock()
		defer configLock.RUnlock()
		c.JSON(http.StatusOK, config.Rules)
	})

	r.POST("/api/rules", func(c *gin.Context) {
		var rule ForwardRule
		if err := c.ShouldBindJSON(&rule); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if rule.ID == "" {
			rule.ID = fmt.Sprintf("rule_%d", time.Now().UnixNano())
		}
		configLock.Lock()
		config.Rules = append(config.Rules, rule)
		saveConfigNoLock()
		configLock.Unlock()
		c.JSON(http.StatusOK, rule)
	})

	r.PUT("/api/rules/:id", func(c *gin.Context) {
		id := c.Param("id")
		var rule ForwardRule
		if err := c.ShouldBindJSON(&rule); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		configLock.Lock()
		for i, r := range config.Rules {
			if r.ID == id {
				rule.ID = id
				config.Rules[i] = rule
				break
			}
		}
		saveConfigNoLock()
		configLock.Unlock()
		c.JSON(http.StatusOK, rule)
	})

	r.DELETE("/api/rules/:id", func(c *gin.Context) {
		id := c.Param("id")
		configLock.Lock()
		newRules := make([]ForwardRule, 0)
		for _, r := range config.Rules {
			if r.ID != id {
				newRules = append(newRules, r)
			}
		}
		config.Rules = newRules
		saveConfigNoLock()
		configLock.Unlock()
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	// ===== 消息与日志 =====
	r.GET("/api/logs", func(c *gin.Context) {
		logsMutex.Lock()
		defer logsMutex.Unlock()
		c.JSON(http.StatusOK, logs)
	})

	r.GET("/api/messages", func(c *gin.Context) {
		status := c.Query("status")
		limit := 50
		offset := 0
		messages, err := getMessages(status, limit, offset)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// 隐私保护：即使是 pending 状态的邮件，发给前端时也不返回正文（模板目前也只需显示标题等信息）
		for i := range messages {
			messages[i].Body = "已隐藏（隐私保护）"
			messages[i].BodyHTML = ""
		}

		c.JSON(http.StatusOK, messages)
	})

	r.GET("/api/stats", func(c *gin.Context) {
		stats, err := getMessageStats()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		lastChecks := make(map[string]string)
		accountLastCheck.Range(func(key, value interface{}) bool {
			lastChecks[key.(string)] = value.(string)
			return true
		})

		// 合并状态数据与检查时间数据
		response := gin.H{
			"pending":     stats["pending"],
			"sent":        stats["sent"],
			"failed":      stats["failed"],
			"ignored":     stats["ignored"],
			"last_checks": lastChecks,
		}
		c.JSON(http.StatusOK, response)
	})

	// ===== 全局配置 =====
	r.GET("/api/config", func(c *gin.Context) {
		configLock.RLock()
		defer configLock.RUnlock()
		c.JSON(http.StatusOK, gin.H{
			"default_interval": config.DefaultInterval,
			"max_retries":      config.MaxRetries,
		})
	})

	r.PUT("/api/config", func(c *gin.Context) {
		var updates struct {
			DefaultInterval *int `json:"default_interval"`
			MaxRetries      *int `json:"max_retries"`
		}
		if err := c.ShouldBindJSON(&updates); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		configLock.Lock()
		if updates.DefaultInterval != nil {
			config.DefaultInterval = *updates.DefaultInterval
		}
		if updates.MaxRetries != nil {
			config.MaxRetries = *updates.MaxRetries
		}
		saveConfigNoLock()
		configLock.Unlock()
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	// 测试 Webhook
	r.POST("/api/webhooks/:id/test", func(c *gin.Context) {
		id := c.Param("id")
		configLock.RLock()
		var webhook *WebhookTarget
		for _, wh := range config.Webhooks {
			if wh.ID == id {
				webhook = &wh
				break
			}
		}
		configLock.RUnlock()

		if webhook == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Webhook not found"})
			return
		}

		var err error
		switch webhook.Type {
		case "feishu":
			err = sendToFeishu(webhook.URL, "测试消息", "test@test.com", time.Now().Format("2006-01-02"), "这是一条测试消息")
		case "slack":
			err = sendToSlack(webhook.URL, "测试消息", "test@test.com", time.Now().Format("2006-01-02"), "这是一条测试消息")
		case "discord":
			err = sendToDiscord(webhook.URL, "测试消息", "test@test.com", time.Now().Format("2006-01-02"), "这是一条测试消息")
		case "custom":
			err = sendToCustomWebhook(webhook.URL, "测试消息", "test@test.com", time.Now().Format("2006-01-02"), "这是一条测试消息")
		}

		if err != nil {
			c.JSON(http.StatusOK, gin.H{"success": false, "error": err.Error()})
		} else {
			c.JSON(http.StatusOK, gin.H{"success": true})
		}
	})
}

// ===================== 主函数 =====================

func main() {
	// 初始化
	initDB()
	loadConfig()

	addLog("系统启动", "info")

	// 启动后台任务
	startBackgroundTasks()

	// 启动 Web 服务
	r := gin.Default()

	// 设置模板
	tmpl := template.Must(template.New("").ParseFS(templatesFS, "templates/*.html"))
	r.SetHTMLTemplate(tmpl)

	// 设置 API
	setupAPI(r)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: r,
	}

	go func() {
		addLog(fmt.Sprintf("Web 服务启动在端口: %s", port), "info")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	// 等待中断信号来优雅地关闭服务器
	quit := make(chan os.Signal, 1)
	// kill 默认是信号 SIGTERM (比如 docker-compose stop)
	// 用户控制台的 CTRL+C 会发送 SIGINT
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	addLog("接收到关闭信号，正在进行优雅停机...", "warning")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server Shutdown:", err)
	}

	addLog("安全断开数据库连接...", "info")
	if db != nil {
		db.Close()
	}

	time.Sleep(1 * time.Second)
	log.Println("Server exiting")
}
