package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/gin-gonic/gin"
)

// ===================== HTTP API =====================

func setupAPI(r *gin.Engine) {
	r.GET("/static/:file", func(c *gin.Context) {
		name := c.Param("file")
		if strings.Contains(name, "/") || strings.Contains(name, "\\") {
			c.Status(http.StatusNotFound)
			return
		}
		data, err := templatesFS.ReadFile("static/" + name)
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		contentType := "text/plain; charset=utf-8"
		if strings.HasSuffix(name, ".css") {
			contentType = "text/css; charset=utf-8"
		} else if strings.HasSuffix(name, ".js") {
			contentType = "application/javascript; charset=utf-8"
		}
		c.Data(http.StatusOK, contentType, data)
	})

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

	// ===== 过滤规则管理 =====
	r.GET("/api/filters", func(c *gin.Context) {
		configLock.RLock()
		defer configLock.RUnlock()
		c.JSON(http.StatusOK, config.FilterRules)
	})

	r.POST("/api/filters", func(c *gin.Context) {
		var filter FilterRule
		if err := c.ShouldBindJSON(&filter); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if filter.ID == "" {
			filter.ID = fmt.Sprintf("filter_%d", time.Now().UnixNano())
		}
		filter = normalizeFilterRule(filter)
		configLock.Lock()
		config.FilterRules = append(config.FilterRules, filter)
		saveConfigNoLock()
		configLock.Unlock()
		c.JSON(http.StatusOK, filter)
	})

	r.PUT("/api/filters/:id", func(c *gin.Context) {
		id := c.Param("id")
		var filter FilterRule
		if err := c.ShouldBindJSON(&filter); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		configLock.Lock()
		for i, f := range config.FilterRules {
			if f.ID == id {
				filter.ID = id
				filter = normalizeFilterRule(filter)
				config.FilterRules[i] = filter
				break
			}
		}
		saveConfigNoLock()
		configLock.Unlock()
		c.JSON(http.StatusOK, filter)
	})

	r.DELETE("/api/filters/:id", func(c *gin.Context) {
		id := c.Param("id")
		if id == DefaultSenderBlacklistID || id == DefaultSenderWhitelistID {
			c.JSON(http.StatusBadRequest, gin.H{"error": "默认发件人过滤规则不能删除"})
			return
		}
		configLock.Lock()
		newFilters := make([]FilterRule, 0, len(config.FilterRules))
		for _, f := range config.FilterRules {
			if f.ID != id {
				newFilters = append(newFilters, f)
			}
		}
		config.FilterRules = newFilters
		for i := range config.Rules {
			config.Rules[i].FilterRuleIDs = removeString(config.Rules[i].FilterRuleIDs, id)
		}
		saveConfigNoLock()
		configLock.Unlock()
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	r.POST("/api/filters/default-senders", func(c *gin.Context) {
		var req struct {
			Mode   string `json:"mode"`
			Sender string `json:"sender"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if req.Mode != "blacklist" && req.Mode != "whitelist" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "mode must be blacklist or whitelist"})
			return
		}
		configLock.Lock()
		rule, added := addSenderToDefaultFilterRuleNoLock(req.Mode, req.Sender)
		saveConfigNoLock()
		configLock.Unlock()
		c.JSON(http.StatusOK, gin.H{"success": true, "added": added, "rule": rule})
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
			"filtered":    stats["filtered"],
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
		case "dingtalk":
			err = sendToDingTalk(webhook.URL, "测试消息", "test@test.com", time.Now().Format("2006-01-02"), "这是一条测试消息")
		case "wecom":
			err = sendToWeCom(webhook.URL, "测试消息", "test@test.com", time.Now().Format("2006-01-02"), "这是一条测试消息")
		case "slack":
			err = sendToSlack(webhook.URL, "测试消息", "test@test.com", time.Now().Format("2006-01-02"), "这是一条测试消息")
		case "discord":
			err = sendToDiscord(webhook.URL, "测试消息", "test@test.com", time.Now().Format("2006-01-02"), "这是一条测试消息")
		case "custom":
			err = sendToCustomWebhook(webhook.URL, "测试消息", "test@test.com", time.Now().Format("2006-01-02"), "这是一条测试消息")
		default:
			err = fmt.Errorf("不支持的 Webhook 类型: %s", webhook.Type)
		}

		if err != nil {
			c.JSON(http.StatusOK, gin.H{"success": false, "error": err.Error()})
		} else {
			c.JSON(http.StatusOK, gin.H{"success": true})
		}
	})
}
