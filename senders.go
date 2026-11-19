package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

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
	return checkErrcodeResponse(resp)
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
	return checkErrcodeResponse(resp)
}

// 钉钉和企业微信出错时也返回 HTTP 200，需要检查响应体中的 errcode
func checkErrcodeResponse(resp *http.Response) error {
	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}
	var result struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return fmt.Errorf("响应解析失败: %s", string(bodyBytes))
	}
	if result.ErrCode != 0 {
		return fmt.Errorf("errcode %d: %s", result.ErrCode, result.ErrMsg)
	}
	return nil
}
