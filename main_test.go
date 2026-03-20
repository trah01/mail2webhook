package main

import (
	"strings"
	"testing"
)

func TestCleanHTML_PreservesReadableStructure(t *testing.T) {
	html := `<html><body><h1>标题</h1><p>第一段</p><p>第二段</p><ul><li>事项A</li><li>事项B</li></ul><a href="https://example.com/path?utm_source=test">点击查看详情</a></body></html>`

	got := cleanHTML(html)

	if !strings.Contains(got, "标题") {
		t.Fatalf("expected title in output, got: %q", got)
	}
	if !strings.Contains(got, "第一段\n\n第二段") {
		t.Fatalf("expected paragraph break preserved, got: %q", got)
	}
	if !strings.Contains(got, "- 事项A") || !strings.Contains(got, "- 事项B") {
		t.Fatalf("expected list items to be bullet points, got: %q", got)
	}
	if !strings.Contains(got, "[点击查看详情](https://example.com/path)") {
		t.Fatalf("expected tracking params removed and markdown link kept, got: %q", got)
	}
}

func TestFormatPlainTextBody_ConvertsURLToMarkdownAndTruncatesLongLinks(t *testing.T) {
	body := "请查看 https://example.com/docs?id=1 和这个超长链接 https://example.com/" + strings.Repeat("a", 650)

	got := formatPlainTextBody(body)

	if !strings.Contains(got, "[https://example.com/docs?id=1](https://example.com/docs?id=1)") {
		t.Fatalf("expected normal URL converted to markdown link, got: %q", got)
	}
	if !strings.Contains(got, "长链接由于超长已被过滤") {
		t.Fatalf("expected overlong URL filtered message, got: %q", got)
	}
}

func TestCleanHTML_EscapesMarkdownLinkTextAndBlocksUnsafeScheme(t *testing.T) {
	html := `<html><body><a href="javascript:alert(1)">x](y)</a><a href="https://example.com/a_(b)?utm_source=xx">括号](链接)</a></body></html>`

	got := cleanHTML(html)

	if strings.Contains(got, "javascript:") {
		t.Fatalf("expected javascript scheme to be removed, got: %q", got)
	}
	if !strings.Contains(got, `x\\]\\(y\\)`) {
		t.Fatalf("expected unsafe-scheme anchor text kept as escaped plain text, got: %q", got)
	}
	if !strings.Contains(got, "括号") || !strings.Contains(got, "链接") {
		t.Fatalf("expected anchor text preserved, got: %q", got)
	}
	if !strings.Contains(got, "https://example.com/a_%28b%29") {
		t.Fatalf("expected escaped markdown link URL destination, got: %q", got)
	}
}

func TestFormatPlainTextBody_FirstLineUsesTwoSpaceIndent(t *testing.T) {
	body := "        第一行有很多前导空格\n\n第二行正文"

	got := formatPlainTextBody(body)

	lines := strings.Split(got, "\n")
	if len(lines) == 0 {
		t.Fatalf("expected non-empty output")
	}
	if !strings.HasPrefix(lines[0], "  ") {
		t.Fatalf("expected first line to have two-space indent, got: %q", lines[0])
	}
	if strings.HasPrefix(lines[0], "   ") {
		t.Fatalf("expected first line to be exactly two spaces, got: %q", lines[0])
	}
}
