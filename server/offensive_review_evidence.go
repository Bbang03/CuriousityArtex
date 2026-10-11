package server

// Candidate review consumes an immutable, bounded evidence bundle. Preparing
// it does not execute uploaded code, issue target requests, or call a model.
import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/offensivereview"
)

type preparedOffensiveReview struct {
	Kind           string
	EvidenceSHA256 string
	LegacyTaskID   string
	Candidates     []offensivereview.Candidate
	AutoResults    map[string]offensivereview.Result
}

type offensiveReviewArtifact struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

type offensiveReviewReport struct {
	offensiveRun
	Tool        string                        `json:"tool"`
	ToolVersion string                        `json:"tool_version"`
	Summary     string                        `json:"summary"`
	Limitations []string                      `json:"limitations"`
	Candidates  []offensiveReviewRawCandidate `json:"candidates"`
	Artifacts   []offensiveReviewArtifact     `json:"artifacts"`
}

// Scanner evidence is an object, not the prepared excerpt list. Never unmarshal
// its user-controlled shape directly into the trusted review input.
type offensiveReviewRawCandidate struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	RuleID  string `json:"rule_id"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Message string `json:"message"`
}

func offensiveReviewDigest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func offensiveReviewClip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "\n[근거 길이 제한으로 이후 내용 생략]"
}

var offensiveReviewSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{12,}\b`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`),
	regexp.MustCompile(`(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)(["']?(?:password|passwd|secret|access_token|refresh_token|api_key|authorization|cookie|set-cookie)["']?\s*[:=]\s*)["'][^"'\r\n]+["']`),
	regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`),
}

func offensiveReviewRedact(s string) string {
	for _, p := range offensiveReviewSecretPatterns {
		s = p.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}

func (s *Server) prepareOffensiveReview(ctx context.Context, id string) (*preparedOffensiveReview, error) {
	cfg, _ := loadOffensiveConfig()
	if cfg == nil {
		return nil, errors.New("진단 실행기 연결을 확인하세요")
	}
	raw, status, err := offensiveRequest(ctx, cfg, "GET", "/runs/"+id, nil, offensiveJSONLimit)
	if err != nil || status != 200 {
		return nil, errors.New("도구 진단 실행을 읽을 수 없습니다")
	}
	var run offensiveReviewReport
	if json.Unmarshal(raw, &run) != nil || run.ID != id || !offensiveTargetAllowed(run.Kind, run.TargetID) || run.Status != "completed" {
		return nil, errors.New("완료된 도구 진단만 후보를 검토할 수 있습니다")
	}
	read := func(name string, artifacts []offensiveReviewArtifact) ([]byte, error) {
		var digest string
		for _, a := range artifacts {
			if a.Name == name {
				if digest != "" {
					return nil, errors.New("중복 근거 파일")
				}
				digest = a.SHA256
			}
		}
		if !offensiveSHA256Pattern.MatchString(digest) {
			return nil, fmt.Errorf("근거 해시가 없습니다: %s", name)
		}
		b, code, e := offensiveRequest(ctx, cfg, "GET", "/runs/"+id+"/artifacts/"+name, nil, offensiveArtifactLimit)
		if e != nil || code != 200 || offensiveReviewDigest(b) != digest {
			return nil, fmt.Errorf("근거 무결성을 확인할 수 없습니다: %s", name)
		}
		if strings.Contains(string(b), cfg.token) {
			return nil, errors.New("근거에 실행기 인증값이 포함되어 있습니다")
		}
		return b, nil
	}
	reportBytes, err := read("report.json", run.Artifacts)
	if err != nil {
		return nil, err
	}
	var report offensiveReviewReport
	if json.Unmarshal(reportBytes, &report) != nil || report.ID != id || report.Kind != run.Kind || report.TargetID != run.TargetID || report.Status != "completed" {
		return nil, errors.New("저장된 보고서와 진단 실행이 일치하지 않습니다")
	}
	if len(report.Candidates) > 100 {
		return nil, errors.New("검토 후보는 실행당 최대 100개입니다")
	}
	var sourceRoot string
	if report.Kind == "source" {
		if report.TargetID == "benchmark" {
			sourceRoot = "/app/offensive/benchmark"
		} else {
			if s.m == nil || s.m.dir == "" {
				return nil, errors.New("소스 저장 경로가 없습니다")
			}
			sourceRoot = filepath.Join(s.m.dir, "offensive", "targets", report.TargetID, "source")
		}
	}
	artifacts := map[string][]byte{}
	names := []string{"http.har", "scoped-openapi.json"}
	if report.Kind == "source" {
		names = []string{"source-manifest.json"}
	}
	if len(report.Candidates) > 0 {
		for _, name := range names {
			b, e := read(name, report.Artifacts)
			if e != nil {
				return nil, e
			}
			artifacts[name] = b
		}
	}
	prepared, err := prepareOffensiveCandidates(report, reportBytes, artifacts, sourceRoot)
	if err != nil {
		return nil, err
	}
	prepared.LegacyTaskID = run.TaskID
	return prepared, nil
}

type offensiveReviewHAR struct {
	Log struct {
		Entries []offensiveReviewHTTP `json:"entries"`
	} `json:"log"`
}

type offensiveReviewHTTP struct {
	Request struct {
		Method string `json:"method"`
		URL    string `json:"url"`
	} `json:"request"`
	Response struct {
		Status  int `json:"status"`
		Content struct {
			Text     string `json:"text"`
			Encoding string `json:"encoding"`
			MimeType string `json:"mimeType"`
		} `json:"content"`
	} `json:"response"`
}

func offensiveReviewPathMatch(template, path string) bool {
	a, b := strings.Split(template, "/"), strings.Split(path, "/")
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] && !(strings.HasPrefix(a[i], "{") && strings.HasSuffix(a[i], "}") && b[i] != "") {
			return false
		}
	}
	return true
}

func offensiveReviewOrigin(u *url.URL) string {
	port := u.Port()
	if port == "" {
		if u.Scheme == "http" {
			port = "80"
		} else if u.Scheme == "https" {
			port = "443"
		}
	}
	return strings.ToLower(u.Scheme + "://" + u.Hostname() + ":" + port)
}

func prepareOffensiveCandidates(report offensiveReviewReport, reportBytes []byte, artifacts map[string][]byte, sourceRoot string) (*preparedOffensiveReview, error) {
	p := &preparedOffensiveReview{Kind: report.Kind, Candidates: []offensivereview.Candidate{}, AutoResults: map[string]offensivereview.Result{}}
	manifest := map[string]string{}
	var har offensiveReviewHAR
	var schema struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if len(report.Candidates) > 0 {
		if report.Kind == "source" {
			var entries []struct {
				File   string `json:"file"`
				SHA256 string `json:"sha256"`
			}
			if json.Unmarshal(artifacts["source-manifest.json"], &entries) != nil {
				return nil, errors.New("소스 근거 목록을 읽을 수 없습니다")
			}
			for _, entry := range entries {
				if !offensiveSHA256Pattern.MatchString(entry.SHA256) || manifest[entry.File] != "" {
					return nil, errors.New("소스 근거 목록이 올바르지 않습니다")
				}
				manifest[entry.File] = entry.SHA256
			}
		} else if report.Kind == "api" {
			if json.Unmarshal(artifacts["http.har"], &har) != nil || json.Unmarshal(artifacts["scoped-openapi.json"], &schema) != nil {
				return nil, errors.New("HTTP 진단 근거를 읽을 수 없습니다")
			}
		} else {
			return nil, errors.New("지원하지 않는 후보 종류입니다")
		}
	}
	seen := map[string]bool{}
	priorities := map[string]int{}
	for _, rawCandidate := range report.Candidates {
		c := offensivereview.Candidate{ID: rawCandidate.ID, Title: rawCandidate.Title, RuleID: rawCandidate.RuleID, File: rawCandidate.File, Line: rawCandidate.Line, Message: rawCandidate.Message}
		if !regexp.MustCompile(`^C[0-9]{4}$`).MatchString(c.ID) || seen[c.ID] {
			return nil, errors.New("후보 식별자가 올바르지 않습니다")
		}
		seen[c.ID] = true
		c.Kind = report.Kind
		c.Message = offensiveReviewClip(offensiveReviewRedact(c.Message), 2000)
		c.Title = offensiveReviewClip(offensiveReviewRedact(c.Title), 300)
		c.RuleID = offensiveReviewClip(offensiveReviewRedact(c.RuleID), 300)
		c.Evidence = []offensivereview.Evidence{{Ref: c.ID + ":report", Path: "report.json", SHA256: offensiveReviewDigest(reportBytes), Text: offensiveReviewClip(offensiveReviewRedact(fmt.Sprintf("도구: %s %s\n종류: %s\n후보 %s: %s\n%s\n한계: %s\n정적 후보/관측 응답은 취약점 확정이 아닙니다.", report.Tool, report.ToolVersion, report.Kind, c.ID, c.Title, c.Message, strings.Join(report.Limitations, " / "))), 4000)}}
		if report.Kind == "source" {
			b, err := offensiveReviewReadSource(sourceRoot, c.File, manifest[c.File])
			if err != nil {
				return nil, err
			}
			lines := strings.Split(string(b), "\n")
			if c.Line < 1 || c.Line > len(lines) {
				return nil, errors.New("후보 소스 줄 번호가 범위를 벗어났습니다")
			}
			start, end := 0, len(lines)
			if len(lines) > 300 {
				start = max(0, c.Line-121)
				end = min(len(lines), c.Line+120)
			}
			text := fmt.Sprintf("해시가 원본 manifest와 일치합니다. 파일 총 %d줄 중 %d~%d줄. 생략된 호출부/함수는 검증한 것으로 간주하지 마세요.\n", len(lines), start+1, end)
			for i := start; i < end; i++ {
				text += fmt.Sprintf("%d: %s\n", i+1, lines[i])
			}
			c.Evidence = append(c.Evidence, offensivereview.Evidence{Ref: c.ID + ":source", Path: c.File, SHA256: manifest[c.File], StartLine: start + 1, Text: offensiveReviewClip(offensiveReviewRedact(text), 22000)})
			priorities[c.ID] = 20
			if strings.Contains(c.RuleID, "runtime-exec") || strings.Contains(c.RuleID, "sql-") {
				priorities[c.ID] = 5
			}
		} else {
			priority, auto, err := offensiveReviewAPIEvidence(&c, report, har, schema.Paths, artifacts)
			if err != nil {
				return nil, err
			}
			priorities[c.ID] = priority
			if auto != nil {
				p.AutoResults[c.ID] = *auto
			}
		}
		// JSON escaping and multibyte source text count toward the model's byte
		// budget, not rune counts. Keep headroom under the reviewer's 96 KiB cap.
		for {
			encoded, _ := json.Marshal(c)
			if len(encoded) <= 72<<10 {
				break
			}
			largest := -1
			for i := range c.Evidence {
				if largest < 0 || len(c.Evidence[i].Text) > len(c.Evidence[largest].Text) {
					largest = i
				}
			}
			if largest < 0 || len(c.Evidence[largest].Text) < 256 {
				return nil, errors.New("후보 근거가 크기 제한을 초과했습니다")
			}
			c.Evidence[largest].Text = offensiveReviewClip(c.Evidence[largest].Text, len([]rune(c.Evidence[largest].Text))/2)
		}
		p.Candidates = append(p.Candidates, c)
	}
	sort.SliceStable(p.Candidates, func(i, j int) bool { return priorities[p.Candidates[i].ID] < priorities[p.Candidates[j].ID] })
	// Includes prepared source bytes through their hashes, artifact identity and
	// selection/ordering so resume refuses changed evidence or candidate sets.
	identity, _ := json.Marshal(struct {
		Report     string
		Candidates []offensivereview.Candidate
	}{offensiveReviewDigest(reportBytes), p.Candidates})
	p.EvidenceSHA256 = offensiveReviewDigest(identity)
	return p, nil
}

func offensiveReviewAPIEvidence(c *offensivereview.Candidate, report offensiveReviewReport, har offensiveReviewHAR, paths map[string]map[string]json.RawMessage, artifacts map[string][]byte) (int, *offensivereview.Result, error) {
	method, template, ok := strings.Cut(c.Title, " ")
	if !ok || (method != "GET" && method != "HEAD") || len(paths[template][strings.ToLower(method)]) == 0 {
		return 0, nil, errors.New("후보가 저장된 API 요청 범위와 일치하지 않습니다")
	}
	base := report.TargetSnapshot.URL
	if base == "" && report.TargetID == "crapi" {
		base = "http://crapi-web:80"
	}
	u, err := url.Parse(base)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return 0, nil, errors.New("진단 API 주소를 확인할 수 없습니다")
	}
	var matches []offensiveReviewHTTP
	for _, e := range har.Log.Entries {
		req, err := url.Parse(e.Request.URL)
		if err == nil && req.User == nil && offensiveReviewOrigin(req) == offensiveReviewOrigin(u) && e.Request.Method == method && offensiveReviewPathMatch(strings.TrimRight(u.Path, "/")+template, req.Path) {
			matches = append(matches, e)
		}
	}
	priority, authOnly := 30, len(matches) > 0
	for _, e := range matches {
		if e.Response.Status != 401 && e.Response.Status != 403 {
			authOnly = false
		}
		if e.Response.Status >= 500 {
			priority = 0
		} else if e.Response.Status >= 200 && e.Response.Status < 300 && priority > 5 {
			priority = 5
		}
	}
	sort.SliceStable(matches, func(i, j int) bool { return matches[i].Response.Status > matches[j].Response.Status })
	refs := []string{}
	for i, e := range matches {
		if i >= 3 {
			break
		}
		u, _ := url.Parse(e.Request.URL)
		body := e.Response.Content.Text
		if e.Response.Content.Encoding == "base64" {
			if b, err := base64.StdEncoding.DecodeString(body); err == nil {
				body = string(b)
			} else {
				body = "[본문 디코딩 실패]"
			}
		}
		keys := []string{}
		for k := range u.Query() {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ref := fmt.Sprintf("%s:http:%d", c.ID, i+1)
		refs = append(refs, ref)
		c.Evidence = append(c.Evidence, offensivereview.Evidence{Ref: ref, Path: "http.har", SHA256: offensiveReviewDigest(artifacts["http.har"]), Text: fmt.Sprintf("기존 진단에서 기록한 응답(%d건 중 최대3건 발췌). 새 재현 요청 아님.\n%s %s\n쿼리 필드(값 제외): %s\nHTTP %d\n%s", len(matches), method, u.Path, strings.Join(keys, ", "), e.Response.Status, offensiveReviewClip(offensiveReviewRedact(body), 4000))})
	}
	c.Evidence = append(c.Evidence, offensivereview.Evidence{Ref: c.ID + ":schema", Path: "scoped-openapi.json", SHA256: offensiveReviewDigest(artifacts["scoped-openapi.json"]), Text: offensiveReviewClip(offensiveReviewRedact(string(paths[template][strings.ToLower(method)])), 3000)})
	if report.TargetSnapshot.InputMode == "url" || report.TargetSnapshot.InputMode == "har" {
		c.Evidence[len(c.Evidence)-1].Text = "URL/HAR에서 추정한 요청 목록이며 공식 응답 계약이 아닙니다.\n" + c.Evidence[len(c.Evidence)-1].Text
	}
	if len(matches) == 0 {
		c.Evidence = append(c.Evidence, offensivereview.Evidence{Ref: c.ID + ":missing", Text: "선택된 경로/출처에 맞는 응답 원문을 찾지 못했습니다. 보고서의 메시지만으로 재현이나 취약점을 확정하지 마세요."})
	}
	if authOnly {
		return 90, &offensivereview.Result{CandidateID: c.ID, Status: "auth_required", Summary: "인증·인가로 제한된 응답", Rationale: fmt.Sprintf("해당 경로의 저장된 응답 %d건이 모두 401/403입니다. 보안 취약점으로 확정하지 않고 인증 조건이 갖춰진 별도 검증이 필요한 것으로 분류했습니다. AI 호출 없이 실제 응답 코드로 분류했습니다.", len(matches)), EvidenceRefs: refs, Limitations: []string{"인증 후 행동과 계정 간 인가를 검증하지 않았습니다.", "미문서화 상태코드는 별도의 명세 품질 문제일 수 있습니다."}}, nil
	}
	return priority, nil, nil
}

func offensiveReviewReadSource(root, relative, digest string) ([]byte, error) {
	if root == "" || !offensiveSHA256Pattern.MatchString(digest) || relative == "" || filepath.IsAbs(relative) || filepath.ToSlash(filepath.Clean(relative)) != relative || strings.Contains(relative, "\\") || relative == ".." || strings.HasPrefix(relative, "../") {
		return nil, errors.New("소스 근거 경로/해시가 올바르지 않습니다")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, errors.New("소스 경로 확인 실패")
	}
	// Check every component, including the selected root, before opening through
	// os.Root (which also prevents resolution from escaping this directory).
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Join(abs, relative), string(filepath.Separator)), string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("소스 파일이 없거나 심볼릭 링크입니다")
		}
	}
	r, err := os.OpenRoot(abs)
	if err != nil {
		return nil, errors.New("소스 디렉터리 열기 실패")
	}
	defer r.Close()
	f, err := r.Open(relative)
	if err != nil {
		return nil, errors.New("소스 파일 열기 실패")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("소스 파일 종류/크기 제한")
	}
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(b) > 1<<20 || offensiveReviewDigest(b) != digest {
		return nil, errors.New("진단 이후 소스가 변경됐습니다. 새 도구 진단을 실행하세요")
	}
	return b, nil
}
