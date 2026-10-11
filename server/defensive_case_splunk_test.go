package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/securitysource"
)

func TestDefensiveCaseSplunkPreviewCallbackAndRevision(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(fmt.Sprintf("revision_changed_%t", revoke), func(t *testing.T) {
			s, request := defensiveAPIFixture(t)
			in := defensiveAPIInput()
			var calls atomic.Int32
			const token = "test-only-investigation-run-token"
			remoteBody := fmt.Sprintf(`{"preview":false,"lastrow":true,"result":{"_time":%q,"id":"remote-followup","target":"app.example","path":"/ftp/followup.txt","source_ip":"192.0.2.44","message":"original-remote-evidence-marker","large_value":9007199254740993}}`+"\n", in.Scope.Start.Add(2*time.Minute).Format(time.RFC3339Nano))
			endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := calls.Add(1)
				if r.Method != "POST" || r.URL.Path != "/services/search/v2/jobs/export" {
					t.Errorf("unexpected writable or non-export endpoint: %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer "+token {
					t.Error("missing saved encrypted credential")
				}
				if err := r.ParseForm(); err != nil {
					t.Error(err)
					return
				}
				query := r.FormValue("search")
				for _, part := range []string{`index="test_index"`, `sourcetype="web"`, `app\\.example`, `"/ftp"`} {
					if !strings.Contains(query, part) {
						t.Errorf("query missing authorized scope %q: %s", part, query)
					}
				}
				if strings.Contains(query, `sourcetype="alerts"`) || strings.Contains(query, "delete") {
					t.Errorf("query broadened source or became writable: %s", query)
				}
				for key, value := range map[string]string{"earliest_time": fmt.Sprintf("%d.%09d", in.Scope.Start.Unix(), in.Scope.Start.Nanosecond()), "latest_time": fmt.Sprintf("%d.%09d", in.Scope.End.Unix(), in.Scope.End.Nanosecond()), "preview": "false"} {
					if r.FormValue(key) != value {
						t.Errorf("wrong %s: %s", key, r.FormValue(key))
					}
				}
				if n == 1 {
					fmt.Fprintf(w, `{"preview":false,"lastrow":true,"result":{"_time":%q,"id":"seed-splunk","target":"app.example","path":"/ftp/initial.txt"}}`+"\n", in.Scope.Start.Add(time.Minute).Format(time.RFC3339Nano))
					return
				}
				if n != 2 {
					t.Errorf("unbounded remote calls: %d", n)
				}
				if !strings.Contains(query, `tostring('source_ip') = "192.0.2.44"`) || !strings.Contains(query, `followup\\.txt`) {
					t.Errorf("missing literal follow-up filters: %s", query)
				}
				fmt.Fprint(w, remoteBody)
			}))
			defer endpoint.Close()
			pin := sha256.Sum256(endpoint.Certificate().Raw)
			cfg := securitysource.Config{BaseURL: endpoint.URL, Index: "test_index", AuditSourcetype: "web", AlertSourcetype: "alerts", CorrelationField: "artex_verification_id", ActionField: "action", TLSFingerprint: hex.EncodeToString(pin[:])}
			cipher, err := s.encryptSourceCredentials(securitysource.Credentials{Token: token})
			if err != nil {
				t.Fatal(err)
			}
			source, err := s.m.pg.SaveSecuritySource(t.Context(), 0, 0, "mocked investigation source", cfg, true, cipher)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM security_sources WHERE id=$1`, source.ID) })
			in.SourceKind = "splunk"
			in.SourceID = source.ID
			in.ExpectedSourceRevision = source.Revision
			in.Files = nil
			in.Sourcetypes = []string{"web"}
			raw, _ := json.Marshal(in)
			basePath := "/api/defensive/cases"
			w := request("POST", basePath+"/preview", string(raw))
			if w.Code != 200 || calls.Load() != 0 {
				t.Fatal("preview executed remote query", w.Code, w.Body.String())
			}
			w = request("POST", basePath, string(raw))
			if w.Code != 201 {
				t.Fatal(w.Code, w.Body.String())
			}
			var base db.DefensiveCase
			if err = json.Unmarshal(w.Body.Bytes(), &base); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM defensive_cases WHERE id=$1`, base.ID) })
			p := &investigationSplunkRunProvider{revoked: revoke}
			if revoke {
				p.beforeSearch = func() error {
					_, err := s.m.pg.SaveSecuritySource(t.Context(), source.ID, source.Revision, "changed during active run", cfg, true, nil)
					return err
				}
			}
			s.llmProv = p
			s.llmOn = true
			s.llmCfg = agent.Config{Model: "local-scripted-mock", Stream: false}
			path := fmt.Sprintf("%s/%d/runs", basePath, base.ID)
			w = request("POST", path, `{"question":"원격 후속 로그로 파일 요청을 확인하세요."}`)
			if w.Code != 202 {
				t.Fatal(w.Code, w.Body.String())
			}
			var started db.DefensiveCaseRun
			if err = json.Unmarshal(w.Body.Bytes(), &started); err != nil {
				t.Fatal(err)
			}
			done := waitDefensiveCaseRun(t, s, &started)
			var report agent.InvestigatorReport
			if err = json.Unmarshal(done.Result, &report); err != nil {
				t.Fatal(err)
			}
			proofs := []investigationQueryProof{}
			for _, event := range done.Events {
				if event.Kind == "evidence_collection" {
					var proof investigationQueryProof
					if err = json.Unmarshal(event.Payload, &proof); err != nil {
						t.Fatal(err)
					}
					proofs = append(proofs, proof)
				}
			}
			if revoke {
				if done.Status != "insufficient_data" || calls.Load() != 1 || len(proofs) != 0 || len(report.Observations) != 1 || report.Observations[0].Kind != "insufficient_data" {
					t.Fatalf("revoked source still queried or not recorded: status=%s calls=%d proofs=%d result=%s", done.Status, calls.Load(), len(proofs), done.Result)
				}
				return
			}
			if done.Status != "completed" || calls.Load() != 2 || len(proofs) != 1 || len(report.Observations) != 1 || report.Observations[0].Kind != "observed" || p.calls.Load() != 5 {
				t.Fatalf("server callback did not finish actual agent loop: status=%s calls=%d modelcalls=%d proofs=%d result=%s", done.Status, calls.Load(), p.calls.Load(), len(proofs), done.Result)
			}
			proof := proofs[0]
			if !proof.Search.Remote || proof.Search.SourceIP != "192.0.2.44" || len(proof.Collection.Events) != 1 || proof.Collection.Events[0].Ref != report.Observations[0].EvidenceRefs[0] || !strings.Contains(proof.Collection.Events[0].Raw, "9007199254740993") {
				t.Fatalf("remote evidence linkage/original numeric value lost: %+v", proof)
			}
			wantHash := sha256.Sum256([]byte(remoteBody))
			foundOriginal := false
			for _, file := range proof.Collection.Files {
				if file.Name == "splunk-export.jsonl" {
					foundOriginal = file.Content == remoteBody && file.SHA256 == hex.EncodeToString(wantHash[:])
				}
			}
			if !foundOriginal {
				t.Fatal("exact export stream and hash not preserved in evidence event")
			}
			w = request("GET", fmt.Sprintf("%s/%d", path, done.ID), "")
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			var preview db.DefensiveCaseRun
			if err = json.Unmarshal(w.Body.Bytes(), &preview); err != nil {
				t.Fatal(err)
			}
			for _, event := range preview.Events {
				if event.Kind == "evidence_collection" {
					var item investigationQueryProof
					_ = json.Unmarshal(event.Payload, &item)
					for _, file := range item.Collection.Files {
						if file.Content != "" {
							t.Fatal("poll response leaked whole source file")
						}
					}
					if len(item.Collection.Events) != 1 || item.Collection.Events[0].Raw == "" || item.Collection.Query == "" {
						t.Fatal("poll response omitted citation raw or source query")
					}
				}
			}
			w = request("GET", fmt.Sprintf("%s/%d/export", path, done.ID), "")
			if w.Code != 200 || w.Header().Get("Content-Disposition") == "" {
				t.Fatal("export failed", w.Code)
			}
			if strings.Contains(w.Body.String(), token) || strings.Contains(w.Body.String(), "secret_cipher") || strings.Contains(w.Body.String(), string(cipher)) {
				t.Fatal("credential leaked into agent export")
			}
			var exported struct {
				Run db.DefensiveCaseRun `json:"run"`
			}
			if err = json.Unmarshal(w.Body.Bytes(), &exported); err != nil {
				t.Fatal(err)
			}
			foundOriginal = false
			for _, event := range exported.Run.Events {
				if event.Kind == "evidence_collection" {
					var item investigationQueryProof
					_ = json.Unmarshal(event.Payload, &item)
					for _, file := range item.Collection.Files {
						if file.Name == "splunk-export.jsonl" && file.Content == remoteBody {
							foundOriginal = true
						}
					}
				}
			}
			if !foundOriginal {
				t.Fatal("download omitted full remote query proof")
			}
		})
	}
}
