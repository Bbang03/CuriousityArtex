# AegisLoop 소스 분석과 첫 구현 범위

최초 분석 기준은 로컬 ARTEX-KO 확장본의 `a530a22`입니다. 이후 추가한 독립 사건·오프라인 평가·실제 실행 루프의 연결 지점을 함께 기록합니다. 상류 저장소의 최신 구현을 확인했다는 의미가 아닙니다. 기존 진단·방어 검증·침해 조사 기능을 재사용합니다.

## 실제 실행 구조

| 역할 | 확인한 소스와 연결 관계 |
|---|---|
| 웹·API | Next.js 정적 내보내기 → Go 바이너리 내장 UI. [`server/server.go`](../server/server.go)의 `Handler`가 인증을 적용한 API를 등록합니다. |
| 작업 실행 | [`server/engine.go`](../server/engine.go)의 `Engine.Run` → `plannerLoop` / `workerLoop` → `Planner.Plan` / `Worker.Execute` 또는 `ExecuteWithMessage`. |
| 메인 에이전트 | [`agent/mainagent.go`](../agent/mainagent.go)의 `MainAgent.Chat`를 작업 대화에서 호출합니다. 계획·실행 에이전트와 역할이 구분됩니다. |
| 계획·도구 실행 | [`agent/planner.go`](../agent/planner.go), [`agent/worker.go`](../agent/worker.go)가 norma의 `agentcore`를 사용합니다. [`agent/tools.go`](../agent/tools.go)의 `ToolSet`과 [`agent/tools_insert.go`](../agent/tools_insert.go)의 도구 구성을 재사용합니다. |
| 진단 결과 | [`agent/finding_recorder.go`](../agent/finding_recorder.go)의 `FindingRecorder`로 저장 책임을 호스트에 위임합니다. 취약점·자산·트래픽 근거는 기존 DB 구조에 남습니다. |
| 방어 검증 | [`server/purple_execution.go`](../server/purple_execution.go), [`server/purple_upload.go`](../server/purple_upload.go), [`db/purple_execution.go`](../db/purple_execution.go)가 재검증 실행과 파일/Splunk 수집 결과를 연결합니다. |
| 로그 수집 | [`investigation/parse.go`](../investigation/parse.go)의 파일 파서, [`securitysource`](../securitysource/)의 범위 제한 Splunk 검색을 재사용합니다. |
| AI 침해 조사 | [`agent/investigator.go`](../agent/investigator.go)의 `RunInvestigation` → Planner의 가설·계획 → Worker의 조회·원문 확인·관측 기록 → 재계획. 공격 도구 세트는 전달하지 않습니다. |
| 실제 실행 루프 | [`server/closedloop_live.go`](../server/closedloop_live.go) → [`db/closedloop_live.go`](../db/closedloop_live.go) → 기존 ARTEX 재검증 실행. [`securitysource/closedloop_rule.go`](../securitysource/closedloop_rule.go)가 실제 파일/Splunk 감사 근거에 구조화 규칙을 적용합니다. |
| 저장·마이그레이션 | [`db/db.go`](../db/db.go)가 내장 [`db/schema.sql`](../db/schema.sql)을 시작 시 적용합니다. 기존 테이블과 암호화 인증 정보를 보존하는 추가 스키마 방식입니다. |

기존 `finding_investigations`와 `finding_investigation_runs`는 취약점 FK가 필수입니다. 따라서 메뉴 이동만으로는 경보·로그에서 독립적으로 조사를 시작할 수 없습니다.

## 재사용과 추가 개발

| 구분 | 범위 |
|---|---|
| 그대로 재사용 | Offensive 작업·Planner·Worker·도구, 취약점 및 트래픽 근거, 인증, LLM 설정, 파일 파서, Splunk 연결, 제한된 조사 엔진. |
| 최소 수정 | 기존 웹 메뉴를 통합 개요·Offensive·Defensive·Closed-loop로 구성. 기존 대시보드와 상세 페이지 경로를 유지하고 Offensive 개요를 별도 제공. |
| 신규 | 취약점 없이 생성하는 방어 사건, 사건별 불변 로그 스냅샷과 AI 실행 기록, 규칙 후보의 별도 데이터 평가, 실제 재검증 한 쌍과 관측·규칙 revision, 원본 내보내기. |

최초 구현의 연결 키는 `finding_id`(선택), `case_id`(선택), 평가 iteration ID와 원본 SHA-256입니다. 링크는 관련 근거를 연결하며, 해당 로그가 실제 공격 실행에서 발생했다는 사실을 자동으로 증명하지 않습니다.

실제 실행 루프는 원본 `finding_id`, baseline/current 방어 execution ID, 각각 다른 검증 UUID와 재검증 시간 구간을 함께 저장합니다. 원본 계획·근거와 로그 연결의 변경 상태를 확인하고, 현재 규칙 revision 및 로그 SHA-256에 관측을 연결합니다. 기존 alert와 새 재실행의 동일 감사 로그에서 계산한 기준/후보 shadow 결과는 별도로 보존합니다. 운영 SIEM의 후보 자동 배포는 이 API에 포함하지 않습니다.

## UI 선택

기존 Next.js UI 확장을 선택합니다. 로그인·권한·설정·정적 배포·컴포넌트를 재사용할 수 있고, 두 프론트엔드의 인증·타입·배포 동기화 비용을 피할 수 있습니다. 각 업무의 API와 저장 구조는 분리하므로 독립 테스트가 가능합니다. 기존 Offensive 대시보드는 `/offensive`, 통합 개요는 `/dashboard`, 독립 사건은 `/defensive`, 평가 이력은 `/closed-loop`입니다.

## 이번 MVP와 후속 요구사항

이번 구현은 **독립 사건 조사, 오프라인 규칙 개선 평가와 사용자가 시작하는 실제 실행 루프**를 제공합니다. 실제 루프는 기준 ARTEX 재검증 → 실제 파일/Splunk 근거 → 기준 감사 로그의 후보 개선 → 새 UUID 재검증 → 근거 비교입니다. 한 루프는 두 실행으로 고정하며, 실제 경보와 그림자 규칙 일치를 구분합니다. 공격 두 번만으로 precision/recall/FPR/MTTD/MTTR을 산출하지 않습니다.

기존 로그 규칙 평가 탭에서는 후보를 개선용 데이터만 보고 생성하고, 같은 평가용 데이터에 기준·후보 규칙을 각각 적용해 TP/FP/TN/FN과 precision/recall/FPR을 계산합니다. 반복 또는 동일 내용의 개선·평가 이벤트를 거부하고 분모가 없는 지표는 `null`로 남깁니다. 이 탭의 합성 예제 수치를 실제 실행 루프의 성능 수치로 사용하지 않습니다.

다음 항목은 별도 구현·검증이 필요합니다. 기존 범용 도구 실행이 있다는 이유로 전용 기능이 구현됐다고 간주하지 않습니다.

- 코드·바이너리 분석, Scanner·Fuzzer의 구조화된 어댑터와 실행 증거 계약.
- 정답이 있는 취약점 벤치마크, 공격 경로·PoC 재현성 및 진단 오탐 평가.
- Sigma·Suricata 실행 엔진을 사용하는 규칙 검증과 운영 시스템 배포 승인.
- ATT&CK coverage의 분모·시나리오 범위를 명시한 평가.
- 실제 경보 수신 기반 Alert Triage와 운영 대응 Playbook, MTTR 측정.
- 평가 결과를 Offensive 계획에 정책·승인을 거쳐 반영하는 자동화.

이번 규칙 비교는 제한된 JSON 필드 매처이며 Sigma·Suricata 실행을 대신하지 않습니다. 라벨의 정답성은 업로더 확인에 의존합니다. 평가용 데이터도 반복적으로 보고 규칙을 조정하면 평가 정보가 개선에 사용되므로, 연구의 최종 성능 주장은 별도 미사용 데이터로 다시 검증해야 합니다.

Cyber Range와 Juice Shop은 별도 실습 대상입니다. 기본 제품 설치는 ARTEX와 PostgreSQL 두 서비스로 유지합니다. AWS는 실제 동작을 시연하고 증적을 수집하기 위한 임시 환경이며, 장기 서비스 인프라 운영은 제품 목표와 구분합니다.
