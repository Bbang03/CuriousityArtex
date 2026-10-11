# WAF·Splunk 방어 검증 실습

ARTEX로 로컬 취약점 진단을 실행하고, 같은 요청이 WAF에서 차단되는지와 Splunk에서 탐지되는지를 확인하는 선택형 실습 환경입니다. Juice Shop, ModSecurity·OWASP CRS, 로그 수집기와 Splunk를 별도 Docker Compose 프로젝트로 실행합니다. 제품의 기본 실행은 기존처럼 ARTEX와 PostgreSQL입니다.

## 연결 구조

```text
ARTEX → purple-lab-target:8080 → WAF → Juice Shop
                                  ↓ 실제 검사·조치 로그
                              로그 수집기 → Splunk
                                              ↓ 실제 탐지 규칙 결과
                                      ARTEX 방어 검증
```

브라우저에서 대상에 접속할 때도 WAF 주소를 사용합니다. Juice Shop 직접 주소로 요청하면 WAF 차단 검증에 사용할 수 없습니다. WAF 검사 결과와 실제 요청 처리 기록은 감사 로그로 수집하며, Splunk 탐지 규칙의 결과는 별도의 경보 로그로 수집합니다. 초기 WAF 모드는 `DetectionOnly`이며 `blocking`으로 바꿔야 실제 차단을 검증할 수 있습니다. HTTP 상태 코드나 검증 UUID 자체를 탐지·차단 근거로 삼지 않습니다.

| 접속 대상 | 기본 주소 | 용도 |
| --- | --- | --- |
| ARTEX | <http://localhost:8787> | 진단·방어 검증·침해 조사 |
| WAF 앞단의 Juice Shop | <http://localhost:18790> | 브라우저에서 실습 대상 확인 |
| Splunk Web | <http://localhost:18000> | 수집 로그와 탐지 규칙 결과 확인 |
| ARTEX 컨테이너의 진단 대상 | `http://purple-lab-target:8080` | WAF를 통과하는 진단·재검증 |
| ARTEX 컨테이너의 Splunk 관리 API | `https://purple-lab-splunk:8089` | 읽기 전용 로그 조회 |

외부에 공개하는 웹 포트는 로컬 컴퓨터의 `127.0.0.1`에 연결합니다. ARTEX는 실습용 Docker 네트워크 `artex-purple-lab-front`에 연결하여 위 별칭에 접근합니다. ARTEX 컨테이너에서 `localhost:18790`이나 `localhost:18000`을 진단·검색 주소로 사용하지 마세요.

## 실습 환경 시작

Docker Desktop 또는 Docker Engine과 Compose v2, 호스트의 Python 3가 필요합니다. Splunk 컨테이너의 메모리 상한은 4 GiB이며 Juice Shop·WAF·ARTEX도 함께 실행하므로 Docker에 충분한 메모리를 할당합니다. ARTEX를 먼저 시작한 뒤 저장소 루트에서 다음 명령을 실행합니다.

```sh
./scripts/local-start.sh
./scripts/purple-lab.sh init
./scripts/purple-lab.sh start --accept-splunk-terms
./scripts/purple-lab.sh status
```

명령의 `--accept-splunk-terms`는 [Splunk 일반 약관](https://www.splunk.com/en_us/legal/splunk-general-terms.html)과 이미지의 라이선스 조건에 동의한다는 명시적 선택입니다. 약관을 확인하고 동의하는 경우에만 사용합니다. `init`은 로컬 폴더와 인증 정보만 준비하며 약관에 동의하거나 컨테이너를 실행하지 않습니다. 한 번 동의를 기록한 이후에는 `start`만으로 다시 시작할 수 있습니다.

최초 실행은 이미지 다운로드와 Splunk 초기 구성 때문에 시간이 걸릴 수 있습니다. Apple Silicon에서는 Splunk의 `linux/amd64` 이미지가 에뮬레이션으로 실행됩니다. 준비 상태를 확인한 뒤 다음 단계로 진행합니다.

Splunk Enterprise의 기본 Trial은 60일입니다. Splunk Free에는 경보 기능과 사용자·역할 기능이 없으므로 이 실습의 실제 경보 및 검색 전용 계정 구성에는 유효한 Enterprise Trial 또는 해당 기능을 지원하는 라이선스가 필요합니다. [Splunk 공식 라이선스 안내](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/configure-splunk-licenses/about-splunk-free)를 참고하세요.

실습 인증 정보와 설정은 Git에서 제외된 `.local-runtime/purple-lab/`, 내보낸 근거는 `evidence-local/purple-lab/`에 보관합니다. 비밀번호나 토큰을 GitHub에 올리지 마세요. 실습 환경에서 생성한 인덱스·검색 계정은 이 실습용 Splunk에만 사용합니다.

## 먼저 환경 자체 확인

2026-10-10 로컬 환경에서 실제 WAF와 Splunk를 실행하여 세 가지 사례를 확인했습니다. 각 사례의 감사 로그는 3건, 실제 Splunk 경보는 각각 2건·2건·0건으로 합계 13건입니다. ARTEX의 Splunk 수집 함수로도 같은 5건·5건·3건을 읽었으며 모두 조회 완료, 경고 0건을 확인했습니다. 수집기·TLS·Splunk 구성의 Python 단위 테스트 42개도 통과했습니다. 화면과 검증 범위는 [실제 실습 검증 기록](evidence/purple-lab-2026-10-10.md)에 정리했습니다.

```sh
./scripts/purple-lab.sh check

# Splunk를 제외하고 실행 중인 WAF와 감사 로그만 확인
./scripts/purple-lab.sh check --waf-only
```

기본 `check`는 탐지·미차단, 탐지·차단, 경보 끄기의 세 가지 사례를 실제 요청과 Splunk 검색으로 확인합니다. 검사가 끝나면 WAF를 `DetectionOnly`, Splunk 경보를 `on`으로 복원합니다. `--waf-only`는 이미 실행 중인 WAF의 처리·감사 로그만 확인하고 WAF를 `DetectionOnly`로 복원하며, Splunk를 시작하거나 약관에 동의하지 않습니다.

각 검사는 고정 Juice Shop 연습파일 `acquisitions.md`의 바이트 수와 SHA-256을 대상 컨테이너에서 읽어 실제 HTTP 응답과 대조합니다. 탐지 전용 구간은 전체 909바이트 파일이 전달되는지, 차단 구간은 같은 파일이 전달되지 않고 WAF 감사 로그에 명시적 차단이 남는지 확인합니다. 원본 파일 본문·계정·토큰은 출력하지 않습니다. 이 확인은 의도적으로 취약한 로컬 연습파일의 접근 성공만 입증하며, 기업 데이터 유출이나 SQLi 악용 성공을 의미하지 않습니다. 현재 준비 상태와 실제 확인 결과는 [환경 준비 기록](evidence/purple-lab-ready-2026-10-10.md)에 정리합니다.

경보를 끄는 사례는 수집·판정 경로가 정상 동작하는지 확인하는 음성 대조입니다. 실제 탐지 성능이나 규칙 개선 효과의 평가 자료로 사용하지 않습니다. 성능 검증은 경보를 켠 상태에서 실제로 놓친 행위와 정상 활동을 함께 수집하고, 규칙을 바꾼 뒤 새 실행으로 확인해야 합니다.

전체 검사 기록은 `evidence-local/purple-lab/environment-check.json`, WAF만 검사한 기록은 `evidence-local/purple-lab/waf-check.json`에 저장됩니다. 이 기록은 독립된 환경 확인이며 ARTEX의 취약점·방어 검증 실행을 생성하지 않습니다. **확인 명령이 만든 UUID와 로그를 다른 ARTEX 재검증의 근거로 대신 업로드하지 마세요.** 실제 ARTEX 실행은 해당 화면에서 생성한 UUID로 별도 검증합니다.

환경 확인은 WAF를 통과하는 실제 로컬 요청, 감사 로그 수집과 Splunk 규칙 실행 결과를 검사합니다. ARTEX의 LLM 진단을 대신 완료하거나 취약점 결과를 생성하지 않습니다. ARTEX 진단·재검증에는 **시스템 → LLM 설정**에서 활성화한 연결이 필요합니다.

실습에는 두 종류의 탐지 조건이 있습니다.

- **정보 노출 경로 보호:** Juice Shop의 `/ftp`와 하위 경로에 대한 명시적인 실습 정책입니다. 이 경로 접근을 허용·탐지하거나 차단하는 개선 전후 비교에 사용합니다.
- **OWASP CRS 공격 검사:** CRS가 식별하는 SQL 인젝션 등 요청 패턴을 검사합니다. 이번 탐지 전용 확인에서 SQLi 요청의 백엔드 응답은 HTTP 500이었으며, 규칙 일치는 SQLi 악용 성공을 입증하지 않습니다. CRS 요청의 차단 결과를 `/ftp` 정보 노출 취약점의 개선 근거로 사용하지 않습니다.

## ARTEX에 연결하고 새 진단 실행

```sh
./scripts/purple-lab.sh connect
```

`connect`는 기본 로컬 ARTEX인 `artex-local-artex-1`이 `http://127.0.0.1:8787`에서 실행 중이고, 같은 체크아웃에 `.local-runtime/jwt.key`가 보존된 구성을 대상으로 합니다. 기존 키를 메모리에서 사용하여 짧은 API 인증을 만들며 비밀번호를 재설정하거나 인증 정보를 출력하지 않습니다. 실습용 Splunk 연결과 새 WAF 자산을 추가하고 ARTEX 컨테이너의 실습 네트워크 접근을 준비합니다. 기존 Splunk 연결과 기존 취약점의 원래 대상 주소는 변경하지 않습니다. 연결 화면은 **방어 검증 → Splunk 로그 연결**에서 확인할 수 있으며, 추가되는 연결명은 **로컬 Purple 실습 Splunk**입니다.

1. 새로운 진단 작업을 만들고 대상에 **`http://purple-lab-target:8080`**을 지정합니다. 예전의 `http://juice-shop:3000` 대상은 WAF를 우회할 수 있으므로 새 실습 작업을 사용합니다.
2. 목표를 `/ftp` 공개 파일·목록의 접근 여부 확인처럼 좁게 지정하고, 이 로컬 대상만 점검하도록 범위를 정합니다.
3. 실제 진단이 발견한 취약점 상세를 엽니다. 기존 취약점 3번을 새 WAF 주소로 고쳐 사용하지 않습니다.
4. **방어 검증**에서 탐지 가설과 방어 계획을 저장한 뒤 **로컬 Purple 실습 Splunk** 연결을 선택합니다.
5. **ARTEX 진단 + 방어 검증 시작**을 누릅니다. 실제 재현 요청에는 서버가 만든 `X-ARTEX-Verification-ID`가 전달되며, 감사 로그와 경보에 같은 UUID가 남아야 합니다.
6. 진단이 정상 종료된 뒤 최소 60초를 기다리고, 로그 전달·경보 처리가 끝났는지 확인한 다음 **로그·경보 수집**을 누릅니다.

연결 테스트 성공은 Splunk 관리 API의 통신·인증 확인입니다. 실제 감사 로그나 탐지 경보가 있다는 뜻은 아니므로 각 실행의 근거를 수집해 확인합니다.

실습 연결의 설정은 다음과 같습니다. 인증서 SHA-256 지문은 실행 중인 실습 Splunk에서 확인한 정확한 값이며, 비밀값이 없는 `.local-runtime/purple-lab/connector-template.json`에도 저장됩니다.

| 설정 | 값 |
| --- | --- |
| 인덱스 | `artex_lab` |
| 감사 sourcetype | `artex:lab:audit` |
| 경보 sourcetype | `artex:lab:alert` |
| UUID 필드 | `artex_verification_id` |
| 실제 조치 필드 | `action` |
| 읽기 전용 계정 | `artex_lab_search` |

검색 계정은 이 인덱스의 조회와 서버 정보 확인에 필요한 권한만 사용합니다. 관리자 인증은 실습 Splunk의 초기 구성에 사용하고 ARTEX 연결에 저장하지 않습니다. 인덱스 보존 상한은 256 MiB·7일이므로 장기간 실습에서 오래된 기록은 사라질 수 있습니다.

Splunk 경보 규칙은 1분마다 최근 3분의 실제 WAF 감사 이벤트에서 `/ftp` 보호 규칙 `1001001` 또는 CRS SQL 인젝션 규칙 `942xxx`가 일치한 요청을 검사합니다. 모든 CRS 일치를 경보로 복제하지 않으며, 원래 `rule_ids`는 감사 로그에 보존합니다. 경보의 검색 시각 `_time`은 탐지 대상 요청의 원래 시각이며, 경보가 생성된 시각은 `alert_created_at`으로 별도 보존합니다. 규칙 실행과 인덱싱이 늦을 수 있으므로 ARTEX의 종료 후 60초 대기만으로 전달 완료를 가정하지 말고 경보·처리 상태를 확인한 뒤 수집하세요. 늦게 인덱싱된 경보는 같은 실행에서 재수집할 수 있습니다.

## 세 가지 비교 실습

정책은 새 재검증을 시작하기 전에 설정하고, 해당 실행의 로그 수집까지 유지합니다. 경보를 off에서 on으로 바꿀 때 새 활성화 시각을 기록하여 꺼져 있던 구간의 요청이 이후 조회에서 소급 탐지되지 않도록 합니다. 끄기 전에 이미 시작된 검색은 완료될 수 있으므로 상태를 확인한 뒤 새 실습 요청을 보냅니다. 같은 취약점과 같은 Splunk 연결을 사용하여 새 UUID의 실행을 만듭니다.

| 설정 | 명령 | 기대하는 관측 |
| --- | --- | --- |
| 검사만 하고 경보 발생 | `mode detection`, `alerts on` | 감사 로그의 허용 조치와 같은 UUID의 실제 경보 |
| 공격 차단과 경보 발생 | `mode blocking`, `alerts on` | 감사 로그의 명시적 차단 조치와 같은 UUID의 실제 경보 |
| 검사만 하고 경보 끄기 | `mode detection`, `alerts off` | 감사 로그는 있지만 해당 UUID의 경보는 없음 |

```sh
# 탐지되지만 요청은 통과하는 기준 실행
./scripts/purple-lab.sh mode detection
./scripts/purple-lab.sh alerts on

# 기준 실행과 근거 수집이 끝난 후 차단 정책 적용
./scripts/purple-lab.sh mode blocking
./scripts/purple-lab.sh alerts on

# 미탐 상황을 확인할 별도 실행
./scripts/purple-lab.sh mode detection
./scripts/purple-lab.sh alerts off
```

`mode`는 WAF 컨테이너를 재생성하므로 모드를 바꾼 뒤 준비 상태를 확인하고 새 ARTEX 재검증을 시작합니다. 다음 HTTP 확인이 성공할 때까지 기다립니다. 이 준비 요청에는 실행 UUID를 넣지 않습니다.

```sh
./scripts/purple-lab.sh status
curl --fail --silent --show-error \
  -H 'Host: purple-lab-target:8080' \
  http://localhost:18790/healthz
```

표의 결과는 기대값입니다. 실제 요청이 규칙에 일치하고 진단이 정상 완료됐는지, 동일 UUID의 감사·경보가 수집됐는지 확인한 뒤 ARTEX가 판정합니다. 정상 요청은 공격 차단 기대값에 포함하지 않습니다. 재검증이 실패·중단됐거나 감사 로그가 없으면 미탐지로 확정하지 않습니다. WAF 차단은 앞단 방어 정책의 효과이며 Juice Shop 내부 취약 코드가 제거됐다는 증거는 아닙니다.

방어 검증 화면에서 **개선 전 기준 실행**을 선택하고 적용한 정책 변경을 적은 뒤 개선 실행을 시작합니다. WAF 모드와 경보 규칙의 변경은 실습용 정책이며 ARTEX에 저장된 Splunk 연결 설정이나 취약점 대상은 유지하여 비교할 수 있습니다.

## 파일로도 같은 근거 확인

```sh
./scripts/purple-lab.sh export \
  --uuid '화면에 표시된 실제 실행 UUID' \
  --start '2026-10-10T12:00:00+09:00' \
  --end '2026-10-10T12:05:00+09:00'
```

UUID와 위 예시 시간을 실제 실행 값으로 바꿉니다. 시작·종료 시각에는 `+09:00`이나 `Z`처럼 시간대가 있는 ISO 8601 값을 입력하며, 실행 시작 30초 전부터 종료 60초 후까지를 포함합니다. 실제 실행 UUID와 해당 시간 범위의 Splunk 감사·경보 `_raw`를 JSONL로 내보내 파일 방식으로 검증할 수 있습니다. 출력 폴더의 `audit.jsonl`, `alert.jsonl`과 `manifest.json`을 보관합니다. 내보내기는 수집의 완전성을 자동으로 확인하지 않으며 manifest의 `completeness_confirmed`는 기본 `false`입니다. 경보를 끈 실습이라면 경보 파일이 비었는지 확인하고 **조회 범위에 경보 없음**을 선택합니다. 로그가 없거나 내보내기가 실패한 상태를 경보 없음으로 확인하지 않습니다.

파일 업로드의 필드 매핑은 내보내기가 안내한 값으로 지정합니다. 로그의 `target`은 실습 자산 `purple-lab-target:8080`이며 실제 요청의 Host 값은 `request_host`로 별도 보존합니다. 원문 ModSecurity 감사 로그는 `evidence-local/purple-lab/logs/modsec_audit.log`, 정규화한 감사 로그는 같은 폴더의 `audit.jsonl`에 보존합니다. `allowed`는 WAF 정책이 요청을 허용했다는 뜻이며 취약점 악용 성공이나 응답 본문 전달 완료를 증명하지 않습니다. 전체 수집 확인은 실행 시작 30초 전부터 종료 60초 후까지의 감사·경보가 포함됐고 수집 공백이나 한도 초과가 없을 때만 선택합니다. 파일 업로드와 Splunk 조회의 의미·한도는 [방어 검증 가이드](purple-validation.md)를 참고하세요.

## 결과가 판단 불가일 때

- **진단이 아직 진행 중이거나 실패·중단됨:** 진단 대화에서 LLM·대상 접근과 재현 여부를 확인합니다. 정상 완료된 새 실행으로 검증합니다.
- **같은 UUID의 감사 로그 없음:** 실제 요청이 WAF 앞단 주소로 갔는지와 검증 헤더가 기록됐는지 확인합니다.
- **감사 로그 조치 누락:** 실제 WAF 조치를 담은 `action` 필드를 연결에 매핑합니다. HTTP 403을 차단 필드로 대신 사용하지 않습니다.
- **경보가 없음:** 경보 규칙 활성 여부, 규칙 조건 일치와 로그 전달을 각각 확인합니다. 단순 로그 검색 결과를 경보로 대신 사용하지 않습니다.
- **수집이 늦음:** 전달·검색 처리가 완료된 뒤 같은 실행에서 재수집합니다. ARTEX 조회 구간은 종료 후 60초로 고정되어 있어, 이 구간보다 늦은 이벤트 시각의 경보는 별도 조사가 필요합니다.
- **검색 경고·행 한도 초과:** 감사·경보 각각 200건 이내의 재현 요청으로 다시 검증합니다. 부분 결과로 미탐지를 확정하지 않습니다.

과거 공격 흐름을 조사하려면 **침해 조사 → 로그 근거 준비**에서 UUID로 좁힌 파일 대신 해당 대상의 기간 전체 기록을 선택합니다. Splunk 직접 조회와 파일 업로드를 모두 사용할 수 있으며, 자세한 순서는 [침해 조사 가이드](cert-investigation.md)에 있습니다.

## 실습 환경 중지

```sh
./scripts/purple-lab.sh stop
```

실습 환경만 중지하며 데이터를 보존합니다. ARTEX와 PostgreSQL은 기존 실행 구성으로 관리합니다. 다음 실습에서 다시 `start`를 실행하고 상태·정책·경보 설정을 확인하세요.
