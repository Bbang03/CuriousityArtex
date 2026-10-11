# API · 소스 코드 진단

Offensive에서 **API 명세·URL·HAR 또는 소스 ZIP을 등록 → 대상 선택 → 도구 진단 → ARTEX 심층 검토** 순서로 사용합니다. crAPI·Benchmark는 선택 가능한 예제입니다. 탐지·Splunk·방어 검증 기능은 변경하지 않습니다.

## 시작

Docker를 실행한 뒤 저장소 루트에서:

```sh
./scripts/offensive-start.sh
```

첫 실행은 공식 실습 소스·이미지와 분석 도구를 내려받아 빌드합니다. 기존 ARTEX 계정·LLM 설정을 사용하며, 신규 설치라면 웹의 초기 설정을 완료하세요.

[Offensive → API · 소스 코드 진단 열기](http://localhost:8787/offensive/assessments/)

## 내 API 진단

1. **API 진단**을 선택하고 **OpenAPI 명세 / URL 탐색 / HAR 업로드** 중 하나를 고릅니다.
2. 대상 이름과 진단 컨테이너에서 접근할 수 있는 **API 기본 주소**를 입력합니다.
3. 아래 방식으로 요청 목록을 준비하고, 발견한 **GET/HEAD 경로**를 확인·선택합니다. 실행당 최대 40개입니다.
4. 필요한 경우 이번 검사에 쓸 Bearer 토큰을 입력하고 **API 진단 시작**을 누릅니다.
5. 실제 요청·응답, 검사 후보, 인증 제한과 탐색 공백을 확인합니다. 필요하면 **ARTEX 심층 검토**로 이어갑니다.

| 입력 방식 | 준비 방법 | 검사 범위 |
|---|---|---|
| OpenAPI 명세 | JSON/YAML 파일(8 MiB 이하) 등록 | 명세에 따른 입력 생성·응답 계약·서버 오류 검사 |
| URL 탐색 | 웹 또는 API 주소 입력 → **URL에서 API 찾기** | 같은 출처·지정 경로 범위의 HTML·연결된 JS에서 요청 후보를 찾고, 선택 후 서버 오류 검사 |
| HAR 업로드 | 실제 요청 기록 `.har`/`.json`(16 MiB 이하) 등록 | 지정된 출처·경로의 GET/HEAD 기록을 추출하고, 선택 후 서버 오류 검사 |

URL/HAR로 만든 요청 목록은 공식 명세가 아니므로 응답 계약 위반을 판정하지 않습니다. URL 탐색은 브라우저 JavaScript 실행이나 로그인 자동화를 하지 않으며, 찾은 문자열이 실제 API가 아닐 수 있습니다. 동적으로 만들어지는 요청과 로그인 후의 경로는 HAR로 보완할 수 있습니다.

### 로컬 crAPI로 연습

- URL 탐색: 기본 주소 `http://crapi-web:80` 입력 → 탐색 → 후보 선택.
- 명세 업로드: 같은 주소와 공식 crAPI 명세 파일을 등록합니다.
- HAR 업로드: 기본 주소 `http://host.docker.internal:18888`, 브라우저에서 기록한 원본 주소가 다르면 **HAR 원본 주소**에 `http://localhost:18888`을 입력합니다. 같은 출처의 기록이라면 원본 주소는 비워도 됩니다.

HAR 원본 주소는 파일에서 어떤 출처를 추출할지 지정하는 값입니다. 그 주소로 접속하지 않으며 실제 요청은 입력한 API 기본 주소로만 보냅니다. 경로는 유지하고, 다른 출처와 범위 밖의 요청은 제외합니다.

HAR는 브라우저 개발자 도구의 Network에서 실제 기능을 사용한 후 내보낼 수 있습니다. 원본 HAR의 인증 헤더·쿠키·쿼리값·본문은 보관하거나 자동 재사용하지 않습니다. 인증이 필요한 검사는 실행할 때 토큰을 따로 입력하세요. URL 경로 자체에 민감한 값이 들어 있는 기록은 업로드 전에 제거하세요.

API 기본 주소는 브라우저가 아니라 **진단 컨테이너에서 접근 가능한 주소**여야 합니다. 호스트 API는 `http://host.docker.internal:<포트>`, 원격 API는 점검 권한이 있는 서비스 주소를 사용합니다. 선택하지 않은 경로와 다른 호스트의 리다이렉트는 따라가지 않습니다.

현재 POST·PUT·PATCH·DELETE, 복잡한 OAuth 로그인, mTLS, API 전수 검사는 지원하지 않습니다. GET도 서비스 구현에 따라 부작용이 있을 수 있으므로 점검용 계정과 환경을 사용하세요. 401/403이나 404/405만 확인한 결과를 API가 안전하다는 뜻으로 해석하지 마세요.

## 내 소스 코드 진단

1. **소스 코드 진단**을 선택합니다.
2. 대상 이름과 **소스 ZIP(최대 20 MiB)**을 등록합니다.
3. 지원 언어·등록 파일 수를 확인하고 **소스 코드 진단 시작**을 누릅니다.
4. 후보의 **파일·줄·규칙·코드 문맥**을 확인합니다. 원본 결과와 해시도 내려받을 수 있습니다.

지원 언어는 **Java·Python·JavaScript·TypeScript**입니다. 코드를 빌드하거나 실행하지 않고 제한된 로컬 Semgrep 규칙으로 정적 후보를 찾습니다. Git 이력·의존성 디렉터리·대표적인 비밀 설정 파일은 제외하고 누락 범위를 결과에 남깁니다. 이 제외 처리가 모든 코드에 숨은 비밀값을 찾아내는 것은 아니므로 업로드 전 키·개인정보를 제거하세요.

등록한 대상은 목록에 유지됩니다. 소스가 바뀌었으면 새 ZIP을 등록하세요. 각 실행은 그때 선택한 대상·업로드 해시·근거를 보존합니다.

## 결과와 ARTEX 심층 검토

도구의 **후보는 확정 취약점이 아닙니다**. 계약 위반·서버 오류나 위험한 함수 사용을 확인한 뒤 실제 보안 영향과 방어 로직을 따로 검토합니다. 도구 실행 실패·검사 오류·범위 밖의 파일을 취약점 없음으로 해석하지 마세요.

LLM을 선택하고 **ARTEX 심층 검토 시작**을 누르면 기존 작업 화면으로 이어집니다. 선택한 업로드 대상의 소스·진단 근거가 LLM 입력에 포함되며 모델 사용량이 발생합니다. 도구 진단에 입력한 Bearer 토큰은 심층 검토에 전달하지 않습니다. 추가 인증이 필요한 재현은 미검증으로 남을 수 있습니다.

도구 진단은 한 번에 하나만 실행합니다. ARTEX 검토는 600초 안에 대표 후보 최대 5개를 우선 검토하며, 시간초과·모델 오류·미검토 항목을 결과와 구분합니다.

## API 입력 선택 화면

![명세·URL·HAR 선택](evidence/images/offensive-discovery-form-20261011.jpg)

[URL·HAR 실제 웹 검증 결과](evidence/offensive-api-discovery-validation-2026-10-11.md)

[업로드·진단 실제 검증 결과](evidence/offensive-upload-validation-2026-10-11.md)

## 예제 환경

| 대상 | 실행 내용 |
|---|---|
| OWASP crAPI | 미리 선정한 GET API 6개, 일반 실습 계정 인증, Schemathesis 응답 검사 |
| OWASP Benchmark Java | 공식 Java 소스에 로컬 규칙 5개를 적용한 정적 분석 |

- [crAPI 웹](http://localhost:18888/) / [실습 메일](http://localhost:18025/)
- Benchmark는 소스만 연결하며 Java 웹 서버를 실행하지 않습니다.
- crAPI의 GenAI 챗봇과 외부 API 게이트웨이 실습은 포함하지 않습니다.

아래는 초기 예제 대상에서 실제 실행한 화면입니다. 사용자 업로드 대상은 같은 화면의 등록·선택 기능으로 진단합니다. 실습 이력은 새 설치에 포함되지 않습니다.

![crAPI API 진단 결과](evidence/images/offensive-api-assessment-20261011.jpg)

![Benchmark 소스 진단 결과](evidence/images/offensive-source-assessment-20261011.jpg)

[초기 실행·검증 기록](evidence/offensive-assessments-2026-10-11.md)

## Skill · 도구 · MCP

- **Skill**: `api-assessment`, `source-assessment`가 ARTEX의 검토 순서와 근거 기준을 제공합니다.
- **분석 도구**: Schemathesis와 Semgrep이 별도 실행 컨테이너에서 실제 진단합니다.
- **MCP**: 외부 도구 연결에 사용할 수 있는 인터페이스입니다. 이번 연동은 내부 HTTP API를 사용하므로 별도 MCP 설정은 필요하지 않습니다.

## 보관과 중지

```sh
./scripts/offensive-stop.sh
```

신규 진단 서비스만 중지하며 기존 ARTEX·Splunk와 저장된 근거는 유지됩니다. 다시 시작하려면 `offensive-start.sh`를 실행하세요.

- 실습 소스·실행기 인증 정보: Git에서 제외된 `.local-runtime/offensive/`
- 사용자 업로드 대상: `data/offensive/targets/`
- 진단 이력·근거: `data/offensive/runs/`

업로드와 결과는 서버에 보관되며 Git과 Docker 빌드 대상에서 제외됩니다. ARTEX에는 업로드 소스를 읽기 전용으로 연결합니다. 사용자 API에 접근하기 위한 실행기만 외부 통신 네트워크에 연결하고, 취약 예제 서비스는 내부 Docker 네트워크에 둡니다. 예제 웹 공개 포트는 localhost로 제한합니다.

공식 예제 소스는 [crAPI](https://github.com/OWASP/crAPI/tree/700f03d12a392d9e408260b4beae72ed02a4a1a4), [Benchmark Java](https://github.com/OWASP-Benchmark/BenchmarkJava/tree/8b67a88d73b2594570fc21150705283de884620b) 커밋에 고정합니다. 다운로드한 제3자 소스는 각 프로젝트의 라이선스를 따르며 이 저장소에 복사해 배포하지 않습니다.
