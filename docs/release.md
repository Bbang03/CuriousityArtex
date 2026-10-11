# 소스 배포와 새 체크아웃 검증

배포 단위는 이 저장소의 소스와 문서입니다. 기본 실행은 `Dockerfile.local`에서 소스를 빌드하고 `docker-compose.local.yml`로 **ARTEX와 PostgreSQL**을 시작합니다. 공개되지 않은 상류 ARTEX 이미지, 개발자의 API 키, 기존 운영 DB가 필요하지 않습니다. Juice Shop은 화면 증적을 만들 때 별도로 사용한 실습 대상이며 기본 제품 배포에 포함하지 않습니다.

[사용 가이드](USER_GUIDE_KO.md)와 직접 수행한 진단·방어 검증·침해 조사 캡처 7장을 함께 제공합니다. GitHub에는 소스와 `docs/`를 함께 올려야 이미지가 표시됩니다. ZIP만 올리는 대신 압축 안의 소스를 저장소에 반영하고, 커밋·푸시는 저장소 소유자가 진행합니다. 이번 배포의 확인 범위는 [최신 배포 검증 기록](evidence/release-guide-validation-2026-10-11.md)에 있습니다.

## 처음 받는 사용자의 실행 순서

1. 저장소를 clone하거나 소스 압축을 내려받아 압축을 풉니다.
2. Docker Desktop 또는 Docker Engine과 Compose v2를 실행합니다.
3. 저장소 루트에서 다음 명령을 실행합니다.

```sh
./scripts/local-start.sh
```

현재 UI와 Go 백엔드를 컨테이너 안에서 빌드하므로 호스트 Go·Node.js는 필요하지 않습니다. 최초 빌드는 이미지, 패키지와 브라우저 런타임을 내려받습니다.

[http://localhost:8787/setup/](http://localhost:8787/setup/)에서 본인의 관리자 비밀번호를 설정합니다. 취약점 점검·재검증이나 AI 조사를 실행할 때는 **시스템 → LLM 설정**에서 본인이 사용할 연결을 설정합니다. 초기 실행과 파일 근거 준비에는 모델 키가 필요하지 않습니다. Splunk를 사용할 때만 자신의 검색 계정 또는 토큰으로 연결합니다.

스크립트는 `.env.local`에 임의 DB 비밀번호, `.local-runtime/jwt.key`에 로그인 서명·연결 인증 정보 암호화용 키를 생성합니다. 기존 파일은 유지하며, 기존 키가 비어 있으면 자동 교체하지 않고 복구를 요청합니다. JWT 키는 해당 DB와 함께 로컬에 보존해야 하며 공개 저장소에 포함하지 않습니다.

자세한 운영 명령과 포트 변경은 [로컬 실행 안내](local-development.md)를 참고하세요. 루트의 기존 `install.sh`·`docker-compose.yml`은 상류 참고 경로이며, 이 확장의 기본 설치 절차가 아닙니다.

## 선택형 AWS Windows 실습 연결

새 체크아웃의 **Closed-loop → AWS Windows 실습**은 미설정 상태로 시작합니다. 공개 소스에는 브리지와 예약 작업 체인 실행기가 포함되지만 Windows·Splunk 서버, 개인 연결 설정과 과거 실행 이력은 포함되지 않습니다. 기본 실행만으로 AWS 자원을 만들거나 시나리오를 실행하지 않습니다.

이미 소유하고 준비한 실습 환경을 연결하려면 [AWS Windows 실습 가이드](aws-windows-loop.md)의 기존 세션 확인·브리지 설정·감사 수집 준비 절차를 따릅니다. 본인의 `.local-runtime/attack-range/bridge/compose.env`가 준비돼 있을 때만 `local-start.sh`가 `docker-compose.range-bridge.yml`을 함께 읽습니다. 이 파일과 연결 키·토큰·원본 근거는 공개 배포본에 복사하지 않습니다. 공식 Attack Range 4321 관리 화면은 이 연결과 별개입니다.

예약 작업 체인은 고정된 공격·정상 대조와 별도 변형 표본을 실행하고, 실습 Splunk의 제한된 탐지 프로파일을 실제 적용합니다. 일반 Splunk 검색 연결의 권한과 구분합니다. 확인한 표본과 한계는 [실제 체인 검증 기록](evidence/windows-task-chain-2026-10-11.md)에 있습니다. 공개 캡처와 요약은 참고 증적이며 새 설치의 DB나 실행 이력으로 자동 적재하지 않습니다.

## 테스트

저장소 루트에서 실행합니다.

```sh
./scripts/local-test.sh
python3 -I scripts/check-doc-links.py
```

첫 명령은 별도의 `artex-purple-test` Compose 프로젝트와 임시 PostgreSQL을 사용합니다. 동시 검증에서는 `ARTEX_TEST_PROJECT_NAME=artex-clean-test ./scripts/local-test.sh`처럼 다른 테스트 프로젝트 이름을 지정할 수 있습니다. 실서비스 DB·실제 LLM·실제 Splunk에 접근하지 않고 확장 기능의 통합 테스트를 수행한 뒤 테스트 컨테이너를 정리합니다. 두 번째 명령은 Python 3가 있는 호스트에서 문서 내부 경로와 앵커를 검사합니다.

`local-start.sh`의 소스 빌드에는 프런트엔드 정적 빌드와 Go 컴파일이 포함됩니다. 테스트의 TLS 모의 Splunk는 연결·검색 범위·인증 정보 처리·원문 보존을 확인하지만, 기업 환경의 실제 로그 수집이나 탐지 품질을 검증한 것은 아닙니다. 모델 실행 테스트 역시 모의 응답으로 실행 제어를 검증하며 실제 공급자 호출의 성공을 보장하지 않습니다.

## 공개 파일의 범위

| 포함 | 제외 |
|---|---|
| 애플리케이션 소스, 의존성 잠금 파일, 테스트 | `.env`, `.env.local`, 기타 실제 환경 설정 파일 |
| 소스 빌드용 Dockerfile·Compose·실행 스크립트 | JWT 키, API 키, 인증 토큰, 인증서 개인키 |
| README와 기능·개발·배포 문서 | `data/`, `.local-runtime/`, `evidence-local/`, DB 덤프·볼륨 |
| 검토한 별도 로컬 실습 화면 | 원본 업로드 로그, 운영 취약점·조사 결과 전체 내보내기 |
| 원본 및 한국어판의 저작권 표시와 라이선스 | 개발자 전용 워크스페이스·검증 산출물 |

테스트 코드의 가상 계정·토큰과 설명용 예시는 실제 접근 권한이 없는 픽스처입니다. 실사용 값을 테스트 예시로 바꾸어 저장하면 안 됩니다. `.gitignore`는 신규 파일을 제외할 뿐, 이미 추적된 파일이나 과거 커밋에서 비밀을 제거하지 않습니다.

소스 압축이나 공개 커밋에는 `Dockerfile.range-bridge`, `docker-compose.range-bridge.yml`, `lab/attack-range/bridge.py`·`runtime.py`·`chain_runtime.py`와 `requirements-bridge.txt`, 설정·감사 준비 도구, 관련 테스트를 함께 포함합니다. 특히 새 `chain_runtime.py`를 빠뜨리면 선택형 브리지 이미지 빌드가 실패합니다. `git archive HEAD`는 마지막 커밋만 포함하므로 아직 커밋하지 않은 변경·새 파일이 빠집니다. 압축 전에 포함 목록과 파일 내용을 확인합니다. 기존 `build.sh`의 플랫폼별 바이너리 ZIP은 이 Docker 소스 배포본과 다른 산출물입니다.

공개할 커밋에서 다음을 확인합니다.

- `git status --short`와 `git diff --cached --stat`로 의도한 소스·문서·검토된 화면만 포함됐는지 확인합니다.
- 새 파일뿐 아니라 실제 공개될 Git 이력에서도 API 키·비밀번호·JWT·원본 로그·DB 덤프를 제외합니다.
- 화면의 사용자 정보, 연결 주소, 로그 내용에 공개하면 안 되는 값이 없는지 직접 확인합니다.
- 초기 설정 화면에서 새 관리자 비밀번호를 요구하는지, 다른 사용자의 작업·로그·연결이 없는지 확인합니다.
- 기본 실행으로 별도 실습 앱이나 Splunk가 생성되지 않는지 확인합니다.

## 독립된 체크아웃에서 확인하기

기존 개발 폴더의 `.env.local`, `.local-runtime`, `data/`를 복사하지 않은 새 체크아웃을 사용합니다. 동일 컴퓨터에 기존 앱이 실행 중이라면 프로젝트·이미지·호스트 포트를 분리합니다.

```sh
ARTEX_PROJECT_NAME=artex-clean-check \
ARTEX_LOCAL_IMAGE=artex-clean-check:dev \
ARTEX_LOCAL_PORT=18887 \
ARTEX_LOCAL_PROXY_PORT=18888 \
./scripts/local-start.sh
```

[http://localhost:18887/setup/](http://localhost:18887/setup/)에서 새 초기 설정 화면을 확인합니다. 키·DB를 복사하지 않았으므로 기존 개발자의 로그인, LLM 연결, 작업과 로그가 나타나면 안 됩니다. 이 명령은 자체 데이터 볼륨을 만들며 실제 점검이나 AI 조사를 자동 실행하지 않습니다.

확인이 끝나면 같은 프로젝트 이름으로 테스트용 앱을 중지합니다. 아래 명령은 데이터를 삭제하지 않습니다.

```sh
ARTEX_PROJECT_NAME=artex-clean-check \
ARTEX_LOCAL_IMAGE=artex-clean-check:dev \
ARTEX_LOCAL_PORT=18887 \
ARTEX_LOCAL_PROXY_PORT=18888 \
docker compose --env-file .env.local -f docker-compose.local.yml stop
```

실습 화면과 실제 확인한 범위는 [공개 증적 안내](evidence/README.md)에 분리해서 기록합니다. 구현·테스트 통과, 로컬 화면 확인, 실제 외부 시스템 검증을 같은 성공으로 표현하지 않습니다.
