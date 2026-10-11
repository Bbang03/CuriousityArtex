# 소스 배포 검증 — 2026-10-11

현재 기능을 유지한 채 공개 소스·문서·검토한 화면만 별도 폴더에 복사해 검증했다. 기존 개발자의 `.env.local`, `.local-runtime`, DB와 로그를 복사하지 않았다. 이 과정에서 AWS 공격을 새로 실행하거나 클라우드 자원을 변경하지 않았다.

## 처음 설치하는 환경

별도의 로컬 Docker Compose 프로젝트에서 다음과 같이 실행했다. LLM 관련 환경 변수도 비워 외부 모델 연결을 사용하지 않았다.

```sh
ARTEX_PROJECT_NAME=aegisloop-release-check \
ARTEX_LOCAL_IMAGE=aegisloop-release-check:20261011 \
ARTEX_LOCAL_PORT=18887 \
ARTEX_LOCAL_PROXY_PORT=18888 \
OPENAI_API_KEY= ANTHROPIC_API_KEY= \
ARTEX_LLM_PROVIDER= ARTEX_LLM_MODEL= \
ARTEX_LLM_BASE_URL= ARTEX_LLM_PROXY= \
./scripts/local-start.sh
```

- Docker 소스 빌드와 ARTEX·PostgreSQL 두 컨테이너의 health check가 통과했다. 이미 검증한 의존성·웹 빌드 레이어는 Docker 캐시를 사용했다.
- 브라우저에서 `/setup/`의 최초 관리자 비밀번호 설정 화면을 확인했다. 비밀번호를 대신 설정하거나 로그인하지 않았다.
- 새 DB의 LLM 연결, 보안 로그 연결, 작업, 취약점, Defensive 사건, 실제 루프, 취약점 조사 기록은 각각 0건이었다.
- Juice Shop, Splunk, AWS bridge는 기본 설치에 생성되지 않았다.
- 확인한 별도 검증 컨테이너는 중지했다. 기존 앱과 실습 환경은 유지했다.

![개인 데이터 없는 배포 소스의 최초 설정 화면](images/release-clean-setup-2026-10-11.jpg)

## 코드와 공개 범위 확인

- Windows 체인·실행기·브리지 회귀 테스트 27개 통과.
- 직전 구현 검증에서 웹 TypeScript·Biome·36개 경로 정적 빌드 통과. 배포 검증에서도 같은 소스를 Docker로 빌드했다.
- 기본 실행 스크립트 셸 문법, 문서 내부 파일·이미지·앵커 참조 및 공백 오류를 확인했다.
- 공개 대상 텍스트와 기존 Git 이력에 비밀 탐지 검사를 수행했다. 탐지된 테스트·모의 API 문자열은 실제 인증 정보가 아닌지 문맥을 검토했다.
- 로컬에서 사용하는 실제 비밀값과 공개 대상 파일을 대조했으며 일치가 없었다. 오래된 도구 사용 예제의 고정 API 키 문자열은 명시적인 placeholder로 교체했다.
- 새 캡처는 실제 웹 결과와 최초 설정 화면이다. 개인 접속 정보나 원본 로그를 담지 않은 화면을 직접 확인했다.

소스 ZIP에는 `.git` 이력, 실제 환경 파일·키·AWS/Splunk 인증, DB, 원본 Windows 로그, 원본 내보내기, 로컬 빌드 산출물을 포함하지 않는다. 테스트용 가상 데이터와 공개 설정 예시는 포함한다. 새 체인 실행 소스·테스트·로그 준비 도구·Docker COPY 항목 및 현재 수정 파일도 포함한다.

`SOURCE_MANIFEST.sha256`은 배포 폴더의 파일 목록과 SHA-256을 기록한다(목록 파일 자신은 제외). ZIP 파일의 SHA-256은 옆의 `.zip.sha256` 파일로 별도 제공한다. 이는 파일 무결성 확인 자료이며 보안 인증을 뜻하지 않는다.

실제 공격·탐지 검증은 [Windows 체인 기록](windows-task-chain-2026-10-11.md)에 별도로 정리했다. 소스 설치 성공과 탐지 품질 검증을 구분한다. 현재 범위와 업로드 방법은 [배포 노트](../../RELEASE_NOTES.md)를 참고한다.
