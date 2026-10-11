# 공식 Splunk Attack Range 로컬 설치

이 구성은 공식 [Splunk Attack Range](https://github.com/splunk/attack_range)의 **관리 웹 화면·API**를 별도 Docker Compose 프로젝트로 설치합니다. 기존 AegisLoop·PostgreSQL과 [Juice Shop·WAF·Splunk 실습 환경](purple-lab.md)은 각자의 구성으로 유지합니다.

**관리 서비스 설치와 실제 실습 서버 구축은 별개입니다.** 이 Compose를 실행해도 Windows·Linux 대상 서버나 새로운 Splunk 서버가 로컬 Docker에 생성되지 않습니다. 공식 Attack Range는 템플릿과 Terraform·Ansible로 AWS·Azure·GCP 대상 환경을 구축하고, 대상 서버에서 Atomic Red Team 등으로 행위를 실행합니다. 클라우드 선택·자원 규모·예산·전용 접근 권한을 정한 뒤 별도 구축해야 합니다. 이 로컬 설치는 사용자의 기존 클라우드 로그인과 자격 증명을 연결하지 않습니다.

## 실행

Docker Compose, Git, Python 3가 필요합니다. 제품 기본 설치에는 Attack Range가 필요하지 않습니다.

```sh
# 고정 공식 소스 준비 → 이미지 빌드 → 관리 서비스 시작 → 조회 확인
./scripts/attack-range.sh install
```

단계를 나누어 실행할 수도 있습니다.

```sh
./scripts/attack-range.sh init
./scripts/attack-range.sh build
./scripts/attack-range.sh start
./scripts/attack-range.sh doctor
./scripts/attack-range.sh status
```

| 항목 | 주소·경로 |
| --- | --- |
| 관리 웹 화면 | <http://localhost:4321> |
| 관리 API | <http://localhost:4000> |
| OpenAPI JSON 문서 | <http://localhost:4000/openapi/openapi.json> |
| 공식 고정 소스 | `.local-runtime/attack-range/upstream/` |
| 개인 설정·SSH 키 | `.local-runtime/attack-range/config/`, `ssh_keys/` |
| 설치 증거 | `.local-runtime/attack-range/installation.json` |
| 조회 확인 증거 | `.local-runtime/attack-range/doctor.json` |

4000·4321 포트는 공식 소스의 브라우저 CORS 허용값에 맞춰 사용합니다. 다른 프로그램이 포트를 사용 중이면 먼저 충돌을 확인하세요. 관리 포트는 `127.0.0.1`에만 공개하며, 인증이 없는 공식 관리 API를 외부 네트워크에 공개하지 않습니다.

첫 빌드는 공식 Dockerfile이 Python·Node·Terraform·AWS CLI·Azure CLI·Google Cloud CLI 및 프로젝트 의존성을 다운로드하므로 시간이 걸리고 네트워크가 필요합니다. API·앱 이미지 빌드는 메모리 부담을 줄이기 위해 순차 실행합니다. 이미지 빌드 시에는 해당 도구의 공급자에 접근하지만 클라우드 계정 인증이나 서버 생성은 수행하지 않습니다. API 런타임 메모리는 1 GiB, UI는 512 MiB로 제한했습니다. 기존 Splunk 실습 환경을 함께 실행하면 Docker 메모리 사용량을 확인하세요.

## 재현성과 기존 상태 보존

[upstream.json](../lab/attack-range/upstream.json)에 공식 저장소와 커밋 `fc9b9e719d8835da0bbb5c20d46c52a9778d64e2`를 기록했습니다. 공식 API·앱 Dockerfile을 변경하지 않고 그 소스로 빌드합니다. 새 소스는 임시 폴더에서 다운로드·검증한 뒤에만 `upstream/`으로 옮기므로, 다운로드 실패 후에는 같은 명령으로 다시 시도할 수 있습니다. 로컬 소스가 다른 커밋이거나 수정된 상태이면 초기화·빌드가 중단되며 자동 덮어쓰기하지 않습니다. 기존 개인 설정·SSH 키도 교체하거나 삭제하지 않습니다.

상류 README는 v5를 설명하지만 API health는 `1.0.0`, Python 프로젝트 메타데이터는 `3.1.2`를 표기합니다. 버전 문자열 하나로 설치 결과를 판정하지 않습니다. `installation.json`에는 고정 소스 커밋·Compose SHA-256·실제 빌드 이미지 ID를 기록합니다. 기반 이미지와 일부 다운로드는 상류 Dockerfile 자체에서 가변 버전을 사용하므로 같은 소스 커밋의 재빌드가 항상 동일한 이미지 바이트를 만든다는 보장은 없습니다.

개인 설정과 원본 체크아웃은 Git 제외 경로인 `.local-runtime/`에만 저장합니다. 공개 저장소에는 Compose·래퍼·고정 커밋 정보·설명만 포함합니다. 별도 관리 네트워크를 사용하며 AegisLoop·실습 대상 네트워크에 자동 연결하지 않습니다.

## `doctor`가 확인하는 범위

`doctor`는 다음 GET 요청만 수행합니다.

- `/health`: API 준비 상태
- `/templates`: 템플릿 목록
- `/configs`: 저장 설정 목록
- `/attack-range/list`: 실습 목록
- `/openapi/openapi.json`: API 문서 형식과 경로 개수
- UI `/`: 웹 화면 응답

확인 결과에는 목록 개수와 고정 커밋 등만 남깁니다. 응답 원문·설정 본문·접속 비밀번호·VPN 설정은 기록하지 않습니다. `doctor`는 cloud build·simulate·destroy API를 호출하지 않습니다.

상류 안내의 `/openapi/swagger`는 이 공식 Dockerfile로 빌드한 이미지에서는 404를 반환합니다. 현재 상류 의존성에는 Swagger UI 추가 패키지가 없으므로, 설치 검증은 정상 제공되는 OpenAPI JSON 문서를 사용합니다.

조회는 GET으로 제한하지만, 상류 `/attack-range/list` 구현은 오래된 구축 상태를 오류 상태로 갱신할 수 있습니다. 상류 내부 설정의 완전한 불변성을 보장하는 검사는 아니며, 저장 설정이 없는 첫 설치에는 이 상태 갱신이 적용되지 않습니다.

**템플릿의 `provider_available: true`는 인증 검증 결과가 아닙니다.** 이 고정 소스는 해당 표시에 실제 CLI·자격 증명 확인을 수행하지 않습니다. 웹 화면이 열리는 것과 클라우드 실습 환경이 구축되는 것을 구분하세요.

클라우드 인증 경로는 비어 있는 전용 `.local-runtime/attack-range/cloud-disabled/` 폴더에만 연결합니다. 사용자 `~/.aws`, `~/.azure`, `~/.config/gcloud`와 호스트 Docker 소켓·특권 모드는 사용하지 않습니다. AWS 인스턴스 메타데이터를 통한 자격 증명 조회도 비활성화했습니다. 이 구성에서는 UI의 클라우드 생성 버튼을 눌러도 사용할 계정이 연결되어 있지 않습니다.

## 기존 AWS CLI 인증 사용

이미 로컬 AWS CLI 프로필로 인증했다면 다시 로그인할 필요가 없습니다. 현재 실습에서는 로컬 `attack-range` 프로필의 인증을 사용합니다. 사용하려는 프로필의 계정과 역할은 다음 읽기 전용 명령으로 확인합니다.

```sh
aws sts get-caller-identity --profile <your-profile>
```

`<your-profile>`을 자신의 프로필 이름으로 바꾸세요. 응답의 계정·역할이 실습 대상으로 맞는지 확인하고, 응답 원문이나 임시 자격 증명을 공개 저장소에 넣지 않습니다. 인증 성공과 EC2·VPC·IAM 등의 생성·삭제 권한은 별도로 확인합니다.

로컬 인증은 조회·계획·적용·정리를 위한 **일회성 컨테이너**에만 전달합니다. 실행 후 컨테이너를 제거하며, 계속 실행 중인 Attack Range 관리 API·UI에는 호스트 인증을 연결하지 않습니다. 기존 호스트 프로필·키·세션을 이 프로젝트의 SSO 폴더로 복사하거나 변경할 필요도 없습니다.

## 선택적 AWS SSO 로그인 준비

[AWS 준비안](attack-range-aws-plan.md)에 계정 정보 확인 위치, Windows 구성, 실제 가격표 기반 비용 계산과 재구축·후속 실습 순서를 정리했습니다. 현재 수동 운영 환경의 실제 설치·로그 수집 검증은 [AWS 구축 기록](evidence/attack-range-aws-deployment-2026-10-11.md)에 있습니다.

AWS 콘솔에서 **IAM Identity Center → Dashboard → Settings summary**를 열고 **AWS access portal URL**을 확인합니다. SSO 시작 주소는 보통 `https://d-xxxxxxxxxx.awsapps.com/start` 형태입니다. 같은 IAM Identity Center 화면의 리전을 SSO 리전으로 사용합니다. 이 위치는 [AWS 공식 안내](https://docs.aws.amazon.com/singlesignon/latest/userguide/howtochangeURL.html)에 설명돼 있습니다. 주소를 사용자 지정하거나 설정을 변경할 필요는 없습니다.

포털 주소가 없고 활성화 안내가 보이면 기존 SSO가 준비되지 않은 상태입니다. 조직 계정은 관리자에게 기존 접속 주소와 실습 계정 권한을 확인하고, 개인 계정은 로그인 방식과 SSO 준비 여부부터 확인합니다. 계정 권한 선택은 로그인 후 진행하며, 실제 구축에는 선택한 실습 계정에서 EC2·VPC 자원을 생성·조회·삭제할 권한이 필요합니다. 공식 S3 backend를 사용할 때는 S3 상태 관리 권한도 필요하지만 현재 수동 운영은 로컬 상태를 사용합니다. 이 설치가 새 IAM 권한을 자동 부여하지는 않습니다.

로컬 CLI 인증이 없고 이 프로젝트의 별도 SSO 프로필을 사용하려는 경우에만 아래 래퍼를 실행합니다. AWS IAM Identity Center의 **SSO 시작 URL과 SSO 리전**을 준비합니다. SSO 리전은 이후 대상 서버를 설치할 AWS 리전과 다를 수 있습니다. 계정·Permission Set을 선택할 권한이 있는 사용자로 브라우저에 직접 로그인해야 합니다. 장기 Access Key를 채팅이나 공개 설정 파일에 입력하지 않습니다.

```sh
# 공식 API 이미지에 포함된 AWS CLI를 별도 임시 컨테이너로 실행
./scripts/attack-range.sh sso-configure

# 설정한 aegisloop 프로필의 세션이 만료됐을 때 다시 로그인
./scripts/attack-range.sh sso-login
```

설정 마법사에서 SSO 시작 주소·SSO 리전·계정·역할을 직접 선택합니다. `CLI profile name`에는 **`aegisloop`**를 입력하세요. `--use-device-code --no-browser`를 사용하므로 터미널에 표시된 AWS 인증 URL을 브라우저에서 열어 로그인·승인을 완료합니다. 옵션은 AWS 공식 [configure sso](https://docs.aws.amazon.com/cli/latest/reference/configure/sso.html)와 [sso login](https://docs.aws.amazon.com/cli/latest/reference/sso/login.html) 문서에 따른 것입니다.

SSO 설정·세션 캐시는 `.local-runtime/attack-range/aws-sso/`에만 저장하며 Git에서 제외됩니다. 이 폴더 하나만 임시 CLI 컨테이너의 `/root/.aws`에 연결하고 호스트의 기존 `~/.aws`는 읽거나 변경하지 않습니다. 기존 SSO 설정과 캐시는 래퍼가 삭제하지 않으며 AWS CLI가 설정·로그인 과정에서 갱신합니다. 임시 컨테이너는 종료 후 제거되고 메모리 512 MiB·CPU 1개로 제한합니다.

**이 단계는 AWS 로그인과 임시 자격 증명 준비까지만 수행합니다.** EC2·S3·VPC 생성, Attack Range 구축·공격 시뮬레이션, 관리 API에 자격 증명 연결은 포함하지 않습니다. 클라우드 비용 한도와 대상 구성을 별도로 확인한 뒤 다음 구축 단계에 진행합니다.

## AegisLoop 테스트에 사용할 순서

1. 현재 Docker 웹 실습에서 실제 요청·정상 활동·WAF·Splunk 근거 수집을 확인합니다.
2. Attack Range의 템플릿과 지원 OS·로그 수집 구성을 검토합니다.
3. 클라우드 공급자·예산·자원 규모·종료 기준을 정하고 전용 접근 권한으로 대상 서버를 구축합니다.
4. 구축한 Splunk에 AegisLoop의 검색 연결을 등록하거나 원본 로그를 내보내 조사에 사용합니다. 이 연동은 자동 등록되지 않습니다.
5. 실행 기록·대상 상태로 공격 행위를 확인한 뒤 실제 경보와 조사 결과를 비교합니다. 관리 화면 설치 성공만으로 공격 재현·탐지 성능을 입증하지 않습니다.

Windows AD·Sysmon 등 실제 Windows 동작을 검증하려면 해당 Windows 대상 서버가 필요합니다. 이 macOS Docker 관리 설치는 Windows 서버 실행을 대신하지 않습니다.

## 중지와 단위 검증

```sh
./scripts/attack-range.sh stop
python3 -m unittest discover -s lab/attack-range/tests -v
```

`stop`은 `aegis-attack-range` 프로젝트만 중지하고 소스·개인 상태를 보존합니다. 단위 검증은 모의 응답을 사용하여 소스 변경 보호, 개인 키 보존, 조회 경로 제한, 자격 증명 없는 집계 기록을 검사하며 클라우드와 Docker를 실행하지 않습니다.
