# AWS 실습 준비안

로컬 [Attack Range 관리 서비스](attack-range.md)와 [실제 웹 로그 실습](evidence/purple-lab-ready-2026-10-10.md)은 실행 중입니다. AWS 공급자와 하루 10달러 예산을 정했고, 기존 로컬 AWS CLI `attack-range` 프로필의 인증을 사용합니다. 사용자 요청에 따라 **일주일 운영 후 직접 정리**하는 새 Seoul `ap-northeast-2` 계획을 검토·적용했습니다. 서버 3대·디스크 150 GiB·NAT 1개가 생성되었으며, 자동 종료용 IAM·Lambda·Scheduler는 설치하지 않았습니다. 공식 역할 설치와 실제 Windows 로그 3종의 Splunk 수집까지 확인했으며, 결과·한계는 [AWS 구축 기록](evidence/attack-range-aws-deployment-2026-10-11.md)에 있습니다.

## 먼저 확인할 정보

1. 이미 인증한 로컬 AWS CLI 프로필에서 사용할 실습 계정과 역할을 확인합니다. [기존 CLI 인증 사용](attack-range.md#기존-aws-cli-인증-사용)의 `aws sts get-caller-identity` 명령을 사용하며, 새 인증을 중복으로 요구하지 않습니다.
2. 실습 리전을 정합니다. 개인 계획 준비 도구는 Seoul `ap-northeast-2`와 Frankfurt `eu-central-1`을 지원하며, 생략 시 공식 템플릿과 같은 Frankfurt를 사용합니다. SSO 리전과 대상 서버 리전은 별개입니다.
3. EC2·VPC 자원의 생성·조회·삭제 권한을 실제 계획에 맞춰 검증합니다. 수동 운영은 로컬 Terraform 상태를 사용하며 자동 종료용 IAM·Lambda·Scheduler 권한을 요구하지 않습니다. 일부 서비스 조회가 거부된 것만으로 모든 생성 작업이 불가능하다고 판단하지 않습니다.
4. 로컬 CLI 인증이 없을 때만 [선택적 SSO 설정](attack-range.md#선택적-aws-sso-로그인-준비)을 진행합니다. **IAM Identity Center → Dashboard → Settings summary → AWS access portal URL**에서 시작 주소와 SSO 리전을 확인합니다. 관리 콘솔 주소 자체는 SSO 시작 주소가 아닙니다. [AWS 공식 안내](https://docs.aws.amazon.com/singlesignon/latest/userguide/howtochangeURL.html)

활성화 화면만 보이면 기존 SSO가 준비되지 않은 상태입니다. 조직 계정에서는 담당 관리자에게 기존 포털 주소·실습 계정·역할을 확인합니다. 개인 계정이라면 SSO 준비 여부와 로그인 방법을 먼저 정합니다. 비밀번호·장기 Access Key를 채팅이나 Git에 넣지 않습니다.

## 첫 대상 구성

공식 Windows 단일 대상 템플릿을 첫 후보로 사용합니다. AD 도메인 구성은 다음 실습으로 분리하며 동시에 여러 Range를 만들지 않습니다.

| 자원 | 고정 소스의 기본 구성 |
| --- | --- |
| VPN Router | Ubuntu 22.04, `t3.small`, gp3 30 GiB |
| Splunk·Guacamole | Ubuntu 22.04, `t3.xlarge`, gp3 60 GiB |
| Windows 대상 | Windows Server 2022, `t3.large`, gp3 60 GiB |
| 네트워크 | VPC, 공개·비공개 서브넷, NAT Gateway 1개, 공인 IPv4 2개 |
| Terraform 상태 | 버전 관리되는 S3 버킷 |
| 실습 리전 | 준비 도구 기본값은 공식 템플릿과 같은 Frankfurt `eu-central-1`; 현재 Seoul `ap-northeast-2` 계획을 검토 완료 |

이 템플릿의 첫 VPN 구축 단계부터 전체 EC2·EBS·NAT 자원이 생성됩니다. Router만 과금되는 단계로 생각하면 안 됩니다. 근거는 고정 커밋의 [Windows 템플릿](https://github.com/splunk/attack_range/blob/fc9b9e719d8835da0bbb5c20d46c52a9778d64e2/templates/aws/splunk_windows_aws.yml)과 [Terraform 자원](https://github.com/splunk/attack_range/blob/fc9b9e719d8835da0bbb5c20d46c52a9778d64e2/terraform/aws/resources.tf)입니다.

## 하루 10달러 운영 범위

2026-10-10 23:06 KST에 AWS 공개 가격표를 조회했습니다. On-Demand, Shared tenancy, Linux 무료 OS·Windows 라이선스 포함, gp3 기본 성능·30일 월 환산 기준입니다. 아래는 EC2·NAT 시간·공인 IPv4·EBS의 **기본액 계산이며 비용 상한이 아닙니다.**

| 구성 | Frankfurt 24시간 | Seoul 24시간 |
| --- | ---: | ---: |
| Router·Splunk·Linux 대상 1대 | $9.45 | $10.22 |
| Router·Splunk·Windows 대상 1대 | $10.11 | $10.89 |
| Router·Splunk·Windows DC·Windows 대상 | $13.27 | $14.23 |

공식 Windows 기본 구성은 24시간 계속 실행하면 기본액부터 10달러를 넘습니다. 현재 요청한 일주일 수동 운영에서는 Windows만 `t3.medium`(2 vCPU·4 GiB)으로 줄이고 Router·Splunk·네트워크·디스크는 유지합니다. Seoul의 Windows 시간 요금 `$0.0704`를 적용하면 기본액은 **하루 $9.4176, 일주일 $65.9232**입니다. [EC2 사양](https://docs.aws.amazon.com/ec2/latest/instancetypes/gp.html)과 [Windows 요구 사양](https://learn.microsoft.com/en-us/windows-server/get-started/hardware-requirements)을 만족하는 작은 실습 구성으로 공식 역할 설치·무해한 명령·로그 수집은 확인했습니다. 대규모 Atomic 실행이나 장시간 부하 성능을 검증한 것은 아닙니다.

선택형 자동 종료 도구는 기존의 **준비 시작부터 최대 4시간 세션**을 유지합니다. 기본 Windows 구성의 4시간 기본액은 Frankfurt 약 $1.69, Seoul 약 $1.81입니다. 종료 코드와 단위 검증은 추가했으나 AWS에 설치하거나 실제 삭제를 검증한 상태는 아닙니다. 수동 운영에는 종료 예약을 설치하지 않으며 만료 태그는 사용자가 정리할 목표 시각을 기록할 뿐입니다.

세금·NAT 처리 GB·인터넷/교차 AZ 전송·T3 Unlimited CPU 초과 크레딧·스냅샷·S3/CloudWatch·유료 Splunk 라이선스·LLM 비용은 별도입니다. 기본액이 예산 안에 있어도 청구액의 상한을 보장하지 않습니다. 사용 후에는 해당 Range의 Terraform destroy와 잔존 자원 조회로 정리합니다. **EC2 중지만으로 NAT·EIP·EBS 비용이 끝나지는 않습니다.**

계산 근거: [Frankfurt EC2 공개 가격표](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEC2/20261009203134/eu-central-1/index.csv), [Seoul EC2 공개 가격표](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEC2/20261009203134/ap-northeast-2/index.csv), [VPC 가격](https://aws.amazon.com/vpc/pricing/). 카탈로그 버전은 `20261009203134`입니다. 예를 들어 Frankfurt Windows 시간 기본액은 `(0.024 + 0.192 + 0.1236 + 0.052 + 2×0.005)`에 EBS `150×0.0952/30/24`를 더해 약 `$0.42143`으로 계산했습니다.

## 재구축과 후속 실습 순서

- 기존 로컬 CLI 인증으로 사용할 계정·역할·권한과 실제 리전을 확인합니다.
- 개인 템플릿에서 공개 SSH·WireGuard 접근을 사용자 공인 IP `/32`로 제한합니다. Splunk·대상 서버는 비공개 서브넷에 유지합니다.
- 상류의 기본 암호를 general과 각 Splunk·Guacamole·Windows role 변수에서 모두 교체합니다. general 값만 변경하면 개별 role의 기본 암호가 남습니다. 개인 YAML·Terraform 상태는 비공개 경로에 보관합니다.
- Terraform 공급자·VPC 모듈 버전과 AMI를 확인하고 실제 plan의 자원·추가 과금을 검토합니다.
- 일주일 후 직접 정리와 실패 시 정리, EC2·NAT·EIP·EBS 잔존 확인을 준비합니다. 상류의 S3 backend를 별도로 사용하는 경우 과거 버전·delete marker도 확인해야 합니다.
- 실제 Windows 행위·호스트 로그와 Splunk 경보를 수집하고 AegisLoop에 검색 연결 또는 파일 근거로 등록합니다.

현재 로컬 CLI 인증은 준비되어 있으므로 별도 SSO 인증 링크를 다시 승인할 필요가 없습니다. 인증은 조회·계획·적용·정리를 위한 일회성 컨테이너에만 연결하고, 상시 실행하는 관리 API에는 연결하지 않습니다. 세션이 만료되면 해당 프로필의 기존 로그인 방식으로 갱신합니다. 프로젝트의 SSO 래퍼는 별도 인증이 필요한 사용자를 위한 선택 사항입니다.

## 비공개 설정 준비와 plan 검토

[aws_plan.py](../lab/attack-range/aws_plan.py)는 공식 고정 소스를 확인한 뒤 새 `.local-runtime/attack-range/aws-plans/<UUID>/`에만 개인 설정을 만듭니다. 기존 상류 체크아웃·키·설정을 수정하지 않습니다. 기본 암호 6곳을 난수 암호로 교체하고, Router의 SSH·WireGuard 접근을 공개 IPv4 한 개의 `/32`로 제한합니다. 대상 서버는 공인 IP를 받지 않고 VPC 안에서만 수신합니다. EC2 종료 보호를 해제하고 인스턴스·루트 디스크에 소유·만료 태그를 기록합니다.

```sh
# 실제 현재 공인 IPv4를 입력합니다. 예약 주소나 0.0.0.0/0은 거부됩니다.
RANGE_PUBLIC_IP="실제_공인_IP"
python3 lab/attack-range/aws_plan.py prepare \
  --whitelist "$RANGE_PUBLIC_IP/32" \
  --region ap-northeast-2 \
  --lifecycle-mode manual --session-hours 168 \
  --windows-instance-type t3.medium \
  --aws-provider-version 6.68.0 \
  --vpc-module-version 6.7.3
```

`--region`은 `ap-northeast-2` 또는 `eu-central-1`만 허용하며, 생략하면 `eu-central-1`입니다. `manual`은 1~168시간의 수동 정리 목표를 기록합니다. 이 선택 인수를 생략하면 기존 `automatic`·4시간·`t3.large` 준비를 사용합니다. Terraform은 `1.14.4`로 고정합니다. 공급자·모듈도 정확한 버전을 사용하며, 준비 이후 소스·변수 해시 변경을 거부합니다. `prepare`는 이미 설치된 공식 API 이미지의 Python을 네트워크 없이 사용해 YAML을 읽을 뿐, Terraform이나 AWS API를 실행하지 않습니다.

개인 폴더에서 Terraform `init`, `validate`, 인증 후 읽기 전용 `plan -out`과 `show -json`을 실행합니다. 사전 계획은 **로컬 backend**를 사용하므로 SSH 키 import나 S3 상태 버킷 생성 없이 검토할 수 있습니다. Seoul의 수동 계획은 이 명령들과 AMI·보안 그룹·자원·태그 구조 검토를 통과했고, 동일 저장 계획을 적용한 뒤 실제 8 vCPU 실행을 확인했습니다. 계획·상태·변수·전체 로그에는 암호가 들어갈 수 있으므로 모두 Git 제외 폴더에 보관하고 내용을 공개하지 않습니다.

```sh
python3 lab/attack-range/aws_plan.py validate-plan "$PRIVATE_PLAN_JSON" \
  --preparation "$PRIVATE_PREPARATION_JSON"
```

검사는 서버 3대·gp3 총 150 GiB·NAT/EIP 각 1개, 수신 출처·디스크 암호화·종료 삭제·종료 보호·소유 태그·AMI 루트 디스크를 확인합니다. 추가 자원·기존 자원 변경·필수 조건 미확정·만료 계획은 거부합니다. 검토 기록에는 확정 AMI ID와 해시를 남기지만 암호나 변수 본문은 복사하지 않습니다. AMI 조회는 상류의 최신 필터를 사용하므로 **검토한 동일 saved plan을 적용**해야 확정한 AMI를 그대로 사용합니다.

공식 `build`는 SSH 키와 S3 backend를 먼저 만들고 Terraform `init -upgrade` 및 직접 apply를 수행합니다. 이 도구가 검토한 plan을 공식 `build`가 자동으로 적용하는 것은 아닙니다. 실제 계정의 계획을 검토하고 선택한 운영·정리 방식을 확인한 뒤 같은 saved plan을 적용합니다.

## 선택형 4시간 자동 종료 장치 준비

아래 단계는 자동 종료를 선택할 때만 사용합니다. 현재 일주일 수동 운영에는 적용하지 않습니다.

[aws_ttl.py](../lab/attack-range/aws_ttl.py)는 한 세션의 Lambda ZIP, IAM 정책·신뢰 문서, EventBridge Scheduler 요청 자료를 비공개 새 폴더에 생성합니다. **자료 생성은 AWS 호출·권한 부여·예약 설치를 수행하지 않습니다.** 계정·리전·UUID·UTC 만료 시간을 plan과 정확히 맞춰야 합니다.

[종료 Lambda](../lab/attack-range/aws_cleanup.py)는 해당 계정·리전·UUID와 소유·만료 태그가 모두 맞고 기한이 지난 자원만 정리합니다. EC2 종료, NAT 삭제, 분리된 EIP·EBS 삭제를 순서대로 요청하고, 비동기 삭제·부분 실패는 다음 5분 주기에 다시 확인합니다. 삭제 요청 성공을 정리 완료로 판단하지 않으며, 다시 조회해 잔존 자원이 없어야 완료를 기록합니다. 유료 자원이 남거나 조회 오류가 있으면 SSH 키와 원격 상태를 보존합니다.

원격 설치에는 전용 실행 역할, 로그 보관 1일의 로그 그룹, 예약 그룹이 필요합니다. 먼저 `inspect` 모드로 계정·함수·세션 일치와 읽기 전용 빈 조회를 검증하고, 실행 역할의 범위 및 실제 삭제 권한을 확인합니다. 예약은 만료 이후 시작하며 5분 간격·서비스 실행 지연·NAT 삭제 지연이 있으므로 정확히 4시간에 모든 비용이 사라지는 보장은 아닙니다.

S3 backend를 실제 사용한다면 정상 Terraform destroy와 비공개 상태 백업을 우선 준비합니다. 비상 정리는 과거 객체 버전·delete marker까지 삭제할 수 있으므로 복구용 로컬 상태 없이 원격 버킷만 의존하면 안 됩니다. Lambda의 EC2 계열 정리는 소유·만료 태그로, S3 정리는 세션 전용 정확한 버킷 이름·계정·만료 조건으로 제한합니다. 무료 VPC 자원과 종료 장치 자체의 역할·예약·로그는 이후 정상 절차로 정리해야 합니다.

```sh
python3 -m unittest discover -s lab/attack-range/tests
```

단위 검증은 모의 SDK·plan을 사용합니다. 통과하더라도 실제 AWS 로그인·IAM 권한·자원 삭제·비용 상한을 입증한 것은 아닙니다.

## 종료 장치 권한이 없는 실행 계정

[aws_permissions.py](../lab/attack-range/aws_permissions.py)는 세션의 정확한 ARN에 한정한 컨트롤러 정책과 관리자 역할 준비 절차를 생성합니다. AWS 호출·정책 업로드·주체 권한 변경을 수행하지 않습니다.

```sh
python3 lab/attack-range/aws_permissions.py \
  --session "$PRIVATE_TTL_SESSION_JSON" \
  --output "$PRIVATE_PERMISSIONS_DIR"
```

관리자는 먼저 TTL 자료의 신뢰·실행 정책으로 종료 Lambda와 Scheduler 역할 두 개를 만듭니다. 실행 계정에는 이 두 역할의 전체 정책 조회와 서비스별 `PassRole`, 해당 세션의 Lambda·로그·예약 설치, 정확한 EC2 vCPU 할당량 조회만 추가합니다. 실행 계정이 역할을 만들거나 정책을 수정하는 권한은 포함하지 않습니다. 기존 계정에 `AdministratorAccess`를 부여하는 방식도 사용하지 않습니다.

출력의 `admin-instructions.txt`와 `admin-roles-recipe.json`에 구체적인 순서와 역할·파일 이름을 기록합니다. 생성 정책이 IAM 사용자 인라인 한도 2,048자를 넘으면 관리자가 고객 관리형 정책으로 생성·연결해야 합니다. 기존 역할을 덮어쓰지 않으며, 전체 신뢰 정책 일치·예상 인라인 정책 하나·관리형 정책 연결 없음까지 확인합니다. 추가 권한도 실제 IAM 평가와 원격 종료 장치 점검을 대신하지 않습니다.

개발 중 IAM Policy Autopilot `0.3.0`도 실행해 정적 분석을 확인했습니다. 종료 코드의 동적 클라이언트·함수 참조 전달을 놓쳐 `s3:ListBucket` 한 작업만 반환했으므로 그 결과는 실행 권한으로 사용하지 않습니다. 컨트롤러 문서는 별도로 명시한 API 작업과 AWS Service Authorization Reference의 자원·조건 지원을 기준으로 검토했습니다. Autopilot 재검토 명령은 다음과 같으며 정책을 업로드하지 않습니다.

```sh
uvx iam-policy-autopilot@latest generate-policies \
  "$PWD/lab/attack-range/aws_cleanup.py" \
  --region ap-northeast-2 --account "$RANGE_ACCOUNT_ID" \
  --service-hints ec2 s3 sts \
  --tf-dir "$PWD/.local-runtime/attack-range/upstream/terraform/aws" \
  --pretty
```
