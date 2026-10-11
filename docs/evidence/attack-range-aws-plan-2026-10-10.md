# 로컬 AWS 인증과 서울 실습 계획 검증

2026-10-10 23:46 KST에 사용자가 이미 인증한 로컬 CLI 프로필을 확인했습니다. SSO 로그인을 다시 진행하지 않았습니다. 기존 인증으로 조회·계획·DryRun만 수행했으며 **클라우드 자원은 생성하지 않았습니다.**

| 확인 | 결과 |
| --- | --- |
| 로컬 CLI | AWS CLI `2.37.12`, macOS arm64 |
| 기존 인증 | STS `GetCallerIdentity` 성공; 키 값 출력·복사 없음 |
| 대상 리전 | Seoul `ap-northeast-2` |
| 기존 EC2 | 실행·대기 인스턴스 0개 조회 |
| Terraform | `1.14.4`, AWS 공급자 `6.68.0`, VPC 모듈 `6.7.3` |
| 실제 init·validate·plan | 각각 종료 코드 0 |
| 실제 계획 구조 검사 | 통과, 모든 managed 변경은 새 자원 생성 계획 |
| EC2 실행 권한 | `DryRun=true` 요청의 `DryRunOperation`; 실제 실행·할당량 검증은 아님 |
| 종료 역할·함수·예약 조회 | 이번 세션의 정확한 이름으로도 `AccessDenied` |
| EC2 vCPU 할당량 조회 | `servicequotas:GetServiceQuota` 거부; 8 vCPU 허용 여부 미확인 |
| apply·키 import·S3 생성·IAM 변경 | 수행하지 않음 |

계획에는 Router `t3.small` 1대, Splunk `t3.xlarge` 1대, Windows `t3.large` 1대가 포함됩니다. gp3 루트 디스크는 30·60·60 GiB, NAT Gateway와 NAT EIP는 각 1개입니다. Router에만 공인 IP를 연결하며 SSH·WireGuard는 현재 공인 IP `/32`로 제한합니다. EC2와 루트 EBS의 소유·만료 태그, 디스크 암호화·종료 삭제, EC2 종료 보호 해제를 검사했습니다.

실제 계획 JSON은 조회를 마친 AMI 자료를 `prior_state`에 보관했습니다. AWS 공급자의 루트 EBS 사전은 하나이고 나머지는 EBS가 비어 있는 명시적 ephemeral 매핑임을 확인했습니다. 검사기를 이 실제 출력 형태에 맞추되 추가 EBS와 불명확한 매핑은 계속 거부합니다. VPC 모듈의 기본 보안 그룹 관리도 해제했습니다. 각 EC2는 별도로 검토한 전용 보안 그룹만 사용하며, 미확정 기본 그룹 규칙을 검사 통과로 처리하지 않습니다.

AWS 인증 파일은 일회성 공식 Terraform 컨테이너에 읽기 전용으로만 연결했습니다. 상시 관리 API에는 연결하지 않았습니다. 저장된 plan·변수·암호·로그·계정 정보는 비공개 `.local-runtime/`에 보관하며 이 공개 기록에는 포함하지 않습니다.

다음 단계는 [AWS 준비안](../attack-range-aws-plan.md)의 종료 역할·권한 준비, 실제 vCPU 한도 확인, 원격 종료 장치 점검입니다. 구조 검토와 DryRun이 성공해도 IAM·NAT·용량·자동 종료·비용 상한까지 검증된 것은 아닙니다. 권한과 종료 장치를 확인한 뒤 같은 saved plan만 적용하고 호스트 구성·실제 로그 수집을 진행해야 합니다.
