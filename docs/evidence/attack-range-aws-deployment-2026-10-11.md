# AWS Attack Range 수동 운영 구축 기록

2026-10-11 KST에 사용자가 요청한 일주일 수동 운영 구성으로 AWS 자원을 생성했습니다. 기존 로컬 CLI 인증을 사용했으며, 자동 종료용 IAM 역할·Lambda·Scheduler는 설치하지 않았습니다. 공개 키만 AWS에 등록하고 비밀 키·암호·Terraform 상태는 Git 제외 폴더에 보관했습니다.

| 확인 | 실제 결과 |
| --- | --- |
| 리전·운영 방식 | Seoul `ap-northeast-2`, 일주일 후 사용자 직접 정리 |
| 준비·계획 | Terraform `1.14.4`, 공급자 `6.68.0`, VPC 모듈 `6.7.3`; init·validate·plan·구조 검사 통과 |
| 적용 | 해시로 확인한 동일 saved plan, apply 종료 코드 0 |
| EC2 조회 | Router `t3.small`·Splunk `t3.xlarge`·Windows `t3.medium` 각각 1대 `running`, 총 8 vCPU |
| EBS 조회 | 루트 디스크 3개, 총 150 GiB, 모두 암호화 |
| 네트워크 조회 | NAT Gateway 1개 `available`, 할당 EIP 1개; Router에만 별도 공인 IP |
| 소유·종료 목표 태그 | EC2·EBS·NAT·EIP에서 이번 세션·계획 종료 시각·프로젝트와 일치 |
| Router SSH | 전용 키로 연결, Linux 커널 확인 |
| 자동 종료 | 미설치; 만료 태그는 예약 종료를 실행하지 않음 |

앞선 [인증·기본 계획 검증](attack-range-aws-plan-2026-10-10.md)에서는 자원을 생성하지 않았습니다. 이후 수동 운영 요청에 따라 Windows를 4 GiB로 줄인 새 세션을 준비·검토하고 적용했습니다. EC2 할당량 조회 권한은 없지만 실제 8 vCPU 실행을 확인했습니다. 이는 추가 서버 생성 여유나 서비스 전체 권한을 입증하지 않습니다.

동일 공개 가격표 기준 기본액은 하루 `$9.4176`, 7일 `$65.9232`입니다. 세금·전송·NAT 처리량·T3 CPU 초과 크레딧·유료 라이선스·LLM 비용을 포함한 청구액 상한은 아닙니다. 계산과 출처는 [AWS 운영 준비안](../attack-range-aws-plan.md)에 있습니다.

## 실제 호스트 설치와 로그 전달

2026-10-11 00:27 KST에 공식 역할 설치와 별도 검증을 마쳤습니다. 설치와 최종 검증의 Ansible 종료 코드는 각각 0이며, 두 호스트의 최종 검증에서 `failed=0`, `unreachable=0`을 확인했습니다.

| 확인 | 실제 결과 |
| --- | --- |
| Splunk·Guacamole | 웹 HTTP 200; Guacamole 새 `admin` 계정 인증·연결 목록 조회 성공, Windows RDP 연결 1개 |
| Windows 서비스 | Sysmon·SplunkForwarder·WinRM 실행 중, 전달 목적지 `10.0.2.10:9997` |
| Sysmon | 설치 버전 `15.22`, Authenticode `Valid`, Microsoft 발행자 확인; 설치 파일 SHA256 사설 보관 |
| Windows 감사 | 프로세스 생성 감사·명령줄 기록 활성화 |
| PowerShell | script block·invocation logging 활성화 |
| Atomic Red Team | manifest 검사·절대 경로 import·`Invoke-AtomicTest` 함수 준비 성공, 모듈 버전 `2.1.0` |
| 최종 endpoint 검사 | 15개 조건 모두 참, 실패 조건 없음 |

무해한 `cmd.exe /d /c "whoami & rem AEGIS_VERIFY_<고유값>"`를 실제 Windows에서 실행했습니다. 검색은 실행마다 새 marker·인증한 실제 호스트 이름·이번 검증 시작 10초 전부터 각 검색 실행 시각까지의 UTC 범위를 요구합니다. 이전 실행의 로그를 대신 집계하지 않습니다. Splunk `index=win`에서 동일 marker와 `whoami`를 포함하는 이벤트를 종류별로 따로 요구하고 다음을 확인했습니다.

| 원본 로그 | Event ID | 실제 수집 건수 |
| --- | ---: | ---: |
| Sysmon Operational | 1 | 2 |
| Windows Security | 4688 | 1 |
| PowerShell Operational | 4104 | 1 |

이 4건은 **실제 명령의 로그 수집·상관 근거**입니다. 공격 성공·경보 발화·탐지 정확도·AegisLoop의 클라우드 Splunk 검색 연결을 검증한 결과는 아닙니다. 공식 Windows 역할은 Microsoft Defender 기능을 제거했으며, 현재 호스트에서도 `Installed=false`입니다. Defender·EDR 탐지 결과를 주장하지 않습니다.

## 재현 범위와 사설 운영 자료

공식 Attack Range 소스는 `fc9b9e719d8835da0bbb5c20d46c52a9778d64e2`를 유지했습니다. 역할은 다음 커밋의 캐시에서 사설 폴더로 복사했으며 원본·캐시는 수정하지 않았습니다.

- Splunk: `f1bf753a9bb24a9a752c19756a00e7e43662bcce`
- Guacamole: `af0b971a5c69e5d471aa1f3dc70770634dc85b7c`
- Windows: `b5d08da3a30dc1c7a185b163c828b20369382faf`

사설 실행본에서는 연결 대기 후 Windows facts 수집, Linux cloud-init 완료 대기, Sysmon·UF 설치 전 서명 검사, MSI 암호 로그 숨김, 4688 명령줄 감사 레지스트리 이름 보정을 적용했습니다. Atomic 모듈은 공식 설치 경로가 일반 모듈 검색 경로 밖에 있으므로, 단순 목록 조회를 파일·manifest·실제 import·함수 준비 검사로 고쳤습니다. 설치 중 Windows 10/11 전용 Defender 조건이 Server에서 Ansible의 엄격한 boolean 검사에 걸려 한 번 무시됐지만, 다음 Server 전용 제거 작업과 전체 설치는 완료됐습니다.

역할 커밋 고정과 실행 파일의 서명 검증은 별개입니다. 외부 Sysmon·Atomic 다운로드 전체를 커밋이나 공개 예상 해시로 고정한 것은 아니며, SHA 기록은 사용한 파일의 식별 근거입니다.

접속 안내·새 암호·SSH 키·고유 marker·원본 검증 JSON·상태 백업은 Git 제외 폴더에 보관했습니다. 로컬 SSH 터널로 Splunk·Guacamole·Windows에 접근하며 추가 공개 관리 포트는 열지 않았습니다. 사설 정리 실행 파일은 해당 세션의 Terraform destroy 후 EC2·EBS·NAT·EIP 잔존을 다시 조회하도록 준비했습니다. **실제 삭제는 아직 실행하지 않았고**, 사용자 요청대로 환경을 유지합니다.
