package investigation

// BuildDefensivePlan starts with a user-selected asset/time range and evidence,
// without inventing a vulnerability. An optional finding is handled separately
// by the case snapshot and does not establish that an intrusion occurred.
func BuildDefensivePlan() Plan {
	return Plan{EngineVersion: EngineVersion, Method: "로그 근거 기반 독립 조사", Family: "defensive",
		Summary: "선택한 대상·기간의 실제 로그에서 관측 행동과 정상 대안을 검토합니다.",
		Hypotheses: []Hypothesis{
			{ID: "path_access", Title: "조사 범위의 접근 기록", Statement: "로그에 기록된 접근을 확인합니다. 접근 기록만으로 공격이나 침해를 확정하지 않습니다.", RequiredLogs: []string{"선택한 대상의 요청·감사 로그"}, RequiredFields: []string{"시각", "대상", "경로 또는 이벤트 종류"}, Hunt: "조사 대상·기간·경로와 일치하는 이벤트를 확인하고 등록된 ARTEX 검증 요청을 구분합니다.", BenignAlternatives: []string{"정상 사용자 활동", "승인된 보안 점검", "운영·모니터링 작업"}, NextSteps: []string{"원본 이벤트와 승인된 작업 이력을 대조하세요."}},
			{ID: "multi_path", Title: "동일 로그 출처의 요청 흐름", Statement: "동일 출처·대상·세션 또는 출발지의 여러 경로 요청을 검토합니다. 동일 IP만으로 동일 행위자를 확정하지 않습니다.", RequiredLogs: []string{"웹 요청·세션 로그"}, RequiredFields: []string{"시각", "대상", "경로", "세션 또는 출발지"}, Hunt: "같은 출처에서 10분 내 서로 다른 경로 요청을 확인하고 정상 리소스 로딩과 대조합니다.", BenignAlternatives: []string{"정상 브라우저 요청", "NAT·공유 프록시", "승인된 점검"}, NextSteps: []string{"세션·계정·운영 이력으로 요청 흐름을 검토하세요."}},
			{ID: "additional_evidence", Title: "경보와 후속 활동의 근거", Statement: "경보 자체와 공격 성공은 구분합니다. 인증·호스트·네트워크 활동은 해당 원본 로그가 있을 때 검토합니다.", RequiredLogs: []string{"경보 원본", "필요한 인증·호스트·네트워크 로그"}, RequiredFields: []string{"시각", "대상", "이벤트 종류", "계정 또는 세션"}, Hunt: "원본 경보를 확인하고 필요한 추가 로그와 조사 범위를 기록합니다.", BenignAlternatives: []string{"탐지 오탐", "승인된 관리 작업"}, NextSteps: []string{"없는 로그를 추정하지 말고 필요한 자료를 확보하세요."}},
		}, Limitations: []string{"이 기록은 취약점 진단 없이 시작한 독립 방어 조사입니다.", "정적 분석은 범위 내 이벤트와 제한된 요청 흐름을 정리하며 침해 여부를 확정하지 않습니다.", "AI 조사는 별도로 시작하며 허용 범위 안의 읽기 전용 근거만 사용합니다."}}
}
