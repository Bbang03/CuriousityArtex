import { resolveLocale } from "@/i18n/config";

import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

// 브라우저 탭 제목·검색엔진 메타 설명. layout.tsx 의 정적 metadata 로 들어가 모든
// 페이지의 <title>·<meta name="description"> 에 렌더되므로, 활성 locale 에 맞춰
// 한국어(ko)·중국어(zh)를 분기한다. zh 는 상류 대조를 위해 원문을 그대로 보존한다.
// ko 제목은 엠대시 대신 콜론을 써서 "제품명: 설명" 형태로 둔다.
const META_BY_LOCALE = {
  ko: {
    title: "AegisLoop: 공격·방어 보안 운영",
    description: "ARTEX 기반 취약점 진단·침해 조사·공격 방어 개선 콘솔",
  },
  zh: {
    title: "AegisLoop — 攻防安全运营",
    description: "基于 ARTEX 的漏洞诊断、事件调查与攻防改进控制台",
  },
} as const;

export const APP_CONFIG = {
  name: "AegisLoop",
  version: packageJson.version,
  copyright: `© ${currentYear}, ARTEX.`,
  meta: META_BY_LOCALE[resolveLocale()],
};
