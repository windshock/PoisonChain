#!/usr/bin/env python3
"""
외부 통신 가능 서버 탐지 스크립트.

tracert.skplanet.com tcping API를 사용해 Jenkins 인스턴스 및 서비스 서버가
외부 인터넷(www.google.com:443, 8.8.8.8:53)에 통신 가능한지 확인한다.

공급망 공격(postinstall 실행) 서버 중 외부 통신 가능한 서버 = 데이터 유출 위험

Usage:
    python3 scripts/check_external_connectivity.py [--jenkins-only] [--nat-only] [--dry-run]

  --nat-only   : infrase CMDB에서 NAT 할당 서버를 자동 조회해 스캔 (권장)
  --jenkins-only: Jenkins 인스턴스 전체 스캔 (NAT 무관)
  --dry-run    : 실제 요청 없이 대상 목록만 출력

Environment:
    PNET_ID / PNET_PW  사내 포털 계정 — tracert/infrase 자동 로그인에 사용
    TRACERT_COOKIE     (선택) 수동 세션 쿠키 (없으면 PNET_ID/PW로 자동 로그인)
"""

import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
import http.cookiejar
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "internal" / "config"
REPORTS_DIR = BASE_DIR / "internal" / "reports" / "data"

INFRASE_BASE       = "https://infrase.skplanet.com"
INFRASE_LOGIN      = f"{INFRASE_BASE}/login.php?request_uri=/serverlist/"
INFRASE_QUERY      = f"{INFRASE_BASE}/serverlist/queryCmdb.php"
INFRASE_SIMPLECMDB = f"{INFRASE_BASE}/simpleCMDB/index.php"

TRACERT_URL = "https://tracert.skplanet.com/tracert.php"
# 테스트할 외부 대상 목록 (한 개라도 통신되면 외부 접근 가능으로 판단)
PROBE_TARGETS = [
    {"dip": "www.google.com", "dport": "443"},
    {"dip": "8.8.8.8",        "dport": "53"},
    {"dip": "registry.npmjs.org", "dport": "443"},
]
REQUEST_DELAY = 0.5   # 서버 부하 방지 (초)
TIMEOUT = 15


def load_env():
    env_path = BASE_DIR / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip("'\""))


def login_tracert() -> str:
    """PNET_ID / PNET_PW로 tracert.skplanet.com에 로그인해 PHPSESSID를 반환."""
    pnet_id = os.environ.get("PNET_ID", "")
    pnet_pw = os.environ.get("PNET_PW", "")
    if not pnet_id or not pnet_pw:
        return ""

    data = urllib.parse.urlencode({"id": pnet_id, "password": pnet_pw}).encode()
    req = urllib.request.Request(
        "https://tracert.skplanet.com/login.php",
        data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0",
        },
    )
    # redirect를 따라가지 않고 Set-Cookie만 수집
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
    urllib.request.install_opener(opener)

    import http.cookiejar
    jar = http.cookiejar.CookieJar()
    opener2 = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    try:
        opener2.open(req, timeout=10)
    except Exception:
        pass
    for c in jar:
        if c.name == "PHPSESSID":
            return f"PHPSESSID={c.value}"
    return ""


def get_cookie() -> str:
    cookie = os.environ.get("TRACERT_COOKIE", "")
    if cookie:
        return cookie

    # TRACERT_COOKIE 없으면 PNET_ID/PNET_PW로 자동 로그인 시도
    pnet_id = os.environ.get("PNET_ID", "")
    if pnet_id:
        print(f"🔑 TRACERT_COOKIE 없음 — PNET_ID({pnet_id})로 자동 로그인 시도...")
        cookie = login_tracert()
        if cookie:
            print(f"  ✅ 로그인 성공 (세션 획득)")
            return cookie
        print("  ❌ 자동 로그인 실패")

    print("❌ TRACERT_COOKIE 또는 PNET_ID/PNET_PW가 없습니다.")
    print("   .env에 PNET_ID=xxx 와 PNET_PW=yyy 를 추가하세요.")
    sys.exit(1)


def tcping(sip: str, dip: str, dport: str, cookie: str, dry_run: bool) -> bool | None:
    """
    tracert.skplanet.com으로 sip → dip:dport tcping 요청.
    Returns: True=통신가능, False=차단, None=오류
    """
    if dry_run:
        print(f"    [dry-run] tcping {sip} → {dip}:{dport}")
        return None

    data = urllib.parse.urlencode({
        "type": "tcping",
        "sip": sip,
        "dip": dip,
        "dport": dport,
    }).encode()

    req = urllib.request.Request(
        TRACERT_URL, data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Cookie": cookie,
            "User-Agent": "Mozilla/5.0",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": "https://tracert.skplanet.com/",
            "Origin": "https://tracert.skplanet.com",
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            body = r.read().decode("utf-8", errors="ignore")
            # 응답에 "Success" 또는 연결 성공 지표가 있으면 통신 가능
            body_lower = body.lower()
            if any(kw in body_lower for kw in ["success", "open", "connected", "alive"]):
                return True
            if any(kw in body_lower for kw in ["fail", "timeout", "refused", "closed", "filtered"]):
                return False
            # 응답 내용 불명확 → 원문 출력 후 None
            print(f"      응답 불명확: {body[:120]}")
            return None
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print("  ❌ 인증 실패 — TRACERT_COOKIE가 만료됐을 수 있습니다.")
        return None
    except Exception as e:
        return None


def check_server(ip: str, label: str, cookie: str, dry_run: bool) -> dict:
    """IP 하나에 대해 모든 probe target을 순서대로 tcping. 하나라도 성공하면 reachable."""
    result = {
        "ip": ip,
        "label": label,
        "reachable": False,
        "reachable_via": None,
        "probes": [],
    }
    for target in PROBE_TARGETS:
        dip, dport = target["dip"], target["dport"]
        ok = tcping(ip, dip, dport, cookie, dry_run)
        result["probes"].append({"dip": dip, "dport": dport, "result": ok})
        if ok is True:
            result["reachable"] = True
            result["reachable_via"] = f"{dip}:{dport}"
            break  # 하나 성공하면 충분
        time.sleep(REQUEST_DELAY)
    return result


def load_targets(jenkins_only: bool) -> list[dict]:
    """Jenkins 인스턴스 + (옵션) 서버 인벤토리에서 스캔 대상 IP 목록 생성."""
    targets = []
    seen = set()

    # Jenkins 인스턴스
    jf = CONFIG_DIR / "jenkins-instances.json"
    if jf.exists():
        d = json.loads(jf.read_text())
        for inst in d.get("instances", []):
            ip = inst["ip"]
            if ip not in seen:
                seen.add(ip)
                targets.append({
                    "ip": ip,
                    "label": f"Jenkins#{inst['id']} ({inst['url']})",
                    "source": "jenkins",
                    "jenkins_id": inst["id"],
                })

    if jenkins_only:
        return targets

    # 서버 인벤토리
    sf = CONFIG_DIR / "server-inventory.json"
    if sf.exists():
        d = json.loads(sf.read_text())
        for srv in d.get("servers", []):
            ip = srv["ip"]
            if ip not in seen:
                seen.add(ip)
                targets.append({
                    "ip": ip,
                    "label": srv["hostname"],
                    "source": "inventory",
                })

    return targets


def enrich_with_scan_results(results: list[dict]) -> list[dict]:
    """jenkins-scan-result.json 로드해서 CRITICAL/HIGH 잡이 있는 Jenkins IP 표시."""
    scan_file = REPORTS_DIR / "jenkins-scan-result.json"
    if not scan_file.exists():
        return results

    scan = json.loads(scan_file.read_text())
    # instance_url → risk_levels 맵핑
    risk_map: dict[str, list[str]] = {}
    for job in scan.get("results", []):
        url = job.get("instance_url", "")
        risk = job.get("risk_level", "")
        if url and risk in ("CRITICAL", "HIGH"):
            risk_map.setdefault(url, []).append(risk)

    for r in results:
        # IP로 instance_url 매칭
        ip = r["ip"]
        matched_risks = []
        for url, risks in risk_map.items():
            if ip in url:
                matched_risks.extend(risks)
        if matched_risks:
            r["jenkins_risk"] = "CRITICAL" if "CRITICAL" in matched_risks else "HIGH"
            r["jenkins_risk_count"] = len(matched_risks)
        else:
            r["jenkins_risk"] = None

    return results


def login_infrase() -> str:
    """PNET_ID/PNET_PW로 infrase.skplanet.com에 로그인해 PHPSESSID를 반환."""
    pnet_id = os.environ.get("PNET_ID", "")
    pnet_pw = os.environ.get("PNET_PW", "")
    if not pnet_id or not pnet_pw:
        return ""
    data = urllib.parse.urlencode({"id": pnet_id, "password": pnet_pw}).encode()
    req = urllib.request.Request(
        INFRASE_LOGIN, data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0"},
    )
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    try:
        opener.open(req, timeout=10)
    except Exception:
        pass
    for c in jar:
        if c.name == "PHPSESSID":
            return c.value
    return ""


def fetch_nat_from_infrase(ips: list[str], infrase_session: str, today: str) -> dict[str, dict]:
    """
    infrase CMDB에서 IP 목록의 NAT 정보를 일괄 조회.
    Returns: {ip: {hostname, zone, nat_public_ip, service_name, ...}}
    """
    if not infrase_session or not ips:
        return {}

    where_parts = " OR ".join(f"Access_IP = '{ip}'" for ip in ips)
    args = {
        "date": today,
        "select": ["HostName","Access_IP","OS","Not_collected_data","Service_Name",
                   "Service_Code","IDC","Zone","Server_Model","CPU_Model","Memory_Total","NAT_OUT_Public_IP"],
        "where": f"NAT_OUT_Public_IP != 'CF;' AND ({where_parts})",
        "limit": "1000",
        "idc": "all",
        "orderBy": "HostName",
    }
    data = urllib.parse.urlencode({"action": "whereQuery", "args": json.dumps(args)}).encode()
    req = urllib.request.Request(
        INFRASE_QUERY, data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Cookie": f"PHPSESSID={infrase_session}",
            "X-Requested-With": "XMLHttpRequest",
            "User-Agent": "Mozilla/5.0",
            "Origin": INFRASE_BASE,
            "Referer": f"{INFRASE_BASE}/serverlist/",
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = json.loads(r.read().decode("utf-8"))
    except Exception as e:
        print(f"  ⚠️  infrase 조회 실패: {e}")
        return {}

    result = {}
    rows = raw.values() if isinstance(raw, dict) else raw
    for row in rows:
        if not isinstance(row, dict):
            continue
        ip = row.get("Access_IP", "")
        nat = row.get("NAT_OUT_Public_IP", "").rstrip(";")
        if ip and nat:
            result[ip] = {
                "hostname": row.get("HostName", ip),
                "zone": row.get("Zone", ""),
                "nat_public_ip": nat,
                "service_name": row.get("Service_Name", ""),
                "service_code": row.get("Service_Code", ""),
                "idc": row.get("IDC", ""),
                "os": row.get("OS", ""),
            }
    return result


def fetch_contact(ip: str, infrase_session: str) -> dict:
    """
    infrase simpleCMDB에서 서버 IP의 개발담당 연락처 + hostname + 서비스명 조회.
    Returns: {hostname, service, se: [...], primary: {name, team, phone, email}, secondary: [...]}
    """
    if not infrase_session:
        return {}
    req = urllib.request.Request(
        f"{INFRASE_SIMPLECMDB}?accessIP={ip}",
        headers={"User-Agent": "Mozilla/5.0", "Cookie": f"PHPSESSID={infrase_session}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            html = r.read().decode("utf-8", errors="ignore")
    except Exception:
        return {}

    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text).strip()

    def parse_person(raw: str) -> dict:
        m = re.match(r"(.+?)\((.+?)\)\s*/\s*([\d\-]+)\s*/\s*(\S+@\S+)", raw.strip())
        if m:
            return {"name": m.group(1).strip(), "team": m.group(2).strip(),
                    "phone": m.group(3).strip(), "email": m.group(4).strip()}
        return {"name": raw.strip()}

    result: dict = {}

    # Hostname 파싱
    m_host = re.search(r"Hostname\s+(\S+)", text)
    if m_host:
        result["hostname"] = m_host.group(1).strip()

    # 서비스명 파싱
    m_svc = re.search(r"서비스명\(코드\)\s+(.+?)\s+SE담당", text)
    if m_svc:
        result["service"] = m_svc.group(1).strip()

    m_se = re.search(r"SE담당\s+(.+?)\s+개발담당", text)
    if m_se:
        result["se"] = [n.strip() for n in m_se.group(1).split("-") if n.strip()]

    m_pri = re.search(r"개발담당\(정\)\s+(.+?)(?=개발담당\(부\)|$)", text)
    if m_pri:
        result["primary"] = parse_person(m_pri.group(1))

    secondary = []
    for m_sec in re.finditer(r"개발담당\(부\)\s+(.+?)(?=개발담당\(부\)|$)", text):
        secondary.append(parse_person(m_sec.group(1)))
    if secondary:
        result["secondary"] = secondary

    return result


def enrich_contacts(results: list[dict], infrase_session: str) -> list[dict]:
    """외부통신 가능 서버에 개발담당 연락처를 추가."""
    if not infrase_session:
        return results
    reachable = [r for r in results if r.get("reachable")]
    if not reachable:
        return results
    print(f"\n📇 개발담당 연락처 조회 중 ({len(reachable)}개 서버)...")
    for r in reachable:
        contact = fetch_contact(r["ip"], infrase_session)
        r["contact"] = contact
        if contact.get("primary"):
            p = contact["primary"]
            print(f"  {r['ip']:16} {p.get('name','?')}({p.get('team','?')}) {p.get('email','')}")
        time.sleep(0.3)
    return results
    """
    infrase CMDB에서 IP 목록의 NAT 정보를 일괄 조회.
    Returns: {ip: {hostname, zone, nat_public_ip, service_name, ...}}
    """
    if not infrase_session or not ips:
        return {}

    where_parts = " OR ".join(f"Access_IP = '{ip}'" for ip in ips)
    args = {
        "date": today,
        "select": ["HostName","Access_IP","OS","Not_collected_data","Service_Name",
                   "Service_Code","IDC","Zone","Server_Model","CPU_Model","Memory_Total","NAT_OUT_Public_IP"],
        "where": f"NAT_OUT_Public_IP != 'CF;' AND ({where_parts})",
        "limit": "1000",
        "idc": "all",
        "orderBy": "HostName",
    }
    data = urllib.parse.urlencode({"action": "whereQuery", "args": json.dumps(args)}).encode()
    req = urllib.request.Request(
        INFRASE_QUERY, data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Cookie": f"PHPSESSID={infrase_session}",
            "X-Requested-With": "XMLHttpRequest",
            "User-Agent": "Mozilla/5.0",
            "Origin": INFRASE_BASE,
            "Referer": f"{INFRASE_BASE}/serverlist/",
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = json.loads(r.read().decode("utf-8"))
    except Exception as e:
        print(f"  ⚠️  infrase 조회 실패: {e}")
        return {}

    result = {}
    rows = raw.values() if isinstance(raw, dict) else raw
    for row in rows:
        if not isinstance(row, dict):
            continue  # total 등 정수 필드 스킵
        ip = row.get("Access_IP", "")
        nat = row.get("NAT_OUT_Public_IP", "").rstrip(";")
        if ip and nat:
            result[ip] = {
                "hostname": row.get("HostName", ip),
                "zone": row.get("Zone", ""),
                "nat_public_ip": nat,
                "service_name": row.get("Service_Name", ""),
                "service_code": row.get("Service_Code", ""),
                "idc": row.get("IDC", ""),
                "os": row.get("OS", ""),
            }
    return result


def load_nat_targets(infrase_session: str = "") -> list[dict]:
    """
    infrase CMDB에서 모든 Jenkins IP의 NAT 할당 여부를 자동 조회.
    NAT 있는 서버만 스캔 대상으로 반환. nat-inventory.json을 함께 갱신한다.
    """
    jf = CONFIG_DIR / "jenkins-instances.json"
    if not jf.exists():
        return []

    jenkins_data = json.loads(jf.read_text())
    jenkins_map: dict[str, dict] = {}
    for inst in jenkins_data.get("instances", []):
        jenkins_map.setdefault(inst["ip"], inst)
    all_ips = list(jenkins_map.keys())

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    print("🔍 infrase CMDB에서 NAT 할당 정보 자동 조회 중...")
    if not infrase_session:
        pnet_id = os.environ.get("PNET_ID", "")
        if pnet_id:
            infrase_session = login_infrase()

    if infrase_session:
        nat_map = fetch_nat_from_infrase(all_ips, infrase_session, today)
        print(f"  ✅ infrase 응답: {len(nat_map)}개 NAT 서버 확인")
    else:
        print("  ⚠️  infrase 로그인 실패 — nat-inventory.json 사용")
        nat_map = {}

    # fallback: nat-inventory.json
    nat_file = CONFIG_DIR / "nat-inventory.json"
    if not nat_map and nat_file.exists():
        d = json.loads(nat_file.read_text())
        for srv in d.get("servers", []):
            ip = srv["ip"]
            nat_map[ip] = {
                "hostname": srv["hostname"], "zone": srv["zone"],
                "nat_public_ip": srv["nat_public_ip"],
                "service_name": srv.get("service_name",""), "service_code": srv.get("service_code",""),
                "idc": "", "os": "",
            }

    # nat-inventory.json 갱신 (infrase에서 실제로 조회한 경우만)
    if nat_map and infrase_session:
        servers = []
        for ip, info in nat_map.items():
            servers.append({"ip": ip, **info})
        nat_file.write_text(json.dumps(
            {"_generated": today, "_count": len(servers), "servers": servers},
            ensure_ascii=False, indent=2
        ))

    # 대상 목록 구성 (Jenkins 우선, 비Jenkins NAT 서버도 포함)
    targets = []
    seen: set[str] = set()
    for ip, info in nat_map.items():
        if ip in seen:
            continue
        seen.add(ip)
        j = jenkins_map.get(ip)
        zone = info.get("zone", "")
        nat_ip = info.get("nat_public_ip", "")
        label = f"{info['hostname']} (NAT={nat_ip}, zone={zone})"
        if j:
            label += f" Jenkins#{j['id']}"
        targets.append({
            "ip": ip, "label": label, "source": "nat",
            "hostname": info["hostname"], "zone": zone,
            "nat_public_ip": nat_ip, "jenkins_id": j["id"] if j else None,
        })

    # Jenkins 이면서 NAT 없는 서버도 별도 표기 (참고용, 스캔 제외)
    no_nat = [ip for ip in all_ips if ip not in nat_map]
    if no_nat:
        print(f"  ℹ️  NAT 없는 Jenkins 서버 {len(no_nat)}개 — 스캔 제외")

    print(f"📋 스캔 대상: {len(targets)}개 IP (NAT 할당 Jenkins + 서비스 서버)\n")
    return targets


def main():
    load_env()

    args = sys.argv[1:]
    dry_run = "--dry-run" in args
    jenkins_only = "--jenkins-only" in args
    nat_only = "--nat-only" in args

    if dry_run:
        print("🔍 Dry-run 모드: 실제 요청 없이 대상 목록만 출력")
    cookie = "" if dry_run else get_cookie()

    # infrase 세션 (NAT 조회 + 담당자 조회 공용)
    infrase_session = ""
    pnet_id = os.environ.get("PNET_ID", "")
    if pnet_id and not dry_run:
        infrase_session = login_infrase()

    if nat_only:
        targets = load_nat_targets(infrase_session)
    else:
        targets = load_targets(jenkins_only)
        print(f"📋 스캔 대상: {len(targets)}개 IP (jenkins_only={jenkins_only})")
    probe_list = [t["dip"] + ":" + t["dport"] for t in PROBE_TARGETS]
    print(f"🌐 Probe 대상: {probe_list}\n")

    raw_results = []
    for i, t in enumerate(targets, 1):
        ip, label = t["ip"], t["label"]
        print(f"[{i:3}/{len(targets)}] {ip:16} {label}")
        r = check_server(ip, label, cookie, dry_run)
        r.update({k: v for k, v in t.items() if k not in r})
        raw_results.append(r)
        status = "✅ 외부통신 가능" if r["reachable"] else ("⛔ 차단" if not dry_run else "")
        if r["reachable"]:
            print(f"            → {status} via {r['reachable_via']}")
        if not dry_run:
            time.sleep(REQUEST_DELAY)

    # Jenkins 위험도 + 개발담당 연락처 enrichment
    results = enrich_with_scan_results(raw_results)
    if not dry_run and infrase_session:
        results = enrich_contacts(results, infrase_session)

    # 요약
    reachable = [r for r in results if r["reachable"]]
    critical_reachable = [r for r in reachable if r.get("jenkins_risk") == "CRITICAL"]
    high_reachable = [r for r in reachable if r.get("jenkins_risk") == "HIGH"]

    print(f"\n{'='*70}")
    print(f"외부 통신 가능 서버: {len(reachable)}/{len(results)}개")
    print(f"  ⚠️  CRITICAL 잡 있음 + 외부통신 가능: {len(critical_reachable)}개  ← 데이터 유출 최우선 조사")
    print(f"  ⚠️  HIGH 잡 있음    + 외부통신 가능: {len(high_reachable)}개")

    if critical_reachable:
        print("\n🔴 CRITICAL + 외부통신 가능 서버:")
        for r in critical_reachable:
            contact = r.get("contact", {}).get("primary", {})
            contact_str = f" → {contact.get('name','?')} {contact.get('email','')}" if contact else ""
            print(f"   {r['ip']:16} {r['label']} (via {r['reachable_via']}){contact_str}")

    # 리포트 저장
    REPORTS_DIR.mkdir(exist_ok=True)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_scanned": len(results),
        "reachable_count": len(reachable),
        "critical_reachable_count": len(critical_reachable),
        "high_reachable_count": len(high_reachable),
        "results": results,
    }
    out_path = REPORTS_DIR / "external-connectivity-result.json"
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"\n📄 결과: {out_path}")


if __name__ == "__main__":
    main()
