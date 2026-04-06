#!/usr/bin/env python3
"""
Employee status checker via pnet.skplanet.com
Checks if committers from axios scan are still active employees.
Status: 3 = active, others = resigned/inactive
"""

import json
import os
import re
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bitbucket_workspace import strip_personal_from_scan
import subprocess
import urllib.parse

ROOT_DIR = Path(__file__).resolve().parent.parent
REPORTS_DATA_DIR = ROOT_DIR / "internal" / "reports" / "data"
SCAN_JSON_PATH = REPORTS_DATA_DIR / "bitbucket-full-scan-result.json"
EMPLOYEE_STATUS_JSON_PATH = REPORTS_DATA_DIR / "employee-status-check.json"


def _default_env_path():
    return ROOT_DIR / ".env"


def load_env(path=None):
    """Load .env from repo root. Values in file always win (override empty shell/IDE env)."""
    path = path or _default_env_path()
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
                v = v[1:-1]
            os.environ[k] = v


load_env()

BASE_URL = "https://pnet.skplanet.com/SKPUnit114/SearchUser.aspx"
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"


def pnet_cookies():
    """Cookie string for curl -b (from .env PNET_COOKIE)."""
    c = os.environ.get("PNET_COOKIE", "").strip().strip('"\'')
    if not c:
        sys.exit(
            "ERROR: PNET_COOKIE not set. Add to .env — same format as curl -b "
            "(e.g. name=value; name2=value2). See public/.env.example."
        )
    return c


def get_page(cookies):
    result = subprocess.run([
        'curl', '-s', '-k', BASE_URL,
        '-b', cookies,
        '-H', f'User-Agent: {UA}'
    ], capture_output=True, text=True, timeout=30)
    return result.stdout


def extract_asp_fields(page_html):
    fields = {}
    for name in ['__VIEWSTATE', '__EVENTVALIDATION', '__VIEWSTATEGENERATOR', '__PREVIOUSPAGE']:
        m = re.search(rf'{name}[^>]*value="([^"]*)"', page_html)
        if m:
            fields[name] = m.group(1)
    return fields


def extract_asp_from_delta(resp):
    """Extract ASP.NET fields from async delta response."""
    fields = {}
    for name in ['__VIEWSTATE', '__EVENTVALIDATION', '__VIEWSTATEGENERATOR', '__PREVIOUSPAGE']:
        m = re.search(rf'{name}\|([^|]*)\|', resp)
        if m:
            fields[name] = m.group(1)
    return fields


def search_user(search_text, asp_fields, cookies):
    form_data = {
        'ScriptManager2': 'upList|ucSearchBox$btnSearch2',
        'ucSearchBox$ddlCompany': 'ALL',
        'ucSearchBox$ddlSearchType': 'ALL',
        'ucSearchBox$txtSearchText': search_text,
        'ucTree$ucDDlCompany': 'SKP',
        'ucTree$hdnBMark': '',
        'ucTree$hdnLoginID': 'xx',
        'ucTree$hdUserLanguage': 'KOR',
        'ucTree$hdScrollPos': '',
        'GroupCode': '',
        'txtLoginID': 'xx',
        'Company': '',
        'CompanyName': '',
        'Type': '',
        'Text': '',
        'code': '',
        'userCompany': '',
        'SearchCompany': 'ALL',
        'SearchCompanyName': '',
        'SearchType': 'ALL',
        'SearchText': '',
        'hddMSGUsers': '',
        'hddSMSUsers': '',
        'hhdXmlContainer': '',
        'hhdSMSUrl': '',
        'hhdMobile': '',
        'hhdEmployeeID': 'xx',
        'hhdUserKey': '',
        'hhdSearchField': '',
        'hhdDepartmentNumber': '',
        'hhdUserLanguage': 'KOR',
        'hhdEZPGName': '',
        'hhdEZClassName': '',
        'hhdEZCapName': '',
        '__EVENTTARGET': '',
        '__EVENTARGUMENT': '',
        '__LASTFOCUS': '',
        '__SCROLLPOSITIONX': '0',
        '__SCROLLPOSITIONY': '0',
        '__ASYNCPOST': 'true',
        'ucSearchBox$btnSearch2': '',
    }
    form_data.update(asp_fields)
    encoded = urllib.parse.urlencode(form_data)

    result = subprocess.run([
        'curl', '-s', '-k', BASE_URL,
        '-b', cookies,
        '-H', f'User-Agent: {UA}',
        '-H', 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8',
        '-H', 'X-MicrosoftAjax: Delta=true',
        '-H', 'Origin: https://pnet.skplanet.com',
        '-H', f'Referer: {BASE_URL}',
        '--data-raw', encoded
    ], capture_output=True, text=True, timeout=30)
    return result.stdout


def extract_pnet_org_team_from_grid(resp: str, prefer_email: Optional[str] = None) -> str:
    """
    SearchUser.aspx 결과 그리드(gvList)에서 조직/팀명 추출.
    실제 마크업: <a id="gvList_ctl02_btnOrgName" ...>MP솔루션개발팀</a>
    (hidden hdnDept* 가 아니라 링크 텍스트로 온다.)
    """
    if not resp:
        return ""
    ctls = re.findall(r"gvList\$ctl(\d+)\$hdnCode", resp)
    if not ctls:
        return ""
    uniq = sorted(set(ctls), key=lambda x: int(x, 10))
    want = (prefer_email or "").strip().lower()

    def org_for_ctl(ctl: str) -> str:
        m = re.search(rf'id="gvList_ctl{ctl}_btnOrgName"[^>]*>([^<]+)</a>', resp)
        return (m.group(1) or "").strip() if m else ""

    if want:
        for ctl in uniq:
            m = re.search(rf'id="gvList_ctl{ctl}_hdnSipUri"[^>]*value="([^"]*)"', resp)
            if m and m.group(1).strip().lower() == want:
                v = org_for_ctl(ctl)
                if v:
                    return v
    return org_for_ctl(uniq[0])


def extract_pnet_dept_html(resp):
    """보조: 일부 화면에서만 쓰이는 hidden 부서 필드."""
    for pat in (
        r'hdnDeptName[^>]*value=["\']([^"\']*)["\']',
        r'name=["\']hdnDeptName["\'][^>]*value=["\']([^"\']*)["\']',
        r'hdnOrganizationName[^>]*value=["\']([^"\']*)["\']',
        r'hdnPartName[^>]*value=["\']([^"\']*)["\']',
        r'hdnDisplayDept[^>]*value=["\']([^"\']*)["\']',
    ):
        m = re.search(pat, resp, re.I)
        if m:
            v = (m.group(1) or "").strip()
            if v and "@" not in v:
                return v
    return ""


def parse_result(resp, search_email: Optional[str] = None):
    """Parse user data from response. Returns dict with user info."""
    if 'error|500' in resp:
        return None

    rows = re.findall(
        r'hdnCompany.*?value.*?["\']([^"\']*)["\'].*?'
        r'hdnCode.*?value.*?["\']([^"\']*)["\'].*?'
        r'hdnUserStatus.*?value.*?["\'](\d+)["\'].*?'
        r'hdnSipUri.*?value.*?["\']([^"\']*)["\']',
        resp, re.DOTALL
    )

    if rows:
        company, empid, status, email = rows[0]
        name_m = re.findall(r"UserView\('([^']*)',\s*'([^']*)',\s*'([^']*)',\s*'([^']*)',\s*'([^']*)'\)", resp)
        pnet_user_view = list(name_m[0]) if name_m else None
        pnet_dept = extract_pnet_org_team_from_grid(resp, prefer_email=search_email)
        if not pnet_dept:
            pnet_dept = extract_pnet_dept_html(resp)

        return {
            'empid': empid,
            'company': company,
            'status': int(status),
            'status_text': '재직' if status == '3' else '퇴직/비활성',
            'pnet_email': email,
            'pnet_dept': pnet_dept,
            'pnet_user_view': pnet_user_view,
        }

    return None


def main():
    cookies = pnet_cookies()

    # Load scan results
    with open(SCAN_JSON_PATH) as f:
        scan = json.load(f)

    dropped = strip_personal_from_scan(scan)
    if dropped:
        print(f"개인 워크스페이스(~…) axios 리포 {dropped}개 제외 후 재직 조회\n")

    # Collect unique committer emails (only @sk.com)
    all_emails = set()
    email_to_repos = {}
    for repo in scan['axios_versions']:
        for c in repo.get('committers', []):
            email = c['email']
            if '@sk.com' in email or '@sk-inc.com' in email:
                all_emails.add(email)
                if email not in email_to_repos:
                    email_to_repos[email] = []
                email_to_repos[email].append(repo['name'])

    emails = sorted(all_emails)
    print(f"=== Employee Status Check ===")
    print(f"Total @sk.com committers: {len(emails)}")
    print(f"Skipping external emails (non-sk.com)")
    print()

    # Get initial VIEWSTATE
    print("Getting fresh page...")
    page = get_page(cookies)
    asp = extract_asp_fields(page)
    print(f"Got VIEWSTATE. Starting lookups...\n")

    results = []
    not_found = []
    active = 0
    inactive = 0

    for i, email in enumerate(emails):
        try:
            resp = search_user(email, asp, cookies)
            # Extract new ASP fields for chaining
            new_asp = extract_asp_from_delta(resp)
            if new_asp.get('__VIEWSTATE'):
                asp = new_asp

            user = parse_result(resp, search_email=email)
            if user:
                user['search_email'] = email
                user['repos'] = email_to_repos.get(email, [])
                results.append(user)
                if user['status'] == 3:
                    active += 1
                else:
                    inactive += 1
                    print(f"  ⚠️  INACTIVE: {email} → empid={user['empid']} status={user['status']}")
            else:
                not_found.append(email)

        except Exception as e:
            not_found.append(email)

        if (i + 1) % 20 == 0:
            print(f"  [{i+1}/{len(emails)}] active={active}, inactive={inactive}, not_found={len(not_found)}")
            # Refresh VIEWSTATE periodically
            if (i + 1) % 50 == 0:
                page = get_page(cookies)
                asp = extract_asp_fields(page)

    print(f"\n=== Results ===")
    print(f"Total checked:  {len(emails)}")
    print(f"Active (재직):  {active}")
    print(f"Inactive (퇴직): {inactive}")
    print(f"Not found:      {len(not_found)}")

    if inactive > 0:
        print(f"\n⚠️  Inactive/Resigned committers:")
        for r in results:
            if r['status'] != 3:
                print(f"  {r['search_email']} (empid: {r['empid']}, repos: {', '.join(r['repos'][:3])})")

    if not_found:
        print(f"\n❓ Not found in pnet (external/deleted):")
        for e in not_found[:10]:
            print(f"  {e}")
        if len(not_found) > 10:
            print(f"  ... and {len(not_found) - 10} more")

    # Save results
    output = {
        'total_checked': len(emails),
        'active': active,
        'inactive': inactive,
        'not_found_count': len(not_found),
        'results': results,
        'not_found_emails': not_found,
    }

    REPORTS_DATA_DIR.mkdir(parents=True, exist_ok=True)

    with open(EMPLOYEE_STATUS_JSON_PATH, 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    # Update scan result with employee status
    for repo in scan['axios_versions']:
        for c in repo.get('committers', []):
            for r in results:
                if c['email'] == r['search_email']:
                    c['employee_status'] = r['status_text']
                    c['empid'] = r['empid']
                    # 항상 갱신(빈 문자열이면 이전 오탐 이메일·부서값 제거)
                    c['pnet_dept'] = (r.get('pnet_dept') or '').strip()
                    if r.get('pnet_user_view') is not None:
                        c['pnet_user_view'] = r['pnet_user_view']

    with open(SCAN_JSON_PATH, 'w') as f:
        json.dump(scan, f, indent=2, ensure_ascii=False)

    print(f"\n✅ Saved: {EMPLOYEE_STATUS_JSON_PATH.relative_to(ROOT_DIR)}")
    print(f"✅ Updated: {SCAN_JSON_PATH.relative_to(ROOT_DIR)} (with employee status)")


if __name__ == '__main__':
    main()
