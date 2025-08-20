#!/usr/bin/env python3
# mitmproxy addon that detects OAuth linking flows and scope over-collection
from mitmproxy import http, ctx
import re, json, os, time

OAUTH_AUTHZ = re.compile(r"/authorize\b", re.I)
OAUTH_TOKEN = re.compile(r"/token\b", re.I)
SENSITIVE = {"profile", "email", "name", "zip", "postal", "location"}

class SkillLinkGuard:
    def __init__(self):
        self.findings = []
        self.out_path = "evidence/skilllinkguard_findings.json"

    def request(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        if OAUTH_AUTHZ.search(url):
            qs = dict(flow.request.query)
            scopes = set(qs.get("scope","").split()) if "scope" in qs else set()
            record = {
                "type": "authorize",
                "url": url,
                "params": {k: qs.get(k) for k in ["client_id", "redirect_uri", "state"] if k in qs},
                "pkce": ("code_challenge" in qs) or ("code_challenge_method" in qs),
                "missing_state": ("state" not in qs),
                "overcollect": bool(scopes & SENSITIVE),
                "scopes": sorted(scopes),
                "ts": time.time()
            }
            self.findings.append(record)
            ctx.log.info(f"[SkillLinkGuard] authorize: {record}")

        if OAUTH_TOKEN.search(url):
            self.findings.append({"type":"token","url":url,"ts":time.time()})
            ctx.log.info(f"[SkillLinkGuard] token: {url}")

    def done(self):
        os.makedirs("evidence", exist_ok=True)
        with open(self.out_path, "w", encoding="utf-8") as f:
            json.dump(self.findings, f, indent=2)
        ctx.log.info(f"[SkillLinkGuard] wrote {self.out_path} ({len(self.findings)} items)")

addons = [SkillLinkGuard()]
