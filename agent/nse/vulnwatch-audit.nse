description = [[
VulnWatch custom audit script.

Three sub-modules:
1. Aggregator — collects findings from built-in vuln NSE scripts
2. CVE mapper — correlates service+version against an embedded CVE database
3. Topology mapper — detects role (gateway/dns/fileserver/workstation) and risk score

Emits structured JSON per host for consumption by VulnWatch platform.
]]
author = "VulnWatch — A. Giurgiuveanu"
license = "Same as Nmap (NPSL)"
categories = {"safe", "discovery", "vuln"}

local stdnse = require "stdnse"
local nmap = require "nmap"
local json = require "json"
local string = require "string"
local table = require "table"

-- ================================================================
-- SUB-MODULE 1: AGGREGATOR
-- ================================================================
local aggregator = {}

-- Maparea service → list of NSE scripts care produc finding-uri utile
local SERVICE_TO_SCRIPTS = {
  ["microsoft-ds"] = {"smb-vuln-ms17-010", "smb-vuln-ms08-067"},
  ["netbios-ssn"]  = {"smb-vuln-ms17-010"},
  ["http"]         = {"http-vuln-cve2017-5638", "http-csrf"},
  ["https"]        = {"ssl-poodle", "ssl-heartbleed"},
  ["ssl"]          = {"ssl-poodle", "ssl-heartbleed"},
  ["ssh"]          = {"ssh-auth-methods"},
  ["ftp"]          = {"ftp-anon"},
  ["ms-wbt-server"] = {"rdp-vuln-ms12-020"},
}

-- Severitate per script (mapping known scripts to severity)
local SCRIPT_SEVERITY = {
  ["smb-vuln-ms17-010"]      = "critical",
  ["smb-vuln-ms08-067"]      = "critical",
  ["rdp-vuln-ms12-020"]      = "high",
  ["ssl-heartbleed"]         = "critical",
  ["ssl-poodle"]             = "high",
  ["http-vuln-cve2017-5638"] = "critical",
  ["ftp-anon"]               = "medium",
}

function aggregator.collect(host, port)
  -- Nmap rulează deja aceste scripts când includem categoria "vuln" sau le
  -- specificăm explicit. Aici doar inspectăm rezultatele existente pe port
  -- și le normalizăm.
  local findings = {}
  local scripts_for_service = SERVICE_TO_SCRIPTS[port.service or ""] or {}

  -- port.script_results e populat de nmap dacă scripts au rulat
  if port.script_results then
    for _, sr in ipairs(port.script_results) do
      local script_id = sr.id
      local output = sr.output or ""
      -- Detectăm „VULNERABLE" în output (convenția NSE pentru finding pozitiv)
      if string.match(output, "VULNERABLE") or string.match(output, "Vulnerable") then
        local severity = SCRIPT_SEVERITY[script_id] or "medium"
        table.insert(findings, {
          rule_id = "NMAP-" .. string.upper(script_id):gsub("-", "_"),
          severity = severity,
          title = "Detected by NSE: " .. script_id,
          evidence = {
            port = port.number,
            service = port.service,
            nse_script = script_id,
            nse_output = string.sub(output, 1, 500),  -- truncate
          },
        })
      end
    end
  end
  return findings
end

-- ================================================================
-- SUB-MODULE 2: CVE MAPPER
-- ================================================================
local cve_mapper = {}

-- DB embedded: service → list of {version_pattern, cve, severity, title}
local CVE_DB = {
  ["microsoft-ds"] = {
    {pattern = ".*",                cve = "CVE-2017-0144", severity = "critical",
     title = "EternalBlue (MS17-010) — verifica patch SMB"},
  },
  ["netbios-ssn"] = {
    {pattern = ".*",                cve = "CVE-2017-0144", severity = "high",
     title = "NetBIOS expus — risc EternalBlue dacă SMB neactualizat"},
  },
  ["http"] = {
    {pattern = "[Aa]pache 2%.4%.49", cve = "CVE-2021-41773", severity = "critical",
     title = "Apache 2.4.49 path traversal RCE"},
    {pattern = "[Aa]pache 2%.4%.50", cve = "CVE-2021-42013", severity = "critical",
     title = "Apache 2.4.50 path traversal (incomplete fix for CVE-2021-41773)"},
    {pattern = "[Nn]ginx 1%.1[0-7]%.", cve = "CVE-2021-23017", severity = "high",
     title = "nginx DNS resolver buffer overflow"},
  },
  ["https"] = {
    {pattern = ".*",                cve = "Heartbleed check needed", severity = "info",
     title = "Verifică versiunea OpenSSL pe acest host (Heartbleed CVE-2014-0160 dacă 1.0.1a-f)"},
  },
  ["ssh"] = {
    {pattern = "[Oo]pen[Ss][Ss][Hh] 7%.[0-6]", cve = "CVE-2018-15473", severity = "medium",
     title = "OpenSSH ≤7.7 username enumeration"},
    {pattern = "[Oo]pen[Ss][Ss][Hh] 7%.[0-3]", cve = "CVE-2016-10009", severity = "high",
     title = "OpenSSH ≤7.4 forwarded auth agent abuse"},
  },
  ["ftp"] = {
    {pattern = "vsftpd 2%.3%.4", cve = "CVE-2011-2523", severity = "critical",
     title = "vsftpd 2.3.4 backdoor — orice user:pass acceptat"},
    {pattern = "ProFTPD 1%.3%.5", cve = "CVE-2015-3306", severity = "high",
     title = "ProFTPD 1.3.5 mod_copy RCE"},
  },
  ["telnet"] = {
    {pattern = ".*",                cve = "Plaintext protocol", severity = "high",
     title = "Telnet — protocol necriptat; folosește SSH"},
  },
  ["ms-wbt-server"] = {
    {pattern = ".*",                cve = "CVE-2019-0708", severity = "critical",
     title = "BlueKeep — verifică patch RDP pe Windows 7/Server 2008"},
  },
  ["mysql"] = {
    {pattern = "5%.[0-6]%.", cve = "Multiple CVEs", severity = "high",
     title = "MySQL 5.0-5.6 — versiune end-of-life, multiple CVE-uri"},
  },
  ["postgresql"] = {
    {pattern = "10%.", cve = "CVE-2018-1058", severity = "medium",
     title = "PostgreSQL 10.x — verifică privilegii pe search_path (CVE-2018-1058)"},
  },
  ["redis"] = {
    {pattern = ".*",                cve = "Unauth access common", severity = "high",
     title = "Redis — verifică AUTH config (default e fără parolă)"},
  },
  ["mongodb"] = {
    {pattern = ".*",                cve = "Unauth access common", severity = "high",
     title = "MongoDB — verifică authentication (default e fără auth)"},
  },
}

function cve_mapper.correlate(host, port)
  local findings = {}
  local service = port.service or ""
  local version = port.version or ""
  local product = (port.product or "")
  local search_str = product .. " " .. version

  local entries = CVE_DB[service]
  if not entries then return findings end

  for _, entry in ipairs(entries) do
    if string.match(search_str, entry.pattern) then
      table.insert(findings, {
        rule_id = "NMAP-CVE-MAPPER-" .. entry.cve:gsub("[^%w]", "_"),
        severity = entry.severity,
        title = entry.title,
        evidence = {
          host_ip = host.ip,
          port = port.number,
          service = service,
          version_detected = search_str,
          cve = entry.cve,
          source = "vulnwatch-audit/cve_mapper",
        },
      })
    end
  end
  return findings
end

-- ================================================================
-- SUB-MODULE 3: TOPOLOGY MAPPER
-- ================================================================
local topology = {}

function topology.discover(host)
  local role = "workstation"
  local risk_score = 0
  local reasons = {}

  local open_ports = {}
  for _, p in ipairs(host.ports or {}) do
    if p.state == "open" then
      table.insert(open_ports, p.number)
    end
  end

  -- Determine role
  for _, port in ipairs(open_ports) do
    if port == 53 then
      role = "dns"
      table.insert(reasons, "dns_port_open")
      break
    end
    if port == 445 or port == 139 then
      if role == "workstation" then role = "fileserver" end
      table.insert(reasons, "smb_open")
    end
    if port == 22 or port == 80 or port == 443 then
      table.insert(reasons, "internet_facing_service")
    end
  end

  -- Risk score
  local n_ports = #open_ports
  risk_score = risk_score + math.min(30, n_ports * 2)  -- 0-30 din # ports

  -- OS confidence
  if host.os and host.os.osmatches and #host.os.osmatches > 0 then
    local best = host.os.osmatches[1]
    if best.accuracy and tonumber(best.accuracy) < 70 then
      risk_score = risk_score + 10
      table.insert(reasons, "os_unidentified")
    end
    if best.name and string.match(best.name:lower(), "windows xp") then
      risk_score = risk_score + 30
      table.insert(reasons, "outdated_os")
    end
    if best.name and string.match(best.name:lower(), "windows 7") then
      risk_score = risk_score + 20
      table.insert(reasons, "outdated_os")
    end
  end

  return {
    role = role,
    risk_score = math.min(100, risk_score),
    reasons = reasons,
  }
end

-- ================================================================
-- ENTRY POINT
-- ================================================================
hostrule = function(host)
  return host.state == "up" or host.state == nil
end

action = function(host)
  local output = {
    host_ip = host.ip or "",
    findings = {},
    topology = {},
  }

  for _, port in ipairs(host.ports or {}) do
    if port.state == "open" then
      for _, f in ipairs(aggregator.collect(host, port)) do
        table.insert(output.findings, f)
      end
      for _, f in ipairs(cve_mapper.correlate(host, port)) do
        table.insert(output.findings, f)
      end
    end
  end

  output.topology = topology.discover(host)

  -- Output JSON ca string (NSE convention: return a string from action)
  local ok, encoded = pcall(json.generate, output)
  if not ok then
    return "vulnwatch-audit: JSON encode error"
  end
  return encoded
end
