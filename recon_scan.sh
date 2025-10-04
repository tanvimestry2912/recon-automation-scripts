#!/bin/bash
# recon_scan.sh - improved safe wrapper of your original script
# Usage: ~/recon_scan.sh example.com
set -euo pipefail
IFS=$'\n\t'

if [ -z "${1:-}" ]; then
  echo "Usage: $0 <target-domain>"
  exit 1
fi

domain="$1"
workdir="${domain}_recon"
mkdir -p "$workdir"
cd "$workdir" || exit 1

echo "[*] Starting recon for: $domain"
logf="recon.log"
echo "Recon started: $(date) for $domain" > "$logf"

# Output files
all_subs="totalsub.txt"
live_subs="live.txt"
params_file="param.txt"
dir_file="dir.txt"
xss_vuln="xss_vuln.txt"
sql_vuln="sql_vuln.txt"
end_vuln="end_vuln.txt"
final_vuln="final_vuln.txt"

touch "$all_subs" "$live_subs" "$params_file" "$dir_file" "$xss_vuln" "$sql_vuln" "$end_vuln" "$final_vuln"

tool_ok() { command -v "$1" >/dev/null 2>&1; }

### 1. Subdomain Enumeration
echo "[*] Finding subdomains..."
echo "[*] tools: amass subfinder findomain sublist3r" >> "$logf"

# run each if available, redirect output but ignore failures
if tool_ok amass; then
  echo "[*] running amass..."
  amass enum -d "$domain" -o amass.txt || true
else echo "[!] amass not found, skipping" >> "$logf"; fi

if tool_ok subfinder; then
  echo "[*] running subfinder..."
  subfinder -d "$domain" -silent -o subfinder.txt || true
else echo "[!] subfinder not found, skipping" >> "$logf"; fi

if tool_ok findomain; then
  echo "[*] running findomain..."
  findomain -t "$domain" -u findomain.txt || true
else echo "[!] findomain not found, skipping" >> "$logf"; fi

if tool_ok sublist3r; then
  echo "[*] running sublist3r..."
  sublist3r -d "$domain" -o sublist3r.txt || true
else
  # try local copy under /opt/recon_tools/Sublist3r
  if [ -f /opt/recon_tools/Sublist3r/sublist3r.py ]; then
    python3 /opt/recon_tools/Sublist3r/sublist3r.py -d "$domain" -o sublist3r.txt || true
  else
    echo "[!] sublist3r not found, skipping" >> "$logf"
  fi
fi

# combine lists
cat amass.txt 2>/dev/null || true
cat subfinder.txt 2>/dev/null || true
cat findomain.txt 2>/dev/null || true
cat sublist3r.txt 2>/dev/null || true
# safely combine (only existing files)
{ [ -f amass.txt ] && cat amass.txt; } 2>/dev/null > /dev/null || true
cat amass.txt subfinder.txt findomain.txt sublist3r.txt 2>/dev/null | sort -u > "$all_subs" || true
echo "[+] Subdomain enumeration completed. Saved to $all_subs" >> "$logf"

### 2. Live Subdomain Check
echo "[*] Checking live subdomains..."
if tool_ok httpx; then
  cat "$all_subs" 2>/dev/null | httpx -silent > "$live_subs" || true
else
  # fallback: use curl to test simple HTTP response (slow)
  echo "[!] httpx not found, using curl fallback" >> "$logf"
  > "$live_subs"
  if [ -f "$all_subs" ]; then
    while read -r host; do
      url="http://$host"
      if curl -s --max-time 5 -I "$url" >/dev/null 2>&1; then
        echo "$url" >> "$live_subs"
      elif curl -s --max-time 5 -I "https://$host" >/dev/null 2>&1; then
        echo "https://$host" >> "$live_subs"
      fi
    done < "$all_subs"
  fi
fi
echo "[+] Live subdomains saved to $live_subs" >> "$logf"

### 3. Find Endpoints and Parameters
echo "[*] Crawling with katana and paramspider..."
if tool_ok katana && [ -s "$live_subs" ]; then
  katana -list "$live_subs" -silent -o katana.txt || true
else echo "[!] katana missing or live list empty, skipping" >> "$logf"; fi

# ParamSpider: run per-host if available
> paramspider.txt
if tool_ok paramspider && [ -s "$live_subs" ]; then
  while read -r url; do
    paramspider -d "$url" --quiet >> paramspider.txt || true
  done < "$live_subs"
else
  echo "[!] paramspider not found or no live hosts" >> "$logf"
fi

cat katana.txt paramspider.txt 2>/dev/null | sort -u > "$params_file" || true
echo "[+] Parameters and endpoints saved to $params_file" >> "$logf"

### 4. Directory Brute-force
echo "[*] Scanning directories..."
> "$dir_file"
if tool_ok ffuf && [ -s "$live_subs" ]; then
  while read -r sub; do
    tmpf="$(mktemp)"
    ffuf -u "${sub}/FUZZ" -w /usr/share/wordlists/dirb/common.txt -mc all -of csv -o "$tmpf" -t 50 &>/dev/null || true
    if [ -f "$tmpf" ]; then
      grep -E ",403|,404" "$tmpf" | cut -d',' -f1,6 >> "$dir_file" || true
      rm -f "$tmpf"
    fi
  done < "$live_subs"
else
  echo "[!] ffuf not found, skipping dir brute" >> "$logf"
fi
sort -u "$dir_file" -o "$dir_file" || true
echo "[+] Directory brute-force results saved to $dir_file" >> "$logf"

### 5. Handle 403 and 404
echo "[*] Handling 403 and 404 responses..."
# 403 Bypass (requires a script)
if [ -f /opt/recon_tools/403bypasser.py ] || tool_ok 403bypasser.py ; then
  grep "403" "$dir_file" 2>/dev/null | cut -d',' -f1 | while read -r url; do
    if [ -f /opt/recon_tools/403bypasser.py ]; then
      python3 /opt/recon_tools/403bypasser.py -u "$url" >> "$end_vuln" || true
    else
      403bypasser.py -u "$url" >> "$end_vuln" || true
    fi
  done
else
  echo "[!] 403bypasser not found, skipping 403 bypass" >> "$logf"
fi

# Subdomain takeover (subzy) for 404s
if tool_ok subzy; then
  grep "404" "$dir_file" 2>/dev/null | cut -d',' -f1 > takeover_targets.txt || true
  while read -r target; do
    subzy -targets "$target" >> "$end_vuln" || true
  done < takeover_targets.txt
else
  echo "[!] subzy not found, skipping takeover checks" >> "$logf"
fi
echo "[+] 403 Bypass and takeover attempts saved to $end_vuln" >> "$logf"

### 6. XSS Testing
echo "[*] Checking for XSS..."
grep -E "\?.+=" "$params_file" 2>/dev/null | sort -u > xss_targets.txt || true

if [ -s xss_targets.txt ]; then
  if tool_ok dalfox; then
    dalfox file xss_targets.txt --silence --output dalfox.txt || true
    cat dalfox.txt >> "$xss_vuln" || true
  else
    echo "[!] dalfox not found, skipping dalfox" >> "$logf"
  fi

  if tool_ok xsstrike || [ -f /opt/recon_tools/XSStrike/xsstrike.py ]; then
    while read -r url; do
      if tool_ok xsstrike; then
        xsstrike -u "$url" --crawl --skip --timeout 5 --blind --json-report xsstrike.json &>/dev/null || true
        [ -f xsstrike.json ] && jq -r '.vulnerabilities[].url' xsstrike.json >> "$xss_vuln" || true
        rm -f xsstrike.json || true
      else
        # run local copy
        python3 /opt/recon_tools/XSStrike/xsstrike.py -u "$url" --crawl --skip --timeout 5 --blind --json-report xsstrike.json &>/dev/null || true
        [ -f xsstrike.json ] && jq -r '.vulnerabilities[].url' xsstrike.json >> "$xss_vuln" || true
        rm -f xsstrike.json || true
      fi
    done < xss_targets.txt
  else
    echo "[!] xsstrike/dalfox not available for XSS checks" >> "$logf"
  fi
fi
sort -u "$xss_vuln" -o "$xss_vuln" || true
echo "[+] XSS results saved to $xss_vuln" >> "$logf"

### 7. SQLi Testing
echo "[*] Checking for SQL Injection..."
grep -E "\?.+=" "$params_file" 2>/dev/null | sort -u > sqli_targets.txt || true

if [ -s sqli_targets.txt ]; then
  if tool_ok sqlmap; then
    while read -r url; do
      sqlmap -u "$url" --batch --level=2 --risk=2 --random-agent --crawl=1 --output-dir=sqlmap_output &>/dev/null || true
      if grep -q "is vulnerable" sqlmap_output/*/log 2>/dev/null; then
        echo "$url [SQLMAP]" >> "$sql_vuln"
      fi
    done < sqli_targets.txt
  else
    echo "[!] sqlmap not found, skipping sqlmap tests" >> "$logf"
  fi

  # Ghauri (venv wrapper)
  if tool_ok ghauri; then
    while read -r url; do
      ghauri -u "$url" --batch >> ghauri_result.txt 2>/dev/null || true
      if grep -q "VULNERABLE" ghauri_result.txt 2>/dev/null; then
        echo "$url [GHAURI]" >> "$sql_vuln"
      fi
    done < sqli_targets.txt
  else
    echo "[!] ghauri not found, skipping ghauri tests" >> "$logf"
  fi
fi
sort -u "$sql_vuln" -o "$sql_vuln" || true
echo "[+] SQL Injection results saved to $sql_vuln" >> "$logf"

### 8. Final Report
echo "[*] Generating final vulnerability report..."
cat "$xss_vuln" "$sql_vuln" "$end_vuln" 2>/dev/null | sort -u > "$final_vuln" || true
echo "[+] Final vulnerability report saved to $final_vuln" >> "$logf"

echo "[✔] Recon and vuln scan completed for $domain"
echo "Reports: $final_vuln | $xss_vuln | $sql_vuln | $end_vuln"
echo "Log: $logf"
