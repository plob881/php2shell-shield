#!/usr/bin/env bash
# Rol php2shell-shield uit naar alle servers in servers.txt (één per regel:
# host, user@host of host:poort; regels met # zijn commentaar).
#
#   ./uitrollen.sh                                   -> install (strict) op alle servers
#   ./uitrollen.sh "install --dry-run"               -> eerst kijken wat er zou gebeuren
#   ./uitrollen.sh "install --mode strict --trust 203.0.113.5"
#   ./uitrollen.sh status | ./uitrollen.sh test | ./uitrollen.sh scan
#   ./uitrollen.sh "uninstall"                       -> na het patchen
#
# Het script wordt via ssh als bestand neergezet (/root/php2shell-shield.sh) en
# van daaruit gestart, zodat ook de watch-service zichzelf kan installeren.
# Werkt vanuit Git Bash op Windows en vanaf elke Linux/macOS-machine.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
LIST="${SERVERS:-$HERE/servers.txt}"
OPDRACHT="${1:-install}"
SCRIPT="$HERE/php2shell-shield.sh"
LOGBESTAND="$HERE/uitrol-$(date +%Y%m%d-%H%M).log"

[ -f "$LIST" ]   || { echo "servers.txt ontbreekt: $LIST (zie servers.txt.voorbeeld)"; exit 1; }
[ -f "$SCRIPT" ] || { echo "php2shell-shield.sh ontbreekt naast dit script"; exit 1; }
grep -q $'\r' "$SCRIPT" && { echo "php2shell-shield.sh heeft Windows-regeleinden; herstel met: sed -i 's/\\r\$//' php2shell-shield.sh"; exit 1; }

while IFS= read -r regel || [ -n "$regel" ]; do
  regel="${regel%%#*}"; regel="${regel//$'\r'/}"; regel="${regel// /}"
  [ -z "$regel" ] && continue
  server="$regel"; poort=22
  case "$server" in *:*) poort="${server##*:}"; server="${server%:*}" ;; esac
  case "$server" in *@*) ;; *) server="root@$server" ;; esac
  echo "=================================================================="
  echo "=== $server (poort $poort): php2shell-shield $OPDRACHT"
  echo "=================================================================="
  ssh -p "$poort" -o ConnectTimeout=20 "$server" \
      "cat > /root/php2shell-shield.sh && chmod 700 /root/php2shell-shield.sh && bash /root/php2shell-shield.sh $OPDRACHT" \
      < "$SCRIPT" 2>&1 | tee -a "$LOGBESTAND"
  echo "--- exitstatus: ${PIPESTATUS[0]}" | tee -a "$LOGBESTAND"
  echo
done < "$LIST"
echo "Log: $LOGBESTAND"
