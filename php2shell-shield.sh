#!/usr/bin/env bash
# =============================================================================
#  php2shell-shield  -  serverbrede noodmaatregel tegen "PHP2Shell"
#  CVE-2026-109618 / CVE-2026-109619  (PHP multipart/form-data, pre-auth RCE)
#
#  Eén script voor DirectAdmin, Plesk, cPanel en kale Apache/nginx/LiteSpeed:
#   1. blokkeert multipart/form-data-verzoeken op WEBSERVERNIVEAU, dus vóórdat
#      PHP de body ooit ziet - voor ALLE sites op de server tegelijk
#      (Apache <If> / nginx map+if / LiteSpeed rewrite); vertrouwde IP's en een
#      optionele hostlijst (scope) blijven buiten schot
#   2. zet session.upload_progress.enabled = Off in álle php.ini's + drop-ins
#      (de tot nu toe bekende aanvalsroute) en herlaadt alle PHP-FPM-diensten
#   3. logt elk geblokkeerd verzoek centraal en draait een watch-service die
#      scanners (één IP, meerdere hosts) automatisch in de firewall zet
#   4. test zichzelf met curl, toont status/patchstand, en draait zichzelf
#      volledig terug met "uninstall" zodra PHP overal gepatcht is
#
#  Gebruik (als root):
#    php2shell-shield.sh install [--mode strict|monitor|signature]
#                               [--trust IP[,IP/CIDR,...]] [--trust-file BESTAND]
#                               [--scope all|BESTAND]
#                               [--no-php-ini] [--no-watch] [--no-test] [--dry-run]
#                               [--memory-unlimited]  (PHP-advies memory_limit=-1 tegen
#                                CVE-2026-109618; alleen met cgroup/containerlimiet als vangnet)
#    php2shell-shield.sh trust list | add IP[,IP/CIDR,...] | remove IP | clear
#                                           (lijst in /etc/php2shell-shield/trust.txt,
#                                            wijzigingen gaan direct live)
#    php2shell-shield.sh status | test [--probe DOMEIN] | scan | reapply
#    php2shell-shield.sh eol-domains        (hostlijst met EOL-PHP voor --scope)
#    php2shell-shield.sh uninstall [--restore-php-ini]
#    php2shell-shield.sh cleanup            (na uninstall: include-bestanden weg zodra geen
#                                            gegenereerde config er nog naar verwijst)
#    php2shell-shield.sh watch              (wordt door systemd gestart)
#    php2shell-shield.sh unban IP | bans
#
#  Vertrouwde adressen (--trust, --trust-file, trust add) mogen multipart blijven
#  sturen en worden nooit gebant: je kantoor-IP, het OpenVPN-clientsubnet
#  (bijv. 10.8.0.0/24) of het NAT-adres van de VPN-gateway zoals de webserver het
#  ziet. Kijk in /var/log/php2shell-shield/blocked.log welk bron-IP jij hebt.
#
#  Modi:
#    strict    : blokkeer álle multipart-verzoeken (uploads/formulieren met
#                bijlagen vallen uit, maar de server is dicht)  [standaard]
#    monitor   : alleen loggen, niets blokkeren (impactmeting vooraf)
#    signature : géén multipart-blok; alleen php.ini-hardening + ModSecurity-
#                regels op het bekende aanvalspatroon (waar ModSecurity draait)
# =============================================================================

VERSION="1.2.7"
SHIELD_DIR="/etc/php2shell-shield"
STATE_FILE="$SHIELD_DIR/state.conf"
TRUST_FILE="$SHIELD_DIR/trust.txt"     # één IP of IP/CIDR per regel, # = commentaar
TRUST_IMPORT=""                        # --trust-file: lokaal bestand dat in trust.txt wordt samengevoegd
CREATED_LIST="$SHIELD_DIR/created-files.list"
MODIFIED_LIST="$SHIELD_DIR/modified-files.list"
INI_BACKUP_LIST="$SHIELD_DIR/php-ini-backups.list"
BACKUP_DIR="$SHIELD_DIR/backups"
LOG_DIR="/var/log/php2shell-shield"
BLOCK_LOG="$LOG_DIR/blocked.log"
BAN_LOG="$LOG_DIR/bans.log"
BIN_TARGET="/usr/local/sbin/php2shell-shield"
UNIT_NAME="php2shell-watch"
DROPIN_NAME="99-php2shell-shield.ini"
RUN_STAMP="$(date +%Y%m%d-%H%M%S)"

# --- standaardinstellingen (opties overschrijven, state onthoudt) -------------
MODE="strict"
TRUST=""
SCOPE="all"
DO_PHP_INI=1
DO_WATCH=1
DO_TEST=1
DRY_RUN=0
QUIET=0
STRICT_SESSIONS=0
MEMORY_UNLIMITED=0   # --memory-unlimited: PHP-advies memory_limit=-1 (alleen met cgroup/containerlimiet als vangnet)
RESTORE_PHP_INI=0
BAN_HOSTS=8          # ban als één IP op >= N verschillende hosts geblokkeerd wordt (scanner-gedrag)
BAN_COUNT=0          # ban als één IP >= N geblokkeerde verzoeken stuurt (0 = uit; pas op met bulk-uploads)
BAN_PATHS=10         # ban als één IP >= N verschillende host+pad-combinaties raakt (scanner probeert veel paden; 0 = uit)
BAN_TTL=3600         # seconden (csf/ipset/nft verlopen vanzelf)
BAN_WINDOW=300       # seconden waarbinnen geteld wordt
# Verwachte gefixte versies (per PHP-tak). Controleer na de release op php.net
# en overschrijf zo nodig met --fixed "8.2.35,8.3.36,8.4.27,8.5.12"
FIXED_VERSIONS="8.2.35,8.3.36,8.4.27,8.5.12"
PROBE_DOMAIN=""

# --- omgevingsdetectie (wordt gevuld door detect_env) ------------------------
PANEL="none"          # directadmin | plesk | cpanel | none
DA_WEBSERVER=""       # apache | nginx | nginx_apache | openlitespeed | litespeed
HAVE_APACHE=0; APACHE_BIN=""; APACHE_UNIT=""; APACHE_ROOT=""
HAVE_NGINX=0
HAVE_OLS=0; HAVE_LSWS=0
HAVE_SYSTEMD=0
CHANGED_APACHE=0; CHANGED_NGINX=0; CHANGED_LSWS=0; CHANGED_PHP=0; CHANGED_DA=0; CHANGED_PLESK=0
NEED_DA_REWRITE=0; NEED_PLESK_RECONFIGURE=0
PLESK_NEW_DOMAINS=""      # domeinen die bij reapply afzonderlijk herconfigureerd worden
PLESK_RECONF_ALL=1        # install/uninstall: alles; reapply: alleen nieuwe domeinen

set -u -o pipefail
shopt -s nullglob
export LC_ALL=C

# =============================================================================
#  Hulpfuncties
# =============================================================================
if [ -t 1 ]; then
  C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'; C_BLU=$'\e[34m'; C_OFF=$'\e[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_OFF=""
fi
say()  { [ "$QUIET" = 1 ] || printf '%s\n' "$*"; }
ok()   { [ "$QUIET" = 1 ] || printf '%s[ OK ]%s %s\n' "$C_GRN" "$C_OFF" "$*"; }
info() { [ "$QUIET" = 1 ] || printf '%s[ .. ]%s %s\n' "$C_BLU" "$C_OFF" "$*"; }
warn() { printf '%s[LET OP]%s %s\n' "$C_YEL" "$C_OFF" "$*" >&2; }
err()  { printf '%s[FOUT]%s %s\n' "$C_RED" "$C_OFF" "$*" >&2; }
die()  { err "$*"; exit 1; }
hr()   { [ "$QUIET" = 1 ] || printf '%s\n' "------------------------------------------------------------------------"; }

need_root() { [ "$(id -u)" = 0 ] || die "Dit script moet als root draaien."; }

# run CMD... : voer uit, tenzij dry-run
run() {
  if [ "$DRY_RUN" = 1 ]; then say "  [dry-run] $*"; return 0; fi
  "$@"
}

track_created()  { mkdir -p "$SHIELD_DIR"; grep -qxF "$1" "$CREATED_LIST" 2>/dev/null || echo "$1" >> "$CREATED_LIST"; }
track_modified() { mkdir -p "$SHIELD_DIR"; grep -qxF "$1" "$MODIFIED_LIST" 2>/dev/null || echo "$1" >> "$MODIFIED_LIST"; }

# backup_file FILE : één kopie per bestand per run
backup_file() {
  local f="$1" dest
  [ -f "$f" ] || return 0
  mkdir -p "$BACKUP_DIR"
  dest="$BACKUP_DIR/$(printf '%s' "$f" | sed 's#^/##; s#/#__#g').$RUN_STAMP"
  [ -f "$dest" ] || cp -p "$f" "$dest"
}

# write_file FILE CONTENT : schrijf alleen als de inhoud verschilt (0=gewijzigd)
write_file() {
  local file="$1" content="$2"
  if [ -f "$file" ] && [ "$(cat "$file")" = "$content" ]; then return 1; fi
  if [ "$DRY_RUN" = 1 ]; then say "  [dry-run] zou schrijven: $file"; return 0; fi
  mkdir -p "$(dirname "$file")"
  [ -f "$file" ] && backup_file "$file"
  [ -f "$file" ] || track_created "$file"
  printf '%s\n' "$content" > "$file"
  chmod 644 "$file"
  return 0
}

# ensure_block FILE CONTENT [COMMENTCHAR] : plaats/ververs een gemarkeerd blok
# (0 = gewijzigd, 1 = was al identiek). Maakt het bestand aan als het ontbreekt.
ensure_block() {
  local file="$1" content="$2" cc="${3:-#}" mb me existing tmp
  mb="$cc >>> php2shell-shield >>>"; me="$cc <<< php2shell-shield <<<"
  if [ -f "$file" ]; then
    existing=$(awk -v b="$mb" -v e="$me" '$0==b{f=1;next} $0==e{f=0;next} f' "$file")
    [ "$existing" = "$content" ] && return 1
  fi
  if [ "$DRY_RUN" = 1 ]; then say "  [dry-run] zou blok plaatsen in: $file"; return 0; fi
  mkdir -p "$(dirname "$file")"
  if [ -f "$file" ]; then
    backup_file "$file"; track_modified "$file"
    tmp=$(mktemp)
    awk -v b="$mb" -v e="$me" '$0==b{f=1;next} $0==e{f=0;next} !f' "$file" > "$tmp"
    cat "$tmp" > "$file"; rm -f "$tmp"
  else
    : > "$file"; chmod 644 "$file"; track_created "$file"
  fi
  { echo "$mb"; printf '%s\n' "$content"; echo "$me"; } >> "$file"
  return 0
}

# remove_block FILE [COMMENTCHAR] : verwijder ons blok (0 = gewijzigd)
remove_block() {
  local file="$1" cc="${2:-#}" mb me tmp
  mb="$cc >>> php2shell-shield >>>"; me="$cc <<< php2shell-shield <<<"
  [ -f "$file" ] || return 1
  grep -qxF "$mb" "$file" || return 1
  if [ "$DRY_RUN" = 1 ]; then say "  [dry-run] zou blok verwijderen uit: $file"; return 0; fi
  backup_file "$file"
  tmp=$(mktemp)
  awk -v b="$mb" -v e="$me" '$0==b{f=1;next} $0==e{f=0;next} !f' "$file" > "$tmp"
  cat "$tmp" > "$file"; rm -f "$tmp"
  # door ons aangemaakt en nu leeg -> opruimen (behalve Plesk-includes: die
  # worden door de gegenereerde config nog genoemd tot de volgende reconfigure)
  if [ ! -s "$file" ] && grep -qxF "$file" "$CREATED_LIST" 2>/dev/null; then
    case "$file" in /var/www/vhosts/system/*) ;; *) rm -f "$file" ;; esac
  fi
  return 0
}

save_state() {
  mkdir -p "$SHIELD_DIR"
  cat > "$STATE_FILE" <<EOF
MODE=$MODE
TRUST=$TRUST
SCOPE=$SCOPE
STRICT_SESSIONS=$STRICT_SESSIONS
MEMORY_UNLIMITED=$MEMORY_UNLIMITED
BAN_HOSTS=$BAN_HOSTS
BAN_COUNT=$BAN_COUNT
BAN_PATHS=$BAN_PATHS
BAN_TTL=$BAN_TTL
BAN_WINDOW=$BAN_WINDOW
FIXED_VERSIONS=$FIXED_VERSIONS
INSTALLED_AT=$(date -Is)
INSTALLED_VERSION=$VERSION
EOF
}

load_state() {
  [ -f "$STATE_FILE" ] || return 1
  local k v
  while IFS='=' read -r k v; do
    case "$k" in
      MODE|TRUST|SCOPE|STRICT_SESSIONS|MEMORY_UNLIMITED|BAN_HOSTS|BAN_COUNT|BAN_PATHS|BAN_TTL|BAN_WINDOW|FIXED_VERSIONS)
        printf -v "$k" '%s' "$v" ;;
    esac
  done < "$STATE_FILE"
  return 0
}

# --- IP-hulpfuncties ----------------------------------------------------------
is_ipv4() {
  local o
  [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for o in "${BASH_REMATCH[@]:1}"; do [ "$o" -le 255 ] || return 1; done
}
is_ipv4_cidr() { [[ "$1" == */* ]] && is_ipv4 "${1%/*}" && [[ "${1#*/}" =~ ^([0-9]|[12][0-9]|3[0-2])$ ]]; }
is_ipv6()      { [[ "$1" =~ ^[0-9A-Fa-f:]+(/[0-9]{1,3})?$ ]] && [[ "$1" == *:* ]]; }

ip4_to_int() { local a b c d; IFS=. read -r a b c d <<< "$1"; echo $(( (a<<24) + (b<<16) + (c<<8) + d )); }
# ip4_in_cidr IP CIDR
ip4_in_cidr() {
  local ip="$1" cidr="$2" net bits ipi neti mask
  net="${cidr%/*}"; bits="${cidr#*/}"; [ "$bits" = "$cidr" ] && bits=32
  is_ipv4 "$ip" && is_ipv4 "$net" || return 1
  ipi=$(ip4_to_int "$ip"); neti=$(ip4_to_int "$net")
  if [ "$bits" -eq 0 ]; then return 0; fi
  mask=$(( (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
  [ $(( ipi & mask )) -eq $(( neti & mask )) ]
}

# normaliseer een vertrouwd adres naar CIDR-notatie
norm_cidr() {
  local x="$1"
  if is_ipv4 "$x"; then echo "$x/32"
  elif is_ipv4_cidr "$x"; then echo "$x"
  elif is_ipv6 "$x"; then [[ "$x" == */* ]] && echo "$x" || echo "$x/128"
  else return 1; fi
}

# ruwe invoer uit --trust (komma's/spaties) en uit een bestand (# = commentaar)
trust_raw_opts() { printf '%s' "$TRUST" | tr ', ' '\n\n' | grep -v '^$'; }
trust_raw_file() { [ -f "$1" ] && sed 's/#.*//; s/[[:space:]]//g' "$1" | grep -v '^$'; return 0; }

validate_trust() {
  local item n=0
  while read -r item; do
    norm_cidr "$item" >/dev/null || die "Ongeldig vertrouwd adres: '$item' (gebruik IP of IP/CIDR)"
  done < <(trust_raw_opts)
  while read -r item; do
    n=$((n+1)); norm_cidr "$item" >/dev/null || die "Ongeldig adres in $TRUST_FILE: '$item'"
  done < <(trust_raw_file "$TRUST_FILE")
  if [ -n "$TRUST_IMPORT" ]; then
    [ -f "$TRUST_IMPORT" ] || die "--trust-file: $TRUST_IMPORT bestaat niet"
    while read -r item; do
      norm_cidr "$item" >/dev/null || die "Ongeldig adres in $TRUST_IMPORT: '$item'"
    done < <(trust_raw_file "$TRUST_IMPORT")
  fi
}

# effectieve lijst: --trust/state + trust.txt, genormaliseerd (CIDR) en ontdubbeld
trust_list() {
  { trust_raw_opts; trust_raw_file "$TRUST_FILE"; } | while read -r item; do norm_cidr "$item" || true; done | sort -u
}
trust_summary() { local s; s=$(trust_list | paste -sd, -); printf '%s' "${s:-geen}"; }

# voeg adressen toe aan trust.txt (0 = iets toegevoegd). Args: IP's, komma- of spatiegescheiden
trust_file_add() {
  local item c added=1
  mkdir -p "$SHIELD_DIR"; touch "$TRUST_FILE"
  for item in $(printf '%s' "$*" | tr ',' ' '); do
    c=$(norm_cidr "$item") || die "Ongeldig adres: '$item' (gebruik IP of IP/CIDR)"
    grep -qxF "$c" "$TRUST_FILE" || { echo "$c" >> "$TRUST_FILE"; added=0; }
  done
  return $added
}
trust_file_remove() {
  local item c tmp removed=1
  [ -f "$TRUST_FILE" ] || return 1
  for item in $(printf '%s' "$*" | tr ',' ' '); do
    c=$(norm_cidr "$item") || die "Ongeldig adres: '$item'"
    if grep -qxF "$c" "$TRUST_FILE"; then
      tmp=$(mktemp); grep -vxF "$c" "$TRUST_FILE" > "$tmp"; cat "$tmp" > "$TRUST_FILE"; rm -f "$tmp"; removed=0
    else
      warn "$c staat niet in $TRUST_FILE$(printf '%s' "$TRUST" | grep -q . && printf ' (staat het in de bij install opgegeven --trust? draai dan install opnieuw met een nieuwe --trust)')"
    fi
  done
  return $removed
}

# --- scope (hostlijst) --------------------------------------------------------
scope_hosts() {   # genormaliseerde hostnamen uit het scopebestand
  [ "$SCOPE" = all ] && return 0
  [ -f "$SCOPE" ] || die "Scopebestand niet gevonden: $SCOPE"
  sed 's/#.*//; s/[[:space:]]//g' "$SCOPE" | tr 'A-Z' 'a-z' | grep -E '^[a-z0-9.-]+$' | sort -u
}
scope_regex() {   # PCRE die host (en alle subdomeinen) matcht, zonder ankers
  local alt
  alt=$(scope_hosts | sed 's/\./\\./g' | paste -sd'|' -)
  [ -n "$alt" ] || die "Scopebestand $SCOPE bevat geen geldige hostnamen"
  printf '(?:[a-z0-9-]+\\.)*(?:%s)' "$alt"
}

# =============================================================================
#  Omgevingsdetectie
# =============================================================================
detect_env() {
  command -v systemctl >/dev/null 2>&1 && HAVE_SYSTEMD=1
  if [ -x /usr/local/directadmin/directadmin ]; then
    PANEL="directadmin"
    DA_WEBSERVER=$(grep -E '^webserver=' /usr/local/directadmin/custombuild/options.conf 2>/dev/null | cut -d= -f2)
  elif [ -f /usr/local/psa/version ]; then
    PANEL="plesk"
  elif [ -d /usr/local/cpanel ]; then
    PANEL="cpanel"
  fi

  if [ -d /etc/httpd ] && [ -f /etc/httpd/conf/httpd.conf ]; then APACHE_ROOT=/etc/httpd
  elif [ -d /etc/apache2 ]; then APACHE_ROOT=/etc/apache2; fi

  if command -v httpd >/dev/null 2>&1 || [ -x /usr/sbin/httpd ]; then
    HAVE_APACHE=1; APACHE_BIN="httpd"; APACHE_UNIT="httpd"
  elif command -v apache2ctl >/dev/null 2>&1; then
    HAVE_APACHE=1; APACHE_BIN="apache2"; APACHE_UNIT="apache2"
  fi
  # LiteSpeed Enterprise gebruikt Apache-configs maar heeft geen httpd-binary
  if [ -x /usr/local/lsws/bin/openlitespeed ] || [ "$DA_WEBSERVER" = openlitespeed ]; then HAVE_OLS=1; fi
  if [ -x /usr/local/lsws/bin/lshttpd ] && [ "$HAVE_OLS" = 0 ]; then HAVE_LSWS=1; fi
  [ "$DA_WEBSERVER" = litespeed ] && HAVE_LSWS=1
  if [ "$DA_WEBSERVER" = openlitespeed ] || [ "$DA_WEBSERVER" = litespeed ]; then
    HAVE_APACHE=0   # DA genereert dan geen draaiende Apache
  fi

  if command -v nginx >/dev/null 2>&1 || [ -x /usr/sbin/nginx ]; then
    if pgrep -x nginx >/dev/null 2>&1 || { [ "$HAVE_SYSTEMD" = 1 ] && systemctl is-active --quiet nginx 2>/dev/null; }; then
      HAVE_NGINX=1
    fi
  fi
}

print_env() {
  hr
  say "Omgeving : paneel=$PANEL${DA_WEBSERVER:+ (webserver=$DA_WEBSERVER)}  apache=$HAVE_APACHE  nginx=$HAVE_NGINX  openlitespeed=$HAVE_OLS  litespeed=$HAVE_LSWS"
  say "Instelling: mode=$MODE  scope=$SCOPE  trust=$(trust_summary)  php.ini=$DO_PHP_INI  watch=$DO_WATCH  dry-run=$DRY_RUN"
  hr
}

# =============================================================================
#  Configuratie-generatoren
# =============================================================================

# Apache-expressie: multipart én niet-vertrouwd én (optioneel) binnen scope
apache_expr() {
  local reqfn="${1:-req_novary}" e t c
  e="$reqfn('Content-Type') =~ /multipart/i"
  t=""
  while read -r c; do
    [ -z "$c" ] && continue
    t="${t:+$t || }-R '$c'"
  done < <(trust_list)
  [ -n "$t" ] && e="$e && !($t)"
  if [ "$SCOPE" != all ]; then
    e="$e && tolower($reqfn('Host')) =~ /^$(scope_regex)(?::[0-9]+)?\$/"
  fi
  printf '%s' "$e"
}

# ModSecurity-regels (bekend aanvalspatroon + misvormde multipart-bodies).
modsec_rules() {
  cat <<'EOF'
# ModSecurity 2 (Apache): blokkeer het bekende aanvalspatroon, ook als de
# globale engine op DetectionOnly staat (ctl:ruleEngine=On per regel).
<IfModule security2_module>
    SecRule REQUEST_HEADERS:Content-Type "@rx (?i)multipart" \
        "id:99901,phase:1,pass,nolog,t:none,ctl:requestBodyAccess=On"
    SecRule ARGS_NAMES|FILES_NAMES "@beginsWith PHP_SESSION_UPLOAD_PROGRESS" \
        "id:99902,phase:2,deny,status:403,log,t:none,msg:'php2shell-shield: session upload-progress veld (CVE-2026-109618)',ctl:ruleEngine=On"
    SecRule MULTIPART_STRICT_ERROR "!@eq 0" \
        "id:99903,phase:2,deny,status:403,log,t:none,msg:'php2shell-shield: misvormde multipart-body',ctl:ruleEngine=On"
    SecRule MULTIPART_UNMATCHED_BOUNDARY "@eq 1" \
        "id:99904,phase:2,deny,status:403,log,t:none,msg:'php2shell-shield: multipart boundary mismatch',ctl:ruleEngine=On"
</IfModule>
EOF
}

# Apache, servercontext (globale include). $1 = req-functie, $2 = 1 voor GlobalLog
apache_server_conf() {
  local reqfn="$1" with_log="$2" e
  e=$(apache_expr "$reqfn")
  echo "# php2shell-shield - mode=$MODE - scope=$SCOPE - trust=$(trust_summary)"
  echo "# Globale Apache-maatregel tegen CVE-2026-109618 / CVE-2026-109619."
  echo "# Verwijderen: php2shell-shield uninstall"
  if [ "$MODE" != signature ]; then
    cat <<EOF
<IfModule mod_setenvif.c>
    SetEnvIfExpr "$e" php2shell_block
</IfModule>
EOF
  fi
  if [ "$MODE" = strict ]; then
    cat <<EOF
<If "$e">
    Require all denied
    ErrorDocument 403 "Multipart uploads are temporarily disabled on this server (emergency PHP security measure, CVE-2026-109618 / CVE-2026-109619). Please try again later."
</If>
EOF
  fi
  if [ "$with_log" = 1 ] && [ "$MODE" != signature ]; then
    cat <<EOF
<IfModule mod_log_config.c>
    LogFormat "%{%Y-%m-%dT%H:%M:%S%z}t %a %{Host}i %m %U %>s" php2shell_shield
    GlobalLog "$BLOCK_LOG" php2shell_shield env=php2shell_block
</IfModule>
EOF
  fi
  if [ "$MEMORY_UNLIMITED" = 1 ]; then
    cat <<'EOF'
# PHP-advies tegen CVE-2026-109618 (mod_php): geheugenlimiet administratief uit, niet overschrijfbaar
<IfModule php_module>
    php_admin_value memory_limit -1
</IfModule>
<IfModule php7_module>
    php_admin_value memory_limit -1
</IfModule>
EOF
  fi
  modsec_rules
}

# Apache, vhost-context (fallback/LiteSpeed Enterprise): geen GlobalLog
apache_vhost_conf() {
  local reqfn="$1" e
  echo "# php2shell-shield - mode=$MODE - scope=$SCOPE - trust=$(trust_summary) - vhost-variant"
  if [ "$HAVE_LSWS" = 1 ] || [ "$DA_WEBSERVER" = litespeed ]; then
    rewrite_rules
    return
  fi
  e=$(apache_expr "$reqfn")
  if [ "$MODE" != signature ]; then
    cat <<EOF
<IfModule mod_setenvif.c>
    SetEnvIfExpr "$e" php2shell_block
</IfModule>
EOF
  fi
  if [ "$MODE" = strict ]; then
    cat <<EOF
<If "$e">
    Require all denied
    ErrorDocument 403 "Multipart uploads are temporarily disabled on this server (emergency PHP security measure, CVE-2026-109618 / CVE-2026-109619). Please try again later."
</If>
EOF
  fi
  modsec_rules
}

# mod_rewrite-variant (LiteSpeed Enterprise / OpenLiteSpeed / .htaccess)
rewrite_rules() {
  local c ips="" re
  [ "$MODE" = strict ] || { echo "# (mode=$MODE: geen rewrite-blokkade)"; return; }
  echo "RewriteEngine On"
  echo "RewriteCond %{HTTP:Content-Type} multipart [NC]"
  while read -r c; do
    [ -z "$c" ] && continue
    case "$c" in
      */32)   re=$(printf '%s' "${c%/32}" | sed 's/\./\\./g'); ips="${ips:+$ips|}$re" ;;
      */24)   re=$(printf '%s' "${c%/24}" | sed 's/\.[0-9]*$//; s/\./\\./g'); ips="${ips:+$ips|}$re\\.[0-9]+" ;;
      */16)   re=$(printf '%s' "${c%/16}" | sed 's/\.[0-9]*\.[0-9]*$//; s/\./\\./g'); ips="${ips:+$ips|}$re\\.[0-9]+\\.[0-9]+" ;;
      */8)    re=$(printf '%s' "${c%/8}" | sed 's/\..*$//'); ips="${ips:+$ips|}$re\\.[0-9]+\\.[0-9]+\\.[0-9]+" ;;
      */128)  re=$(printf '%s' "${c%/128}" | sed 's/\./\\./g'); ips="${ips:+$ips|}$re" ;;
      *)      warn "Vertrouwd adres $c wordt in de rewrite-variant genegeerd (alleen /8,/16,/24,/32 ondersteund)" ;;
    esac
  done < <(trust_list)
  [ -n "$ips" ] && echo "RewriteCond %{REMOTE_ADDR} !^($ips)\$"
  if [ "$SCOPE" != all ]; then
    echo "RewriteCond %{HTTP_HOST} ^$(scope_regex)(:[0-9]+)?\$ [NC]"
  fi
  echo "RewriteRule ^ - [F,L]"
}

# nginx, http-context
nginx_http_conf() {
  local c
  echo "# php2shell-shield - mode=$MODE - scope=$SCOPE - trust=$(trust_summary) - http-context"
  echo "geo \$php2shell_trusted {"
  echo "    default 0;"
  while read -r c; do [ -n "$c" ] && echo "    $c 1;"; done < <(trust_list)
  echo "}"
  if [ "$SCOPE" = all ]; then
    printf 'map $host $php2shell_scoped {\n    default 1;\n}\n'
  else
    printf 'map $host $php2shell_scoped {\n    default 0;\n    "~*^%s$" 1;\n}\n' "$(scope_regex)"
  fi
  cat <<'EOF'
map "$php2shell_trusted:$php2shell_scoped:$http_content_type" $php2shell_block {
    default 0;
    "~*^0:1:.*multipart" 1;
}
log_format php2shell_shield '$time_iso8601 $remote_addr $host $request_method $uri $status';
EOF
}

# nginx, server-context (wordt in elk server{}-blok ingesloten)
nginx_server_conf() {
  echo "# php2shell-shield - mode=$MODE - server-context"
  if [ "$MODE" = strict ]; then
    printf 'if ($php2shell_block) {\n    return 403;\n}\n'
  fi
  if [ "$MODE" != signature ]; then
    printf 'access_log %s php2shell_shield if=$php2shell_block;\n' "$BLOCK_LOG"
  fi
}

# =============================================================================
#  Apache
# =============================================================================
apache_configtest() {
  case "$APACHE_BIN" in
    apache2) apache2ctl configtest 2>&1 ;;
    *)       httpd -t 2>&1 ;;
  esac
}
apache_reload() {
  [ "$DRY_RUN" = 1 ] && { say "  [dry-run] apache herladen"; return 0; }
  if [ "$HAVE_SYSTEMD" = 1 ]; then systemctl reload-or-restart "$APACHE_UNIT" 2>/dev/null && return 0; fi
  service "$APACHE_UNIT" reload 2>/dev/null || service "$APACHE_UNIT" restart 2>/dev/null
}

# schrijf de globale include + de include-regel in het juiste systeembestand
apache_install_global() {
  local inc_line="Include $SHIELD_DIR/apache-server.conf" variant out ok_variant=""
  # 1) vind een globale haak
  case "$PANEL" in
    directadmin)
      APACHE_HOOK="/etc/httpd/conf/extra/httpd-includes.conf"
      if ! grep -qs 'httpd-includes.conf' /etc/httpd/conf/httpd.conf; then
        warn "httpd.conf verwijst niet naar httpd-includes.conf; globale Apache-haak niet beschikbaar"
        APACHE_HOOK=""
      fi ;;
    cpanel)
      APACHE_HOOK="/etc/apache2/conf.d/includes/pre_main_global.conf" ;;
    *)
      if [ "$APACHE_ROOT" = /etc/httpd ]; then
        APACHE_HOOK="/etc/httpd/conf.d/zz-php2shell-shield.conf"
        grep -qsE '^\s*Include(Optional)?\s+("?)conf\.d/\*\.conf' /etc/httpd/conf/httpd.conf || warn "httpd.conf lijkt conf.d/*.conf niet in te lezen"
      else
        APACHE_HOOK="/etc/apache2/conf-available/zz-php2shell-shield.conf"
      fi ;;
  esac
  [ -n "$APACHE_HOOK" ] || return 1

  # 2) probeer varianten tot de configtest slaagt
  for variant in "req_novary 1" "req 1" "req 0"; do
    set -- $variant
    write_file "$SHIELD_DIR/apache-server.conf" "$(apache_server_conf "$1" "$2")" && CHANGED_APACHE=1
    case "$APACHE_HOOK" in
      *zz-php2shell-shield.conf) write_file "$APACHE_HOOK" "$inc_line" && CHANGED_APACHE=1 ;;
      *) ensure_block "$APACHE_HOOK" "$inc_line" && CHANGED_APACHE=1 ;;
    esac
    if [ "$APACHE_ROOT" = /etc/apache2 ] && [ "$PANEL" != cpanel ] && [ "$PANEL" != directadmin ]; then
      [ -e /etc/apache2/conf-enabled/zz-php2shell-shield.conf ] || { run a2enconf zz-php2shell-shield >/dev/null 2>&1 || run ln -s ../conf-available/zz-php2shell-shield.conf /etc/apache2/conf-enabled/zz-php2shell-shield.conf; CHANGED_APACHE=1; }
    fi
    [ "$DRY_RUN" = 1 ] && { ok_variant="$variant"; break; }
    out=$(apache_configtest)
    if printf '%s' "$out" | grep -qi 'syntax ok'; then ok_variant="$variant"; break; fi
    warn "Apache-configtest faalde met variant '$variant':"; printf '%s\n' "$out" | sed 's/^/      /' >&2
  done
  if [ -z "$ok_variant" ]; then
    err "Geen werkende Apache-variant; globale include wordt weer verwijderd."
    apache_remove_global
    return 1
  fi
  ok "Apache: globale regel geplaatst via $APACHE_HOOK (variant: $ok_variant)"
  return 0
}

apache_remove_global() {
  local f
  for f in /etc/httpd/conf/extra/httpd-includes.conf /etc/apache2/conf.d/includes/pre_main_global.conf; do
    [ -f "$f" ] && remove_block "$f" && CHANGED_APACHE=1
  done
  for f in /etc/httpd/conf.d/zz-php2shell-shield.conf /etc/apache2/conf-available/zz-php2shell-shield.conf /etc/apache2/conf-enabled/zz-php2shell-shield.conf; do
    [ -e "$f" ] && { run rm -f "$f"; CHANGED_APACHE=1; }
  done
}

# vhost-niveau (fallback): DirectAdmin-token / Plesk vhost.conf+vhost_ssl.conf
apache_install_vhost_level() {
  local inc="Include $SHIELD_DIR/apache-vhost.conf" d n=0
  write_file "$SHIELD_DIR/apache-vhost.conf" "$(apache_vhost_conf req_novary)" && CHANGED_APACHE=1
  case "$PANEL" in
    directadmin)
      ensure_block /usr/local/directadmin/data/templates/custom/cust_httpd.CUSTOM.1.pre "$inc" && { CHANGED_DA=1; NEED_DA_REWRITE=1; }
      ok "DirectAdmin: Apache vhost-token geplaatst (cust_httpd.CUSTOM.1.pre)" ;;
    plesk)
      for d in /var/www/vhosts/system/*/conf; do
        [ -d "$d" ] || continue
        ensure_block "$d/vhost.conf" "$inc" && { NEED_PLESK_RECONFIGURE=1; n=$((n+1)); plesk_mark_domain "$d"; }
        ensure_block "$d/vhost_ssl.conf" "$inc" && { NEED_PLESK_RECONFIGURE=1; plesk_mark_domain "$d"; }
      done
      ok "Plesk: Apache vhost-includes geplaatst voor $n domein(en)" ;;
    *)
      warn "Geen vhost-haak bekend voor paneel '$PANEL'; voeg zelf toe aan elke <VirtualHost>:  $inc" ;;
  esac
}

apache_remove_vhost_level() {
  local d
  [ -f /usr/local/directadmin/data/templates/custom/cust_httpd.CUSTOM.1.pre ] && remove_block /usr/local/directadmin/data/templates/custom/cust_httpd.CUSTOM.1.pre && { CHANGED_DA=1; NEED_DA_REWRITE=1; }
  for d in /var/www/vhosts/system/*/conf; do
    remove_block "$d/vhost.conf" && NEED_PLESK_RECONFIGURE=1
    remove_block "$d/vhost_ssl.conf" && NEED_PLESK_RECONFIGURE=1
  done
}

# =============================================================================
#  nginx
# =============================================================================
nginx_configtest() { nginx -t 2>&1; }
nginx_reload() {
  [ "$DRY_RUN" = 1 ] && { say "  [dry-run] nginx herladen"; return 0; }
  if [ "$HAVE_SYSTEMD" = 1 ]; then systemctl reload-or-restart nginx 2>/dev/null && return 0; fi
  service nginx reload 2>/dev/null || nginx -s reload 2>/dev/null
}

nginx_http_hooks() {   # kandidaat-paden voor de http-context-include, in volgorde
  if [ "$PANEL" = directadmin ] && grep -qs 'nginx-includes.conf' /etc/nginx/nginx.conf; then
    echo "/etc/nginx/nginx-includes.conf"
  fi
  if grep -qsE '^\s*include\s+(/etc/nginx/)?conf\.d/\*\.conf;' /etc/nginx/nginx.conf; then
    echo "/etc/nginx/conf.d/zz-php2shell-shield.conf"
  fi
}

nginx_http_hook_remove() {
  [ -f /etc/nginx/nginx-includes.conf ] && remove_block /etc/nginx/nginx-includes.conf && CHANGED_NGINX=1
  [ -e /etc/nginx/conf.d/zz-php2shell-shield.conf ] && { run rm -f /etc/nginx/conf.d/zz-php2shell-shield.conf; CHANGED_NGINX=1; }
  return 0
}

nginx_install() {
  local hook inc_line="include $SHIELD_DIR/nginx-http.conf;" srv_inc="include $SHIELD_DIR/nginx-server.conf;" d n=0 f out hook_ok=""
  write_file "$SHIELD_DIR/nginx-http.conf"   "$(nginx_http_conf)"   && CHANGED_NGINX=1
  write_file "$SHIELD_DIR/nginx-server.conf" "$(nginx_server_conf)" && CHANGED_NGINX=1
  # http-context: probeer de haken in volgorde; de include moet op zichzelf
  # al een geldige config opleveren (geo/map/log_format horen in http{})
  for hook in $(nginx_http_hooks); do
    case "$hook" in
      *zz-php2shell-shield.conf) write_file "$hook" "$inc_line" && CHANGED_NGINX=1 ;;
      *) ensure_block "$hook" "$inc_line" && CHANGED_NGINX=1 ;;
    esac
    [ "$DRY_RUN" = 1 ] && { hook_ok="$hook"; break; }
    out=$(nginx_configtest)
    if printf '%s' "$out" | grep -qi 'syntax is ok'; then hook_ok="$hook"; break; fi
    warn "nginx-configtest faalde met haak $hook; probeer volgende:"; printf '%s\n' "$out" | sed 's/^/      /' >&2
    nginx_http_hook_remove
  done
  if [ -z "$hook_ok" ]; then
    warn "nginx: geen werkende http-context-haak; voeg zelf toe binnen http{}:  $inc_line"
    return 1
  fi
  ok "nginx: http-context include via $hook_ok"

  # server-context: per paneel
  case "$PANEL" in
    directadmin)
      ensure_block /usr/local/directadmin/data/templates/custom/cust_nginx.CUSTOM.post "$srv_inc" && { CHANGED_DA=1; NEED_DA_REWRITE=1; }
      ok "DirectAdmin: nginx server-token geplaatst (cust_nginx.CUSTOM.post)" ;;
    plesk)
      for d in /var/www/vhosts/system/*/conf; do
        [ -d "$d" ] || continue
        ensure_block "$d/vhost_nginx.conf" "$srv_inc" && { NEED_PLESK_RECONFIGURE=1; n=$((n+1)); plesk_mark_domain "$d"; }
      done
      ok "Plesk: nginx server-includes geplaatst/gecontroleerd ($n nieuw)" ;;
    cpanel)
      write_file /etc/nginx/conf.d/server-includes/php2shell-shield.conf "$srv_inc" && CHANGED_NGINX=1
      ok "cPanel: nginx server-include geplaatst" ;;
    *)
      # kale nginx: include-regel direct na elke 'server {' in sites-enabled en conf.d
      for f in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
        [ -f "$f" ] || continue
        case "$f" in *zz-php2shell-shield.conf) continue ;; esac
        grep -q 'php2shell-shield' "$f" && continue
        grep -qE '^\s*server\s*\{' "$f" || continue
        if [ "$DRY_RUN" = 1 ]; then say "  [dry-run] zou server-include invoegen in $f"; continue; fi
        backup_file "$f"; track_modified "$f"
        sed -i -E "s#^(\s*server\s*\{.*)\$#\1\n    $srv_inc # php2shell-shield#" "$f"
        CHANGED_NGINX=1; n=$((n+1))
      done
      ok "nginx: server-include ingevoegd in $n bestand(en)" ;;
  esac

  if [ "$DRY_RUN" = 0 ] && [ "$NEED_PLESK_RECONFIGURE" = 0 ] && [ "$NEED_DA_REWRITE" = 0 ]; then
    out=$(nginx_configtest)
    if ! printf '%s' "$out" | grep -qi 'syntax is ok'; then
      err "nginx-configtest faalde; nginx-wijzigingen worden teruggedraaid:"; printf '%s\n' "$out" | sed 's/^/      /' >&2
      nginx_remove; return 1
    fi
  fi
  return 0
}

nginx_remove() {
  local d f
  nginx_http_hook_remove
  [ -e /etc/nginx/conf.d/server-includes/php2shell-shield.conf ] && { run rm -f /etc/nginx/conf.d/server-includes/php2shell-shield.conf; CHANGED_NGINX=1; }
  [ -f /usr/local/directadmin/data/templates/custom/cust_nginx.CUSTOM.post ] && remove_block /usr/local/directadmin/data/templates/custom/cust_nginx.CUSTOM.post && { CHANGED_DA=1; NEED_DA_REWRITE=1; }
  for d in /var/www/vhosts/system/*/conf; do
    remove_block "$d/vhost_nginx.conf" && NEED_PLESK_RECONFIGURE=1
  done
  for f in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
    [ -f "$f" ] || continue
    grep -q '# php2shell-shield' "$f" || continue
    [ "$DRY_RUN" = 1 ] && continue
    backup_file "$f"; sed -i '/# php2shell-shield$/d' "$f"; CHANGED_NGINX=1
  done
}

# =============================================================================
#  OpenLiteSpeed / LiteSpeed (DirectAdmin)
# =============================================================================
ols_install() {
  [ "$PANEL" = directadmin ] || { warn "OpenLiteSpeed buiten DirectAdmin: voeg de rewrite-regels zelf toe aan elke vhost (zie $SHIELD_DIR/rewrite-rules.txt)"; write_file "$SHIELD_DIR/rewrite-rules.txt" "$(rewrite_rules)"; return 0; }
  ensure_block /usr/local/directadmin/data/templates/custom/cust_openlitespeed.CUSTOM.5.pre "$(rewrite_rules)" && { CHANGED_LSWS=1; NEED_DA_REWRITE=1; }
  ok "DirectAdmin/OpenLiteSpeed: rewrite-token geplaatst (cust_openlitespeed.CUSTOM.5.pre)"
}
ols_remove() {
  [ -f /usr/local/directadmin/data/templates/custom/cust_openlitespeed.CUSTOM.5.pre ] && remove_block /usr/local/directadmin/data/templates/custom/cust_openlitespeed.CUSTOM.5.pre && { CHANGED_LSWS=1; NEED_DA_REWRITE=1; }
}
lsws_restart() {
  [ "$DRY_RUN" = 1 ] && { say "  [dry-run] lsws herstarten"; return 0; }
  if [ -x /usr/local/lsws/bin/lswsctrl ]; then /usr/local/lsws/bin/lswsctrl restart >/dev/null 2>&1; return; fi
  [ "$HAVE_SYSTEMD" = 1 ] && systemctl restart lsws 2>/dev/null
}

# =============================================================================
#  DirectAdmin / Plesk herschrijven
# =============================================================================
da_rewrite_confs() {
  local i=0
  [ "$DRY_RUN" = 1 ] && { say "  [dry-run] DirectAdmin: webserverconfigs herschrijven"; return 0; }
  info "DirectAdmin: webserverconfiguraties herschrijven (task.queue)..."
  echo "action=rewrite&value=httpd" >> /usr/local/directadmin/data/task.queue
  /usr/local/directadmin/dataskq d >/dev/null 2>&1 || true
  # de cron-dataskq kan de taak al opgepakt hebben; wacht tot de queue leeg is en er
  # geen dataskq meer draait (max 10 min), anders test je een half herschreven config
  while { [ -s /usr/local/directadmin/data/task.queue ] || pgrep -x dataskq >/dev/null 2>&1; } && [ $i -lt 300 ]; do
    sleep 2; i=$((i+1))
  done
  sleep 2
}

# configtest_ok FUNCTIE PATROON [POGINGEN] : herhaal de configtest (standaard 5x, 3 s pauze)
configtest_ok() {
  local n=0 max="${3:-5}"
  while [ $n -lt "$max" ]; do
    "$1" 2>&1 | grep -qi "$2" && return 0
    n=$((n+1)); sleep 3
  done
  return 1
}

# verwijzen gegenereerde webserverconfigs (DirectAdmin-users, Plesk-vhosts) nog naar onze
# include-bestanden? Zolang dat zo is, mogen die bestanden niet weg (anders start nginx/Apache niet)
shield_refs_remaining() {
  local f
  if [ "$HAVE_NGINX" = 1 ] && nginx -T 2>/dev/null | grep -q 'php2shell-shield/nginx-'; then return 0; fi
  if [ "$HAVE_APACHE" = 1 ]; then
    { case "$APACHE_BIN" in apache2) apache2ctl -t -D DUMP_INCLUDES ;; *) httpd -t -D DUMP_INCLUDES ;; esac; } 2>/dev/null \
      | grep -q 'php2shell-shield/apache-' && return 0
  fi
  for f in /usr/local/directadmin/data/users/*/nginx.conf /usr/local/directadmin/data/users/*/httpd.conf \
           /etc/nginx/plesk.conf.d/vhosts/*.conf /etc/httpd/conf/plesk.conf.d/vhosts/*.conf /etc/apache2/plesk.conf.d/vhosts/*.conf; do
    [ -f "$f" ] && grep -q 'php2shell-shield' "$f" && return 0
  done
  return 1
}
wait_no_shield_refs() {   # tot 2 minuten wachten tot DirectAdmin/Plesk klaar is met herschrijven
  local i=0
  while shield_refs_remaining && [ $i -lt 40 ]; do sleep 3; i=$((i+1)); done
  ! shield_refs_remaining
}
plesk_mark_domain() {   # $1 = /var/www/vhosts/system/DOMEIN/conf
  local dom; dom=$(basename "$(dirname "$1")")
  case " $PLESK_NEW_DOMAINS " in *" $dom "*) ;; *) PLESK_NEW_DOMAINS="${PLESK_NEW_DOMAINS:+$PLESK_NEW_DOMAINS }$dom" ;; esac
}
plesk_httpdmng() {
  if command -v plesk >/dev/null 2>&1; then plesk sbin httpdmng "$@"; else /usr/local/psa/admin/sbin/httpdmng "$@"; fi
}
plesk_reconfigure_all() {
  local dom
  [ "$DRY_RUN" = 1 ] && { say "  [dry-run] Plesk: httpdmng --reconfigure-all"; return 0; }
  if [ "$PLESK_RECONF_ALL" = 1 ] || [ -z "$PLESK_NEW_DOMAINS" ]; then
    info "Plesk: alle vhost-configuraties opnieuw genereren (kan enkele minuten duren)..."
    plesk_httpdmng --reconfigure-all >/dev/null 2>&1 || warn "httpdmng --reconfigure-all meldde een fout; controleer 'plesk sbin httpdmng --reconfigure-all'"
  else
    for dom in $PLESK_NEW_DOMAINS; do
      plesk_httpdmng --reconfigure-domain "$dom" >/dev/null 2>&1 || warn "httpdmng --reconfigure-domain $dom faalde"
    done
  fi
}

# =============================================================================
#  PHP: session.upload_progress uitzetten
# =============================================================================
php_ini_files() {
  local f
  for f in /usr/local/php*/lib/php.ini /usr/local/lib/php.ini /opt/plesk/php/*/etc/php.ini /etc/php.ini \
           /etc/php/*/*/php.ini /etc/opt/remi/php*/php.ini /opt/remi/php*/root/etc/php.ini \
           /opt/cpanel/ea-php*/root/etc/php.ini /opt/alt/php*/etc/php.ini \
           /usr/local/lsws/lsphp*/etc/php.ini /usr/local/lsws/lsphp*/etc/php/*/litespeed/php.ini \
           /usr/local/psa/admin/conf/php.ini; do
    [ -f "$f" ] && echo "$f"
  done | sort -u
}
php_dropin_dirs() {
  local d
  for d in /usr/local/php*/lib/php.conf.d /opt/plesk/php/*/etc/php.d /etc/php.d /etc/php/*/*/conf.d \
           /etc/opt/remi/php*/php.d /opt/remi/php*/root/etc/php.d /opt/cpanel/ea-php*/root/etc/php.d \
           /opt/alt/php*/etc/php.d /usr/local/lsws/lsphp*/etc/php.d /usr/local/lsws/lsphp*/etc/php/*/mods-available \
           /usr/local/directadmin/custombuild/custom/php.conf.d; do
    [ -d "$d" ] && echo "$d"
  done | sort -u
}
# Alle PHP-binaries (CLI en FPM). Symlinks worden opgelost en ontdubbeld:
# DirectAdmin bouwt met --program-suffix (php81, php-fpm81) en linkt php -> php81.
php_binaries() {
  local b
  for b in /usr/local/php*/bin/php /usr/local/php*/bin/php[0-9]* /usr/local/php*/sbin/php-fpm /usr/local/php*/sbin/php-fpm[0-9]* \
           /opt/plesk/php/*/bin/php /opt/plesk/php/*/sbin/php-fpm \
           /usr/bin/php /usr/bin/php[0-9]* /usr/sbin/php-fpm /usr/sbin/php-fpm[0-9]* /opt/remi/php*/root/usr/bin/php \
           /opt/cpanel/ea-php*/root/usr/bin/php /opt/cpanel/ea-php*/root/usr/sbin/php-fpm /opt/alt/php*/usr/bin/php \
           /usr/local/lsws/lsphp*/bin/php /usr/local/lsws/lsphp*/bin/lsphp /usr/local/psa/admin/bin/php; do
    [ -x "$b" ] || continue
    readlink -f "$b" 2>/dev/null || echo "$b"
  done | sort -u
}

# set_ini_directive FILE KEY VALUE  (0 = gewijzigd)
set_ini_directive() {
  local file="$1" key="$2" val="$3" tmp
  # al goed (precies één actieve regel met de gewenste waarde) -> niets doen
  if grep -qE "^[[:space:]]*${key}[[:space:]]*=[[:space:]]*${val}[[:space:]]*(;.*)?$" "$file" \
     && [ "$(grep -cE "^[[:space:]]*${key}[[:space:]]*=" "$file")" = 1 ]; then
    return 1
  fi
  if [ "$DRY_RUN" = 1 ]; then say "  [dry-run] zou $key = $val zetten in $file"; return 0; fi
  backup_file "$file"
  grep -qxF "$file|$BACKUP_DIR/$(printf '%s' "$file" | sed 's#^/##; s#/#__#g').$RUN_STAMP" "$INI_BACKUP_LIST" 2>/dev/null \
    || echo "$file|$BACKUP_DIR/$(printf '%s' "$file" | sed 's#^/##; s#/#__#g').$RUN_STAMP" >> "$INI_BACKUP_LIST"
  tmp=$(mktemp)
  awk -v key="$key" -v val="$val" '
    BEGIN { done=0; insession=0 }
    $0 ~ "^[ \t]*" key "[ \t]*=" {
      if (!done) { print key " = " val "  ; php2shell-shield"; done=1 } else { print "; php2shell-shield: " $0 }
      next
    }
    /^\[Session\]/ && !done { print; print key " = " val "  ; php2shell-shield"; done=1; next }
    { print }
    END { if (!done) { print ""; print "[Session]"; print key " = " val "  ; php2shell-shield" } }
  ' "$file" > "$tmp"
  cat "$tmp" > "$file"; rm -f "$tmp"
  return 0
}

php_dropin_content() {
  echo "; php2shell-shield - noodmaatregel CVE-2026-109618 / CVE-2026-109619"
  echo "; session upload-progress: bevestigde route voor CVE-2026-109619 (PHP-advies: uit, ook na patchen)"
  echo "session.upload_progress.enabled = Off"
  echo "; PHP 8.5: bevestigde route via fatal-error-backtraces (oudere versies negeren deze regel)"
  echo "fatal_error_backtraces = 0"
  if [ "$MEMORY_UNLIMITED" = 1 ]; then
    echo "; PHP-advies tegen CVE-2026-109618: geen PHP-geheugenlimiet, zodat het OOM-pad niet aanstuurbaar is"
    echo "memory_limit = -1"
  fi
  [ "$STRICT_SESSIONS" = 1 ] && echo "session.use_strict_mode = 1"
  return 0
}

php_harden() {
  local f d n=0 m=0
  for f in $(php_ini_files); do
    set_ini_directive "$f" "session.upload_progress.enabled" "Off" && { n=$((n+1)); CHANGED_PHP=1; }
    [ "$STRICT_SESSIONS" = 1 ] && { set_ini_directive "$f" "session.use_strict_mode" "1" && CHANGED_PHP=1; }
    [ "$MEMORY_UNLIMITED" = 1 ] && { set_ini_directive "$f" "memory_limit" "-1" && CHANGED_PHP=1; }
  done
  for d in $(php_dropin_dirs); do
    write_file "$d/$DROPIN_NAME" "$(php_dropin_content)" && { m=$((m+1)); CHANGED_PHP=1; }
  done
  ok "PHP: session.upload_progress.enabled=Off gezet in $n php.ini('s) en $m drop-in map(pen)"
  if [ "$PANEL" = plesk ] && [ "$CHANGED_PHP" = 1 ] && [ "$DRY_RUN" = 0 ]; then
    info "Plesk: per-domein PHP-instellingen bijwerken (plesk bin php_settings -u)..."
    plesk bin php_settings -u >/dev/null 2>&1 || warn "plesk bin php_settings -u gaf een fout (per-domein php.ini's mogelijk niet bijgewerkt)"
  fi
}

php_restore() {
  local line orig bak d
  [ -f "$INI_BACKUP_LIST" ] || { warn "Geen php.ini-backups geregistreerd"; }
  if [ -f "$INI_BACKUP_LIST" ]; then
    # laatste (= oudste, eerste) backup per bestand wint
    tac "$INI_BACKUP_LIST" | while IFS='|' read -r orig bak; do
      [ -f "$bak" ] || continue
      run cp -p "$bak" "$orig" && ok "Hersteld: $orig"
    done
  fi
  for d in $(php_dropin_dirs); do
    [ -f "$d/$DROPIN_NAME" ] && run rm -f "$d/$DROPIN_NAME"
  done
  CHANGED_PHP=1
}

php_fpm_units() {
  [ "$HAVE_SYSTEMD" = 1 ] || return 0
  systemctl list-units --type=service --all --plain --no-legend 2>/dev/null | awk '{print $1}' \
    | grep -E '^(php[0-9.]*-?fpm[0-9.]*|php-fpm[0-9.]*|php[0-9]+-php-fpm|plesk-php[0-9]+-fpm[^ ]*|ea-php[0-9]+-php-fpm|alt-php[0-9]+-fpm[^ ]*|sw-engine)\.service$' \
    | sort -u
}
php_reload_all() {
  local u n=0
  [ "$DRY_RUN" = 1 ] && { say "  [dry-run] alle PHP-FPM-diensten herladen"; return 0; }
  for u in $(php_fpm_units); do
    systemctl reload-or-restart "$u" >/dev/null 2>&1 && n=$((n+1))
  done
  ok "PHP-FPM: $n dienst(en) herladen"
  if [ "$HAVE_OLS" = 1 ] || [ "$HAVE_LSWS" = 1 ]; then lsws_restart; ok "LiteSpeed herstart (lsphp leest php.ini opnieuw)"; fi
}

# bevat de binary de functie zend_mm_safe_error_ex (toegevoegd door de backport-commit
# "Avoid state corruption via bailout" voor 7.4, 8.0 en 8.1)? ZEND_API, dus zichtbaar via nm -D
has_backport_symbol() {
  local b="$1"
  if command -v nm >/dev/null 2>&1 && nm -D "$b" 2>/dev/null | grep -q zend_mm_safe_error_ex; then return 0; fi
  grep -aq zend_mm_safe_error_ex "$b" 2>/dev/null   # werkt ook zonder binutils
}

# vergelijk versie: fixed_status VERSIE -> OK | ONGEPATCHT | EOL | ONBEKEND
fixed_status() {
  local v="$1" major minor patch fx fmaj fmin fpat
  [[ "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]] || { echo ONBEKEND; return; }
  major=${BASH_REMATCH[1]}; minor=${BASH_REMATCH[2]}; patch=${BASH_REMATCH[3]}
  # zelf gebouwde backports met een versienummer dat nooit officieel is uitgebracht
  # (7.4.34+, 8.0.31+, 8.1.35+); 8.1.34 is óók de officiële dec-2025 release en bewijst niets,
  # daarom controleert php_report EOL-binaries ook op het fix-symbool zend_mm_safe_error_ex
  if { [ "$major" -eq 7 ] && [ "$minor" -eq 4 ] && [ "$patch" -ge 34 ]; } \
     || { [ "$major" -eq 8 ] && [ "$minor" -eq 0 ] && [ "$patch" -ge 31 ]; } \
     || { [ "$major" -eq 8 ] && [ "$minor" -eq 1 ] && [ "$patch" -ge 35 ]; }; then echo "OK (backport)"; return; fi
  if [ "$major" -lt 8 ] || { [ "$major" -eq 8 ] && [ "$minor" -lt 2 ]; }; then echo EOL; return; fi
  IFS=',' read -ra _fx <<< "$FIXED_VERSIONS"
  for fx in "${_fx[@]}"; do
    [[ "$fx" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || continue
    fmaj=${BASH_REMATCH[1]}; fmin=${BASH_REMATCH[2]}; fpat=${BASH_REMATCH[3]}
    if [ "$major" = "$fmaj" ] && [ "$minor" = "$fmin" ]; then
      [ "$patch" -ge "$fpat" ] && echo "OK" || echo "ONGEPATCHT"; return
    fi
  done
  echo ONBEKEND
}

php_report() {
  local b ver up st
  hr; say "PHP-binaries (versie / upload_progress / patchstand t.o.v. verwachte fixes: $FIXED_VERSIONS)"
  for b in $(php_binaries); do
    ver=$("$b" -v 2>/dev/null | head -1 | awk '{print $2}')
    up=$("$b" -i 2>/dev/null | awk -F'=> ' '/^session.upload_progress.enabled/{gsub(/[[:space:]]/,"",$2); print $2; exit}')
    st=$(fixed_status "${ver:-0}")
    # EOL-binary die het fix-symbool van de officiële backport-commit bevat = toch gepatcht
    if [ "$st" = EOL ] && has_backport_symbol "$b"; then st="OK (backport, symbool aanwezig)"; fi
    printf '  %-52s %-10s upload_progress=%-6s %s\n' "$b" "${ver:-?}" "${up:-?}" "$st"
  done
  say "  (EOL = geen fix van php.net; alleen veilig met een vendor-backport (DirectAdmin CustomBuild, Plesk, distributie)"
  say "   of na migratie naar 8.2+. Zelf gebouwd uit PHP's backport-branch meldt 8.1 zich als 8.1.34 = OK (backport)."
  say "   De blokkade dekt de door PHP gedocumenteerde routes; updaten blijft de enige volledige fix.)"
}

# =============================================================================
#  Logrotate, watch-service, firewall
# =============================================================================
install_logrotate() {
  write_file /etc/logrotate.d/php2shell-shield "$LOG_DIR/*.log {
    weekly
    rotate 4
    missingok
    notifempty
    compress
    copytruncate
}" >/dev/null || true
}

install_self() {
  local src
  src=$(readlink -f "$0" 2>/dev/null || echo "$0")
  [ "$src" = "$BIN_TARGET" ] && return 0
  if [ ! -r "$src" ] || [ "$(basename "$src")" = bash ]; then
    warn "Kan het script niet naar $BIN_TARGET kopiëren (gestart via stdin?). Sla het eerst op als bestand en draai het van daaruit; de watch-service heeft $BIN_TARGET nodig."
    return 1
  fi
  run install -m 755 "$src" "$BIN_TARGET" && ok "Script geïnstalleerd als $BIN_TARGET"
}

install_watch() {
  [ "$HAVE_SYSTEMD" = 1 ] || { warn "Geen systemd: start 'php2shell-shield watch' zelf (bijv. via nohup)"; return 0; }
  write_file "/etc/systemd/system/$UNIT_NAME.service" "[Unit]
Description=php2shell-shield watch: bant scanners die multipart-verzoeken op meerdere sites afvuren
After=network.target

[Service]
Type=simple
ExecStart=$BIN_TARGET watch
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target" >/dev/null || true
  [ "$DRY_RUN" = 1 ] && return 0
  systemctl daemon-reload
  systemctl enable --now "$UNIT_NAME" >/dev/null 2>&1 && systemctl restart "$UNIT_NAME" >/dev/null 2>&1
  ok "Watch-service actief ($UNIT_NAME): ban na >= $(effective_ban_hosts) verschillende hosts (server heeft $(server_host_count) domeinen, max $BAN_HOSTS) of >= $BAN_PATHS verschillende paden$([ "$BAN_COUNT" -gt 0 ] && printf ' of %s verzoeken' "$BAN_COUNT") binnen ${BAN_WINDOW}s, ttl ${BAN_TTL}s; eigen IP's tellen niet mee"
}

remove_watch() {
  [ "$HAVE_SYSTEMD" = 1 ] || return 0
  [ -f "/etc/systemd/system/$UNIT_NAME.service" ] || return 0
  run systemctl disable --now "$UNIT_NAME" >/dev/null 2>&1
  run rm -f "/etc/systemd/system/$UNIT_NAME.service"
  run systemctl daemon-reload
  ok "Watch-service verwijderd"
}

# nooit bannen: loopback, privé, eigen IP's, vertrouwde lijst, Cloudflare
NEVER_BAN_V4="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10
173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18
190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13
104.24.0.0/14 172.64.0.0/13 131.0.72.0/22"
# aantal domeinen op deze server (voor een drempel die past bij kleine servers)
server_host_count() {
  local n=0
  case "$PANEL" in
    directadmin) n=$(awk 'END{print NR}' /etc/virtual/domainowners 2>/dev/null) ;;
    plesk)       n=$(ls -1 /var/www/vhosts/system 2>/dev/null | wc -l) ;;
    cpanel)      n=$(grep -vc '^\*' /etc/userdomains 2>/dev/null) ;;
  esac
  echo "${n:-0}"
}
# effectieve ban-drempel: BAN_HOSTS, maar op een server met minder domeinen
# driekwart daarvan (minimaal 3), anders haalt een scanner de drempel nooit
effective_ban_hosts() {
  local n e; n=$(server_host_count)
  [ "$n" -gt 0 ] || { echo "$BAN_HOSTS"; return; }   # aantal onbekend (kaal systeem): vaste drempel
  e=$(( (n * 3 + 3) / 4 ))
  [ "$e" -lt 3 ] && e=3
  [ "$e" -gt "$BAN_HOSTS" ] && e=$BAN_HOSTS
  echo "$e"
}

# eigen adressen van deze server (zelftest-verkeer komt hiervandaan)
own_ips() { hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^$'; echo 127.0.0.1; }
is_own_ip() { local x; for x in $(own_ips); do [ "$x" = "$1" ] && return 0; done; [[ "$1" == 127.* ]]; }

never_ban() {
  local ip="$1" c
  is_ipv4 "$ip" || return 0        # IPv6 wordt (bewust) niet gebant
  for c in $NEVER_BAN_V4 $(trust_list) $(hostname -I 2>/dev/null); do
    ip4_in_cidr "$ip" "$c" && return 0
  done
  return 1
}

ban_ip() {
  local ip="$1" reason="$2"
  mkdir -p "$LOG_DIR"
  if command -v csf >/dev/null 2>&1; then
    csf -td "$ip" "$BAN_TTL" "php2shell-shield: $reason" >/dev/null 2>&1
  elif command -v ipset >/dev/null 2>&1 && command -v iptables >/dev/null 2>&1; then
    ipset create php2shell_v4 hash:ip family inet timeout "$BAN_TTL" -exist >/dev/null 2>&1
    iptables -C INPUT -m set --match-set php2shell_v4 src -j DROP >/dev/null 2>&1 \
      || iptables -I INPUT -m set --match-set php2shell_v4 src -j DROP
    ipset add php2shell_v4 "$ip" timeout "$BAN_TTL" -exist
  elif command -v nft >/dev/null 2>&1; then
    nft list table inet php2shell >/dev/null 2>&1 || {
      nft add table inet php2shell
      nft add set inet php2shell banned_v4 '{ type ipv4_addr; flags timeout; }'
      nft add chain inet php2shell input '{ type filter hook input priority -10; policy accept; }'
      nft add rule inet php2shell input ip saddr @banned_v4 drop
    }
    nft add element inet php2shell banned_v4 "{ $ip timeout ${BAN_TTL}s }"
  elif command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -s "$ip" -j DROP >/dev/null 2>&1 || iptables -I INPUT -s "$ip" -j DROP
    reason="$reason (iptables zonder ttl: handmatig opruimen)"
  else
    reason="$reason (GEEN firewall-tool gevonden, niet gebant)"
  fi
  echo "$(date -Is) BAN $ip ttl=$BAN_TTL $reason" >> "$BAN_LOG"
  logger -t php2shell-shield "BAN $ip ($reason)" 2>/dev/null || true
}

unban_ip() {
  local ip="$1"
  command -v csf >/dev/null 2>&1 && csf -tr "$ip" >/dev/null 2>&1
  command -v ipset >/dev/null 2>&1 && ipset del php2shell_v4 "$ip" >/dev/null 2>&1
  command -v nft >/dev/null 2>&1 && nft delete element inet php2shell banned_v4 "{ $ip }" >/dev/null 2>&1
  command -v iptables >/dev/null 2>&1 && while iptables -D INPUT -s "$ip" -j DROP >/dev/null 2>&1; do :; done
  echo "$(date -Is) UNBAN $ip" >> "$BAN_LOG"
  ok "$ip vrijgegeven"
}

remove_firewall_sets() {
  command -v iptables >/dev/null 2>&1 && while iptables -D INPUT -m set --match-set php2shell_v4 src -j DROP >/dev/null 2>&1; do :; done
  command -v ipset >/dev/null 2>&1 && ipset destroy php2shell_v4 >/dev/null 2>&1
  command -v nft >/dev/null 2>&1 && nft delete table inet php2shell >/dev/null 2>&1
  return 0
}

# De watch-lus: leest het centrale bloklog en bant IP's die op meerdere hosts
# multipart-verzoeken afvuren (scanner-gedrag). Elke 5 min: reapply (nieuwe
# Plesk-domeinen krijgen de include, verdwenen haken worden teruggezet).
watch_loop() {
  load_state || true
  mkdir -p "$LOG_DIR"; touch "$BLOCK_LOG"
  declare -A ip_first ip_count ip_hosts ip_paths ip_npaths ip_banned
  local ts ip host method uri status now h nh last_maint eff
  last_maint=$(date +%s); eff=$(effective_ban_hosts)
  logger -t php2shell-shield "watch gestart (ban bij >= $eff hosts of >= $BAN_PATHS paden, max hosts $BAN_HOSTS; ban_count=$BAN_COUNT window=${BAN_WINDOW}s ttl=${BAN_TTL}s)" 2>/dev/null || true
  exec 3< <(tail -n 0 -F "$BLOCK_LOG" 2>/dev/null)
  while true; do
    if read -r -t 30 -u 3 ts ip host method uri status; then
      [ -n "${ip:-}" ] || continue
      [ -n "${ip_banned[$ip]:-}" ] && continue
      is_own_ip "$ip" && continue          # zelftest-verkeer telt niet mee
      now=$(date +%s)
      if [ -z "${ip_first[$ip]:-}" ] || [ $(( now - ip_first[$ip] )) -gt "$BAN_WINDOW" ]; then
        ip_first[$ip]=$now; ip_count[$ip]=0; ip_hosts[$ip]=" "; ip_paths[$ip]="|"; ip_npaths[$ip]=0
      fi
      ip_count[$ip]=$(( ip_count[$ip] + 1 ))
      h="${host%%:*}"; h="${h,,}"
      case "${ip_hosts[$ip]}" in *" $h "*) ;; *) ip_hosts[$ip]="${ip_hosts[$ip]}$h " ;; esac
      case "${ip_paths[$ip]}" in *"|$h ${uri:-/}|"*) ;; *) ip_paths[$ip]="${ip_paths[$ip]}$h ${uri:-/}|"; ip_npaths[$ip]=$(( ip_npaths[$ip] + 1 )) ;; esac
      nh=$(printf '%s' "${ip_hosts[$ip]}" | wc -w)
      if [ "$nh" -ge "$eff" ] || { [ "$BAN_PATHS" -gt 0 ] && [ "${ip_npaths[$ip]}" -ge "$BAN_PATHS" ]; } \
         || { [ "$BAN_COUNT" -gt 0 ] && [ "${ip_count[$ip]}" -ge "$BAN_COUNT" ]; }; then
        if never_ban "$ip"; then
          # privé-/vertrouwd/Cloudflare-adres: wel melden, niet bannen
          echo "$(date -Is) SKIP $ip multipart op $nh host(s), ${ip_npaths[$ip]} paden, ${ip_count[$ip]} verzoeken in ${BAN_WINDOW}s - niet gebant (privé/vertrouwd/Cloudflare); zoek uit wie dit is" >> "$BAN_LOG"
        else
          ban_ip "$ip" "multipart op $nh host(s), ${ip_npaths[$ip]} paden, ${ip_count[$ip]} verzoeken in ${BAN_WINDOW}s"
        fi
        ip_banned[$ip]=1
      fi
    fi
    now=$(date +%s)
    if [ $(( now - last_maint )) -ge 300 ]; then
      last_maint=$now; eff=$(effective_ban_hosts)
      QUIET=1 "$BIN_TARGET" reapply >/dev/null 2>&1 || true
    fi
  done
}

# =============================================================================
#  Test & scan
# =============================================================================
test_hosts() {
  case "$PANEL" in
    directadmin) awk -F': ' '{print $1}' /etc/virtual/domainowners 2>/dev/null | head -n 3 ;;
    plesk)       ls /var/www/vhosts/system 2>/dev/null | grep -vE '^(default|chroot)$' | head -n 3 ;;
    cpanel)      awk -F': ' '$1!="*"{print $1}' /etc/userdomains 2>/dev/null | head -n 3 ;;
  esac
  hostname -f 2>/dev/null
}
# IP's om lokaal mee te testen: eerst de echte interface-adressen (daar luisteren
# de vhosts op), loopback als laatste (dat komt bij DirectAdmin op de hoofdserver uit)
probe_ips() {
  { hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; echo 127.0.0.1; } | awk '!seen[$0]++'
}
listen_ports() {   # poorten van apache/nginx/lsws, zonder paneel-/adminpoorten
  ss -ltnp 2>/dev/null | grep -E 'httpd|apache2|nginx|litespeed|lshttpd|openlitespeed' | awk '{print $4}' | sed 's/.*://' \
    | grep -vxE '2222|2083|2087|2096|7080|7081|8443|8880' | sort -un
}

do_test() {
  local hosts h p scheme ip code_get code_mp fails=0 total=0 ips port_list resolve out effhost
  command -v curl >/dev/null 2>&1 || { warn "curl ontbreekt; test overgeslagen"; return 0; }
  hr; say "Zelftest: multipart-POST moet 403 geven, gewone GET niet (redirects worden gevolgd, op de server zelf)"
  hosts=$(test_hosts | sort -u)
  port_list=$(listen_ports); [ -n "$port_list" ] || port_list="80 443"
  ips=$(probe_ips)
  for h in $hosts; do
    for p in $port_list; do
      case "$p" in 443|8081) scheme=https ;; *) scheme=http ;; esac
      for ip in $ips; do
        # --resolve: verbind lokaal met de juiste Host/SNI; redirects naar https blijven op deze server
        resolve="--resolve $h:$p:$ip --resolve $h:80:$ip --resolve $h:443:$ip"
        code_get=$(curl -sk -o /dev/null -m 10 -L --max-redirs 5 $resolve -w '%{http_code}' "$scheme://$h:$p/" 2>/dev/null) || code_get="000"
        [ "$code_get" = "000" ] && continue
        # multipart-POST zónder redirects volgen: een 3xx komt dan van de webserver zelf (Redirect/
        # RewriteRule vóór de toegangscontrole), dus PHP heeft de body nooit gezien; de bestemming
        # krijgt bij een eigen verzoek weer de blokkade. Een 2xx is wél een echt gat.
        out=$(curl -sk -o /dev/null -m 10 $resolve -w '%{http_code} %{redirect_url}' \
                  -F "php2shell_shield_test=1" "$scheme://$h:$p/" 2>/dev/null) || out="000 -"
        code_mp="${out%% *}"; effhost=$(printf '%s' "${out#* }" | sed -E 's#^[a-z]+://([^/:]+).*#\1#')
        total=$((total+1))
        if [ "$MODE" = strict ] && [ "$code_mp" != 403 ] && [[ "$code_mp" =~ ^30[12378]$ ]]; then
          printf '  %s%-34s %-5s GET=%s multipart=%s  (redirect door de webserver vóór PHP, naar %s)%s\n' "$C_YEL" "$h" "$p" "$code_get" "$code_mp" "${effhost:-?}" "$C_OFF"
        elif [ "$MODE" = strict ] && [ "$code_mp" != 403 ]; then
          printf '  %s%-34s %-5s GET=%s multipart=%s  <-- NIET geblokkeerd%s\n' "$C_RED" "$h" "$p" "$code_get" "$code_mp" "$C_OFF"; fails=$((fails+1))
        elif [ "$code_get" = 403 ]; then
          printf '  %s%-34s %-5s GET=%s multipart=%s  <-- GET geeft ook 403 (controleer!)%s\n' "$C_YEL" "$h" "$p" "$code_get" "$code_mp" "$C_OFF"
        else
          printf '  %-34s %-5s GET=%s multipart=%s\n' "$h" "$p" "$code_get" "$code_mp"
        fi
        break   # eerste bereikbare IP per host/poort volstaat
      done
    done
  done
  [ "$total" = 0 ] && warn "Geen bereikbare host/poort-combinatie gevonden voor de test"
  if [ "$MODE" = strict ] && [ "$fails" -gt 0 ]; then
    warn "$fails van $total test(s) blokkeerde NIET. Let op: als je 127.0.0.1 of het server-IP als --trust hebt opgegeven, is dit verwacht."
    return 1
  fi
  [ "$MODE" = strict ] && ok "Multipart wordt geblokkeerd op alle $total geteste combinaties"
  return 0
}

# --probe DOMEIN : plaats tijdelijk een PHP-bestand in de docroot en lees de
# effectieve waarde van session.upload_progress.enabled via HTTP
do_probe() {
  local dom="$1" user docroots="" d f name out scheme ip
  case "$PANEL" in
    directadmin)
      user=$(awk -F': ' -v d="$dom" '$1==d{print $2}' /etc/virtual/domainowners)
      docroots="/home/$user/domains/$dom/public_html"
      # DirectAdmin gebruikt voor https private_html; alleen apart als het geen symlink is
      [ -d "/home/$user/domains/$dom/private_html" ] && [ ! -L "/home/$user/domains/$dom/private_html" ] && docroots="$docroots /home/$user/domains/$dom/private_html" ;;
    plesk)       docroots="/var/www/vhosts/$dom/httpdocs" ;;
    cpanel)      user=$(awk -F': ' -v d="$dom" '$1==d{print $2}' /etc/userdomains); docroots="/home/$user/public_html" ;;
    *)           warn "probe: docroot onbekend voor dit paneel"; return 1 ;;
  esac
  [ -d "${docroots%% *}" ] || { warn "probe: docroot ${docroots%% *} bestaat niet"; return 1; }
  name="p2s-probe-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n').php"
  for d in $docroots; do
    f="$d/$name"
    printf '<?php header("Content-Type: text/plain"); echo "php=", PHP_VERSION, " sapi=", PHP_SAPI, " upload_progress=", var_export(ini_get("session.upload_progress.enabled"), true), "\\n";\n' > "$f"
    chown --reference="$d" "$f" 2>/dev/null
  done
  out=""
  for ip in $(probe_ips); do
    for scheme in https http; do
      out=$(curl -sk -m 10 -L --resolve "$dom:443:$ip" --resolve "$dom:80:$ip" "$scheme://$dom/$name" 2>/dev/null | head -1)
      case "$out" in *upload_progress=*) break 2 ;; esac
    done
  done
  for d in $docroots; do rm -f "$d/$name"; done
  say "  probe $dom: ${out:-geen antwoord}"
  if printf '%s' "$out" | grep -q "upload_progress=''\|upload_progress='0'\|upload_progress=false"; then
    ok "upload_progress staat effectief UIT voor $dom"
  elif printf '%s' "$out" | grep -q "upload_progress="; then
    warn "upload_progress staat nog AAN voor $dom (per-domein php.ini/.user.ini? handler nog niet herladen?)"
  else
    warn "probe kwam niet bij PHP van $dom uit (antwoord: ${out:-leeg}); controleer of de docroot afwijkt van de standaard"
  fi
}

do_scan() {
  local roots f n
  hr; say "Scan: wat is er nog kwetsbaar of verdacht?"
  php_report
  hr; say "SAPI-risico's volgens het PHP-advies (mod_php = hoogste risico; FPM met PHP_VALUE-doorgifte = extra ingang):"
  local i mode rel pv
  if [ "$PANEL" = directadmin ]; then
    for i in 1 2 3 4; do
      rel=$(grep -E "^php${i}_release=" /usr/local/directadmin/custombuild/options.conf 2>/dev/null | cut -d= -f2)
      mode=$(grep -E "^php${i}_mode=" /usr/local/directadmin/custombuild/options.conf 2>/dev/null | cut -d= -f2)
      [ -n "$rel" ] && [ "$rel" != no ] || continue
      if [ "$mode" = mod_php ]; then warn "php$i ($rel) draait als mod_php: zet om naar php-fpm (./build set php${i}_mode php-fpm && ./build php n)"; else say "  php$i ($rel): $mode"; fi
    done
  fi
  if [ "$HAVE_APACHE" = 1 ]; then
    { case "$APACHE_BIN" in apache2) apache2ctl -M ;; *) httpd -M ;; esac; } 2>/dev/null | grep -qiE 'php[0-9]*_module' && warn "Apache heeft mod_php geladen (hoogste risico volgens PHP: RCE bewezen bij standaardlimieten)"
  fi
  if [ "$PANEL" = plesk ] && plesk bin php_handler --list 2>/dev/null | grep -qiE 'module'; then
    warn "Plesk: er bestaat een 'Apache module' (mod_php) PHP-handler; controleer welke domeinen die gebruiken en zet ze op FPM"
  fi
  pv=$(grep -rlsE 'PHP_(ADMIN_)?VALUE' /etc/nginx /etc/httpd /etc/apache2 /usr/local/directadmin/data/users 2>/dev/null | head -5)
  if [ -n "$pv" ]; then warn "Frontend stuurt PHP_VALUE/PHP_ADMIN_VALUE naar FPM (vroege 'consumer' voor CVE-2026-109619); controleer:"; printf '%s\n' "$pv" | sed 's/^/  /'; else say "  geen PHP_VALUE/PHP_ADMIN_VALUE-doorgifte in de webserverconfigs gevonden"; fi
  hr; say "Per-site overrides die upload_progress weer AAN zetten (.user.ini / .htaccess / php.ini):"
  roots="/home /var/www /usr/local/www /var/www/vhosts/system"
  timeout 180 find $roots -maxdepth 7 -type f \( -name .user.ini -o -name .htaccess -o -name php.ini \) 2>/dev/null \
    | xargs -r grep -liE 'session\.upload_progress\.enabled[[:space:]]*(=|[[:space:]])[[:space:]]*(1|on|true|yes)' 2>/dev/null | sed 's/^/  /' | head -50
  hr; say "PHP-FPM crashes (SIGSEGV) in de logs van de laatste 2 dagen (indicatie van exploitpogingen):"
  for f in /var/log/php-fpm*.log /usr/local/php*/var/log/php-fpm.log /opt/plesk/php/*/var/log/php-fpm.log /var/log/php*-fpm.log; do
    [ -f "$f" ] && { n=$(find "$f" -mtime -2 -print -quit); [ -n "$n" ] && grep -cE 'SIGSEGV|signal 11|SIGBUS' "$f" 2>/dev/null | sed "s#^#  $f: #"; }
  done
  [ "$HAVE_SYSTEMD" = 1 ] && journalctl --since '-2 days' 2>/dev/null | grep -ciE 'php-fpm.*(segfault|signal 11|SIGSEGV)' | sed 's/^/  journal: /'
  hr; say "Shells/tools gestart vanuit PHP of de webserver (nu actief):"
  ps -eo pid,ppid,user,comm 2>/dev/null | awk '
    NR>1 { comm[$1]=$4; ppid[$1]=$2; user[$1]=$3 }
    END { for (p in comm) { c=comm[p]; pp=ppid[p];
          if (c ~ /^(sh|bash|dash|zsh|perl|python[0-9.]*|nc|ncat|netcat|curl|wget|socat)$/ && (comm[pp] ~ /php|httpd|apache2|lsphp|litespeed/)) print "  pid " p " " user[p] " " c " (ouder: " comm[pp] ")" } }'
  hr; say "PHP-bestanden gewijzigd in de laatste 48 uur in webroots (max 40):"
  timeout 180 find /home /var/www -maxdepth 8 -type f -name '*.php' -mmin -2880 2>/dev/null | head -40 | sed 's/^/  /'
  hr
}

# =============================================================================
#  eol-domains: hostlijst voor --scope (alleen sites op PHP < 8.2)
# =============================================================================
version_is_eol() { [[ "$1" =~ ^([0-9]+)\.([0-9]+) ]] && { [ "${BASH_REMATCH[1]}" -lt 8 ] || { [ "${BASH_REMATCH[1]}" -eq 8 ] && [ "${BASH_REMATCH[2]}" -lt 2 ]; }; }; }
do_eol_domains() {
  local opts conf dom sel ver i rel1 rel2 rel3 rel4 line name hid v
  case "$PANEL" in
    directadmin)
      opts=/usr/local/directadmin/custombuild/options.conf
      rel1=$(grep -E '^php1_release=' $opts | cut -d= -f2); rel2=$(grep -E '^php2_release=' $opts | cut -d= -f2)
      rel3=$(grep -E '^php3_release=' $opts | cut -d= -f2); rel4=$(grep -E '^php4_release=' $opts | cut -d= -f2)
      for conf in /usr/local/directadmin/data/users/*/domains/*.conf; do
        dom=$(basename "$conf" .conf)
        sel=$(grep -E '^php1_select=' "$conf" | cut -d= -f2); sel=${sel:-1}
        case "$sel" in 1) ver=$rel1;; 2) ver=$rel2;; 3) ver=$rel3;; 4) ver=$rel4;; *) ver=$rel1;; esac
        version_is_eol "${ver:-0}" && { echo "$dom"; [ -f "${conf%.conf}.pointers" ] && cut -d= -f1 "${conf%.conf}.pointers"; }
      done | sort -u ;;
    plesk)
      plesk db -Ne "SELECT d.name, h.php_handler_id FROM domains d JOIN hosting h ON h.dom_id = d.id" 2>/dev/null \
      | while read -r name hid; do
          if [[ "$hid" =~ php([0-9])([0-9]+) ]]; then v="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
          else v=$(/usr/bin/php -v 2>/dev/null | head -1 | awk '{print $2}'); fi
          version_is_eol "${v:-0}" && echo "$name"
        done | sort -u ;;
    *) die "eol-domains werkt alleen op DirectAdmin en Plesk" ;;
  esac
}

# =============================================================================
#  Status
# =============================================================================
do_status() {
  local f state_ok=0
  load_state && state_ok=1      # eerst de opgeslagen instellingen (mode/trust/scope), dan pas tonen
  print_env
  if [ "$state_ok" = 1 ]; then
    say "Geïnstalleerd: $(grep ^INSTALLED_AT= "$STATE_FILE" | cut -d= -f2-)  (v$(grep ^INSTALLED_VERSION= "$STATE_FILE" | cut -d= -f2-))"
  else
    warn "Niet geïnstalleerd (geen $STATE_FILE)"
  fi
  say "Actieve haken:"
  for f in /etc/httpd/conf/extra/httpd-includes.conf /etc/httpd/conf.d/zz-php2shell-shield.conf /etc/apache2/conf-enabled/zz-php2shell-shield.conf \
           /etc/apache2/conf.d/includes/pre_main_global.conf /etc/nginx/nginx-includes.conf /etc/nginx/conf.d/zz-php2shell-shield.conf \
           /etc/nginx/conf.d/server-includes/php2shell-shield.conf /usr/local/directadmin/data/templates/custom/cust_nginx.CUSTOM.post \
           /usr/local/directadmin/data/templates/custom/cust_httpd.CUSTOM.1.pre /usr/local/directadmin/data/templates/custom/cust_openlitespeed.CUSTOM.5.pre; do
    [ -f "$f" ] && grep -q php2shell-shield "$f" && say "  $f"
  done
  if [ "$PANEL" = plesk ]; then
    say "  Plesk vhost_nginx.conf-includes: $(grep -ls php2shell-shield /var/www/vhosts/system/*/conf/vhost_nginx.conf 2>/dev/null | wc -l) domein(en)"
    say "  Plesk vhost.conf-includes      : $(grep -ls php2shell-shield /var/www/vhosts/system/*/conf/vhost.conf 2>/dev/null | wc -l) domein(en)"
  fi
  if [ "$HAVE_SYSTEMD" = 1 ]; then
    say "Watch-service: $(systemctl is-active $UNIT_NAME 2>/dev/null || echo inactief)"
  fi
  if [ -f "$BLOCK_LOG" ]; then
    local own; own=" $(own_ips | paste -sd' ' -) "
    hr; say "Geblokkeerd/gelogd: $(wc -l < "$BLOCK_LOG") regels totaal; top-IP's (laatste 5000):"
    tail -n 5000 "$BLOCK_LOG" | awk '{print $2}' | sort | uniq -c | sort -rn | head -10 \
      | awk -v own="$own" '{lbl=(index(own, " " $2 " ")>0) ? "  (eigen IP: zelftest)" : ""; print "  " $1 " " $2 lbl}'
    say "IP's naar aantal verschillende hosts / paden (scanner-indicatie; ban bij >= $(effective_ban_hosts) hosts of >= $BAN_PATHS paden binnen ${BAN_WINDOW}s; privé/vertrouwd nooit):"
    tail -n 5000 "$BLOCK_LOG" | awk '{split($3,a,":"); print $2, tolower(a[1]), $5}' | sort -u \
      | awk '{p[$1]++; k=$1 SUBSEP $2; if (!(k in seen)) {seen[k]=1; h[$1]++}} END{for (i in p) print h[i] " hosts, " p[i] " paden  " i}' | sort -rn | head -10 \
      | awk -v own="$own" '{lbl=(index(own, " " $NF " ")>0) ? "  (eigen IP: zelftest)" : ""; print "  " $0 lbl}'
    say "Top-hosts (laatste 5000):"
    tail -n 5000 "$BLOCK_LOG" | awk '{print $3}' | sort | uniq -c | sort -rn | head -10 | sed 's/^/  /'
    say "Details van één IP: grep IP $BLOCK_LOG"
  fi
  [ -f "$BAN_LOG" ] && { hr; say "Bans (laatste 10):"; tail -n 10 "$BAN_LOG" | sed 's/^/  /'; }
  php_report
}

# =============================================================================
#  install / reapply / uninstall
# =============================================================================
apply_all() {
  local apache_ok=0 tries=5
  mkdir -p "$SHIELD_DIR" "$LOG_DIR"
  [ "$DRY_RUN" = 1 ] || touch "$BLOCK_LOG"

  # --- webserverlaag ---
  if [ "$MODE" != signature ] || [ "$HAVE_APACHE" = 1 ]; then
    if [ "$HAVE_APACHE" = 1 ]; then
      if apache_install_global; then apache_ok=1; fi
      [ "$apache_ok" = 0 ] && [ "$MODE" != signature ] && apache_install_vhost_level
    fi
    if [ "$HAVE_LSWS" = 1 ] && [ "$PANEL" = directadmin ]; then apache_install_vhost_level; fi
    if [ "$HAVE_OLS" = 1 ]; then ols_install; fi
    if [ "$HAVE_NGINX" = 1 ] && [ "$MODE" != signature ]; then nginx_install || true; fi
  fi
  if [ "$MODE" = signature ]; then
    write_file "$SHIELD_DIR/modsecurity-rules.conf" "$(modsec_rules)" >/dev/null || true
    say "ModSecurity-regels staan in $SHIELD_DIR/modsecurity-rules.conf (Apache: automatisch via de globale include; nginx/OLS/Plesk-WAF: handmatig toevoegen)"
  fi

  # --- PHP-laag ---
  [ "$DO_PHP_INI" = 1 ] && php_harden

  # --- herschrijven en herladen ---
  [ "$NEED_DA_REWRITE" = 1 ] && da_rewrite_confs
  [ "$NEED_PLESK_RECONFIGURE" = 1 ] && plesk_reconfigure_all
  # DirectAdmin 1.7x en Plesk herschrijven asynchroon: tot 2 minuten wachten op een geldige config
  { [ "$NEED_DA_REWRITE" = 1 ] || [ "$NEED_PLESK_RECONFIGURE" = 1 ]; } && tries=40
  if [ "$HAVE_APACHE" = 1 ] && { [ "$CHANGED_APACHE" = 1 ] || [ "$CHANGED_PHP" = 1 ] || [ "$NEED_DA_REWRITE" = 1 ]; }; then
    if [ "$DRY_RUN" = 1 ] || configtest_ok apache_configtest 'syntax ok' "$tries"; then apache_reload && ok "Apache herladen"; else err "Apache-configtest faalt NA de wijzigingen; niet herladen! Draai: $APACHE_BIN -t"; fi
  fi
  if [ "$HAVE_NGINX" = 1 ] && { [ "$CHANGED_NGINX" = 1 ] || [ "$NEED_DA_REWRITE" = 1 ] || [ "$NEED_PLESK_RECONFIGURE" = 1 ]; }; then
    if [ "$DRY_RUN" = 1 ] || configtest_ok nginx_configtest 'syntax is ok' "$tries"; then nginx_reload && ok "nginx herladen"; else err "nginx-configtest faalt NA de wijzigingen; niet herladen! Draai: nginx -t (en daarna: systemctl reload nginx)"; fi
  fi
  if { [ "$HAVE_OLS" = 1 ] || [ "$HAVE_LSWS" = 1 ]; } && { [ "$CHANGED_LSWS" = 1 ] || [ "$NEED_DA_REWRITE" = 1 ]; }; then lsws_restart; ok "LiteSpeed herstart"; fi
  [ "$CHANGED_PHP" = 1 ] && php_reload_all
  return 0
}

do_install() {
  need_root; detect_env; validate_trust
  if [ -n "$TRUST_IMPORT" ] && [ "$DRY_RUN" = 0 ]; then
    trust_file_add "$(trust_raw_file "$TRUST_IMPORT" | paste -sd, -)" && ok "Adressen uit $TRUST_IMPORT samengevoegd in $TRUST_FILE"
  fi
  [ "$SCOPE" = all ] || scope_hosts >/dev/null
  print_env
  if [ "$MODE" = strict ]; then
    warn "Mode strict: ALLE multipart/form-data-verzoeken worden geweigerd (403). Uploads, media-uploads in"
    warn "WordPress, plugin-zips en formulieren die FormData/bijlagen sturen (Contact Form 7, Gravity Forms,"
    warn "WPForms) vallen tijdelijk uit. Alle door PHP gedocumenteerde aanvalsroutes lopen via multipart; updaten blijft de enige volledige fix."
  fi
  [ "$DRY_RUN" = 1 ] && warn "DRY-RUN: er wordt niets gewijzigd."
  apply_all
  if [ "$DRY_RUN" = 0 ]; then
    save_state; install_self; install_logrotate
    [ "$DO_WATCH" = 1 ] && install_watch
    [ "$DO_TEST" = 1 ] && [ "$MODE" != signature ] && { sleep 2; do_test || true; }
    [ -n "$PROBE_DOMAIN" ] && do_probe "$PROBE_DOMAIN"
  fi
  hr
  ok "Klaar. Status: php2shell-shield status   |  Loggen: tail -f $BLOCK_LOG   |  Terugdraaien: php2shell-shield uninstall"
  say "Zodra PHP overal gepatcht is: 'php2shell-shield status' toont per binary OK/ONGEPATCHT/EOL. Haal de blokkade pas"
  say "weg als alles OK is, of beperk hem met --scope tot de EOL-sites (php2shell-shield eol-domains > /etc/php2shell-shield/scope.txt)."
}

do_reapply() {
  need_root; detect_env
  load_state || die "Niet geïnstalleerd; gebruik install"
  validate_trust
  DO_TEST=0; DO_WATCH=0; QUIET=1
  PLESK_RECONF_ALL=0      # alleen nieuwe Plesk-domeinen herconfigureren, niet alles
  apply_all
  return 0
}

# trust list | add ... | remove ... | clear  -> beheert trust.txt en zet de
# wijziging direct live (configs opnieuw genereren, alleen herladen wat veranderde)
do_trust() {
  local sub="${1:-list}"; shift || true
  need_root; detect_env; load_state || true
  case "$sub" in
    list)
      say "Vertrouwde adressen (effectief: --trust uit install + $TRUST_FILE):"
      trust_list | sed 's/^/  /'; [ -n "$(trust_list)" ] || say "  (geen)" ;;
    add)
      [ $# -gt 0 ] || die "Gebruik: php2shell-shield trust add IP[,IP/CIDR,...]"
      trust_file_add "$@" && ok "Toegevoegd aan $TRUST_FILE" || say "Niets nieuws; alles stond er al."
      trust_apply ;;
    remove)
      [ $# -gt 0 ] || die "Gebruik: php2shell-shield trust remove IP[,IP/CIDR,...]"
      trust_file_remove "$@" && ok "Verwijderd uit $TRUST_FILE"
      trust_apply ;;
    clear)
      : > "$TRUST_FILE"; ok "$TRUST_FILE geleegd"; trust_apply ;;
    *) die "Gebruik: php2shell-shield trust list | add IP[,IP] | remove IP[,IP] | clear" ;;
  esac
}
trust_apply() {
  validate_trust
  if [ ! -f "$STATE_FILE" ]; then say "Nog niet geïnstalleerd; de lijst wordt bij 'install' meegenomen."; return 0; fi
  DO_TEST=0; DO_WATCH=0; PLESK_RECONF_ALL=0
  info "Configuratie bijwerken met vertrouwde adressen: $(trust_summary)"
  apply_all
  ok "Live. Deze adressen mogen multipart sturen en worden nooit gebant."
}

do_uninstall() {
  need_root; detect_env; load_state || true
  print_env
  info "Webserver-haken verwijderen..."
  apache_remove_global; apache_remove_vhost_level; nginx_remove; ols_remove
  remove_watch; remove_firewall_sets
  [ -f /etc/logrotate.d/php2shell-shield ] && run rm -f /etc/logrotate.d/php2shell-shield
  [ "$NEED_DA_REWRITE" = 1 ] && da_rewrite_confs
  [ "$NEED_PLESK_RECONFIGURE" = 1 ] && plesk_reconfigure_all
  if [ "$RESTORE_PHP_INI" = 1 ]; then info "php.ini's herstellen uit backup..."; php_restore; else say "php.ini-hardening (upload_progress=Off) blijft staan; gebruik --restore-php-ini om ook dat terug te draaien."; fi
  if [ "$HAVE_APACHE" = 1 ]; then configtest_ok apache_configtest 'syntax ok' 40 && apache_reload && ok "Apache herladen" || err "Apache-configtest faalt; controleer $APACHE_BIN -t"; fi
  if [ "$HAVE_NGINX" = 1 ]; then configtest_ok nginx_configtest 'syntax is ok' 40 && nginx_reload && ok "nginx herladen" || err "nginx-configtest faalt; controleer nginx -t"; fi
  { [ "$HAVE_OLS" = 1 ] || [ "$HAVE_LSWS" = 1 ]; } && lsws_restart
  [ "$CHANGED_PHP" = 1 ] && php_reload_all
  if [ "$DRY_RUN" = 0 ]; then
    rm -f "$SHIELD_DIR"/modsecurity-rules.conf "$SHIELD_DIR"/rewrite-rules.txt "$STATE_FILE"
    do_cleanup
  fi
  ok "Verwijderd. Backups en lijsten staan nog in $SHIELD_DIR (backups/), logs in $LOG_DIR."
}

# cleanup: verwijder de include-bestanden en het script pas als geen gegenereerde config er
# nog naar verwijst; anders leegmaken en laten staan (een lege include is geldig)
do_cleanup() {
  local f
  if wait_no_shield_refs; then
    rm -f "$SHIELD_DIR"/apache-server.conf "$SHIELD_DIR"/apache-vhost.conf "$SHIELD_DIR"/nginx-http.conf "$SHIELD_DIR"/nginx-server.conf
    rm -f "$BIN_TARGET"
    ok "Include-bestanden en $BIN_TARGET verwijderd; geen config verwijst er nog naar."
  else
    for f in apache-server.conf apache-vhost.conf nginx-http.conf nginx-server.conf; do [ -f "$SHIELD_DIR/$f" ] && : > "$SHIELD_DIR/$f"; done
    warn "Gegenereerde webserverconfigs verwijzen nog naar $SHIELD_DIR/*.conf (DirectAdmin/Plesk nog bezig met herschrijven?)."
    warn "Die bestanden zijn leeggemaakt en blijven staan zodat nginx/Apache blijven starten. Draai straks: php2shell-shield cleanup"
  fi
}

usage() {
  awk 'NR==2{next} NR>2 && /^# =+$/ {exit} NR>2 {sub(/^# ?/,""); print}' "$0"
}

# =============================================================================
#  main
# =============================================================================
main() {
  local cmd="${1:-help}"; shift || true
  while [ $# -gt 0 ]; do
    case "$1" in
      --mode)        MODE="$2"; shift ;;
      --trust)       TRUST="${TRUST:+$TRUST,}$2"; shift ;;
      --trust-file)  TRUST_IMPORT="$2"; shift ;;
      --scope)       SCOPE="$2"; shift ;;
      --fixed)       FIXED_VERSIONS="$2"; shift ;;
      --ban-hosts)   BAN_HOSTS="$2"; shift ;;
      --ban-count)   BAN_COUNT="$2"; shift ;;
      --ban-paths)   BAN_PATHS="$2"; shift ;;
      --ban-ttl)     BAN_TTL="$2"; shift ;;
      --ban-window)  BAN_WINDOW="$2"; shift ;;
      --probe)       PROBE_DOMAIN="$2"; shift ;;
      --no-php-ini)  DO_PHP_INI=0 ;;
      --no-watch)    DO_WATCH=0 ;;
      --no-test)     DO_TEST=0 ;;
      --strict-sessions) STRICT_SESSIONS=1 ;;
      --memory-unlimited) MEMORY_UNLIMITED=1 ;;
      --restore-php-ini) RESTORE_PHP_INI=1 ;;
      --dry-run)     DRY_RUN=1 ;;
      --quiet)       QUIET=1 ;;
      -h|--help)     usage; exit 0 ;;
      *) die "Onbekende optie: $1" ;;
    esac
    shift
  done
  case "$MODE" in strict|monitor|signature) ;; *) die "Onbekende mode: $MODE (strict|monitor|signature)";; esac
  case "$cmd" in
    install)     do_install ;;
    reapply)     do_reapply ;;
    uninstall)   do_uninstall ;;
    cleanup)     need_root; detect_env; do_cleanup ;;
    status)      need_root; detect_env; do_status ;;
    test)        need_root; detect_env; load_state || true; do_test; [ -n "$PROBE_DOMAIN" ] && do_probe "$PROBE_DOMAIN"; true ;;
    scan)        need_root; detect_env; load_state || true; do_scan ;;
    eol-domains) need_root; detect_env; do_eol_domains ;;
    watch)       need_root; detect_env; watch_loop ;;
    unban)       need_root; unban_ip "${UNBAN_IP:-}" ;;
    trust)       do_trust "${TRUST_SUB:-list}" ${TRUST_ARGS:+$TRUST_ARGS} ;;
    bans)        [ -f "$BAN_LOG" ] && cat "$BAN_LOG" || say "Nog geen bans." ;;
    version)     echo "php2shell-shield $VERSION" ;;
    help|*)      usage ;;
  esac
}

if [ "${PHP2SHELL_SHIELD_LIB:-0}" != 1 ]; then
  # 'unban IP' en 'trust add|remove IP...' hebben positionele argumenten
  if [ "${1:-}" = unban ]; then UNBAN_IP="${2:-}"; [ -n "$UNBAN_IP" ] || die "Gebruik: php2shell-shield unban IP"; set -- unban; fi
  if [ "${1:-}" = trust ]; then TRUST_SUB="${2:-list}"; shift 2 2>/dev/null || shift $#; TRUST_ARGS="$*"; set -- trust; fi
  main "$@"
fi
