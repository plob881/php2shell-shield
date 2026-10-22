#!/bin/bash
# =============================================================================
#  da-php-rebuild.sh - PHP opnieuw bouwen met de DirectAdmin-patches, buiten CustomBuild om
# =============================================================================
# Voor DirectAdmin-servers waarvan CustomBuild de patches uit custombuild/patches/php-X.Y/
# niet (meer) toepast: een oude CustomBuild 2.0.0 op een legacy-licentie (build-script
# zonder patch_dir_apply), of CentOS 6 waar ./build weigert. De DA-patches bevatten sinds
# 21 oktober 2026 ook de backport voor CVE-2026-109618 / CVE-2026-109619 (5.6 t/m 8.1).
# Zie README: "Eerst kijken: levert CustomBuild de backport al zelf?".
#
# Per versie doet dit script precies wat CustomBuild zou doen:
#   1. configure-regel overnemen van de geinstalleerde PHP (php -i, "Configure Command")
#   2. tarball uit custombuild/cache uitpakken (of van php.net halen)
#   3. alle patches uit custombuild/patches/php-X.Y/ op volgorde toepassen (patch -p1)
#   4. ./configure && make      (installeert NIETS)
# en daarna, als aparte stap, --install: backup, make install, php-fpm/Apache herstarten,
# controle op het backport-symbool (zend_mm_safe_error_ex) met nm.
#
# Gebruik (als root), bouwen duurt lang dus met nohup:
#   nohup bash /root/da-php-rebuild.sh 7.4 5.6 > /root/phpbuild/rebuild.log 2>&1 &
#   tail -f /root/phpbuild/rebuild.log             # wachten op "ALLES GEBOUWD"
#   bash /root/da-php-rebuild.sh --install 7.4 5.6 # installeren, herstarten, controleren
#   bash /root/da-php-rebuild.sh --check 7.4 5.6   # alleen controleren
# Backups: /root/phpXX-backup-DATUM.tar.gz (en /root/httpd.conf.bak-DATUM bij mod_php).
# Bronbomen en logs: /root/phpbuild/.
# =============================================================================
set -o pipefail
CB=/usr/local/directadmin/custombuild
WORK=/root/phpbuild
MODE=build
case "${1:-}" in
  --install) MODE=install; shift ;;
  --check)   MODE=check; shift ;;
  -h|--help|"") sed -n '2,25p' "$0"; exit 0 ;;
esac
[ "$(id -u)" = 0 ] || { echo "Draai dit als root."; exit 1; }
[ $# -gt 0 ] || { echo "Geef een of meer versies op, bijvoorbeeld: 7.4 5.6"; exit 1; }
[ -d "$CB" ] || { echo "Geen DirectAdmin CustomBuild gevonden in $CB."; exit 1; }
mkdir -p "$WORK"

# laatste officiele release per EOL-reeks, voor als de tarball niet in de cache staat
latest_of() {
  case "$1" in
    5.6) echo 5.6.40 ;; 7.0) echo 7.0.33 ;; 7.1) echo 7.1.33 ;; 7.2) echo 7.2.34 ;;
    7.3) echo 7.3.33 ;; 7.4) echo 7.4.33 ;; 8.0) echo 8.0.30 ;; *) echo "" ;;
  esac
}
php_cli() {   # $1 = 74 -> pad van de CLI-binary
  local b
  for b in /usr/local/php$1/bin/php /usr/local/php$1/bin/php$1; do [ -x "$b" ] && { echo "$b"; return 0; }; done
  return 1
}
php_mode() {  # $1 = 7.4 -> php-fpm | mod_php | suphp | fastcgi | lsphp (uit options.conf)
  awk -F= -v r="$1" '
    /^php[0-9]_release=/ { n=substr($1,4,1); rel[n]=$2 }
    /^php[0-9]_mode=/    { n=substr($1,4,1); mode[n]=$2 }
    END { for (n in rel) if (rel[n]==r) { print mode[n]; exit } }' "$CB/options.conf" 2>/dev/null
}
symbol_count() { nm -D "$1" 2>/dev/null | grep -c zend_mm_safe_error_ex; }
report() {    # $1 = 7.4
  local d=${1/./} b
  for b in /usr/local/php$d/bin/php$d /usr/local/php$d/bin/php-cgi$d /usr/local/php$d/sbin/php-fpm$d; do
    [ -x "$b" ] || continue
    echo "  $b: symbool=$(symbol_count "$b")  $("$b" -v 2>/dev/null | head -n 1)"
  done
}

build_one() {   # $1 = 7.4
  local v="$1" d=${1/./} cli conf tb full src n=0 p pl out hits
  cli=$(php_cli "$d") || { echo "[$v] geen /usr/local/php$d/bin/php gevonden; staat die versie wel op deze server?"; return 1; }
  conf=$("$cli" -i 2>/dev/null | sed -n "s/^Configure Command => *'\.\/configure' *//p")
  [ -n "$conf" ] || { echo "[$v] geen 'Configure Command' in php -i"; return 1; }
  printf '%s\n' "$conf" > "$WORK/configure-$d.txt"
  tb=$(ls -1 "$CB"/cache/php-"$v".*.tar.gz 2>/dev/null | sort -V | tail -n 1)
  if [ -z "$tb" ]; then
    full=$(latest_of "$v")
    [ -n "$full" ] || { echo "[$v] geen tarball in $CB/cache en geen bekende laatste release; zet php-$v.X.tar.gz in $CB/cache"; return 1; }
    tb="$WORK/php-$full.tar.gz"
    echo "[$v] tarball niet in de cache; ophalen van php.net: php-$full.tar.gz"
    curl -fsSL "https://www.php.net/distributions/php-$full.tar.gz" -o "$tb" || { echo "[$v] download mislukt"; return 1; }
  fi
  full=$(basename "$tb" .tar.gz); full=${full#php-}
  src="$WORK/php-$full"
  echo "[$v] bron: $tb"
  rm -rf "$src"
  tar xzf "$tb" -C "$WORK" || { echo "[$v] uitpakken mislukt"; return 1; }
  [ -d "$src" ] || { echo "[$v] map $src ontbreekt na uitpakken"; return 1; }
  if [ -d "$CB/patches/php-$v" ]; then
    for p in $(ls -1 "$CB"/patches/php-"$v"/*.patch 2>/dev/null | sort -V); do
      pl=1
      (cd "$src" && patch -p1 -f --dry-run < "$p") >/dev/null 2>&1 \
        || { (cd "$src" && patch -p0 -f --dry-run < "$p") >/dev/null 2>&1 && pl=0; }
      out=$(cd "$src" && patch -p$pl -f < "$p" 2>&1) || {
        echo "[$v] FOUT bij patch $(basename "$p"):"
        echo "$out" | grep -iE 'fail|rej|revers|can.t find' | head -n 5
        return 1
      }
      n=$((n+1))
    done
  else
    echo "[$v] LET OP: geen patchmap $CB/patches/php-$v (draai ./build update, of kopieer de map van een actuele DA-server)"
  fi
  hits=$(grep -c zend_mm_safe_error_ex "$src/Zend/zend_alloc.c" 2>/dev/null)
  echo "[$v] $n patches toegepast; CVE-2026-109618-fix in de bron: ${hits:-0} regel(s)"
  [ "${hits:-0}" -gt 0 ] || echo "[$v] LET OP: de CVE-patch zit niet in de bron; de build is dan NIET gepatcht"
  rm -f "$src/BUILD_OK"
  echo "[$v] configure + make -j$(nproc) gestart om $(date '+%H:%M:%S')"
  ( cd "$src" && sh -c "./configure $conf" > "$WORK/configure-$d.log" 2>&1 ) \
    || { echo "[$v] configure mislukt, zie $WORK/configure-$d.log:"; tail -n 5 "$WORK/configure-$d.log"; return 1; }
  ( cd "$src" && make -j"$(nproc)" > "$WORK/make-$d.log" 2>&1 ) \
    || { echo "[$v] make mislukt, zie $WORK/make-$d.log:"; grep -iE 'error' "$WORK/make-$d.log" | head -n 5; return 1; }
  touch "$src/BUILD_OK"; echo "$full" > "$WORK/built-$d.txt"
  echo "[$v] GEBOUWD om $(date '+%H:%M:%S') (php-$full)"
}

install_one() {   # $1 = 7.4
  local v="$1" d=${1/./} full src mode ts
  full=$(cat "$WORK/built-$d.txt" 2>/dev/null); src="$WORK/php-$full"
  [ -n "$full" ] && [ -f "$src/BUILD_OK" ] || { echo "[$v] nog niet (succesvol) gebouwd; eerst: bash $0 $v"; return 1; }
  mode=$(php_mode "$v")
  ts=$(date +%F-%H%M)
  tar czf "/root/php$d-backup-$ts.tar.gz" "/usr/local/php$d" 2>/dev/null && echo "[$v] backup: /root/php$d-backup-$ts.tar.gz"
  # mod_php: make install laat apxs een LoadModule-regel in httpd.conf zetten; die zetten we terug
  [ "$mode" = mod_php ] && [ -f /etc/httpd/conf/httpd.conf ] && cp -f /etc/httpd/conf/httpd.conf "/root/httpd.conf.bak-$ts"
  ( cd "$src" && make install > "$WORK/install-$d.log" 2>&1 ) \
    || { echo "[$v] make install mislukt, zie $WORK/install-$d.log:"; tail -n 5 "$WORK/install-$d.log"; return 1; }
  if [ "$mode" = mod_php ] && [ -f "/root/httpd.conf.bak-$ts" ] && ! cmp -s "/root/httpd.conf.bak-$ts" /etc/httpd/conf/httpd.conf; then
    cp -f "/root/httpd.conf.bak-$ts" /etc/httpd/conf/httpd.conf && echo "[$v] httpd.conf teruggezet (apxs had hem aangepast)"
  fi
  # zonder --program-suffix heet de fpm-binary php-fpm, terwijl DirectAdmin php-fpmXX start
  if [ -f "/usr/local/php$d/sbin/php-fpm" ] && [ -f "/usr/local/php$d/sbin/php-fpm$d" ] \
     && [ "/usr/local/php$d/sbin/php-fpm" -nt "/usr/local/php$d/sbin/php-fpm$d" ]; then
    cp -f "/usr/local/php$d/sbin/php-fpm" "/usr/local/php$d/sbin/php-fpm$d"
  fi
  case "$mode" in
    php-fpm)
      if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q "^php-fpm$d\.service"; then
        systemctl restart "php-fpm$d" && echo "[$v] php-fpm$d herstart: $(systemctl is-active "php-fpm$d")"
      else
        service "php-fpm$d" restart >/dev/null 2>&1 && echo "[$v] php-fpm$d herstart"
      fi ;;
    mod_php)
      { systemctl restart httpd 2>/dev/null || service httpd restart >/dev/null 2>&1; } && echo "[$v] Apache herstart (mod_php)" ;;
    *)
      echo "[$v] mode ${mode:-onbekend}: geen herstart nodig (suphp/cgi laadt de binary per verzoek)" ;;
  esac
  echo "[$v] geinstalleerd:"; report "$v"
}

case "$MODE" in
  build)
    for v in "$@"; do build_one "$v" || { echo "GESTOPT bij $v (eerdere versies zijn wel gebouwd)"; exit 1; }; done
    echo "ALLES GEBOUWD: $*   Nu installeren: bash $0 --install $*" ;;
  install)
    for v in "$@"; do install_one "$v" || exit 1; done
    echo "KLAAR. Controleer: bash $0 --check $*   en: php2shell-shield status" ;;
  check)
    for v in "$@"; do echo "[$v]"; report "$v"; done ;;
esac
