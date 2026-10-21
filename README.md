# php2shell-shield — serverbrede noodblokkade voor PHP2Shell (CVE-2026-109618 / CVE-2026-109619)

Eén script dat je op elke server draait (DirectAdmin, Plesk, cPanel of kaal
Apache/nginx/LiteSpeed) en dat in één keer **alle websites** op die server
afschermt, totdat PHP overal gepatcht is.

## Waarom dit werkt terwijl per-site maatregelen niet werken

Beide fouten zitten in het inlezen en opruimen van een verzoek door PHP zelf.
Dat gebeurt **vóórdat** ook maar één regel applicatiecode draait:
WordPress-logins, CSRF-checks, security-plugins, maintenance mode, `.htaccess`
met `php_flag` enz. komen allemaal te laat. De enige plek waar je zo'n verzoek
tegenhoudt vóór PHP is de **webserver** (of een WAF/proxy daarvoor).

Sinds de release van 21 oktober 2026 zijn de oorzaken officieel bekend:

- **CVE-2026-109618 (RCE via OOM corruption):** loopt PHP tijdens het inlezen
  van een verzoek tegen `memory_limit` aan, dan blijft half-geïnitialiseerde
  staat achter die bij het opruimen misbruikt wordt. Alle manieren die PHP
  beschrijft om dat af te dwingen lopen via `multipart/form-data`: chunked
  zonder Content-Length (omzeilt `post_max_size`), een onbeperkt aantal
  part-headers, lege bestandsvelden met geneste namen. Bij mod_php is RCE
  bewezen met standaardlimieten; FPM is kwetsbaar maar daar is geen volledig
  exploit gedemonstreerd.
- **CVE-2026-109619 (RCE via stale global state):** staat van een vorig
  verzoek blijft na een fatale fout (OOM, time-out) op dezelfde worker
  achter en wordt door een volgend verzoek gelezen vóór de normale
  initialisatie. Bevestigde routes: session upload-progress (multipart) en op
  PHP 8.5 `fatal_error_backtraces`.

PHP's eigen advies zegt letterlijk: blokkeer multipart aan de voorkant als de
applicatie het niet nodig heeft, zet `session.upload_progress` uit (ook na het
patchen) en op 8.5 `fatal_error_backtraces=0`. Dit script doet precies dat,
serverbreed. PHP zegt óók dat alleen updaten een volledige oplossing is: de
maatregelen dekken de gedocumenteerde routes, niet elke denkbare variant.

Het script legt daarom drie lagen over de hele server heen:

| Laag | Wat | Waar |
|------|-----|------|
| 1. Webserver | Elk verzoek met `Content-Type: multipart/...` krijgt 403, ongeacht methode, pad of site. Vertrouwde IP's (`--trust`) en een optionele hostlijst (`--scope`) vallen erbuiten. | Apache: globale `<If>`-regel met `Require all denied` (servercontext, geldt voor alle vhosts). nginx: `map` + `if ... return 403` in elk `server{}`-blok via de officiële DirectAdmin-tokens / Plesk `vhost_nginx.conf`. OpenLiteSpeed/LiteSpeed: rewrite-regel via DirectAdmin-token. |
| 2. PHP | `session.upload_progress.enabled = Off` in álle php.ini's (DirectAdmin `/usr/local/php*/lib/php.ini`, Plesk `/opt/plesk/php/*/etc/php.ini`, OS-PHP, Remi, cPanel, CloudLinux, lsphp, Plesk-paneel) plus een drop-in `99-php2shell-shield.ini` in elke `php.conf.d`/`php.d`/`conf.d` met ook `fatal_error_backtraces = 0` (PHP 8.5). Daarna worden alle PHP-FPM-diensten herladen. Dit zijn de door PHP bevestigde routes voor CVE-2026-109619; PHP zegt zelf dat dit alléén niet volstaat, daarom laag 1. Optioneel `--memory-unlimited` voor PHP's primaire maatregel tegen CVE-2026-109618 (`memory_limit = -1`, zie kanttekeningen). | overal |
| 3. Watch-service | Elk geblokkeerd verzoek wordt centraal gelogd (`/var/log/php2shell-shield/blocked.log`). Een systemd-service leest dat log en zet IP's die binnen 5 minuten op 8 of meer verschillende hosts multipart afvuren (scanner-gedrag) 1 uur in de firewall (CSF, anders ipset/iptables, anders nftables). Cloudflare-ranges, privé-adressen, de eigen server-IP's en `--trust`-adressen worden nooit gebant. De service past elke 5 minuten ook de configuratie opnieuw toe (nieuwe Plesk-domeinen krijgen de include). | `php2shell-watch.service` |

Daarnaast: ModSecurity-regels (ID 99901–99904) die het bekende exploitpatroon
(`PHP_SESSION_UPLOAD_PROGRESS`-veld, misvormde multipart-bodies) blokkeren waar
ModSecurity 2 in Apache draait, een zelftest met curl, een statusoverzicht met
patchstand per PHP-binary, en een volledige `uninstall`.

## Snel starten (per server, als root)

```bash
# 1. kijk eerst wat er zou gebeuren
bash php2shell-shield.sh install --dry-run --trust JOUW.KANTOOR.IP

# 2. echt installeren (strict = alle multipart-verzoeken blokkeren)
bash php2shell-shield.sh install --trust JOUW.KANTOOR.IP

# 3. controleren
php2shell-shield status
php2shell-shield test --probe klantdomein.nl      # leest de echte PHP-instelling via HTTP
tail -f /var/log/php2shell-shield/blocked.log
```

## Vertrouwde adressen (kantoor, OpenVPN, monitoring)

Vertrouwde adressen mogen multipart blijven sturen (uploads werken daar dus
gewoon) en worden nooit gebant. Je kunt er zoveel opgeven als je wilt, als IP
of als IP/CIDR, en de lijst is op de server zelf te beheren:

```bash
# bij install: komma-gescheiden, en --trust mag meerdere keren
php2shell-shield install --trust 203.0.113.5,10.8.0.0/24 --trust 198.51.100.0/24

# of uit een bestand (één adres per regel, # = commentaar); wordt samengevoegd in /etc/php2shell-shield/trust.txt
php2shell-shield install --trust-file /root/trust.txt

# later, zonder herinstallatie; de wijziging gaat direct live op Apache/nginx en in de watch-service
php2shell-shield trust add 10.8.0.0/24,203.0.113.7
php2shell-shield trust remove 203.0.113.7
php2shell-shield trust list
```

De lijst staat in `/etc/php2shell-shield/trust.txt` en blijft bij `uninstall`
bewaard. Geef **niet** 127.0.0.1 of het server-IP op: dan kan de zelftest de
blokkade niet meer aantonen.

**Welk adres moet erin bij OpenVPN?** Dat hangt af van het pad dat je
webverkeer neemt; de webserver ziet maar één bron-IP:

- Loopt je browserverkeer naar de sites door de tunnel (OpenVPN-server op of
  naast de VM, `redirect-gateway` of een route naar het servernetwerk), dan
  ziet de webserver het **VPN-clientsubnet**, bijvoorbeeld `10.8.0.0/24`.
- Doet de VPN-gateway NAT, dan ziet de webserver het **interne of publieke
  adres van de gateway**; neem dat ene adres op.
- Gebruik je de VPN alleen voor SSH/het paneel en bezoek je de sites via het
  internet, dan is het je **kantoor- of thuis-IP**.

Zeker weten? Verbind via de VPN, doe een upload-poging (of een `curl -F x=1`
naar een site op de server) en kijk welk bron-IP in
`/var/log/php2shell-shield/blocked.log` verschijnt; dat adres voeg je toe met
`trust add`.

**Let op bij een firewall of proxy vóór de VM's.** Staat er een reverse proxy
of load balancer die de verbinding overneemt, dan komt *al* het webverkeer
van hetzelfde interne IP. Dat adres mag je dan nooit vertrouwen (de blokkade
zou voor iedereen wegvallen); laat Apache/nginx dan eerst het echte client-IP
gebruiken (`mod_remoteip` / `real_ip_header` met `X-Forwarded-For`). Gewone
port-forwarding (DNAT) behoudt het bron-IP en is geen probleem. Interne
reeksen (10/8, 172.16/12, 192.168/16) en Cloudflare worden sowieso nooit
gebant.

## Ophalen vanaf GitHub (per server, zonder SFTP)

Repository: https://github.com/plob881/php2shell-shield

Alleen het script, rechtstreeks op de server:

```bash
curl -fsSL https://raw.githubusercontent.com/plob881/php2shell-shield/main/php2shell-shield.sh -o /root/php2shell-shield.sh && chmod 700 /root/php2shell-shield.sh && bash /root/php2shell-shield.sh install --dry-run --trust JOUW.KANTOOR.IP
```

De complete set als zip (laatste release):

```bash
curl -fsSL https://github.com/plob881/php2shell-shield/releases/latest/download/php2shell-shield.zip -o /root/php2shell-shield.zip && cd /root && unzip -o php2shell-shield.zip && bash php2shell-shield.sh install --dry-run --trust JOUW.KANTOOR.IP
```

Een nieuwere versie installeer je door dezelfde regel opnieuw te draaien met
`install` (zonder `--dry-run`); het script kopieert zichzelf dan weer naar
`/usr/local/sbin/php2shell-shield` en past de configuratie bij.

## Alle servers in één keer

Zet je servers in `servers.txt` (zie `servers.txt.voorbeeld`) en draai vanuit
deze map:

```bash
# Git Bash (Windows) / Linux / macOS
./uitrollen.sh "install --dry-run --trust JOUW.KANTOOR.IP"
./uitrollen.sh "install --trust JOUW.KANTOOR.IP"
./uitrollen.sh status
```

```powershell
# Windows PowerShell
.\uitrollen.ps1 "install --dry-run --trust JOUW.KANTOOR.IP"
.\uitrollen.ps1 "install --trust JOUW.KANTOOR.IP"
.\uitrollen.ps1 status
```

Het script gaat via ssh-stdin naar `/root/php2shell-shield.sh` (geen SFTP
nodig) en wordt daar gestart. Elke uitrol schrijft een logbestand in deze map.

## Wat breekt er in strict-mode, en wat zijn de alternatieven

Strict blokkeert elk `multipart/form-data`-verzoek, dus tijdelijk vallen uit:

- bestandsuploads (WordPress-media, plugin-/thema-zips, Roundcube-bijlagen,
  phpMyAdmin-import, productafbeeldingen in webshops);
- formulieren die `FormData` of `enctype="multipart/form-data"` gebruiken,
  ook zonder bestand: **Contact Form 7, Gravity Forms, WPForms, Fluent Forms**.

Gewone formulieren (`x-www-form-urlencoded`), logins, JSON/REST-verkeer,
WooCommerce-checkout, Elementor-opslag en alle GET-verkeer blijven werken. De
bezoeker krijgt bij een geblokkeerd verzoek een leesbare 403-melding.

Alternatieven, in oplopend risico:

| Mode / optie | Beschermt tegen | Nadeel |
|---|---|---|
| `--mode strict` (standaard) | alle door PHP gedocumenteerde aanvalsroutes (allemaal multipart) | uploads/FormData-formulieren uit |
| `--mode strict --scope BESTAND` | alleen de hosts in het bestand (incl. hun subdomeinen) | andere sites zijn open |
| `--mode monitor` | niets; logt alleen welke multipart-verzoeken er zijn | meetinstrument vooraf: hoeveel klanten raak je? |
| `--mode signature` | alleen het bekende patroon (upload-progress-veld), via php.ini + ModSecurity | tweede route blijft open; ModSecurity moet draaien |

Aanbevolen volgorde: nu overal **strict**; zodra je servers gepatcht zijn
`php2shell-shield status` draaien en de blokkade beperken tot de sites die op
een PHP-versie zonder fix draaien:

```bash
php2shell-shield eol-domains > /etc/php2shell-shield/scope.txt   # DirectAdmin/Plesk: alle sites op PHP < 8.2
php2shell-shield install --scope /etc/php2shell-shield/scope.txt --trust JOUW.KANTOOR.IP
```

## Zodra de PHP-patch beschikbaar is

De fix is op 21 oktober 2026 uitgebracht: **8.2.35, 8.3.36, 8.4.27 en
8.5.12** (dat zijn de versies die `status` standaard als "OK" beoordeelt).
Voor **PHP 7.4, 8.0 en 8.1** publiceert PHP geen release, maar wel minimale
bron-backports voor vendors die zelf bouwen:
[PHP-7.4](https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619),
[PHP-8.0](https://github.com/php/php-src/tree/PHP-8.0-CVE-2026-109618-109619),
[PHP-8.1](https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619).
De paneelpakketten lopen uren tot dagen achter op php.net.

- **DirectAdmin (CustomBuild):**
  `cd /usr/local/directadmin/custombuild && ./build update && ./build versions`
  toont zodra de nieuwe versies beschikbaar zijn; dan `./build php n`.
  CustomBuild bouwt PHP uit bron, dus ook een gepatchte 8.1 kan daar komen;
  omdat het versienummer dan gelijk blijft, kijk je in het CustomBuild-
  changelog of DirectAdmin-forum of de backport erin zit. Tot die tijd: de
  blokkade laten staan, of een tweede PHP-versie (8.3/8.4) erbij bouwen en de
  sites daarop zetten.
- **Plesk:** heeft een eigen advisory (KB 44397729587351): alle meegeleverde
  PHP-versies 7.4 t/m 8.5 zijn kwetsbaar en worden herbouwd, en het paneel zelf
  krijgt een sw-engine-hotfix (18.0.80#11 / 18.0.81#4). Installeer dus Plesk-
  updates (Tools & Settings > Updates of `plesk installer update`) én de
  herbouwde pakketten (`apt-get update && apt-get install --only-upgrade
  'plesk-php*'` / `dnf upgrade 'plesk-php*'`). Vergeet de OS-PHP
  (`php-fpm`/`php8.x-fpm`) niet.
- **Kaal Debian/Ubuntu/RHEL:** `apt`/`dnf` zodra de distributie of Sury/Remi
  levert (Remi heeft aangekondigd niet op de releasedag te leveren).

Daarna:

```bash
php2shell-shield status      # per binary: OK / ONGEPATCHT / EOL
php2shell-shield uninstall   # pas als alles OK is; php.ini-hardening blijft staan
php2shell-shield uninstall --restore-php-ini   # ook de php.ini's terugzetten
```

Zijn de officiële versienummers anders dan verwacht, geef ze dan mee:
`php2shell-shield status --fixed "8.2.35,8.3.36,8.4.27,8.5.12"`.

## Watch-service en bans

```bash
systemctl status php2shell-watch
php2shell-shield bans              # banlog
php2shell-shield unban 203.0.113.9 # IP vrijgeven (csf/ipset/nft/iptables)
```

Een IP wordt gebant als het binnen het venster (`--ban-window 300` seconden)
multipart-verzoeken stuurt naar te veel **verschillende hosts** (`--ban-hosts 8`;
op een server met minder domeinen driekwart daarvan, minimaal 3) of naar te
veel **verschillende paden** (`--ban-paths 10`, want een scanner probeert
tientallen paden op één site, een echte gebruiker steeds hetzelfde
upload- of formulierpad). `--ban-count 0` (absoluut aantal) staat uit;
`--ban-ttl 3600` is de banduur. Privé-, vertrouwde en Cloudflare-adressen
worden nooit gebant maar wel als `SKIP` in het banlog gemeld; de eigen IP's
van de server (zelftest) tellen niet mee en staan in `status` gemarkeerd.
IPv6-adressen worden gelogd maar niet gebant. Met `--no-watch` sla je de
service over.

## Wat het script precies aanraakt (en terugdraait)

Alles staat in `/etc/php2shell-shield/` (gegenereerde configs, `state.conf`,
`backups/` met een kopie van elk aangeraakt bestand, lijsten van aangemaakte en
gewijzigde bestanden). Wijzigingen in bestaande bestanden staan altijd tussen
`# >>> php2shell-shield >>>` en `# <<< php2shell-shield <<<`.

| Omgeving | Webserver-haak | Wordt herschreven met |
|---|---|---|
| DirectAdmin + Apache | `/etc/httpd/conf/extra/httpd-includes.conf` (globaal; valt terug op token `custom/cust_httpd.CUSTOM.1.pre`) | `action=rewrite&value=httpd` in de task.queue |
| DirectAdmin + nginx / nginx_apache | `/etc/nginx/nginx-includes.conf` (http) + `custom/cust_nginx.CUSTOM.post` (server) | idem |
| DirectAdmin + OpenLiteSpeed | `custom/cust_openlitespeed.CUSTOM.5.pre` (rewrite-sectie) | idem + `lswsctrl restart` |
| DirectAdmin + LiteSpeed Enterprise | `custom/cust_httpd.CUSTOM.1.pre` met rewrite-regels | idem |
| Plesk | `/etc/httpd/conf.d/zz-php2shell-shield.conf` of `/etc/apache2/conf-available/...` (Apache, globaal), `/etc/nginx/conf.d/zz-php2shell-shield.conf` (http) + `/var/www/vhosts/system/*/conf/vhost_nginx.conf` (server) | `plesk sbin httpdmng --reconfigure-all` (nieuwe domeinen later per domein) |
| cPanel | `/etc/apache2/conf.d/includes/pre_main_global.conf`, `/etc/nginx/conf.d/server-includes/` | – |
| Kaal | `conf.d`/`conf-available` (Apache), `conf.d` + include-regel na elke `server {` (nginx) | – |

Voor elke wijziging wordt `httpd -t` / `nginx -t` gedraaid; faalt dat, dan wordt
de wijziging teruggedraaid en niets herladen. `uninstall` verwijdert de haken,
de service, de firewallsets en de logrotate-regel, en laat de backups staan.

## Kanttekeningen die je moet kennen

- **Geen volledige garantie.** PHP's advisory noemt het blokkeren van multipart
  aan de voorkant expliciet als maatregel, en alle gedocumenteerde manieren om
  de fouten te triggeren lopen via multipart. Maar PHP schrijft ook dat een
  OOM "op applicatiespecifieke manieren" bereikt kan worden en dat alleen
  updaten volledig is. Dit koopt tijd; patchen of migreren blijft nodig.
- **`--memory-unlimited` is PHP's primaire configuratiemaatregel tegen
  CVE-2026-109618** (`memory_limit = -1`, administratief afgedwongen), maar op
  shared hosting haalt het de rem van het geheugengebruik per script. Gebruik
  het alleen met een cgroup- of containerlimiet als vangnet, en nooit via
  `RLIMIT_AS`/`RLIMIT_DATA` (die triggeren juist het kwetsbare pad). Bij
  FPM-pools die zelf een `php_admin_value[memory_limit]` zetten (Plesk,
  sommige DirectAdmin-templates) wint de pool; controleer met `--probe`.
- **mod_php is de gevaarlijkste SAPI** (RCE bewezen met standaardlimieten);
  `php2shell-shield scan` waarschuwt als een PHP-versie als mod_php draait en
  als de webserver `PHP_VALUE`/`PHP_ADMIN_VALUE` naar FPM doorgeeft.
- **Het Plesk-paneel zelf (poort 8443/8880) draait ook PHP** en valt buiten
  deze blokkade. Beperk die poorten in de firewall tot je eigen IP's; Plesks
  eigen "beperk administratieve toegang" zit in PHP en is dus te laat.
  DirectAdmin zelf is geen PHP; de webapps eronder (Roundcube, phpMyAdmin)
  vallen wél onder de blokkade.
- **Cloudflare:** heeft noodregels uitgerold, maar beschermt alleen sites die
  via Cloudflare lopen én alleen als het origin-IP niet rechtstreeks
  bereikbaar is. Deze blokkade werkt juist op het origin.
- **Imunify360:** ruleset 8.83+ bevat een regel voor het publieke exploit;
  update met `imunify360-agent update --force modsec-rules`.
- **Per-site overrides:** `.user.ini`/`.htaccess` kunnen upload_progress weer
  aanzetten; `php2shell-shield scan` zoekt die, plus FPM-segfaults, verdachte
  shells onder PHP en recent gewijzigde PHP-bestanden.
- **EOL-PHP (≤ 8.1)** krijgt geen fix: laat voor die sites de blokkade staan
  (`--scope`) of migreer ze.

## Bronnen

- PHP-aankondiging: https://www.php.net/archive/2026.php (20 okt 2026)
- watchTowr FAQ: https://watchtowr.com/intelligence/php-cve-2026-109618-faq/
- Mitigaties, getest: https://ma.ttias.be/php-cve-2026-109618-early-mitigation/
- Overzicht: https://www.vincentschmalbach.com/cve-2026-109618-and-cve-2026-109619-what-you-should-do-now/
- Sansec (PHP2Shell): https://sansec.io/research/php2shell
- Huntress: https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities
- Plesk-forum: https://talk.plesk.com/threads/eta-for-critical-php-security-updates-cve-2026-109618-cve-2026-109619.395516/
- DirectAdmin-docs (custom tokens): https://docs.directadmin.com/webservices/apache/customizing.html
