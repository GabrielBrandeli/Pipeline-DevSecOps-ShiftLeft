# Triagem cega do autor (subamostra de concordancia, D17)

Gerado por `analise/scripts/triagem_cega.py gerar`. Contem apenas os dados das
ferramentas e do codigo, iguais aos de `triagem-contexto.md`.

Como preencher, para cada achado:

- **Classificacao:** VP, FP, NE ou IND (PROTOCOLO-TRIAGEM, secao 3)
- **Justificativa:** uma frase
- **Evidencia:** caminho e linha do codigo, versao instalada contra a faixa
  afetada, ou requisicao e resposta HTTP

Escreva depois dos dois-pontos, na mesma linha. Limite de 10 minutos por
achado; passou disso, IND e o que ficou em aberto na justificativa.
Nao abra `triagem-ia.csv` nem converse com a IA sobre estes achados ate
terminar. Para conferir o que falta: `python analise/scripts/triagem_cega.py ler`.


## T0007 · alvo1 · semgrep · ERROR

`alvos/juice-shop/routes/search.ts:23` · aparece em 9 rodada(s)

Regra: javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection
Mensagem: Detected a sequelize statement that is tainted by user-input. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized. In order to prevent SQL injection, it is recommended to use parameterized queries or prepared statements.

```
    20 |   return (req: Request, res: Response, next: NextFunction) => {
    21 |     let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    22 |     criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
>   23 |     models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
    24 |       .then(([products]: any) => {
    25 |         const dataString = JSON.stringify(products)
    26 |         if (challengeUtils.notSolved(challenges.unionSqlInjectionChallenge)) { // vuln-code-snippet hide-start
```

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0038 · alvo1 · semgrep · WARNING

`alvos/juice-shop/data/static/codefixes/iacLeakedKeyChallenge_2.tf:159` · aparece em 9 rodada(s)

Regra: terraform.aws.security.insecure-load-balancer-tls-version.insecure-load-balancer-tls-version
Mensagem: Detected an AWS load balancer with an insecure TLS version. TLS versions less than 1.2 are considered insecure because they can be broken. To fix this, set your `ssl_policy` to `"ELBSecurityPolicy-TLS13-1-2-Res-2021-06"`, or include a default action to redirect to HTTPS.

```
   156 | resource "aws_lb_listener" "http" {
   157 |   load_balancer_arn = aws_lb.juice_shop.arn
   158 |   port              = 80
>  159 |   protocol          = "HTTP"
   160 | 
   161 |   default_action {
   162 |     type             = "forward"
```

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0051 · alvo1 · trivy-image · CRITICAL

`jsonwebtoken@0.1.0` · aparece em 9 rodada(s)

Pacote: jsonwebtoken 0.1.0
Versao corrigida: 4.2.2
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json
Titulo: nodejs-jsonwebtoken: verification step bypass with an altered token
Advisory: https://avd.aquasec.com/nvd/cve-2015-9235

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0059 · alvo1 · trivy-image · HIGH

`jws@0.2.6` · aparece em 9 rodada(s)

Pacote: jws 0.2.6
Versao corrigida: >=3.0.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/jws/package.json
Titulo: Forgeable Public/Private Tokens
Advisory: https://avd.aquasec.com/nvd/cve-2016-1000223

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0096 · alvo1 · trivy-image · HIGH

`jsonwebtoken@0.1.0` · aparece em 9 rodada(s)

Pacote: jsonwebtoken 0.1.0
Versao corrigida: >=4.2.2
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json
Titulo: Verification Bypass
Advisory:

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0120 · alvo1 · trivy-image · MEDIUM

`jsonwebtoken@0.1.0` · aparece em 9 rodada(s)

Pacote: jsonwebtoken 0.1.0
Versao corrigida: 9.0.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json
Titulo: jsonwebtoken: Insecure implementation of key retrieval function could lead to Forgeable Public/Private Tokens from RSA to HMAC
Advisory: https://avd.aquasec.com/nvd/cve-2022-23541

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0163 · alvo1 · zap · 1

`http://localhost:3000/rolldown-runtime-BoHGiXSq.js` · aparece em 8 rodada(s)

Alerta: Deprecated Feature Policy Header Set (plugin 10063, risco 1, confianca 2, CWE-16)
Requisicao: GET http://localhost:3000/rolldown-runtime-BoHGiXSq.js
Parametro: -
Ataque: -
Evidencia: Feature-Policy
Informacao adicional: -

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0166 · alvo1 · zap · 1

`http://localhost:3000` · aparece em 9 rodada(s)

Alerta: Deprecated Feature Policy Header Set (plugin 10063, risco 1, confianca 2, CWE-16)
Requisicao: GET http://localhost:3000
Parametro: -
Ataque: -
Evidencia: Feature-Policy
Informacao adicional: -

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0196 · alvo1 · zap · 1

`http://localhost:3000 [Cross-Origin-Opener-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Opener-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000
Parametro: Cross-Origin-Opener-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0200 · alvo1 · zap · 2

`http://localhost:3000/ftp/encrypt.pyc` · aparece em 3 rodada(s)

Alerta: Content Security Policy (CSP) Header Not Set (plugin 10038, risco 2, confianca 3, CWE-693)
Requisicao: GET http://localhost:3000/ftp/encrypt.pyc
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0209 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_windows_64.exe.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_windows_64.exe.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_windows_64.exe.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_windows_64.exe.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_windows_64.exe.url]

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0217 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_arm_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_arm_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_arm_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_linux_arm_64.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_arm_64.url]

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0219 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_windows_64.exe.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_windows_64.exe.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_windows_64.exe.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_windows_64.exe.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_windows_64.exe.url]

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0233 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantinebackup/juicy_malware_macos_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantinebackup/juicy_malware_macos_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantinebackup/juicy_malware_macos_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_macos_64.url] is available at [http://localhost:3000/ftp/quarantinebackup/juicy_malware_macos_64.url]

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0237 · alvo1 · zap · 2

`http://localhost:3000/assets/public/favicon_js.ico` · aparece em 2 rodada(s)

Alerta: Cross-Domain Misconfiguration (plugin 10098, risco 2, confianca 2, CWE-264)
Requisicao: GET http://localhost:3000/assets/public/favicon_js.ico
Parametro: -
Ataque: -
Evidencia: Access-Control-Allow-Origin: *
Informacao adicional: The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listin

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0253 · alvo1 · zap · 2

`http://localhost:3000/%2e/ftp/encrypt.pyc` · aparece em 9 rodada(s)

Alerta: Bypassing 403 (plugin 40038, risco 2, confianca 2, CWE-348)
Requisicao: GET http://localhost:3000/%2e/ftp/encrypt.pyc
Parametro: -
Ataque: /%2e/ftp/encrypt.pyc
Evidencia: -
Informacao adicional: http://localhost:3000/ftp/encrypt.pyc

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0256 · alvo1 · zap · 2

`http://localhost:3000/%2e/ftp/suspicious_errors.yml` · aparece em 9 rodada(s)

Alerta: Bypassing 403 (plugin 40038, risco 2, confianca 2, CWE-348)
Requisicao: GET http://localhost:3000/%2e/ftp/suspicious_errors.yml
Parametro: -
Ataque: /%2e/ftp/suspicious_errors.yml
Evidencia: -
Informacao adicional: http://localhost:3000/ftp/suspicious_errors.yml

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0275 · alvo2 · semgrep · ERROR

`alvos/uptime-kuma/extra/release/generate-changelog.mjs:278` · aparece em 9 rodada(s)

Regra: javascript.lang.security.detect-child-process.detect-child-process
Mensagem: Detected calls to child_process from a function argument `previousVersion`. This could lead to a command injection if the input is user controllable. Try to avoid calls to child_process, and if it is needed ensure user input is correctly sanitized or sandboxed.

```
   275 | export async function getPullRequestList(previousVersion, removeAuthor = false) {
   276 |     // Get the date of previousVersion in iso8601-strict format (2026-02-19T13:34:03+08:00) from git
   277 |     const previousVersionDate = childProcess
>  278 |         .execSync(`git log -1 --format=%cd --date=iso8601-strict ${previousVersion}`)
   279 |         .toString()
   280 |         .trim();
   281 | 
```

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0281 · alvo2 · semgrep · ERROR

`alvos/uptime-kuma/.github/workflows/release.yml:135` · aparece em 9 rodada(s)

Regra: yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell
Mensagem: A `run:` step pipes the output of `curl` or `wget` directly into a shell interpreter. This is the "curl | bash" install pattern — if the remote server is compromised or the URL is hijacked, an attacker can execute arbitrary code in your CI runner. Consider downloading the file first, verifying its checksum or signature, and then executing it.

```
   132 |           node-version: 24
   133 | 
   134 |       - name: Install opencode
>  135 |         run: curl -fsSL https://opencode.ai/install | bash
   136 | 
   137 |       - name: Install dependencies
   138 |         run: node extra/release/install-deps.mjs
```

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0300 · alvo2 · trivy-image · CRITICAL

`tar@7.5.11` · aparece em 9 rodada(s)

Pacote: tar 7.5.11
Versao corrigida: 7.5.19
Status na fonte: fixed
Onde esta na imagem: usr/local/lib/node_modules/npm/node_modules/tar/package.json
Titulo: tar: node-tar: Denial of Service via crafted gzip bomb
Advisory: https://avd.aquasec.com/nvd/cve-2026-59873

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0316 · alvo2 · trivy-image · HIGH

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 150.0.7871.46-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: chromium-browser: Side-channel information leakage in Safe Browsing
Advisory: https://avd.aquasec.com/nvd/cve-2026-13809

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0328 · alvo2 · trivy-image · HIGH

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 148.0.7778.215-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: angle: Insufficient validation of untrusted input in ANGLE
Advisory: https://avd.aquasec.com/nvd/cve-2026-9914

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0353 · alvo2 · trivy-image · MEDIUM

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.53-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Incorrect security UI in Payments
Advisory: https://avd.aquasec.com/nvd/cve-2026-11001

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0364 · alvo2 · trivy-image · MEDIUM

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 150.0.7871.46-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: angle: Inappropriate implementation in ANGLE
Advisory: https://avd.aquasec.com/nvd/cve-2026-13859

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0368 · alvo2 · trivy-image · MEDIUM

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 150.0.7871.46-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: chromium-browser: Out of bounds read in V8
Advisory: https://avd.aquasec.com/nvd/cve-2026-14406

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0379 · alvo2 · trivy-image · UNKNOWN

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 151.0.7922.71-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: Inappropriate implementation in Chrome for iOS in Google Chrome on iOS ...
Advisory: https://avd.aquasec.com/nvd/cve-2026-17669

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0390 · alvo2 · trivy-image · UNKNOWN

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 153.0.8010.52-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: Out of bounds write in WebGL in Google Chrome on on Android prior to 1 ...
Advisory: https://avd.aquasec.com/nvd/cve-2026-87438

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0391 · alvo2 · trivy-image · UNKNOWN

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 153.0.8010.52-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: Improper input validation in Passwords in Google Chrome prior to 153.0 ...
Advisory: https://avd.aquasec.com/nvd/cve-2026-87590

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0407 · alvo2 · zap · 1

`http://localhost:3001/sitemap.xml` · aparece em 9 rodada(s)

Alerta: Permissions Policy Header Not Set (plugin 10063, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/sitemap.xml
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---

## T0417 · alvo2 · zap · 1

`http://localhost:3001/sitemap.xml [Cross-Origin-Opener-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Opener-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/sitemap.xml
Parametro: Cross-Origin-Opener-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

**Classificacao:** 
**Justificativa:** 
**Evidencia:** 

---
