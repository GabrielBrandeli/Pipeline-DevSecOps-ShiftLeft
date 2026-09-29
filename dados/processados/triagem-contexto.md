# Contexto para a triagem

Gerado por `analise/scripts/contexto_triagem.py`. Somente dados das ferramentas e do codigo; a classificacao e do avaliador.

## T0001 · alvo1 · semgrep · ERROR

`alvos/juice-shop/routes/userProfile.ts:65` · aparece em 9 rodada(s)

Regra: javascript.lang.security.audit.code-string-concat.code-string-concat
Mensagem: Found data from an Express or Next web request flowing to `eval`. If this data is user-controllable this can lead to execution of arbitrary system commands in the context of your application process. Avoid `eval` whenever possible.

```
    62 |           if (!code) {
    63 |             throw new Error('Username is null')
    64 |           }
>   65 |           username = eval(code) // eslint-disable-line no-eval
    66 |         } catch (err) {
    67 |           username = '\\' + username
    68 |         }
```

## T0002 · alvo1 · semgrep · ERROR

`alvos/juice-shop/data/static/codefixes/dbSchemaChallenge_1.ts:5` · aparece em 9 rodada(s)

Regra: javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection
Mensagem: Detected a sequelize statement that is tainted by user-input. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized. In order to prevent SQL injection, it is recommended to use parameterized queries or prepared statements.

```
     2 |   return (req: Request, res: Response, next: NextFunction) => {
     3 |     let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
     4 |     criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
>    5 |     models.sequelize.query("SELECT * FROM Products WHERE ((name LIKE '%"+criteria+"%' OR description LIKE '%"+criteria+"%') AND deletedAt IS NULL) ORDER BY name
     6 |       .then(([products]: any) => {
     7 |         const dataString = JSON.stringify(products)
     8 |         for (let i = 0; i < products.length; i++) {
```

## T0003 · alvo1 · semgrep · ERROR

`alvos/juice-shop/data/static/codefixes/dbSchemaChallenge_3.ts:11` · aparece em 9 rodada(s)

Regra: javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection
Mensagem: Detected a sequelize statement that is tainted by user-input. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized. In order to prevent SQL injection, it is recommended to use parameterized queries or prepared statements.

```
     8 |       res.status(400).send()
     9 |       return
    10 |     }
>   11 |     models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
    12 |       .then(([products]: any) => {
    13 |         const dataString = JSON.stringify(products)
    14 |         for (let i = 0; i < products.length; i++) {
```

## T0004 · alvo1 · semgrep · ERROR

`alvos/juice-shop/data/static/codefixes/unionSqlInjectionChallenge_1.ts:6` · aparece em 9 rodada(s)

Regra: javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection
Mensagem: Detected a sequelize statement that is tainted by user-input. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized. In order to prevent SQL injection, it is recommended to use parameterized queries or prepared statements.

```
     3 |     let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
     4 |     criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
     5 |     criteria.replace(/"|'|;|and|or/i, "")
>    6 |     models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
     7 |       .then(([products]: any) => {
     8 |         const dataString = JSON.stringify(products)
     9 |         for (let i = 0; i < products.length; i++) {
```

## T0005 · alvo1 · semgrep · ERROR

`alvos/juice-shop/data/static/codefixes/unionSqlInjectionChallenge_3.ts:10` · aparece em 9 rodada(s)

Regra: javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection
Mensagem: Detected a sequelize statement that is tainted by user-input. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized. In order to prevent SQL injection, it is recommended to use parameterized queries or prepared statements.

```
     7 |       res.status(400).send()
     8 |       return
     9 |     }
>   10 |     models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
    11 |       .then(([products]: any) => {
    12 |         const dataString = JSON.stringify(products)
    13 |         for (let i = 0; i < products.length; i++) {
```

## T0006 · alvo1 · semgrep · ERROR

`alvos/juice-shop/routes/login.ts:34` · aparece em 9 rodada(s)

Regra: javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection
Mensagem: Detected a sequelize statement that is tainted by user-input. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized. In order to prevent SQL injection, it is recommended to use parameterized queries or prepared statements.

```
    31 | 
    32 |   return (req: Request, res: Response, next: NextFunction) => {
    33 |     verifyPreLoginChallenges(req) // vuln-code-snippet hide-line
>   34 |     models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt
    35 |       .then((authenticatedUser) => { // vuln-code-snippet neutral-line loginAdminChallenge loginBenderChallenge loginJimChallenge
    36 |         const user = utils.queryResultToJson(authenticatedUser)
    37 |         if (user.data?.id && user.data.totpSecret !== '') {
```

## T0007 · alvo1 · semgrep · ERROR · RETRIAGEM

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

## T0008 · alvo1 · semgrep · ERROR

`alvos/juice-shop/.github/workflows/ci.yml:359` · aparece em 9 rodada(s)

Regra: yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell
Mensagem: A `run:` step pipes the output of `curl` or `wget` directly into a shell interpreter. This is the "curl | bash" install pattern — if the remote server is compromised or the URL is hijacked, an attacker can execute arbitrary code in your CI runner. Consider downloading the file first, verifying its checksum or signature, and then executing it.

```
   356 |       - name: "Check out Git repository"
   357 |         uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 #v7.0.1
   358 |       - name: "Install Heroku CLI"
>  359 |         run: curl https://cli-assets.heroku.com/install.sh | sh
   360 |       - name: "Set Heroku app & branch for ${{ github.ref }}"
   361 |         run: |
   362 |           if [ "$GITHUB_REF" == "refs/heads/master" ]; then
```

## T0009 · alvo1 · semgrep · ERROR

`alvos/juice-shop/.github/workflows/update-challenges-ebook.yml:22` · aparece em 9 rodada(s)

Regra: yaml.github-actions.security.run-shell-injection.run-shell-injection
Mensagem: Using variable interpolation `${{...}}` with `github` context data in a `run:` step could allow an attacker to inject their own code into the runner. This would allow them to steal secrets and code. `github` context data can have arbitrary user input and should be treated as untrusted. Instead, use an intermediate environment variable with `env:` to store the data and use the environment variable in the `run:` script. Be sure to use double-quotes the environment variable, like this: "$ENVVAR".

```
    19 |         repository: juice-shop/pwning-juice-shop
    20 |         ref: ${{ github.ref_name }}
    21 |     - name: Update challenges.yml
>   22 |       run: |
    23 |         cd docs/modules/ROOT/assets/data
    24 |         rm challenges.yml
    25 |         wget https://raw.githubusercontent.com/juice-shop/juice-shop/${{ github.ref_name }}/data/static/challenges.yml
```

## T0010 · alvo1 · semgrep · ERROR

`alvos/juice-shop/.github/workflows/update-challenges-www-legacy.yml:27` · aparece em 9 rodada(s)

Regra: yaml.github-actions.security.run-shell-injection.run-shell-injection
Mensagem: Using variable interpolation `${{...}}` with `github` context data in a `run:` step could allow an attacker to inject their own code into the runner. This would allow them to steal secrets and code. `github` context data can have arbitrary user input and should be treated as untrusted. Instead, use an intermediate environment variable with `env:` to store the data and use the environment variable in the `run:` script. Be sure to use double-quotes the environment variable, like this: "$ENVVAR".

```
    24 |       with:
    25 |         path: juice-shop
    26 |     - name: Update challenges.yml
>   27 |       run: |
    28 |         if [ "${{ github.ref_name }}" = "master" ]; then
    29 |           DEST_FILE="_data/challenges.yml"
    30 |         else
```

## T0011 · alvo1 · semgrep · ERROR

`alvos/juice-shop/.github/workflows/update-challenges-www-legacy.yml:36` · aparece em 9 rodada(s)

Regra: yaml.github-actions.security.run-shell-injection.run-shell-injection
Mensagem: Using variable interpolation `${{...}}` with `github` context data in a `run:` step could allow an attacker to inject their own code into the runner. This would allow them to steal secrets and code. `github` context data can have arbitrary user input and should be treated as untrusted. Instead, use an intermediate environment variable with `env:` to store the data and use the environment variable in the `run:` script. Be sure to use double-quotes the environment variable, like this: "$ENVVAR".

```
    33 |         rm -f $DEST_FILE
    34 |         cp juice-shop/data/static/challenges.yml $DEST_FILE
    35 |     - name: Update snippets
>   36 |       run: |
    37 |         if [ "${{ github.ref_name }}" = "master" ]; then
    38 |           DEST_FILE="_data/snippets.json"
    39 |         else
```

## T0012 · alvo1 · semgrep · ERROR

`alvos/juice-shop/.github/workflows/update-challenges-www.yml:27` · aparece em 9 rodada(s)

Regra: yaml.github-actions.security.run-shell-injection.run-shell-injection
Mensagem: Using variable interpolation `${{...}}` with `github` context data in a `run:` step could allow an attacker to inject their own code into the runner. This would allow them to steal secrets and code. `github` context data can have arbitrary user input and should be treated as untrusted. Instead, use an intermediate environment variable with `env:` to store the data and use the environment variable in the `run:` script. Be sure to use double-quotes the environment variable, like this: "$ENVVAR".

```
    24 |       with:
    25 |         path: juice-shop
    26 |     - name: Update challenges.yml
>   27 |       run: |
    28 |         if [ "${{ github.ref_name }}" = "master" ]; then
    29 |           DEST_FILE="_data/challenges.yml"
    30 |         else
```

## T0013 · alvo1 · semgrep · ERROR

`alvos/juice-shop/.github/workflows/update-challenges-www.yml:36` · aparece em 9 rodada(s)

Regra: yaml.github-actions.security.run-shell-injection.run-shell-injection
Mensagem: Using variable interpolation `${{...}}` with `github` context data in a `run:` step could allow an attacker to inject their own code into the runner. This would allow them to steal secrets and code. `github` context data can have arbitrary user input and should be treated as untrusted. Instead, use an intermediate environment variable with `env:` to store the data and use the environment variable in the `run:` script. Be sure to use double-quotes the environment variable, like this: "$ENVVAR".

```
    33 |         rm -f $DEST_FILE
    34 |         cp juice-shop/data/static/challenges.yml $DEST_FILE
    35 |     - name: Update snippets
>   36 |       run: |
    37 |         if [ "${{ github.ref_name }}" = "master" ]; then
    38 |           DEST_FILE="_data/snippets.json"
    39 |         else
```

## T0014 · alvo1 · semgrep · MEDIUM

`alvos/juice-shop/.npmrc:1` · aparece em 9 rodada(s)

Regra: package_managers.npm.npm-missing-minimum-release-age.npm-missing-minimum-release-age
Mensagem: This .npmrc does not set a minimum release age or sets it too low. Newly published packages can be malicious or unstable. Add `min-release-age = 7` to wait 7 days before resolving newly published package versions. Added in: v11.10 Reference: https://github.blog/changelog/2026-02-18-npm-bulk-trusted-publishing-config-and-script-security-now-generally-available/

```
>    1 | package-lock=false
```

## T0015 · alvo1 · semgrep · MEDIUM

`alvos/juice-shop/frontend/.npmrc:1` · aparece em 9 rodada(s)

Regra: package_managers.npm.npm-missing-minimum-release-age.npm-missing-minimum-release-age
Mensagem: This .npmrc does not set a minimum release age or sets it too low. Newly published packages can be malicious or unstable. Add `min-release-age = 7` to wait 7 days before resolving newly published package versions. Added in: v11.10 Reference: https://github.blog/changelog/2026-02-18-npm-bulk-trusted-publishing-config-and-script-security-now-generally-available/

```
>    1 | package-lock=false
```

## T0016 · alvo1 · semgrep · WARNING

`alvos/juice-shop/frontend/src/app/navbar/navbar.component.html:17` · aparece em 9 rodada(s)

Regra: generic.html-templates.security.unquoted-attribute-var.unquoted-attribute-var
Mensagem: Detected a unquoted template variable as an attribute. If unquoted, a malicious actor could inject custom JavaScript handlers. To fix this, add quotes around the template expression, like this: "{{ expr }}".

```
    14 | 
    15 |     <button mat-button routerLink="/search" class="buttons nav-home-button" aria-label="Back to homepage">
    16 |       <div id="homeButton">
>   17 |         <img [src]="logoSrc" class="logo" alt={{applicationName}}>
    18 |         <span class="hide-lt-sm app-name"> {{applicationName}} </span>
    19 |       </div>
    20 |     </button>
```

## T0017 · alvo1 · semgrep · WARNING

`alvos/juice-shop/frontend/src/app/purchase-basket/purchase-basket.component.html:15` · aparece em 9 rodada(s)

Regra: generic.html-templates.security.unquoted-attribute-var.unquoted-attribute-var
Mensagem: Detected a unquoted template variable as an attribute. If unquoted, a malicious actor could inject custom JavaScript handlers. To fix this, add quotes around the template expression, like this: "{{ expr }}".

```
    12 |   <ng-container matColumnDef="image">
    13 |     <mat-header-cell *matHeaderCellDef class="header-hidden"></mat-header-cell>
    14 |     <mat-cell *matCellDef="let element" class="content-align">
>   15 |       <img [src]="'assets/public/images/products/'+element.image" alt={{element.name}}
    16 |         class="img-responsive img-thumbnail">
    17 |       </mat-cell>
    18 |       <mat-footer-cell *matFooterCellDef class="content-align"></mat-footer-cell>
```

## T0018 · alvo1 · semgrep · WARNING

`alvos/juice-shop/views/dataErasureForm.hbs:38` · aparece em 9 rodada(s)

Regra: generic.html-templates.security.unquoted-attribute-var.unquoted-attribute-var
Mensagem: Detected a unquoted template variable as an attribute. If unquoted, a malicious actor could inject custom JavaScript handlers. To fix this, add quotes around the template expression, like this: "{{ expr }}".

```
    35 |         <form action="/dataerasure" method="POST">
    36 |             <div class="form-field">
    37 |                 <label for="email">Confirm Email Address</label>
>   38 |                 <input type="email" required placeholder={{userEmail}} name="email" id="email">
    39 |             </div>
    40 |             <div class="form-field">
    41 |                 <label for="securityAnswer">Answer</label>
```

## T0019 · alvo1 · semgrep · WARNING

`alvos/juice-shop/server.ts:268` · aparece em 9 rodada(s)

Regra: javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing
Mensagem: Directory listing/indexing is enabled, which may lead to disclosure of sensitive directories and files. It is recommended to disable directory listing unless it is a public resource. If you need directory listing, ensure that sensitive files are inaccessible when querying the resource.

```
   265 |   }
   266 | 
   267 |   /* /infrastructure directory browsing */
>  268 |   app.use('/infrastructure', serveIndexMiddleware, serveIndex('infrastructure', { icons: true, view: 'details', filter: (filename) => filename !== 'README.md' }
   269 |   app.use('/infrastructure', verify.accessControlChallenges())
   270 |   app.use('/infrastructure', (req: Request, res: Response, next: NextFunction) => {
   271 |     const filePath = path.resolve('infrastructure', path.normalize(req.path).replace(/^[\\/]+/, ''))
```

## T0020 · alvo1 · semgrep · WARNING

`alvos/juice-shop/server.ts:288` · aparece em 9 rodada(s)

Regra: javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing
Mensagem: Directory listing/indexing is enabled, which may lead to disclosure of sensitive directories and files. It is recommended to disable directory listing unless it is a public resource. If you need directory listing, ensure that sensitive files are inaccessible when querying the resource.

```
   285 | 
   286 |   // vuln-code-snippet start directoryListingChallenge accessLogDisclosureChallenge
   287 |   /* /ftp directory browsing and file download */ // vuln-code-snippet neutral-line directoryListingChallenge
>  288 |   app.use('/ftp', serveIndexMiddleware, serveIndex('ftp', { icons: true })) // vuln-code-snippet vuln-line directoryListingChallenge
   289 |   app.use('/ftp(?!/quarantine)/:file', servePublicFiles()) // vuln-code-snippet vuln-line directoryListingChallenge
   290 |   app.use('/ftp/quarantine/:file', serveQuarantineFiles()) // vuln-code-snippet neutral-line directoryListingChallenge
   291 | 
```

## T0021 · alvo1 · semgrep · WARNING

`alvos/juice-shop/server.ts:292` · aparece em 9 rodada(s)

Regra: javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing
Mensagem: Directory listing/indexing is enabled, which may lead to disclosure of sensitive directories and files. It is recommended to disable directory listing unless it is a public resource. If you need directory listing, ensure that sensitive files are inaccessible when querying the resource.

```
   289 |   app.use('/ftp(?!/quarantine)/:file', servePublicFiles()) // vuln-code-snippet vuln-line directoryListingChallenge
   290 |   app.use('/ftp/quarantine/:file', serveQuarantineFiles()) // vuln-code-snippet neutral-line directoryListingChallenge
   291 | 
>  292 |   app.use('/.well-known', serveIndexMiddleware, serveIndex('.well-known', { icons: true, view: 'details' }))
   293 |   app.use('/.well-known', express.static('.well-known'))
   294 | 
   295 |   /* /encryptionkeys directory browsing */
```

## T0022 · alvo1 · semgrep · WARNING

`alvos/juice-shop/server.ts:296` · aparece em 9 rodada(s)

Regra: javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing
Mensagem: Directory listing/indexing is enabled, which may lead to disclosure of sensitive directories and files. It is recommended to disable directory listing unless it is a public resource. If you need directory listing, ensure that sensitive files are inaccessible when querying the resource.

```
   293 |   app.use('/.well-known', express.static('.well-known'))
   294 | 
   295 |   /* /encryptionkeys directory browsing */
>  296 |   app.use('/encryptionkeys', serveIndexMiddleware, serveIndex('encryptionkeys', { icons: true, view: 'details' }))
   297 |   app.use('/encryptionkeys/:file', serveKeyFiles())
   298 | 
   299 |   /* /logs directory browsing */ // vuln-code-snippet neutral-line accessLogDisclosureChallenge
```

## T0023 · alvo1 · semgrep · WARNING

`alvos/juice-shop/server.ts:300` · aparece em 9 rodada(s)

Regra: javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing
Mensagem: Directory listing/indexing is enabled, which may lead to disclosure of sensitive directories and files. It is recommended to disable directory listing unless it is a public resource. If you need directory listing, ensure that sensitive files are inaccessible when querying the resource.

```
   297 |   app.use('/encryptionkeys/:file', serveKeyFiles())
   298 | 
   299 |   /* /logs directory browsing */ // vuln-code-snippet neutral-line accessLogDisclosureChallenge
>  300 |   app.use('/support/logs', serveIndexMiddleware, serveIndex('logs', { icons: true, view: 'details' })) // vuln-code-snippet vuln-line accessLogDisclosureChallen
   301 |   app.use('/support/logs', verify.accessControlChallenges()) // vuln-code-snippet hide-line
   302 |   app.use('/support/logs/:file', serveLogFiles()) // vuln-code-snippet vuln-line accessLogDisclosureChallenge
   303 | 
```

## T0024 · alvo1 · semgrep · WARNING

`alvos/juice-shop/routes/redirect.ts:18` · aparece em 9 rodada(s)

Regra: javascript.express.security.audit.express-open-redirect.express-open-redirect
Mensagem: The application redirects to a URL specified by user-supplied input `query` that is not validated. This could redirect users to malicious locations. Consider using an allow-list approach to validate URLs, or warn users they are being redirected to a third-party website.

```
    15 |     if (security.isRedirectAllowed(toUrl)) {
    16 |       challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => { return toUrl === 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJ
    17 |       challengeUtils.solveIf(challenges.redirectChallenge, () => { return isUnintendedRedirect(toUrl) })
>   18 |       res.redirect(toUrl)
    19 |     } else {
    20 |       res.status(406)
    21 |       next(new Error('Unrecognized target URL for redirect: ' + toUrl))
```

## T0025 · alvo1 · semgrep · WARNING

`alvos/juice-shop/routes/fileServer.ts:32` · aparece em 9 rodada(s)

Regra: javascript.express.security.audit.express-res-sendfile.express-res-sendfile
Mensagem: The application processes user-input, this is passed to res.sendFile which can allow an attacker to arbitrarily read files on the system through path traversal. It is recommended to perform input validation in addition to canonicalizing the path. This allows you to validate the path against the intended directory it should be accessing.

```
    29 |       challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return file.toLowerCase() === 'acquisitions.md' })
    30 |       verifySuccessfulPoisonNullByteExploit(file)
    31 | 
>   32 |       res.sendFile(path.resolve('ftp/', file))
    33 |     } else {
    34 |       res.status(403)
    35 |       next(new Error('Only .md and .pdf files are allowed!'))
```

## T0026 · alvo1 · semgrep · WARNING

`alvos/juice-shop/routes/keyServer.ts:14` · aparece em 9 rodada(s)

Regra: javascript.express.security.audit.express-res-sendfile.express-res-sendfile
Mensagem: The application processes user-input, this is passed to res.sendFile which can allow an attacker to arbitrarily read files on the system through path traversal. It is recommended to perform input validation in addition to canonicalizing the path. This allows you to validate the path against the intended directory it should be accessing.

```
    11 |     const file = params.file
    12 | 
    13 |     if (!file.includes('/')) {
>   14 |       res.sendFile(path.resolve('encryptionkeys/', file))
    15 |     } else {
    16 |       res.status(403)
    17 |       next(new Error('File names cannot contain forward slashes!'))
```

## T0027 · alvo1 · semgrep · WARNING

`alvos/juice-shop/routes/logfileServer.ts:14` · aparece em 9 rodada(s)

Regra: javascript.express.security.audit.express-res-sendfile.express-res-sendfile
Mensagem: The application processes user-input, this is passed to res.sendFile which can allow an attacker to arbitrarily read files on the system through path traversal. It is recommended to perform input validation in addition to canonicalizing the path. This allows you to validate the path against the intended directory it should be accessing.

```
    11 |     const file = params.file
    12 | 
    13 |     if (!file.includes('/')) {
>   14 |       res.sendFile(path.resolve('logs/', file))
    15 |     } else {
    16 |       res.status(403)
    17 |       next(new Error('File names cannot contain forward slashes!'))
```

## T0028 · alvo1 · semgrep · WARNING

`alvos/juice-shop/routes/quarantineServer.ts:14` · aparece em 9 rodada(s)

Regra: javascript.express.security.audit.express-res-sendfile.express-res-sendfile
Mensagem: The application processes user-input, this is passed to res.sendFile which can allow an attacker to arbitrarily read files on the system through path traversal. It is recommended to perform input validation in addition to canonicalizing the path. This allows you to validate the path against the intended directory it should be accessing.

```
    11 |     const file = params.file
    12 | 
    13 |     if (!file.includes('/')) {
>   14 |       res.sendFile(path.resolve('ftp/quarantine/', file))
    15 |     } else {
    16 |       res.status(403)
    17 |       next(new Error('File names cannot contain forward slashes!'))
```

## T0029 · alvo1 · semgrep · WARNING

`alvos/juice-shop/routes/redirect.ts:18` · aparece em 9 rodada(s)

Regra: javascript.express.security.audit.possible-user-input-redirect.unknown-value-in-redirect
Mensagem: It looks like 'toUrl' is read from user input and it is used to as a redirect. Ensure 'toUrl' is not externally controlled, otherwise this is an open redirect.

```
    15 |     if (security.isRedirectAllowed(toUrl)) {
    16 |       challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => { return toUrl === 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJ
    17 |       challengeUtils.solveIf(challenges.redirectChallenge, () => { return isUnintendedRedirect(toUrl) })
>   18 |       res.redirect(toUrl)
    19 |     } else {
    20 |       res.status(406)
    21 |       next(new Error('Unrecognized target URL for redirect: ' + toUrl))
```

## T0030 · alvo1 · semgrep · WARNING

`alvos/juice-shop/lib/insecurity.ts:54` · aparece em 9 rodada(s)

Regra: javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret
Mensagem: A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

```
    51 | 
    52 | export const isAuthorized = () => expressJwt(({ secret: publicKey }) as any)
    53 | export const denyAll = () => expressJwt({ secret: '' + Math.random() } as any)
>   54 | export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
    55 | export const verify = (token: string) => token ? (jws.verify as ((token: string, secret: string) => boolean))(token, publicKey) : false
    56 | export const decode = (token: string) => { return jws.decode(token)?.payload }
    57 | 
```

## T0031 · alvo1 · semgrep · WARNING

`alvos/juice-shop/routes/videoHandler.ts:71` · aparece em 9 rodada(s)

Regra: javascript.lang.security.audit.unknown-value-with-script-tag.unknown-value-with-script-tag
Mensagem: Cannot determine what 'subs' is and it is used with a '<script>' tag. This could be susceptible to cross-site scripting (XSS). Ensure 'subs' is not externally controlled, or sanitize this data.

```
    68 |       const pug = (await import('pug')).default
    69 |       const fn = pug.compile(template)
    70 |       let compiledTemplate = fn()
>   71 |       compiledTemplate = compiledTemplate.replace('<script id="subtitle"></script>', '<script id="subtitle" type="text/vtt" data-label="English" data-lang="en">
    72 |       res.send(compiledTemplate)
    73 |     })
    74 |   }
```

## T0032 · alvo1 · semgrep · WARNING

`alvos/juice-shop/data/static/codefixes/iacLeakedKeyChallenge_1.tf:17` · aparece em 9 rodada(s)

Regra: terraform.aws.security.aws-subnet-has-public-ip-address.aws-subnet-has-public-ip-address
Mensagem: Resources in the AWS subnet are assigned a public IP address. Resources should not be exposed on the public internet, but should have access limited to consumers required for the function of your application. Set `map_public_ip_on_launch` to false so that resources are not publicly-accessible.

```
    14 |   }
    15 | }
    16 | 
>   17 | resource "aws_subnet" "public" {
    18 |   count                   = length(var.public_subnet_cidrs)
    19 |   vpc_id                  = aws_vpc.main.id
    20 |   cidr_block              = var.public_subnet_cidrs[count.index]
```

## T0033 · alvo1 · semgrep · WARNING

`alvos/juice-shop/data/static/codefixes/iacLeakedKeyChallenge_2.tf:17` · aparece em 9 rodada(s)

Regra: terraform.aws.security.aws-subnet-has-public-ip-address.aws-subnet-has-public-ip-address
Mensagem: Resources in the AWS subnet are assigned a public IP address. Resources should not be exposed on the public internet, but should have access limited to consumers required for the function of your application. Set `map_public_ip_on_launch` to false so that resources are not publicly-accessible.

```
    14 |   }
    15 | }
    16 | 
>   17 | resource "aws_subnet" "public" {
    18 |   count                   = length(var.public_subnet_cidrs)
    19 |   vpc_id                  = aws_vpc.main.id
    20 |   cidr_block              = var.public_subnet_cidrs[count.index]
```

## T0034 · alvo1 · semgrep · WARNING

`alvos/juice-shop/data/static/codefixes/iacLeakedKeyChallenge_3_correct.tf:17` · aparece em 9 rodada(s)

Regra: terraform.aws.security.aws-subnet-has-public-ip-address.aws-subnet-has-public-ip-address
Mensagem: Resources in the AWS subnet are assigned a public IP address. Resources should not be exposed on the public internet, but should have access limited to consumers required for the function of your application. Set `map_public_ip_on_launch` to false so that resources are not publicly-accessible.

```
    14 |   }
    15 | }
    16 | 
>   17 | resource "aws_subnet" "public" {
    18 |   count                   = length(var.public_subnet_cidrs)
    19 |   vpc_id                  = aws_vpc.main.id
    20 |   cidr_block              = var.public_subnet_cidrs[count.index]
```

## T0035 · alvo1 · semgrep · WARNING

`alvos/juice-shop/infrastructure/terraform/networking.tf:18` · aparece em 9 rodada(s)

Regra: terraform.aws.security.aws-subnet-has-public-ip-address.aws-subnet-has-public-ip-address
Mensagem: Resources in the AWS subnet are assigned a public IP address. Resources should not be exposed on the public internet, but should have access limited to consumers required for the function of your application. Set `map_public_ip_on_launch` to false so that resources are not publicly-accessible.

```
    15 |   }
    16 | }
    17 | 
>   18 | resource "aws_subnet" "public" {
    19 |   count                   = length(var.public_subnet_cidrs)
    20 |   vpc_id                  = aws_vpc.main.id
    21 |   cidr_block              = var.public_subnet_cidrs[count.index]
```

## T0036 · alvo1 · semgrep · WARNING

`alvos/juice-shop/terraform/networking.tf:18` · aparece em 9 rodada(s)

Regra: terraform.aws.security.aws-subnet-has-public-ip-address.aws-subnet-has-public-ip-address
Mensagem: Resources in the AWS subnet are assigned a public IP address. Resources should not be exposed on the public internet, but should have access limited to consumers required for the function of your application. Set `map_public_ip_on_launch` to false so that resources are not publicly-accessible.

```
    15 |   }
    16 | }
    17 | 
>   18 | resource "aws_subnet" "public" {
    19 |   count                   = length(var.public_subnet_cidrs)
    20 |   vpc_id                  = aws_vpc.main.id
    21 |   cidr_block              = var.public_subnet_cidrs[count.index]
```

## T0037 · alvo1 · semgrep · WARNING

`alvos/juice-shop/data/static/codefixes/iacLeakedKeyChallenge_1.tf:159` · aparece em 9 rodada(s)

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

## T0038 · alvo1 · semgrep · WARNING · RETRIAGEM

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

## T0039 · alvo1 · semgrep · WARNING

`alvos/juice-shop/data/static/codefixes/iacLeakedKeyChallenge_3_correct.tf:159` · aparece em 9 rodada(s)

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

## T0040 · alvo1 · semgrep · WARNING

`alvos/juice-shop/infrastructure/terraform/networking.tf:160` · aparece em 9 rodada(s)

Regra: terraform.aws.security.insecure-load-balancer-tls-version.insecure-load-balancer-tls-version
Mensagem: Detected an AWS load balancer with an insecure TLS version. TLS versions less than 1.2 are considered insecure because they can be broken. To fix this, set your `ssl_policy` to `"ELBSecurityPolicy-TLS13-1-2-Res-2021-06"`, or include a default action to redirect to HTTPS.

```
   157 | resource "aws_lb_listener" "http" {
   158 |   load_balancer_arn = aws_lb.juice_shop.arn
   159 |   port              = 80
>  160 |   protocol          = "HTTP"
   161 | 
   162 |   default_action {
   163 |     type             = "forward"
```

## T0041 · alvo1 · semgrep · WARNING

`alvos/juice-shop/terraform/networking.tf:160` · aparece em 9 rodada(s)

Regra: terraform.aws.security.insecure-load-balancer-tls-version.insecure-load-balancer-tls-version
Mensagem: Detected an AWS load balancer with an insecure TLS version. TLS versions less than 1.2 are considered insecure because they can be broken. To fix this, set your `ssl_policy` to `"ELBSecurityPolicy-TLS13-1-2-Res-2021-06"`, or include a default action to redirect to HTTPS.

```
   157 | resource "aws_lb_listener" "http" {
   158 |   load_balancer_arn = aws_lb.juice_shop.arn
   159 |   port              = 80
>  160 |   protocol          = "HTTP"
   161 | 
   162 |   default_action {
   163 |     type             = "forward"
```

## T0042 · alvo1 · semgrep · WARNING

`alvos/juice-shop/.github/workflows/ci.yml:188` · aparece em 9 rodada(s)

Regra: yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag
Mensagem: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

```
   185 |         with:
   186 |           name: api-test-lcov
   187 |       - name: "Publish coverage to Coveralls"
>  188 |         uses: coverallsapp/github-action@v2
   189 |         with:
   190 |           github-token: ${{ secrets.GITHUB_TOKEN }}
   191 |           files: frontend-lcov.info server-lcov.info api-lcov.info
```

## T0043 · alvo1 · semgrep · WARNING

`alvos/juice-shop/.github/workflows/codeql-analysis.yml:23` · aparece em 9 rodada(s)

Regra: yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag
Mensagem: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

```
    20 |     - name: Checkout repository
    21 |       uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 #v7.0.1
    22 |     - name: Initialize CodeQL
>   23 |       uses: github/codeql-action/init@v3
    24 |       with:
    25 |         languages: ${{ matrix.language }}
    26 |         queries: security-extended
```

## T0044 · alvo1 · semgrep · WARNING

`alvos/juice-shop/.github/workflows/codeql-analysis.yml:34` · aparece em 9 rodada(s)

Regra: yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag
Mensagem: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

```
    31 |           - exclude:
    32 |                id: js/missing-rate-limiting
    33 |     - name: Autobuild
>   34 |       uses: github/codeql-action/autobuild@v3
    35 |     - name: Perform CodeQL Analysis
    36 |       uses: github/codeql-action/analyze@v3
```

## T0045 · alvo1 · semgrep · WARNING

`alvos/juice-shop/.github/workflows/codeql-analysis.yml:36` · aparece em 9 rodada(s)

Regra: yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag
Mensagem: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

```
    33 |     - name: Autobuild
    34 |       uses: github/codeql-action/autobuild@v3
    35 |     - name: Perform CodeQL Analysis
>   36 |       uses: github/codeql-action/analyze@v3
```

## T0046 · alvo1 · semgrep · WARNING

`alvos/juice-shop/.github/workflows/image_actions.yml:30` · aparece em 9 rodada(s)

Regra: yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag
Mensagem: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

```
    27 |        github.event.pull_request.head.repo.full_name == github.repository)
    28 |     steps:
    29 |       - name: Checkout Branch
>   30 |         uses: actions/checkout@v6
    31 |       - name: Compress Images
    32 |         id: calibre
    33 |         uses: calibreapp/image-actions@main
```

## T0047 · alvo1 · semgrep · WARNING

`alvos/juice-shop/.github/workflows/image_actions.yml:33` · aparece em 9 rodada(s)

Regra: yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag
Mensagem: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

```
    30 |         uses: actions/checkout@v6
    31 |       - name: Compress Images
    32 |         id: calibre
>   33 |         uses: calibreapp/image-actions@main
    34 |         with:
    35 |           githubToken: ${{ secrets.GITHUB_TOKEN }}
    36 |           ignorePaths: '**/3d_keychain.jpg,**/favorite-hiking-place.png,**/5.png'
```

## T0048 · alvo1 · semgrep · WARNING

`alvos/juice-shop/.github/workflows/image_actions.yml:42` · aparece em 9 rodada(s)

Regra: yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag
Mensagem: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

```
    39 |         if: |
    40 |           github.event_name != 'pull_request' &&
    41 |           steps.calibre.outputs.markdown != ''
>   42 |         uses: peter-evans/create-pull-request@v8
    43 |         with:
    44 |           title: Auto Compress Images
    45 |           delete-branch: true
```

## T0049 · alvo1 · trivy-config · LOW

`Dockerfile:None` · aparece em 9 rodada(s)

Regra: DS-0026 (No HEALTHCHECK defined)
Arquivo: Dockerfile
Mensagem: Add HEALTHCHECK instruction in your Dockerfile
Resolucao sugerida pela ferramenta: Add HEALTHCHECK instruction in Dockerfile


## T0050 · alvo1 · trivy-config · MEDIUM

`Dockerfile:22` · aparece em 9 rodada(s)

Regra: DS-0001 (':latest' tag used)
Arquivo: Dockerfile
Mensagem: Specify a tag in the 'FROM' statement for image 'gcr.io/distroless/nodejs24-debian13'
Resolucao sugerida pela ferramenta: Add a tag to the image in the 'FROM' statement

```
   22 | FROM gcr.io/distroless/nodejs24-debian13
```

## T0051 · alvo1 · trivy-image · CRITICAL · RETRIAGEM

`jsonwebtoken@0.1.0` · aparece em 9 rodada(s)

Pacote: jsonwebtoken 0.1.0
Versao corrigida: 4.2.2
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json
Titulo: nodejs-jsonwebtoken: verification step bypass with an altered token
Advisory: https://avd.aquasec.com/nvd/cve-2015-9235

## T0052 · alvo1 · trivy-image · CRITICAL

`jsonwebtoken@0.4.0` · aparece em 9 rodada(s)

Pacote: jsonwebtoken 0.4.0
Versao corrigida: 4.2.2
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/jsonwebtoken/package.json
Titulo: nodejs-jsonwebtoken: verification step bypass with an altered token
Advisory: https://avd.aquasec.com/nvd/cve-2015-9235

## T0053 · alvo1 · trivy-image · CRITICAL

`lodash@2.4.2` · aparece em 9 rodada(s)

Pacote: lodash 2.4.2
Versao corrigida: 4.17.12
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sanitize-html/node_modules/lodash/package.json
Titulo: nodejs-lodash: prototype pollution in defaultsDeep function leading to modifying properties
Advisory: https://avd.aquasec.com/nvd/cve-2019-10744

## T0054 · alvo1 · trivy-image · CRITICAL

`crypto-js@3.3.0` · aparece em 9 rodada(s)

Pacote: crypto-js 3.3.0
Versao corrigida: 4.2.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/crypto-js/package.json
Titulo: crypto-js: PBKDF2 1,000 times weaker than specified in 1993 and 1.3M times weaker than current standard
Advisory: https://avd.aquasec.com/nvd/cve-2023-46233

## T0055 · alvo1 · trivy-image · CRITICAL

`decompress@4.2.1` · aparece em 9 rodada(s)

Pacote: decompress 4.2.1
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: juice-shop/node_modules/decompress/package.json
Titulo: decompress: @xhmikosr/decompress: Decompress: Arbitrary file read/write via crafted archive extraction
Advisory: https://avd.aquasec.com/nvd/cve-2026-53486

## T0056 · alvo1 · trivy-image · CRITICAL

`tar@6.2.1` · aparece em 9 rodada(s)

Pacote: tar 6.2.1
Versao corrigida: 7.5.19
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sqlite3/node_modules/tar/package.json
Titulo: tar: node-tar: Denial of Service via crafted gzip bomb
Advisory: https://avd.aquasec.com/nvd/cve-2026-59873

## T0057 · alvo1 · trivy-image · CRITICAL

`crypto-js@3.3.0` · aparece em 9 rodada(s)

Pacote: crypto-js 3.3.0
Versao corrigida: 4.0.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/crypto-js/package.json
Titulo: crypto-js: crypto-js: Insufficient Entropy in Cryptographic Secret Generation via Vulnerable CryptoJS Dependency Chain
Advisory: https://avd.aquasec.com/nvd/cve-2026-71851

## T0058 · alvo1 · trivy-image · CRITICAL

`marsdb@0.6.11` · aparece em 9 rodada(s)

Pacote: marsdb 0.6.11
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: juice-shop/node_modules/marsdb/package.json
Titulo: Command Injection in marsdb
Advisory: https://github.com/advisories/GHSA-5mrr-rgp6-x4gr

## T0059 · alvo1 · trivy-image · HIGH · RETRIAGEM

`jws@0.2.6` · aparece em 9 rodada(s)

Pacote: jws 0.2.6
Versao corrigida: >=3.0.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/jws/package.json
Titulo: Forgeable Public/Private Tokens
Advisory: https://avd.aquasec.com/nvd/cve-2016-1000223

## T0060 · alvo1 · trivy-image · HIGH

`moment@2.0.0` · aparece em 9 rodada(s)

Pacote: moment 2.0.0
Versao corrigida: 2.19.3
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/express-jwt/node_modules/moment/package.json
Titulo: nodejs-moment: Regular expression denial of service
Advisory: https://avd.aquasec.com/nvd/cve-2017-18214

## T0061 · alvo1 · trivy-image · HIGH

`lodash@2.4.2` · aparece em 9 rodada(s)

Pacote: lodash 2.4.2
Versao corrigida: >=4.17.11
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sanitize-html/node_modules/lodash/package.json
Titulo: lodash: Prototype pollution in utilities function
Advisory: https://avd.aquasec.com/nvd/cve-2018-16487

## T0062 · alvo1 · trivy-image · HIGH

`express-jwt@0.1.3` · aparece em 9 rodada(s)

Pacote: express-jwt 0.1.3
Versao corrigida: 6.0.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/express-jwt/package.json
Titulo: Authorization bypass in express-jwt
Advisory: https://avd.aquasec.com/nvd/cve-2020-15084

## T0063 · alvo1 · trivy-image · HIGH

`lodash@2.4.2` · aparece em 9 rodada(s)

Pacote: lodash 2.4.2
Versao corrigida: 4.17.21
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sanitize-html/node_modules/lodash/package.json
Titulo: nodejs-lodash: command injection via template
Advisory: https://avd.aquasec.com/nvd/cve-2021-23337

## T0064 · alvo1 · trivy-image · HIGH

`jsonwebtoken@0.1.0` · aparece em 9 rodada(s)

Pacote: jsonwebtoken 0.1.0
Versao corrigida: 9.0.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json
Titulo: jsonwebtoken: Unrestricted key type could lead to legacy keys usagen
Advisory: https://avd.aquasec.com/nvd/cve-2022-23539

## T0065 · alvo1 · trivy-image · HIGH

`jsonwebtoken@0.4.0` · aparece em 9 rodada(s)

Pacote: jsonwebtoken 0.4.0
Versao corrigida: 9.0.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/jsonwebtoken/package.json
Titulo: jsonwebtoken: Unrestricted key type could lead to legacy keys usagen
Advisory: https://avd.aquasec.com/nvd/cve-2022-23539

## T0066 · alvo1 · trivy-image · HIGH

`moment@2.0.0` · aparece em 9 rodada(s)

Pacote: moment 2.0.0
Versao corrigida: 2.29.2
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/express-jwt/node_modules/moment/package.json
Titulo: Moment.js: Path traversal  in moment.locale
Advisory: https://avd.aquasec.com/nvd/cve-2022-24785

## T0067 · alvo1 · trivy-image · HIGH

`http-cache-semantics@3.8.1` · aparece em 9 rodada(s)

Pacote: http-cache-semantics 3.8.1
Versao corrigida: 4.1.1
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/http-cache-semantics/package.json
Titulo: http-cache-semantics: Regular Expression Denial of Service (ReDoS) vulnerability
Advisory: https://avd.aquasec.com/nvd/cve-2022-25881

## T0068 · alvo1 · trivy-image · HIGH

`sanitize-html@1.4.2` · aparece em 9 rodada(s)

Pacote: sanitize-html 1.4.2
Versao corrigida: 2.7.1
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sanitize-html/package.json
Titulo: sanitize-html: insecure global regular expression replacement logic may lead to ReDoS
Advisory: https://avd.aquasec.com/nvd/cve-2022-25887

## T0069 · alvo1 · trivy-image · HIGH

`ws@7.4.6` · aparece em 9 rodada(s)

Pacote: ws 7.4.6
Versao corrigida: 5.2.4, 6.2.3, 7.5.10, 8.17.1
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/ws/package.json
Titulo: nodejs-ws: denial of service when handling a request with many HTTP headers
Advisory: https://avd.aquasec.com/nvd/cve-2024-37890

## T0070 · alvo1 · trivy-image · HIGH

`multer@1.4.5-lts.2` · aparece em 9 rodada(s)

Pacote: multer 1.4.5-lts.2
Versao corrigida: 2.0.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/multer/package.json
Titulo: Multer vulnerable to Denial of Service via memory leaks from unclosed streams
Advisory: https://avd.aquasec.com/nvd/cve-2025-47935

## T0071 · alvo1 · trivy-image · HIGH

`multer@1.4.5-lts.2` · aparece em 9 rodada(s)

Pacote: multer 1.4.5-lts.2
Versao corrigida: 2.0.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/multer/package.json
Titulo: Multer vulnerable to Denial of Service from maliciously crafted requests
Advisory: https://avd.aquasec.com/nvd/cve-2025-47944

## T0072 · alvo1 · trivy-image · HIGH

`multer@1.4.5-lts.2` · aparece em 9 rodada(s)

Pacote: multer 1.4.5-lts.2
Versao corrigida: 2.0.1
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/multer/package.json
Titulo: multer: Multer vulnerable to Denial of Service via unhandled exception
Advisory: https://avd.aquasec.com/nvd/cve-2025-48997

## T0073 · alvo1 · trivy-image · HIGH

`jws@0.2.6` · aparece em 9 rodada(s)

Pacote: jws 0.2.6
Versao corrigida: 3.2.3, 4.0.1
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/jws/package.json
Titulo: node-jws: auth0/node-jws: Improper signature verification in HS256 algorithm
Advisory: https://avd.aquasec.com/nvd/cve-2025-65945

## T0074 · alvo1 · trivy-image · HIGH

`multer@1.4.5-lts.2` · aparece em 9 rodada(s)

Pacote: multer 1.4.5-lts.2
Versao corrigida: 2.0.2
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/multer/package.json
Titulo: multer: Multer Denial of Service
Advisory: https://avd.aquasec.com/nvd/cve-2025-7338

## T0075 · alvo1 · trivy-image · HIGH

`multer@1.4.5-lts.2` · aparece em 9 rodada(s)

Pacote: multer 1.4.5-lts.2
Versao corrigida: 2.1.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/multer/package.json
Titulo: multer: Multer: Denial of Service via dropped file upload connections
Advisory: https://avd.aquasec.com/nvd/cve-2026-2359

## T0076 · alvo1 · trivy-image · HIGH

`tar@6.2.1` · aparece em 9 rodada(s)

Pacote: tar 6.2.1
Versao corrigida: 7.5.3
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sqlite3/node_modules/tar/package.json
Titulo: node-tar: tar: node-tar: Arbitrary file overwrite and symlink poisoning via unsanitized linkpaths in archives
Advisory: https://avd.aquasec.com/nvd/cve-2026-23745

## T0077 · alvo1 · trivy-image · HIGH

`tar@6.2.1` · aparece em 9 rodada(s)

Pacote: tar 6.2.1
Versao corrigida: 7.5.4
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sqlite3/node_modules/tar/package.json
Titulo: node-tar: tar: node-tar: Arbitrary file overwrite via Unicode path collision race condition
Advisory: https://avd.aquasec.com/nvd/cve-2026-23950

## T0078 · alvo1 · trivy-image · HIGH

`tar@6.2.1` · aparece em 9 rodada(s)

Pacote: tar 6.2.1
Versao corrigida: 7.5.7
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sqlite3/node_modules/tar/package.json
Titulo: node-tar: tar: node-tar: Arbitrary file creation via path traversal bypass in hardlink security check
Advisory: https://avd.aquasec.com/nvd/cve-2026-24842

## T0079 · alvo1 · trivy-image · HIGH

`tar@6.2.1` · aparece em 9 rodada(s)

Pacote: tar 6.2.1
Versao corrigida: 7.5.8
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sqlite3/node_modules/tar/package.json
Titulo: node-tar: node-tar: Arbitrary file read/write via malicious archive hardlink creation
Advisory: https://avd.aquasec.com/nvd/cve-2026-26960

## T0080 · alvo1 · trivy-image · HIGH

`minimatch@3.0.5` · aparece em 9 rodada(s)

Pacote: minimatch 3.0.5
Versao corrigida: 10.2.1, 9.0.6, 8.0.5, 7.4.7, 6.2.1, 5.1.7, 4.2.4, 3.1.3
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/replace/node_modules/minimatch/package.json
Titulo: minimatch: minimatch: Denial of Service via specially crafted glob patterns
Advisory: https://avd.aquasec.com/nvd/cve-2026-26996

## T0081 · alvo1 · trivy-image · HIGH

`minimatch@3.0.5` · aparece em 9 rodada(s)

Pacote: minimatch 3.0.5
Versao corrigida: 10.2.3, 9.0.7, 8.0.6, 7.4.8, 6.2.2, 5.1.8, 4.2.5, 3.1.3
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/replace/node_modules/minimatch/package.json
Titulo: minimatch: minimatch: Denial of Service due to unbounded recursive backtracking via crafted glob patterns
Advisory: https://avd.aquasec.com/nvd/cve-2026-27903

## T0082 · alvo1 · trivy-image · HIGH

`minimatch@3.0.5` · aparece em 9 rodada(s)

Pacote: minimatch 3.0.5
Versao corrigida: 10.2.3, 9.0.7, 8.0.6, 7.4.8, 6.2.2, 5.1.8, 4.2.5, 3.1.4
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/replace/node_modules/minimatch/package.json
Titulo: minimatch: Minimatch: Denial of Service via catastrophic backtracking in glob expressions
Advisory: https://avd.aquasec.com/nvd/cve-2026-27904

## T0083 · alvo1 · trivy-image · HIGH

`tar@6.2.1` · aparece em 9 rodada(s)

Pacote: tar 6.2.1
Versao corrigida: 7.5.10
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sqlite3/node_modules/tar/package.json
Titulo: node-tar: hardlink path traversal via drive-relative linkpath
Advisory: https://avd.aquasec.com/nvd/cve-2026-29786

## T0084 · alvo1 · trivy-image · HIGH

`tar@6.2.1` · aparece em 9 rodada(s)

Pacote: tar 6.2.1
Versao corrigida: 7.5.11
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sqlite3/node_modules/tar/package.json
Titulo: tar: tar: File overwrite via drive-relative symlink traversal
Advisory: https://avd.aquasec.com/nvd/cve-2026-31802

## T0085 · alvo1 · trivy-image · HIGH

`multer@1.4.5-lts.2` · aparece em 9 rodada(s)

Pacote: multer 1.4.5-lts.2
Versao corrigida: 2.1.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/multer/package.json
Titulo: multer: Multer: Denial of Service via malformed requests
Advisory: https://avd.aquasec.com/nvd/cve-2026-3304

## T0086 · alvo1 · trivy-image · HIGH

`socket.io-parser@4.0.5` · aparece em 9 rodada(s)

Pacote: socket.io-parser 4.0.5
Versao corrigida: 3.3.5, 3.4.4, 4.2.6
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/socket.io-parser/package.json
Titulo: socket.io: Socket.IO: Denial of Service due to excessive buffering of specially crafted packets
Advisory: https://avd.aquasec.com/nvd/cve-2026-33151

## T0087 · alvo1 · trivy-image · HIGH

`multer@1.4.5-lts.2` · aparece em 9 rodada(s)

Pacote: multer 1.4.5-lts.2
Versao corrigida: 2.1.1
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/multer/package.json
Titulo: multer: Multer: Denial of Service via malformed requests
Advisory: https://avd.aquasec.com/nvd/cve-2026-3520

## T0088 · alvo1 · trivy-image · HIGH

`ws@7.4.6` · aparece em 9 rodada(s)

Pacote: ws 7.4.6
Versao corrigida: 5.2.5, 6.2.4, 7.5.11, 8.21.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/ws/package.json
Titulo: ws: ws: Denial of Service via memory exhaustion from small WebSocket fragments
Advisory: https://avd.aquasec.com/nvd/cve-2026-48779

## T0089 · alvo1 · trivy-image · HIGH

`multer@1.4.5-lts.2` · aparece em 9 rodada(s)

Pacote: multer 1.4.5-lts.2
Versao corrigida: 2.2.0, 3.0.0-alpha.2
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/multer/package.json
Titulo: multer: Multer: Denial of Service via deeply nested field names in multipart form data
Advisory: https://avd.aquasec.com/nvd/cve-2026-5079

## T0090 · alvo1 · trivy-image · HIGH

`engine.io@4.1.2` · aparece em 9 rodada(s)

Pacote: engine.io 4.1.2
Versao corrigida: 6.6.7
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/engine.io/package.json
Titulo: socket.io: engine.io: Socket.IO: Denial of Service via invalid binary POST requests
Advisory: https://avd.aquasec.com/nvd/cve-2026-59725

## T0091 · alvo1 · trivy-image · HIGH

`tar@6.2.1` · aparece em 9 rodada(s)

Pacote: tar 6.2.1
Versao corrigida: 7.5.18
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sqlite3/node_modules/tar/package.json
Titulo: tar: Node-tar: Denial of Service via malformed tar archive header
Advisory: https://avd.aquasec.com/nvd/cve-2026-59874

## T0092 · alvo1 · trivy-image · HIGH

`socket.io-parser@4.0.5` · aparece em 9 rodada(s)

Pacote: socket.io-parser 4.0.5
Versao corrigida: 4.2.7, 3.4.5, 3.3.6
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/socket.io-parser/package.json
Titulo: socket.io-parser: Socket.IO: Denial of Service via memory exhaustion from crafted packets
Advisory: https://avd.aquasec.com/nvd/cve-2026-69185

## T0093 · alvo1 · trivy-image · HIGH

`tar@6.2.1` · aparece em 9 rodada(s)

Pacote: tar 6.2.1
Versao corrigida: 7.5.21
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sqlite3/node_modules/tar/package.json
Titulo: tar: node-tar: Denial of Service via crafted long-path tar archive
Advisory: https://avd.aquasec.com/nvd/cve-2026-73566

## T0094 · alvo1 · trivy-image · HIGH

`multer@1.4.5-lts.2` · aparece em 9 rodada(s)

Pacote: multer 1.4.5-lts.2
Versao corrigida: 2.3.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/multer/package.json
Titulo: multer: Multer: Denial of Service via crafted multipart field names
Advisory: https://avd.aquasec.com/nvd/cve-2026-77078

## T0095 · alvo1 · trivy-image · HIGH

`multer@1.4.5-lts.2` · aparece em 9 rodada(s)

Pacote: multer 1.4.5-lts.2
Versao corrigida: 2.3.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/multer/package.json
Titulo: multer: Multer: Denial of Service via oversized array index in field names
Advisory: https://avd.aquasec.com/nvd/cve-2026-82333

## T0096 · alvo1 · trivy-image · HIGH · RETRIAGEM

`jsonwebtoken@0.1.0` · aparece em 9 rodada(s)

Pacote: jsonwebtoken 0.1.0
Versao corrigida: >=4.2.2
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json
Titulo: Verification Bypass
Advisory: 

## T0097 · alvo1 · trivy-image · HIGH

`jsonwebtoken@0.4.0` · aparece em 9 rodada(s)

Pacote: jsonwebtoken 0.4.0
Versao corrigida: >=4.2.2
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/jsonwebtoken/package.json
Titulo: Verification Bypass
Advisory: 

## T0098 · alvo1 · trivy-image · HIGH

`base64url@0.0.6` · aparece em 9 rodada(s)

Pacote: base64url 0.0.6
Versao corrigida: >=3.0.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/base64url/package.json
Titulo: Out-of-bounds Read
Advisory: https://hackerone.com/reports/321687

## T0099 · alvo1 · trivy-image · LOW

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

Pacote: libc6 2.41-12+deb13u4
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-juiceshop:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 13.7)
Titulo: glibc: glob implementation can cause excessive CPU and memory consumption due to crafted glob expressions
Advisory: https://avd.aquasec.com/nvd/cve-2010-4756

## T0100 · alvo1 · trivy-image · LOW

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

Pacote: libc6 2.41-12+deb13u4
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-juiceshop:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 13.7)
Titulo: glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c
Advisory: https://avd.aquasec.com/nvd/cve-2018-20796

## T0101 · alvo1 · trivy-image · LOW

`lodash@2.4.2` · aparece em 9 rodada(s)

Pacote: lodash 2.4.2
Versao corrigida: >=4.17.5
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sanitize-html/node_modules/lodash/package.json
Titulo: lodash: Prototype pollution in utilities function
Advisory: https://avd.aquasec.com/nvd/cve-2018-3721

## T0102 · alvo1 · trivy-image · LOW

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

Pacote: libc6 2.41-12+deb13u4
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-juiceshop:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 13.7)
Titulo: glibc: stack guard protection bypass
Advisory: https://avd.aquasec.com/nvd/cve-2019-1010022

## T0103 · alvo1 · trivy-image · LOW

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

Pacote: libc6 2.41-12+deb13u4
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-juiceshop:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 13.7)
Titulo: glibc: running ldd on malicious ELF leads to code execution because of wrong size computation
Advisory: https://avd.aquasec.com/nvd/cve-2019-1010023

## T0104 · alvo1 · trivy-image · LOW

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

Pacote: libc6 2.41-12+deb13u4
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-juiceshop:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 13.7)
Titulo: glibc: ASLR bypass using cache of thread stack and heap
Advisory: https://avd.aquasec.com/nvd/cve-2019-1010024

## T0105 · alvo1 · trivy-image · LOW

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

Pacote: libc6 2.41-12+deb13u4
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-juiceshop:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 13.7)
Titulo: glibc: information disclosure of heap addresses of pthread_created thread
Advisory: https://avd.aquasec.com/nvd/cve-2019-1010025

## T0106 · alvo1 · trivy-image · LOW

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

Pacote: libc6 2.41-12+deb13u4
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-juiceshop:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 13.7)
Titulo: glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c
Advisory: https://avd.aquasec.com/nvd/cve-2019-9192

## T0107 · alvo1 · trivy-image · LOW

`cookie@0.4.2` · aparece em 9 rodada(s)

Pacote: cookie 0.4.2
Versao corrigida: 0.7.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/engine.io/node_modules/cookie/package.json
Titulo: cookie: cookie accepts cookie name, path, and domain with out of bounds characters
Advisory: https://avd.aquasec.com/nvd/cve-2024-47764

## T0108 · alvo1 · trivy-image · LOW

`messageformat@2.3.0` · aparece em 9 rodada(s)

Pacote: messageformat 2.3.0
Versao corrigida: 3.0.0-beta.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/messageformat/package.json
Titulo: messageformat has a prototype pollution vulnerability
Advisory: https://avd.aquasec.com/nvd/cve-2025-57349

## T0109 · alvo1 · trivy-image · LOW

`@tootallnate/once@1.1.2` · aparece em 9 rodada(s)

Pacote: @tootallnate/once 1.1.2
Versao corrigida: 3.0.1, 2.0.1
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/@tootallnate/once/package.json
Titulo: @tootallnate/once: @tootallnate/once: Denial of Service due to incorrect control flow scoping with AbortSignal
Advisory: https://avd.aquasec.com/nvd/cve-2026-3449

## T0110 · alvo1 · trivy-image · LOW

`multer@1.4.5-lts.2` · aparece em 9 rodada(s)

Pacote: multer 1.4.5-lts.2
Versao corrigida: 2.3.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/multer/package.json
Titulo: multer: Multer: File size limit bypass via asynchronous file filter race condition
Advisory: https://avd.aquasec.com/nvd/cve-2026-77063

## T0111 · alvo1 · trivy-image · MEDIUM

`sanitize-html@1.4.2` · aparece em 9 rodada(s)

Pacote: sanitize-html 1.4.2
Versao corrigida: >=1.4.3
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sanitize-html/package.json
Titulo: XSS - Sanitization not applied recursively
Advisory: https://avd.aquasec.com/nvd/cve-2016-1000237

## T0112 · alvo1 · trivy-image · MEDIUM

`moment@2.0.0` · aparece em 9 rodada(s)

Pacote: moment 2.0.0
Versao corrigida: >=2.11.2
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/express-jwt/node_modules/moment/package.json
Titulo: moment.js: regular expression denial of service
Advisory: https://avd.aquasec.com/nvd/cve-2016-4055

## T0113 · alvo1 · trivy-image · MEDIUM

`sanitize-html@1.4.2` · aparece em 9 rodada(s)

Pacote: sanitize-html 1.4.2
Versao corrigida: 1.11.4
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sanitize-html/package.json
Titulo: Cross-Site Scripting in sanitize-html
Advisory: https://avd.aquasec.com/nvd/cve-2017-16016

## T0114 · alvo1 · trivy-image · MEDIUM

`sanitize-html@1.4.2` · aparece em 9 rodada(s)

Pacote: sanitize-html 1.4.2
Versao corrigida: 2.0.0-beta
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sanitize-html/package.json
Titulo: sanitize-html: sanitize-html cross site scripting
Advisory: https://avd.aquasec.com/nvd/cve-2019-25225

## T0115 · alvo1 · trivy-image · MEDIUM

`notevil@1.3.3` · aparece em 9 rodada(s)

Pacote: notevil 1.3.3
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: juice-shop/node_modules/notevil/package.json
Titulo: Sandbox escape in notevil and argencoders-notevil
Advisory: https://avd.aquasec.com/nvd/cve-2021-23771

## T0116 · alvo1 · trivy-image · MEDIUM

`sanitize-html@1.4.2` · aparece em 9 rodada(s)

Pacote: sanitize-html 1.4.2
Versao corrigida: 2.3.1
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sanitize-html/package.json
Titulo: sanitize-html: improper handling of internationalized domain name (IDN) can lead to bypass hostname whitelist validation
Advisory: https://avd.aquasec.com/nvd/cve-2021-26539

## T0117 · alvo1 · trivy-image · MEDIUM

`sanitize-html@1.4.2` · aparece em 9 rodada(s)

Pacote: sanitize-html 1.4.2
Versao corrigida: 2.3.2
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sanitize-html/package.json
Titulo: sanitize-html: improper validation of hostnames set by the "allowedIframeHostnames" option can lead to bypass hostname whitelist for iframe element
Advisory: https://avd.aquasec.com/nvd/cve-2021-26540

## T0118 · alvo1 · trivy-image · MEDIUM

`jsonwebtoken@0.1.0` · aparece em 9 rodada(s)

Pacote: jsonwebtoken 0.1.0
Versao corrigida: 9.0.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json
Titulo: jsonwebtoken: Insecure default algorithm in jwt.verify() could lead to signature validation bypass
Advisory: https://avd.aquasec.com/nvd/cve-2022-23540

## T0119 · alvo1 · trivy-image · MEDIUM

`jsonwebtoken@0.4.0` · aparece em 9 rodada(s)

Pacote: jsonwebtoken 0.4.0
Versao corrigida: 9.0.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/jsonwebtoken/package.json
Titulo: jsonwebtoken: Insecure default algorithm in jwt.verify() could lead to signature validation bypass
Advisory: https://avd.aquasec.com/nvd/cve-2022-23540

## T0120 · alvo1 · trivy-image · MEDIUM · RETRIAGEM

`jsonwebtoken@0.1.0` · aparece em 9 rodada(s)

Pacote: jsonwebtoken 0.1.0
Versao corrigida: 9.0.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json
Titulo: jsonwebtoken: Insecure implementation of key retrieval function could lead to Forgeable Public/Private Tokens from RSA to HMAC
Advisory: https://avd.aquasec.com/nvd/cve-2022-23541

## T0121 · alvo1 · trivy-image · MEDIUM

`jsonwebtoken@0.4.0` · aparece em 9 rodada(s)

Pacote: jsonwebtoken 0.4.0
Versao corrigida: 9.0.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/jsonwebtoken/package.json
Titulo: jsonwebtoken: Insecure implementation of key retrieval function could lead to Forgeable Public/Private Tokens from RSA to HMAC
Advisory: https://avd.aquasec.com/nvd/cve-2022-23541

## T0122 · alvo1 · trivy-image · MEDIUM

`got@8.3.2` · aparece em 9 rodada(s)

Pacote: got 8.3.2
Versao corrigida: 12.1.0, 11.8.5
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/got/package.json
Titulo: nodejs-got: missing verification of requested URLs allows redirects to UNIX sockets
Advisory: https://avd.aquasec.com/nvd/cve-2022-33987

## T0123 · alvo1 · trivy-image · MEDIUM

`engine.io@4.1.2` · aparece em 9 rodada(s)

Pacote: engine.io 4.1.2
Versao corrigida: 3.6.1, 6.2.1
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/engine.io/package.json
Titulo: engine.io: Specially crafted HTTP request can trigger an uncaught exception
Advisory: https://avd.aquasec.com/nvd/cve-2022-41940

## T0124 · alvo1 · trivy-image · MEDIUM

`socket.io-parser@4.0.5` · aparece em 9 rodada(s)

Pacote: socket.io-parser 4.0.5
Versao corrigida: 4.2.3, 3.4.3, 3.3.4
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/socket.io-parser/package.json
Titulo: socket.io parser is a socket.io encoder and decoder written in JavaScr ...
Advisory: https://avd.aquasec.com/nvd/cve-2023-32695

## T0125 · alvo1 · trivy-image · MEDIUM

`sanitize-html@1.4.2` · aparece em 9 rodada(s)

Pacote: sanitize-html 1.4.2
Versao corrigida: 2.12.1
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sanitize-html/package.json
Titulo: sanitize-html: Information Exposure when used on the backend
Advisory: https://avd.aquasec.com/nvd/cve-2024-21501

## T0126 · alvo1 · trivy-image · MEDIUM

`socket.io@3.1.2` · aparece em 9 rodada(s)

Pacote: socket.io 3.1.2
Versao corrigida: 2.5.1, 4.6.2
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/socket.io/package.json
Titulo: socket.io: Unhandled 'error' event
Advisory: https://avd.aquasec.com/nvd/cve-2024-38355

## T0127 · alvo1 · trivy-image · MEDIUM

`decompress@4.2.1` · aparece em 9 rodada(s)

Pacote: decompress 4.2.1
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: juice-shop/node_modules/decompress/package.json
Titulo: decompress: Decompress: Arbitrary file write leading to remote code execution via crafted ZIP archive (Zip Slip)
Advisory: https://avd.aquasec.com/nvd/cve-2026-10732

## T0128 · alvo1 · trivy-image · MEDIUM

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

Pacote: libc6 2.41-12+deb13u4
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-juiceshop:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 13.7)
Titulo: glibc: glibc: Heap buffer overflow via attacker-controlled fopen mode string
Advisory: https://avd.aquasec.com/nvd/cve-2026-18374

## T0129 · alvo1 · trivy-image · MEDIUM

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

Pacote: libc6 2.41-12+deb13u4
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-juiceshop:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 13.7)
Titulo: glibc: Buffer Overflow in strfmon right-justification padding
Advisory: https://avd.aquasec.com/nvd/cve-2026-19499

## T0130 · alvo1 · trivy-image · MEDIUM

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

Pacote: libc6 2.41-12+deb13u4
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-juiceshop:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 13.7)
Titulo: glibc: Fix out-of-bounds array write in tdelete
Advisory: https://avd.aquasec.com/nvd/cve-2026-19542

## T0131 · alvo1 · trivy-image · MEDIUM

`zlib1g@1:1.3.dfsg+really1.3.1-1+b1` · aparece em 9 rodada(s)

Pacote: zlib1g 1:1.3.dfsg+really1.3.1-1+b1
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-juiceshop:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 13.7)
Titulo: zlib: zlib: Denial of Service via infinite loop in CRC32 combine functions
Advisory: https://avd.aquasec.com/nvd/cve-2026-27171

## T0132 · alvo1 · trivy-image · MEDIUM

`lodash@2.4.2` · aparece em 9 rodada(s)

Pacote: lodash 2.4.2
Versao corrigida: 4.18.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sanitize-html/node_modules/lodash/package.json
Titulo: lodash: Lodash: Prototype pollution allows deletion of built-in prototype properties via array path bypass
Advisory: https://avd.aquasec.com/nvd/cve-2026-2950

## T0133 · alvo1 · trivy-image · MEDIUM

`file-type@16.5.4` · aparece em 9 rodada(s)

Pacote: file-type 16.5.4
Versao corrigida: 21.3.1
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/file-type/package.json
Titulo: file-type: file-type: Denial of Service due to infinite loop in ASF file parsing
Advisory: https://avd.aquasec.com/nvd/cve-2026-31808

## T0134 · alvo1 · trivy-image · MEDIUM

`decompress@4.2.1` · aparece em 9 rodada(s)

Pacote: decompress 4.2.1
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: juice-shop/node_modules/decompress/package.json
Titulo: decompress: Decompress: File disclosure and corruption via arbitrary hardlink creation
Advisory: https://avd.aquasec.com/nvd/cve-2026-39243

## T0135 · alvo1 · trivy-image · MEDIUM

`uuid@8.3.2` · aparece em 9 rodada(s)

Pacote: uuid 8.3.2
Versao corrigida: 11.1.1, 12.0.1, 13.0.1
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/uuid/package.json
Titulo: uuid: uuid: Out-of-bounds write vulnerability impacts data integrity and confidentiality
Advisory: https://avd.aquasec.com/nvd/cve-2026-41907

## T0136 · alvo1 · trivy-image · MEDIUM

`decode-uri-component@0.2.2` · aparece em 9 rodada(s)

Pacote: decode-uri-component 0.2.2
Versao corrigida: 0.5.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/decode-uri-component/package.json
Titulo: decode-uri-component: decode-uri-component: Denial of Service via crafted input
Advisory: https://avd.aquasec.com/nvd/cve-2026-45822

## T0137 · alvo1 · trivy-image · MEDIUM

`tar@6.2.1` · aparece em 9 rodada(s)

Pacote: tar 6.2.1
Versao corrigida: 7.5.16
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sqlite3/node_modules/tar/package.json
Titulo: node-tar: node-tar: File smuggling due to inconsistent tar archive parsing
Advisory: https://avd.aquasec.com/nvd/cve-2026-53655

## T0138 · alvo1 · trivy-image · MEDIUM

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

Pacote: libc6 2.41-12+deb13u4
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-juiceshop:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 13.7)
Titulo: glibc: glibc: Out-of-bounds write via TSIG record processing
Advisory: https://avd.aquasec.com/nvd/cve-2026-5435

## T0139 · alvo1 · trivy-image · MEDIUM

`tar@6.2.1` · aparece em 9 rodada(s)

Pacote: tar 6.2.1
Versao corrigida: 7.5.18
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sqlite3/node_modules/tar/package.json
Titulo: node-tar: node-tar: Denial of Service due to incorrect PAX path handling
Advisory: https://avd.aquasec.com/nvd/cve-2026-59871

## T0140 · alvo1 · trivy-image · MEDIUM

`tar@6.2.1` · aparece em 9 rodada(s)

Pacote: tar 6.2.1
Versao corrigida: 7.5.17
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sqlite3/node_modules/tar/package.json
Titulo: node-tar: node-tar: Denial of Service via crafted archive with NUL bytes in metadata
Advisory: https://avd.aquasec.com/nvd/cve-2026-59875

## T0141 · alvo1 · trivy-image · MEDIUM

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

Pacote: libc6 2.41-12+deb13u4
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-juiceshop:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 13.7)
Titulo: glibc: glibc: Application crash or uninitialized memory read via crafted DNS response
Advisory: https://avd.aquasec.com/nvd/cve-2026-6238

## T0142 · alvo1 · trivy-image · MEDIUM

`sanitize-html@1.4.2` · aparece em 9 rodada(s)

Pacote: sanitize-html 1.4.2
Versao corrigida: 2.17.6
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sanitize-html/package.json
Titulo: ApostropheCMS: Mutation-XSS / allowedTags bypass via literal `</textarea/>` solidus close
Advisory: https://avd.aquasec.com/nvd/cve-2026-63670

## T0143 · alvo1 · trivy-image · MEDIUM

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

Pacote: libc6 2.41-12+deb13u4
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-juiceshop:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 13.7)
Titulo: glibc: glibc: Process abort due to invalid memory in wordexp
Advisory: https://avd.aquasec.com/nvd/cve-2026-6368

## T0144 · alvo1 · trivy-image · MEDIUM

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

Pacote: libc6 2.41-12+deb13u4
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-juiceshop:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 13.7)
Titulo: glibc: Glibc: Denial of Service via stack exhaustion during tilde expansion
Advisory: https://avd.aquasec.com/nvd/cve-2026-6791

## T0145 · alvo1 · trivy-image · MEDIUM

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

Pacote: libc6 2.41-12+deb13u4
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-juiceshop:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 13.7)
Titulo: glibc: Non-progress DoS in SHIFT_JISX0213 -&gt
Advisory: https://avd.aquasec.com/nvd/cve-2026-77117

## T0146 · alvo1 · trivy-image · MEDIUM

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

Pacote: libc6 2.41-12+deb13u4
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-juiceshop:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 13.7)
Titulo: glibc: Non-progress DoS in EUC_JISX0213 -> UCS-4 conversion state
Advisory: https://avd.aquasec.com/nvd/cve-2026-80489

## T0147 · alvo1 · trivy-image · MEDIUM

`zlib1g@1:1.3.dfsg+really1.3.1-1+b1` · aparece em 9 rodada(s)

Pacote: zlib1g 1:1.3.dfsg+really1.3.1-1+b1
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-juiceshop:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 13.7)
Titulo: zlib versions 1.3.1.2 through 1.3.2 contain a heap buffer overflow vul ...
Advisory: https://avd.aquasec.com/nvd/cve-2026-85091

## T0148 · alvo1 · trivy-image · MEDIUM

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

Pacote: libc6 2.41-12+deb13u4
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-juiceshop:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 13.7)
Titulo: glibc: glibc DNS stub resolver: Denial of Service via long search domain in configuration
Advisory: https://avd.aquasec.com/nvd/cve-2026-8674

## T0149 · alvo1 · trivy-image · MEDIUM

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

Pacote: libc6 2.41-12+deb13u4
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-juiceshop:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 13.7)
Titulo: glibc: glibc: Privilege escalation and arbitrary code execution via TOCTOU race condition in dynamic loader
Advisory: https://avd.aquasec.com/nvd/cve-2026-86805

## T0150 · alvo1 · trivy-image · MEDIUM

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

Pacote: libc6 2.41-12+deb13u4
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-juiceshop:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 13.7)
Titulo: glibc: nscd stack overflow leads to degraded DNS resolution
Advisory: https://avd.aquasec.com/nvd/cve-2026-89092

## T0151 · alvo1 · trivy-image · MEDIUM

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

Pacote: libc6 2.41-12+deb13u4
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-juiceshop:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 13.7)
Titulo: glibc: glibc: Local attacker can cause denial of service and information disclosure via stack-based buffer overflow.
Advisory: https://avd.aquasec.com/nvd/cve-2026-95818

## T0152 · alvo1 · trivy-image · MEDIUM

`base64url@0.0.6` · aparece em 9 rodada(s)

Pacote: base64url 0.0.6
Versao corrigida: 3.0.0
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/base64url/package.json
Titulo: Out-of-bounds Read in base64url
Advisory: https://github.com/advisories/GHSA-rvg8-pwq2-xj7q

## T0153 · alvo1 · trivy-image · MEDIUM

`sanitize-html@1.4.2` · aparece em 9 rodada(s)

Pacote: sanitize-html 1.4.2
Versao corrigida: >=1.11.4
Status na fonte: fixed
Onde esta na imagem: juice-shop/node_modules/sanitize-html/package.json
Titulo: Cross Site Scripting
Advisory: 

## T0154 · alvo1 · trivy-secret · HIGH

`infrastructure/terraform/networking.tf:171` · aparece em 9 rodada(s)

Regra: private-key (Asymmetric Private Key)
Arquivo: infrastructure/terraform/networking.tf

```
  171 | ----BEGIN RSA PRIVATE KEY-----**********************************************************************************************************************************
```

## T0155 · alvo1 · trivy-secret · HIGH

`lib/insecurity.ts:21` · aparece em 9 rodada(s)

Regra: private-key (Asymmetric Private Key)
Arquivo: lib/insecurity.ts

```
   21 | ----BEGIN RSA PRIVATE KEY-----**********************************************************************************************************************************
```

## T0156 · alvo1 · trivy-secret · HIGH

`terraform/networking.tf:171` · aparece em 9 rodada(s)

Regra: private-key (Asymmetric Private Key)
Arquivo: terraform/networking.tf

```
  171 | ----BEGIN RSA PRIVATE KEY-----**********************************************************************************************************************************
```

## T0157 · alvo1 · trivy-secret · MEDIUM

`frontend/src/app/app.guard.spec.ts:46` · aparece em 9 rodada(s)

Regra: jwt-token (JWT token)
Arquivo: frontend/src/app/app.guard.spec.ts

```
   46 | ocalStorage.setItem('token', '**********************************************************************************************************************************
```

## T0158 · alvo1 · trivy-secret · MEDIUM

`frontend/src/app/last-login-ip/last-login-ip.component.spec.ts:72` · aparece em 9 rodada(s)

Regra: jwt-token (JWT token)
Arquivo: frontend/src/app/last-login-ip/last-login-ip.component.spec.ts

```
   72 | ocalStorage.setItem('token', '*******************************************************************************************************************************')
```

## T0159 · alvo1 · zap · 1

`http://localhost:3000/socket.io/ [x-content-type-options]` · aparece em 9 rodada(s)

Alerta: X-Content-Type-Options Header Missing (plugin 10021, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/socket.io/?EIO=4&transport=polling&t=Q3fdxwN&sid=Z6B3l7O9IlHHNF_qAAAA
Parametro: x-content-type-options
Ataque: -
Evidencia: -
Informacao adicional: This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.

## T0160 · alvo1 · zap · 1

`http://localhost:3000/api/Hints/` · aparece em 1 rodada(s)

Alerta: Information Disclosure - Debug Error Messages (plugin 10023, risco 1, confianca 2, CWE-1295)
Requisicao: GET http://localhost:3000/api/Hints/
Parametro: -
Ataque: -
Evidencia: Internal Server Error
Informacao adicional: -

## T0161 · alvo1 · zap · 1

`http://localhost:3000/chunk-DBPdFzgj.js` · aparece em 9 rodada(s)

Alerta: Deprecated Feature Policy Header Set (plugin 10063, risco 1, confianca 2, CWE-16)
Requisicao: GET http://localhost:3000/chunk-DBPdFzgj.js
Parametro: -
Ataque: -
Evidencia: Feature-Policy
Informacao adicional: -

## T0162 · alvo1 · zap · 1

`http://localhost:3000/polyfills.js` · aparece em 1 rodada(s)

Alerta: Deprecated Feature Policy Header Set (plugin 10063, risco 1, confianca 2, CWE-16)
Requisicao: GET http://localhost:3000/polyfills.js
Parametro: -
Ataque: -
Evidencia: Feature-Policy
Informacao adicional: -

## T0163 · alvo1 · zap · 1 · RETRIAGEM

`http://localhost:3000/rolldown-runtime-BoHGiXSq.js` · aparece em 8 rodada(s)

Alerta: Deprecated Feature Policy Header Set (plugin 10063, risco 1, confianca 2, CWE-16)
Requisicao: GET http://localhost:3000/rolldown-runtime-BoHGiXSq.js
Parametro: -
Ataque: -
Evidencia: Feature-Policy
Informacao adicional: -

## T0164 · alvo1 · zap · 1

`http://localhost:3000/sitemap.xml` · aparece em 9 rodada(s)

Alerta: Deprecated Feature Policy Header Set (plugin 10063, risco 1, confianca 2, CWE-16)
Requisicao: GET http://localhost:3000/sitemap.xml
Parametro: -
Ataque: -
Evidencia: Feature-Policy
Informacao adicional: -

## T0165 · alvo1 · zap · 1

`http://localhost:3000/` · aparece em 9 rodada(s)

Alerta: Deprecated Feature Policy Header Set (plugin 10063, risco 1, confianca 2, CWE-16)
Requisicao: GET http://localhost:3000/
Parametro: -
Ataque: -
Evidencia: Feature-Policy
Informacao adicional: -

## T0166 · alvo1 · zap · 1 · RETRIAGEM

`http://localhost:3000` · aparece em 9 rodada(s)

Alerta: Deprecated Feature Policy Header Set (plugin 10063, risco 1, confianca 2, CWE-16)
Requisicao: GET http://localhost:3000
Parametro: -
Ataque: -
Evidencia: Feature-Policy
Informacao adicional: -

## T0167 · alvo1 · zap · 1

`http://localhost:3000/sitemap.xml` · aparece em 9 rodada(s)

Alerta: Timestamp Disclosure - Unix (plugin 10096, risco 1, confianca 1, CWE-497)
Requisicao: GET http://localhost:3000/sitemap.xml
Parametro: -
Ataque: -
Evidencia: 1666666667
Informacao adicional: 1666666667, which evaluates to: 2022-10-25 02:57:47.

## T0168 · alvo1 · zap · 1

`http://localhost:3000/styles.css` · aparece em 1 rodada(s)

Alerta: Timestamp Disclosure - Unix (plugin 10096, risco 1, confianca 1, CWE-497)
Requisicao: GET http://localhost:3000/styles.css
Parametro: -
Ataque: -
Evidencia: 1528301887
Informacao adicional: 1528301887, which evaluates to: 2018-06-06 16:18:07.

## T0169 · alvo1 · zap · 1

`http://localhost:3000/` · aparece em 9 rodada(s)

Alerta: Timestamp Disclosure - Unix (plugin 10096, risco 1, confianca 1, CWE-497)
Requisicao: GET http://localhost:3000/
Parametro: -
Ataque: -
Evidencia: 1666666667
Informacao adicional: 1666666667, which evaluates to: 2022-10-25 02:57:47.

## T0170 · alvo1 · zap · 1

`http://localhost:3000` · aparece em 8 rodada(s)

Alerta: Timestamp Disclosure - Unix (plugin 10096, risco 1, confianca 1, CWE-497)
Requisicao: GET http://localhost:3000
Parametro: -
Ataque: -
Evidencia: 1666666667
Informacao adicional: 1666666667, which evaluates to: 2022-10-25 02:57:47.

## T0171 · alvo1 · zap · 1

`http://localhost:3000/about.component-CX4sLWGx.js` · aparece em 9 rodada(s)

Alerta: Dangerous JS Functions (plugin 10110, risco 1, confianca 1, CWE-749)
Requisicao: GET http://localhost:3000/about.component-CX4sLWGx.js
Parametro: -
Ataque: -
Evidencia: bypassSecurityTrustHtml(
Informacao adicional: -

## T0172 · alvo1 · zap · 1

`http://localhost:3000/chunk-Op3DlR8e.js` · aparece em 9 rodada(s)

Alerta: Dangerous JS Functions (plugin 10110, risco 1, confianca 1, CWE-749)
Requisicao: GET http://localhost:3000/chunk-Op3DlR8e.js
Parametro: -
Ataque: -
Evidencia: bypassSecurityTrustHtml(
Informacao adicional: -

## T0173 · alvo1 · zap · 1

`http://localhost:3000/main.js` · aparece em 9 rodada(s)

Alerta: Dangerous JS Functions (plugin 10110, risco 1, confianca 1, CWE-749)
Requisicao: GET http://localhost:3000/main.js
Parametro: -
Ataque: -
Evidencia: bypassSecurityTrustHtml(
Informacao adicional: -

## T0174 · alvo1 · zap · 1

`http://localhost:3000/ftp/coupons_2013.md.bak` · aparece em 9 rodada(s)

Alerta: Full Path Disclosure (plugin 110009, risco 1, confianca 1, CWE-209)
Requisicao: GET http://localhost:3000/ftp/coupons_2013.md.bak
Parametro: -
Ataque: -
Evidencia: /lib/
Informacao adicional: -

## T0175 · alvo1 · zap · 1

`http://localhost:3000/ftp/eastere.gg` · aparece em 9 rodada(s)

Alerta: Full Path Disclosure (plugin 110009, risco 1, confianca 1, CWE-209)
Requisicao: GET http://localhost:3000/ftp/eastere.gg
Parametro: -
Ataque: -
Evidencia: /lib/
Informacao adicional: -

## T0176 · alvo1 · zap · 1

`http://localhost:3000/ftp/encrypt.pyc` · aparece em 9 rodada(s)

Alerta: Full Path Disclosure (plugin 110009, risco 1, confianca 1, CWE-209)
Requisicao: GET http://localhost:3000/ftp/encrypt.pyc
Parametro: -
Ataque: -
Evidencia: /lib/
Informacao adicional: -

## T0177 · alvo1 · zap · 1

`http://localhost:3000/ftp/package-lock.json.bak` · aparece em 9 rodada(s)

Alerta: Full Path Disclosure (plugin 110009, risco 1, confianca 1, CWE-209)
Requisicao: GET http://localhost:3000/ftp/package-lock.json.bak
Parametro: -
Ataque: -
Evidencia: /lib/
Informacao adicional: -

## T0178 · alvo1 · zap · 1

`http://localhost:3000/ftp/package.json.bak` · aparece em 9 rodada(s)

Alerta: Full Path Disclosure (plugin 110009, risco 1, confianca 1, CWE-209)
Requisicao: GET http://localhost:3000/ftp/package.json.bak
Parametro: -
Ataque: -
Evidencia: /lib/
Informacao adicional: -

## T0179 · alvo1 · zap · 1

`http://localhost:3000/ftp/suspicious_errors.yml` · aparece em 9 rodada(s)

Alerta: Full Path Disclosure (plugin 110009, risco 1, confianca 1, CWE-209)
Requisicao: GET http://localhost:3000/ftp/suspicious_errors.yml
Parametro: -
Ataque: -
Evidencia: /lib/
Informacao adicional: -

## T0180 · alvo1 · zap · 1

`http://localhost:3000/#/login [email]` · aparece em 1 rodada(s)

Alerta: Information Disclosure - Sensitive Information in Browser localStorage (plugin 120001, risco 1, confianca 2, CWE-359)
Requisicao: GET http://localhost:3000/#/login
Parametro: email
Ataque: -
Evidencia: -
Informacao adicional: The following data (key=value) was set which matches the pattern for email addresses: email=zaproxy@example.com
Note that alerts will only be raised once for each URL + key.

## T0181 · alvo1 · zap · 1

`http://localhost:3000/rest/admin/application-configuration` · aparece em 9 rodada(s)

Alerta: Private IP Disclosure (plugin 2, risco 1, confianca 2, CWE-497)
Requisicao: GET http://localhost:3000/rest/admin/application-configuration
Parametro: -
Ataque: -
Evidencia: 192.168.99.100:3000
Informacao adicional: 192.168.99.100:3000
192.168.99.100:4200


## T0182 · alvo1 · zap · 1

`http://localhost:3000/api/Complaints [message]` · aparece em 1 rodada(s)

Alerta: Cross Site Scripting Weakness (Persistent in JSON Response) (plugin 40014, risco 1, confianca 1, CWE-79)
Requisicao: GET http://localhost:3000/api/Complaints
Parametro: message
Ataque: <script>alert(1);</script>
Evidencia: -
Informacao adicional: Raised with LOW confidence as the Content-Type is not HTML.

## T0183 · alvo1 · zap · 1

`http://localhost:3000/ftp [Cross-Origin-Embedder-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Embedder-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/ftp
Parametro: Cross-Origin-Embedder-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0184 · alvo1 · zap · 1

`http://localhost:3000/ftp [Cross-Origin-Opener-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Opener-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/ftp
Parametro: Cross-Origin-Opener-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0185 · alvo1 · zap · 1

`http://localhost:3000/juice-shop/build/routes/fileServer.js:68:18 [Cross-Origin-Embedder-Policy]` · aparece em 7 rodada(s)

Alerta: Cross-Origin-Embedder-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/juice-shop/build/routes/fileServer.js:68:18
Parametro: Cross-Origin-Embedder-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0186 · alvo1 · zap · 1

`http://localhost:3000/juice-shop/build/routes/fileServer.js:68:18 [Cross-Origin-Opener-Policy]` · aparece em 7 rodada(s)

Alerta: Cross-Origin-Opener-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/juice-shop/build/routes/fileServer.js:68:18
Parametro: Cross-Origin-Opener-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0187 · alvo1 · zap · 1

`http://localhost:3000/juice-shop/node_modules/express/lib/router/index.js:286:9 [Cross-Origin-Embedder-Policy]` · aparece em 1 rodada(s)

Alerta: Cross-Origin-Embedder-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/juice-shop/node_modules/express/lib/router/index.js:286:9
Parametro: Cross-Origin-Embedder-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0188 · alvo1 · zap · 1

`http://localhost:3000/juice-shop/node_modules/express/lib/router/index.js:286:9 [Cross-Origin-Opener-Policy]` · aparece em 1 rodada(s)

Alerta: Cross-Origin-Opener-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/juice-shop/node_modules/express/lib/router/index.js:286:9
Parametro: Cross-Origin-Opener-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0189 · alvo1 · zap · 1

`http://localhost:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5 [Cross-Origin-Embedder-Policy]` · aparece em 1 rodada(s)

Alerta: Cross-Origin-Embedder-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5
Parametro: Cross-Origin-Embedder-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0190 · alvo1 · zap · 1

`http://localhost:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5 [Cross-Origin-Opener-Policy]` · aparece em 1 rodada(s)

Alerta: Cross-Origin-Opener-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5
Parametro: Cross-Origin-Opener-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0191 · alvo1 · zap · 1

`http://localhost:3000/sitemap.xml [Cross-Origin-Embedder-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Embedder-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/sitemap.xml
Parametro: Cross-Origin-Embedder-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0192 · alvo1 · zap · 1

`http://localhost:3000/sitemap.xml [Cross-Origin-Opener-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Opener-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/sitemap.xml
Parametro: Cross-Origin-Opener-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0193 · alvo1 · zap · 1

`http://localhost:3000/ [Cross-Origin-Embedder-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Embedder-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/
Parametro: Cross-Origin-Embedder-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0194 · alvo1 · zap · 1

`http://localhost:3000/ [Cross-Origin-Opener-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Opener-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/
Parametro: Cross-Origin-Opener-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0195 · alvo1 · zap · 1

`http://localhost:3000 [Cross-Origin-Embedder-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Embedder-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000
Parametro: Cross-Origin-Embedder-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0196 · alvo1 · zap · 1 · RETRIAGEM

`http://localhost:3000 [Cross-Origin-Opener-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Opener-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000
Parametro: Cross-Origin-Opener-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0197 · alvo1 · zap · 2

`http://localhost:3000/socket.io/ [x-frame-options]` · aparece em 9 rodada(s)

Alerta: Missing Anti-clickjacking Header (plugin 10020, risco 2, confianca 2, CWE-1021)
Requisicao: POST http://localhost:3000/socket.io/?EIO=4&transport=polling&t=Q3fdxwJ&sid=Z6B3l7O9IlHHNF_qAAAA
Parametro: x-frame-options
Ataque: -
Evidencia: -
Informacao adicional: -

## T0198 · alvo1 · zap · 2

`http://localhost:3000/ftp/coupons_2013.md.bak` · aparece em 4 rodada(s)

Alerta: Content Security Policy (CSP) Header Not Set (plugin 10038, risco 2, confianca 3, CWE-693)
Requisicao: GET http://localhost:3000/ftp/coupons_2013.md.bak
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

## T0199 · alvo1 · zap · 2

`http://localhost:3000/ftp/eastere.gg` · aparece em 4 rodada(s)

Alerta: Content Security Policy (CSP) Header Not Set (plugin 10038, risco 2, confianca 3, CWE-693)
Requisicao: GET http://localhost:3000/ftp/eastere.gg
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

## T0200 · alvo1 · zap · 2 · RETRIAGEM

`http://localhost:3000/ftp/encrypt.pyc` · aparece em 3 rodada(s)

Alerta: Content Security Policy (CSP) Header Not Set (plugin 10038, risco 2, confianca 3, CWE-693)
Requisicao: GET http://localhost:3000/ftp/encrypt.pyc
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

## T0201 · alvo1 · zap · 2

`http://localhost:3000/ftp/package-lock.json.bak` · aparece em 1 rodada(s)

Alerta: Content Security Policy (CSP) Header Not Set (plugin 10038, risco 2, confianca 3, CWE-693)
Requisicao: GET http://localhost:3000/ftp/package-lock.json.bak
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

## T0202 · alvo1 · zap · 2

`http://localhost:3000/ftp` · aparece em 6 rodada(s)

Alerta: Content Security Policy (CSP) Header Not Set (plugin 10038, risco 2, confianca 3, CWE-693)
Requisicao: GET http://localhost:3000/ftp
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

## T0203 · alvo1 · zap · 2

`http://localhost:3000/sitemap.xml` · aparece em 9 rodada(s)

Alerta: Content Security Policy (CSP) Header Not Set (plugin 10038, risco 2, confianca 3, CWE-693)
Requisicao: GET http://localhost:3000/sitemap.xml
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

## T0204 · alvo1 · zap · 2

`http://localhost:3000/` · aparece em 9 rodada(s)

Alerta: Content Security Policy (CSP) Header Not Set (plugin 10038, risco 2, confianca 3, CWE-693)
Requisicao: GET http://localhost:3000/
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

## T0205 · alvo1 · zap · 2

`http://localhost:3000` · aparece em 9 rodada(s)

Alerta: Content Security Policy (CSP) Header Not Set (plugin 10038, risco 2, confianca 3, CWE-693)
Requisicao: GET http://localhost:3000
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

## T0206 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_amd_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_amd_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_amd_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_linux_amd_64.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_amd_64.url]

## T0207 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_arm_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_arm_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_arm_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_linux_arm_64.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_arm_64.url]

## T0208 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_macos_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_macos_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_macos_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_macos_64.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_macos_64.url]

## T0209 · alvo1 · zap · 2 · RETRIAGEM

`http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_windows_64.exe.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_windows_64.exe.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_windows_64.exe.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_windows_64.exe.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_windows_64.exe.url]

## T0210 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)]

## T0211 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_amd_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_amd_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_amd_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_linux_amd_64.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_amd_64.url]

## T0212 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_arm_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_arm_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_arm_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_linux_arm_64.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_arm_64.url]

## T0213 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_macos_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_macos_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_macos_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_macos_64.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_macos_64.url]

## T0214 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_windows_64.exe.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_windows_64.exe.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_windows_64.exe.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_windows_64.exe.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_windows_64.exe.url]

## T0215 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)]

## T0216 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_amd_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_amd_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_amd_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_linux_amd_64.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_amd_64.url]

## T0217 · alvo1 · zap · 2 · RETRIAGEM

`http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_arm_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_arm_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_arm_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_linux_arm_64.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_arm_64.url]

## T0218 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_macos_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_macos_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_macos_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_macos_64.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_macos_64.url]

## T0219 · alvo1 · zap · 2 · RETRIAGEM

`http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_windows_64.exe.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_windows_64.exe.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_windows_64.exe.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_windows_64.exe.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_windows_64.exe.url]

## T0220 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine%20-%20Copy` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy]

## T0221 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine.backup` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine.backup
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine.backup
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine.backup]

## T0222 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine.bac` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine.bac
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine.bac
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine.bac]

## T0223 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine.bak` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine.bak
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine.bak
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine.bak]

## T0224 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine.jar` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine.jar
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine.jar
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine.jar]

## T0225 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine.log` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine.log
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine.log
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine.log]

## T0226 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine.old` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine.old
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine.old
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine.old]

## T0227 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine.swp` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine.swp
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine.swp
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine.swp]

## T0228 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine.tar` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine.tar
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine.tar
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine.tar]

## T0229 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine.zip` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine.zip
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine.zip
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine.zip]

## T0230 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine.~bk` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine.~bk
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine.~bk
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine.~bk]

## T0231 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantinebackup/juicy_malware_linux_amd_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantinebackup/juicy_malware_linux_amd_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantinebackup/juicy_malware_linux_amd_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_linux_amd_64.url] is available at [http://localhost:3000/ftp/quarantinebackup/juicy_malware_linux_amd_64.url]

## T0232 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantinebackup/juicy_malware_linux_arm_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantinebackup/juicy_malware_linux_arm_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantinebackup/juicy_malware_linux_arm_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_linux_arm_64.url] is available at [http://localhost:3000/ftp/quarantinebackup/juicy_malware_linux_arm_64.url]

## T0233 · alvo1 · zap · 2 · RETRIAGEM

`http://localhost:3000/ftp/quarantinebackup/juicy_malware_macos_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantinebackup/juicy_malware_macos_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantinebackup/juicy_malware_macos_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_macos_64.url] is available at [http://localhost:3000/ftp/quarantinebackup/juicy_malware_macos_64.url]

## T0234 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantinebackup/juicy_malware_windows_64.exe.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantinebackup/juicy_malware_windows_64.exe.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantinebackup/juicy_malware_windows_64.exe.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_windows_64.exe.url] is available at [http://localhost:3000/ftp/quarantinebackup/juicy_malware_windows_64.exe.url]

## T0235 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantinebackup` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantinebackup
Parametro: -
Ataque: http://localhost:3000/ftp/quarantinebackup
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantinebackup]

## T0236 · alvo1 · zap · 2

`http://localhost:3000/ftp/quarantine~` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine~
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine~
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine~]

## T0237 · alvo1 · zap · 2 · RETRIAGEM

`http://localhost:3000/assets/public/favicon_js.ico` · aparece em 2 rodada(s)

Alerta: Cross-Domain Misconfiguration (plugin 10098, risco 2, confianca 2, CWE-264)
Requisicao: GET http://localhost:3000/assets/public/favicon_js.ico
Parametro: -
Ataque: -
Evidencia: Access-Control-Allow-Origin: *
Informacao adicional: The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listin

## T0238 · alvo1 · zap · 2

`http://localhost:3000/chunk-DBPdFzgj.js` · aparece em 2 rodada(s)

Alerta: Cross-Domain Misconfiguration (plugin 10098, risco 2, confianca 2, CWE-264)
Requisicao: GET http://localhost:3000/chunk-DBPdFzgj.js
Parametro: -
Ataque: -
Evidencia: Access-Control-Allow-Origin: *
Informacao adicional: The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listin

## T0239 · alvo1 · zap · 2

`http://localhost:3000/robots.txt` · aparece em 9 rodada(s)

Alerta: Cross-Domain Misconfiguration (plugin 10098, risco 2, confianca 2, CWE-264)
Requisicao: GET http://localhost:3000/robots.txt
Parametro: -
Ataque: -
Evidencia: Access-Control-Allow-Origin: *
Informacao adicional: The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listin

## T0240 · alvo1 · zap · 2

`http://localhost:3000/rolldown-runtime-BoHGiXSq.js` · aparece em 1 rodada(s)

Alerta: Cross-Domain Misconfiguration (plugin 10098, risco 2, confianca 2, CWE-264)
Requisicao: GET http://localhost:3000/rolldown-runtime-BoHGiXSq.js
Parametro: -
Ataque: -
Evidencia: Access-Control-Allow-Origin: *
Informacao adicional: The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listin

## T0241 · alvo1 · zap · 2

`http://localhost:3000/sitemap.xml` · aparece em 9 rodada(s)

Alerta: Cross-Domain Misconfiguration (plugin 10098, risco 2, confianca 2, CWE-264)
Requisicao: GET http://localhost:3000/sitemap.xml
Parametro: -
Ataque: -
Evidencia: Access-Control-Allow-Origin: *
Informacao adicional: The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listin

## T0242 · alvo1 · zap · 2

`http://localhost:3000/styles.css` · aparece em 4 rodada(s)

Alerta: Cross-Domain Misconfiguration (plugin 10098, risco 2, confianca 2, CWE-264)
Requisicao: GET http://localhost:3000/styles.css
Parametro: -
Ataque: -
Evidencia: Access-Control-Allow-Origin: *
Informacao adicional: The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listin

## T0243 · alvo1 · zap · 2

`http://localhost:3000/` · aparece em 9 rodada(s)

Alerta: Cross-Domain Misconfiguration (plugin 10098, risco 2, confianca 2, CWE-264)
Requisicao: GET http://localhost:3000/
Parametro: -
Ataque: -
Evidencia: Access-Control-Allow-Origin: *
Informacao adicional: The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listin

## T0244 · alvo1 · zap · 2

`http://localhost:3000` · aparece em 9 rodada(s)

Alerta: Cross-Domain Misconfiguration (plugin 10098, risco 2, confianca 2, CWE-264)
Requisicao: GET http://localhost:3000
Parametro: -
Ataque: -
Evidencia: Access-Control-Allow-Origin: *
Informacao adicional: The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listin

## T0245 · alvo1 · zap · 2

`http://localhost:3000/api/Hints/` · aparece em 1 rodada(s)

Alerta: Source Code Disclosure - SQL (plugin 10099, risco 2, confianca 2, CWE-540)
Requisicao: GET http://localhost:3000/api/Hints/
Parametro: -
Ataque: -
Evidencia: SELECT attack string to join the relevant data from any such identified system table into the original result.
Informacao adicional: -

## T0246 · alvo1 · zap · 2

`http://localhost:3000/#/forgot-password [token]` · aparece em 1 rodada(s)

Alerta: Information Disclosure - JWT in Browser localStorage (plugin 120002, risco 2, confianca 3, CWE-922)
Requisicao: GET http://localhost:3000/#/forgot-password
Parametro: token
Ataque: -
Evidencia: -
Informacao adicional: The following JWT was set:
Key: token
Header: {"typ":"JWT","alg":"RS256"}
Payload: {"data":{"id":25,"username":"","email":"","password":"d41d8cd98f00b204e9800998ecf8427e","role":"customer","deluxeToken":"","lastLoginIp":"0.0.0.0","profileImage":"/assets/public/images/uploads/default.svg","totpSecret":"","isActive":true,"createdAt":"2026-09-28 20:07:30.901 +00:00","updatedAt":"2026-09-28 20:07:30.901 +00:00","deletedAt":null},"bid":6,"iat":1790626084}
Signature: 2464d18798fd9691cb6823d3b768cabd23

## T0247 · alvo1 · zap · 2

`http://localhost:3000/api/BasketItems/ [ProductId]` · aparece em 1 rodada(s)

Alerta: Integer Overflow Error (plugin 30003, risco 2, confianca 2, CWE-190)
Requisicao: POST http://localhost:3000/api/BasketItems/
Parametro: ProductId
Ataque: 91155956979921398828521629542715942257676033
Evidencia: HTTP/1.1 500 Internal Server Error
Informacao adicional: Potential Integer Overflow. Status code changed on the input of a long string of random integers.

## T0248 · alvo1 · zap · 2

`http://localhost:3000/api/BasketItems/ [quantity]` · aparece em 1 rodada(s)

Alerta: Integer Overflow Error (plugin 30003, risco 2, confianca 2, CWE-190)
Requisicao: POST http://localhost:3000/api/BasketItems/
Parametro: quantity
Ataque: 00000000000000000000000000000000000000000000
Evidencia: HTTP/1.1 500 Internal Server Error
Informacao adicional: Potential Integer Overflow. Status code changed on the input of a long string of zeros.

## T0249 · alvo1 · zap · 2

`http://localhost:3000/api/Complaints/ [UserId]` · aparece em 1 rodada(s)

Alerta: Integer Overflow Error (plugin 30003, risco 2, confianca 2, CWE-190)
Requisicao: POST http://localhost:3000/api/Complaints/
Parametro: UserId
Ataque: 88010430058922824764635094208566666712927343
Evidencia: HTTP/1.1 500 Internal Server Error
Informacao adicional: Potential Integer Overflow. Status code changed on the input of a long string of random integers.

## T0250 · alvo1 · zap · 2

`http://localhost:3000/socket.io/ [sid]` · aparece em 9 rodada(s)

Alerta: Session ID in URL Rewrite (plugin 3, risco 2, confianca 3, CWE-598)
Requisicao: GET http://localhost:3000/socket.io/?EIO=4&transport=polling&t=Q3fdxwN&sid=Z6B3l7O9IlHHNF_qAAAA
Parametro: sid
Ataque: -
Evidencia: Z6B3l7O9IlHHNF_qAAAA
Informacao adicional: -

## T0251 · alvo1 · zap · 2

`http://localhost:3000/%2e/ftp/coupons_2013.md.bak` · aparece em 9 rodada(s)

Alerta: Bypassing 403 (plugin 40038, risco 2, confianca 2, CWE-348)
Requisicao: GET http://localhost:3000/%2e/ftp/coupons_2013.md.bak
Parametro: -
Ataque: /%2e/ftp/coupons_2013.md.bak
Evidencia: -
Informacao adicional: http://localhost:3000/ftp/coupons_2013.md.bak

## T0252 · alvo1 · zap · 2

`http://localhost:3000/%2e/ftp/eastere.gg` · aparece em 9 rodada(s)

Alerta: Bypassing 403 (plugin 40038, risco 2, confianca 2, CWE-348)
Requisicao: GET http://localhost:3000/%2e/ftp/eastere.gg
Parametro: -
Ataque: /%2e/ftp/eastere.gg
Evidencia: -
Informacao adicional: http://localhost:3000/ftp/eastere.gg

## T0253 · alvo1 · zap · 2 · RETRIAGEM

`http://localhost:3000/%2e/ftp/encrypt.pyc` · aparece em 9 rodada(s)

Alerta: Bypassing 403 (plugin 40038, risco 2, confianca 2, CWE-348)
Requisicao: GET http://localhost:3000/%2e/ftp/encrypt.pyc
Parametro: -
Ataque: /%2e/ftp/encrypt.pyc
Evidencia: -
Informacao adicional: http://localhost:3000/ftp/encrypt.pyc

## T0254 · alvo1 · zap · 2

`http://localhost:3000/%2e/ftp/package-lock.json.bak` · aparece em 9 rodada(s)

Alerta: Bypassing 403 (plugin 40038, risco 2, confianca 2, CWE-348)
Requisicao: GET http://localhost:3000/%2e/ftp/package-lock.json.bak
Parametro: -
Ataque: /%2e/ftp/package-lock.json.bak
Evidencia: -
Informacao adicional: http://localhost:3000/ftp/package-lock.json.bak

## T0255 · alvo1 · zap · 2

`http://localhost:3000/%2e/ftp/package.json.bak` · aparece em 9 rodada(s)

Alerta: Bypassing 403 (plugin 40038, risco 2, confianca 2, CWE-348)
Requisicao: GET http://localhost:3000/%2e/ftp/package.json.bak
Parametro: -
Ataque: /%2e/ftp/package.json.bak
Evidencia: -
Informacao adicional: http://localhost:3000/ftp/package.json.bak

## T0256 · alvo1 · zap · 2 · RETRIAGEM

`http://localhost:3000/%2e/ftp/suspicious_errors.yml` · aparece em 9 rodada(s)

Alerta: Bypassing 403 (plugin 40038, risco 2, confianca 2, CWE-348)
Requisicao: GET http://localhost:3000/%2e/ftp/suspicious_errors.yml
Parametro: -
Ataque: /%2e/ftp/suspicious_errors.yml
Evidencia: -
Informacao adicional: http://localhost:3000/ftp/suspicious_errors.yml

## T0257 · alvo1 · zap · 2

`http://localhost:3000/api/Feedbacks/` · aparece em 2 rodada(s)

Alerta: CORS Misconfiguration (plugin 40040, risco 2, confianca 3, CWE-942)
Requisicao: GET http://localhost:3000/api/Feedbacks/
Parametro: -
Ataque: origin: http://Bxi0Qlev.com
Evidencia: -
Informacao adicional: -

## T0258 · alvo1 · zap · 2

`http://localhost:3000/api/Hints/` · aparece em 1 rodada(s)

Alerta: CORS Misconfiguration (plugin 40040, risco 2, confianca 3, CWE-942)
Requisicao: GET http://localhost:3000/api/Hints/
Parametro: -
Ataque: origin: http://iIgEjn86.com
Evidencia: -
Informacao adicional: -

## T0259 · alvo1 · zap · 2

`http://localhost:3000/api/Quantitys/` · aparece em 8 rodada(s)

Alerta: CORS Misconfiguration (plugin 40040, risco 2, confianca 3, CWE-942)
Requisicao: GET http://localhost:3000/api/Quantitys/
Parametro: -
Ataque: origin: http://Bxi0Qlev.com
Evidencia: -
Informacao adicional: -

## T0260 · alvo1 · zap · 2

`http://localhost:3000/api/Recycles/` · aparece em 1 rodada(s)

Alerta: CORS Misconfiguration (plugin 40040, risco 2, confianca 3, CWE-942)
Requisicao: GET http://localhost:3000/api/Recycles/
Parametro: -
Ataque: origin: http://DbKLszGX.com
Evidencia: -
Informacao adicional: -

## T0261 · alvo1 · zap · 2

`http://localhost:3000/api/SecurityQuestions/` · aparece em 7 rodada(s)

Alerta: CORS Misconfiguration (plugin 40040, risco 2, confianca 3, CWE-942)
Requisicao: GET http://localhost:3000/api/SecurityQuestions/
Parametro: -
Ataque: origin: http://Bxi0Qlev.com
Evidencia: -
Informacao adicional: -

## T0262 · alvo1 · zap · 2

`http://localhost:3000/api/Users/` · aparece em 5 rodada(s)

Alerta: CORS Misconfiguration (plugin 40040, risco 2, confianca 3, CWE-942)
Requisicao: POST http://localhost:3000/api/Users/
Parametro: -
Ataque: origin: http://IamjSxHF.com
Evidencia: -
Informacao adicional: -

## T0263 · alvo1 · zap · 2

`http://localhost:3000/rest/captcha/` · aparece em 9 rodada(s)

Alerta: CORS Misconfiguration (plugin 40040, risco 2, confianca 3, CWE-942)
Requisicao: GET http://localhost:3000/rest/captcha/
Parametro: -
Ataque: origin: http://Bxi0Qlev.com
Evidencia: -
Informacao adicional: -

## T0264 · alvo1 · zap · 2

`http://localhost:3000/rest/memories/` · aparece em 9 rodada(s)

Alerta: CORS Misconfiguration (plugin 40040, risco 2, confianca 3, CWE-942)
Requisicao: GET http://localhost:3000/rest/memories/
Parametro: -
Ataque: origin: http://Bxi0Qlev.com
Evidencia: -
Informacao adicional: -

## T0265 · alvo1 · zap · 2

`http://localhost:3000/` · aparece em 3 rodada(s)

Alerta: CORS Misconfiguration (plugin 40040, risco 2, confianca 3, CWE-942)
Requisicao: GET http://localhost:3000/
Parametro: -
Ataque: origin: http://uVD1tYrp.com
Evidencia: -
Informacao adicional: -

## T0266 · alvo1 · zap · 2

`http://localhost:3000/api/Hints/` · aparece em 1 rodada(s)

Alerta: Application Error Disclosure (plugin 90022, risco 2, confianca 2, CWE-550)
Requisicao: GET http://localhost:3000/api/Hints/
Parametro: -
Ataque: -
Evidencia: Internal Server Error
Informacao adicional: -

## T0267 · alvo1 · zap · 3

`http://localhost:3000/redirect [to]` · aparece em 9 rodada(s)

Alerta: Off-site Redirect (plugin 10028, risco 3, confianca 2, CWE-601)
Requisicao: GET http://localhost:3000/redirect?to=https://github.com/juice-shop/juice-shop
Parametro: to
Ataque: -
Evidencia: -
Informacao adicional: The 301 or 302 response to a request for the following URL appeared to contain user input in the location header:

http://localhost:3000/redirect?to=https://github.com/juice-shop/juice-shop

The user input found was:

to=https://github.com/juice-shop/juice-shop

The context was:

https://github.com/juice-shop/juice-shop

## T0268 · alvo1 · zap · 3

`http://localhost:3000/redirect [to]` · aparece em 9 rodada(s)

Alerta: External Redirect (plugin 20019, risco 3, confianca 2, CWE-601)
Requisicao: GET http://localhost:3000/redirect?to=https%3A%2F%2F3588080267780996708.owasp.org%2F%3Fhttps%3A%2F%2Fgithub.com%2Fjuice-shop%2Fjuice-shop
Parametro: to
Ataque: https://3588080267780996708.owasp.org/?https://github.com/juice-shop/juice-shop
Evidencia: https://3588080267780996708.owasp.org/?@@@original@@@
Informacao adicional: The response contains a redirect in its Location header which allows an external Url to be set.

## T0269 · alvo1 · zap · 3

`http://localhost:3000/rest/products/search [q]` · aparece em 9 rodada(s)

Alerta: SQL Injection (plugin 40018, risco 3, confianca 1, CWE-89)
Requisicao: GET http://localhost:3000/rest/products/search?q=%27%28
Parametro: q
Ataque: '(
Evidencia: HTTP/1.1 500 Internal Server Error
Informacao adicional: -

## T0270 · alvo1 · zap · 3

`http://localhost:3000/rest/user/login [email]` · aparece em 9 rodada(s)

Alerta: SQL Injection (plugin 40018, risco 3, confianca 1, CWE-89)
Requisicao: POST http://localhost:3000/rest/user/login
Parametro: email
Ataque: '
Evidencia: HTTP/1.1 500 Internal Server Error
Informacao adicional: -

## T0271 · alvo1 · zap · 3

`http://localhost:3000/api/Feedbacks/ [comment]` · aparece em 1 rodada(s)

Alerta: SQL Injection - SQLite (Time Based) (plugin 40024, risco 3, confianca 2, CWE-89)
Requisicao: POST http://localhost:3000/api/Feedbacks/
Parametro: comment
Ataque: case randomblob(1000000) when not null then 1 else 1 end 
Evidencia: -
Informacao adicional: The query time is controllable using parameter value [case randomblob(1000000) when not null then 1 else 1 end ], which caused the request to take [234] milliseconds, parameter value [case randomblob(10000000) when not null then 1 else 1 end ], which caused the request to take [812] milliseconds, when the original unmodified query with value [ (anonymous)] took [7] milliseconds.

## T0272 · alvo1 · zap · 3

`http://localhost:3000/api/BasketItems/ [BasketId]` · aparece em 1 rodada(s)

Alerta: Source Code Disclosure - File Inclusion (plugin 43, risco 3, confianca 2, CWE-541)
Requisicao: POST http://localhost:3000/api/BasketItems/
Parametro: BasketId
Ataque: -
Evidencia: -
Informacao adicional: The output for the source code filename [] differs sufficiently from that of the random parameter [lcgvzwphrtwkaqaawieumlixrewcawjmmbwfni], at [2%], compared to a threshold of [75%]

## T0273 · alvo1 · zap · 3

`http://localhost:3000/api/BasketItems/ [quantity]` · aparece em 1 rodada(s)

Alerta: Source Code Disclosure - File Inclusion (plugin 43, risco 3, confianca 2, CWE-541)
Requisicao: POST http://localhost:3000/api/BasketItems/
Parametro: quantity
Ataque: -
Evidencia: -
Informacao adicional: The output for the source code filename [] differs sufficiently from that of the random parameter [lcgvzwphrtwkaqaawieumlixrewcawjmmbwfni], at [2%], compared to a threshold of [75%]

## T0274 · alvo1 · zap · 3

`http://localhost:3000/api/Challenges/ [sort]` · aparece em 1 rodada(s)

Alerta: Source Code Disclosure - File Inclusion (plugin 43, risco 3, confianca 2, CWE-541)
Requisicao: GET http://localhost:3000/api/Challenges/?sort=name
Parametro: sort
Ataque: ../
Evidencia: -
Informacao adicional: The output for the source code filename [../] differs sufficiently from that of the random parameter [ldaoasdysblbicjxildwwdbpxvujlpkfvdykkn], at [75%], compared to a threshold of [75%]

## T0275 · alvo2 · semgrep · ERROR · RETRIAGEM

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

## T0276 · alvo2 · semgrep · ERROR

`alvos/uptime-kuma/extra/release/lib.mjs:519` · aparece em 9 rodada(s)

Regra: javascript.lang.security.detect-child-process.detect-child-process
Mensagem: Detected calls to child_process from a function argument `cmd`. This could lead to a command injection if the input is user controllable. Try to avoid calls to child_process, and if it is needed ensure user input is correctly sanitized or sandboxed.

```
   516 |  */
   517 | export function execSync(cmd) {
   518 |     if (!dryRun) {
>  519 |         childProcess.execSync(cmd, { stdio: "inherit" });
   520 |     } else {
   521 |         console.info(`[DRY RUN] ${cmd}`);
   522 |     }
```

## T0277 · alvo2 · semgrep · ERROR

`alvos/uptime-kuma/extra/release/prepare-release.mjs:87` · aparece em 9 rodada(s)

Regra: javascript.lang.security.detect-child-process.detect-child-process
Mensagem: Detected calls to child_process from a function argument `cmd`. This could lead to a command injection if the input is user controllable. Try to avoid calls to child_process, and if it is needed ensure user input is correctly sanitized or sandboxed.

```
    84 |  * @returns {void}
    85 |  */
    86 | function exec(cmd, ignoreFailure = false) {
>   87 |     const result = childProcess.spawnSync(cmd, {
    88 |         shell: true,
    89 |         stdio: "inherit",
    90 |     });
```

## T0278 · alvo2 · semgrep · ERROR

`alvos/uptime-kuma/server/monitor-types/real-browser-monitor-type.js:164` · aparece em 9 rodada(s)

Regra: javascript.lang.security.detect-child-process.detect-child-process
Mensagem: Detected calls to child_process from a function argument `executablePath`. This could lead to a command injection if the input is user controllable. Try to avoid calls to child_process, and if it is needed ensure user input is correctly sanitized or sandboxed.

```
   161 | 
   162 |             if (code === 0) {
   163 |                 log.info("chromium", "Installed Chromium");
>  164 |                 let version = childProcess.execSync(executablePath + " --version").toString("utf8");
   165 |                 log.info("chromium", "Chromium version: " + version);
   166 |                 resolve();
   167 |             } else if (code === 100) {
```

## T0279 · alvo2 · semgrep · ERROR

`alvos/uptime-kuma/extra/download-apprise.mjs:11` · aparece em 9 rodada(s)

Regra: typescript.react.security.react-insecure-request.react-insecure-request
Mensagem: Unencrypted request over HTTP detected.

```
     8 | import * as childProcess from "child_process";
     9 | 
    10 | const baseURL = "http://ftp.debian.org/debian/pool/main/a/apprise/";
>   11 | const response = await fetch(baseURL);
    12 | 
    13 | if (!response.ok) {
    14 |     throw new Error("Failed to fetch page of Apprise Debian repository.");
```

## T0280 · alvo2 · semgrep · ERROR

`alvos/uptime-kuma/server/notification-providers/aliyun-sms.js:70` · aparece em 9 rodada(s)

Regra: typescript.react.security.react-insecure-request.react-insecure-request
Mensagem: Unencrypted request over HTTP detected.

```
    67 |         };
    68 | 
    69 |         params.Signature = this.sign(params, notification.secretAccessKey);
>   70 |         let config = {
    71 |             method: "POST",
    72 |             url: "http://dysmsapi.aliyuncs.com/",
    73 |             headers: {
```

## T0281 · alvo2 · semgrep · ERROR · RETRIAGEM

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

## T0282 · alvo2 · semgrep · WARNING

`alvos/uptime-kuma/extra/healthcheck.go:26` · aparece em 9 rodada(s)

Regra: go.lang.security.audit.crypto.missing-ssl-minversion.missing-ssl-minversion
Mensagem: `MinVersion` is missing from this TLS configuration.  By default, as of Go 1.22, TLS 1.2 is currently used as the minimum. General purpose web applications should default to TLS 1.3 with all other protocols disabled.  Only where it is known that a web server must support legacy clients with unsupported an insecure browsers (such as Internet Explorer 10), it may be necessary to enable TLS 1.0 to provide support. Add `MinVersion: tls.VersionTLS13' to the TLS configuration to bump the minimum version to TLS 1.3.

```
    23 | 	isK8s := strings.HasPrefix(os.Getenv("UPTIME_KUMA_PORT"), "tcp://")
    24 | 
    25 | 	// process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
>   26 | 	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
    27 | 		InsecureSkipVerify: true,
    28 | 	}
    29 | 
```

## T0283 · alvo2 · semgrep · WARNING

`alvos/uptime-kuma/server/routers/api-router.js:215` · aparece em 9 rodada(s)

Regra: javascript.express.security.audit.xss.direct-response-write.direct-response-write
Mensagem: Detected directly writing to a Response object from user-defined input. This bypasses any HTML escaping and may expose your application to a Cross-Site-scripting (XSS) vulnerability. Instead, use 'resp.render()' to render safely escaped HTML.

```
   212 |         const svg = makeBadge(badgeValues);
   213 | 
   214 |         response.type("image/svg+xml");
>  215 |         response.send(svg);
   216 |     } catch (error) {
   217 |         sendHttpError(response, error.message);
   218 |     }
```

## T0284 · alvo2 · semgrep · WARNING

`alvos/uptime-kuma/server/routers/api-router.js:279` · aparece em 9 rodada(s)

Regra: javascript.express.security.audit.xss.direct-response-write.direct-response-write
Mensagem: Detected directly writing to a Response object from user-defined input. This bypasses any HTML escaping and may expose your application to a Cross-Site-scripting (XSS) vulnerability. Instead, use 'resp.render()' to render safely escaped HTML.

```
   276 |         const svg = makeBadge(badgeValues);
   277 | 
   278 |         response.type("image/svg+xml");
>  279 |         response.send(svg);
   280 |     } catch (error) {
   281 |         sendHttpError(response, error.message);
   282 |     }
```

## T0285 · alvo2 · semgrep · WARNING

`alvos/uptime-kuma/server/routers/api-router.js:345` · aparece em 9 rodada(s)

Regra: javascript.express.security.audit.xss.direct-response-write.direct-response-write
Mensagem: Detected directly writing to a Response object from user-defined input. This bypasses any HTML escaping and may expose your application to a Cross-Site-scripting (XSS) vulnerability. Instead, use 'resp.render()' to render safely escaped HTML.

```
   342 |         const svg = makeBadge(badgeValues);
   343 | 
   344 |         response.type("image/svg+xml");
>  345 |         response.send(svg);
   346 |     } catch (error) {
   347 |         sendHttpError(response, error.message);
   348 |     }
```

## T0286 · alvo2 · semgrep · WARNING

`alvos/uptime-kuma/server/routers/api-router.js:418` · aparece em 9 rodada(s)

Regra: javascript.express.security.audit.xss.direct-response-write.direct-response-write
Mensagem: Detected directly writing to a Response object from user-defined input. This bypasses any HTML escaping and may expose your application to a Cross-Site-scripting (XSS) vulnerability. Instead, use 'resp.render()' to render safely escaped HTML.

```
   415 |         const svg = makeBadge(badgeValues);
   416 | 
   417 |         response.type("image/svg+xml");
>  418 |         response.send(svg);
   419 |     } catch (error) {
   420 |         sendHttpError(response, error.message);
   421 |     }
```

## T0287 · alvo2 · semgrep · WARNING

`alvos/uptime-kuma/server/routers/api-router.js:501` · aparece em 9 rodada(s)

Regra: javascript.express.security.audit.xss.direct-response-write.direct-response-write
Mensagem: Detected directly writing to a Response object from user-defined input. This bypasses any HTML escaping and may expose your application to a Cross-Site-scripting (XSS) vulnerability. Instead, use 'resp.render()' to render safely escaped HTML.

```
   498 |         const svg = makeBadge(badgeValues);
   499 | 
   500 |         response.type("image/svg+xml");
>  501 |         response.send(svg);
   502 |     } catch (error) {
   503 |         sendHttpError(response, error.message);
   504 |     }
```

## T0288 · alvo2 · semgrep · WARNING

`alvos/uptime-kuma/server/routers/api-router.js:561` · aparece em 9 rodada(s)

Regra: javascript.express.security.audit.xss.direct-response-write.direct-response-write
Mensagem: Detected directly writing to a Response object from user-defined input. This bypasses any HTML escaping and may expose your application to a Cross-Site-scripting (XSS) vulnerability. Instead, use 'resp.render()' to render safely escaped HTML.

```
   558 |         const svg = makeBadge(badgeValues);
   559 | 
   560 |         response.type("image/svg+xml");
>  561 |         response.send(svg);
   562 |     } catch (error) {
   563 |         sendHttpError(response, error.message);
   564 |     }
```

## T0289 · alvo2 · semgrep · WARNING

`alvos/uptime-kuma/server/routers/status-page-router.js:258` · aparece em 9 rodada(s)

Regra: javascript.express.security.audit.xss.direct-response-write.direct-response-write
Mensagem: Detected directly writing to a Response object from user-defined input. This bypasses any HTML escaping and may expose your application to a Cross-Site-scripting (XSS) vulnerability. Instead, use 'resp.render()' to render safely escaped HTML.

```
   255 |         const svg = makeBadge(badgeValues);
   256 | 
   257 |         response.type("image/svg+xml");
>  258 |         response.send(svg);
   259 |     } catch (error) {
   260 |         sendHttpError(response, error.message);
   261 |     }
```

## T0290 · alvo2 · semgrep · WARNING

`alvos/uptime-kuma/server/model/status_page.js:202` · aparece em 9 rodada(s)

Regra: javascript.lang.security.audit.unknown-value-with-script-tag.unknown-value-with-script-tag
Mensagem: Cannot determine what 'escapedJSONObject' is and it is used with a '<script>' tag. This could be susceptible to cross-site scripting (XSS). Ensure 'escapedJSONObject' is not externally controlled, or sanitize this data.

```
   199 | 
   200 |         const script = $(`
   201 |             <script id="preload-data" data-json="{}">
>  202 |                 window.preloadData = ${escapedJSONObject};
   203 |             </script>
   204 |         `);
   205 | 
```

## T0291 · alvo2 · semgrep · WARNING

`alvos/uptime-kuma/server/notification-providers/teltonika.js:50` · aparece em 9 rodada(s)

Regra: problem-based-packs.insecure-transport.js-node.bypass-tls-verification.bypass-tls-verification
Mensagem: Checks for setting the environment variable NODE_TLS_REJECT_UNAUTHORIZED to 0, which disables TLS verification. This should only be used for debugging purposes. Setting the option rejectUnauthorized to false bypasses verification against the list of trusted CAs, which also leads to insecure transport. These options lead to vulnerability to MTM attacks, and should not be used.

```
    47 |             // certificate. Here we give them an option to disable certificate
    48 |             // validation. It's not desirable, but sometimes the only option.
    49 |             if (notification.teltonikaUnsafeTls) {
>   50 |                 axiosConfig.httpsAgent = new https.Agent({
    51 |                     rejectUnauthorized: false, // Danger! Disables SSL verification
    52 |                 });
    53 |             }
```

## T0292 · alvo2 · trivy-config · CRITICAL

`dockerfile:103` · aparece em 9 rodada(s)

Regra: DS-0031 (Secrets passed via `build-args` or envs or copied secret files)
Arquivo: dockerfile
Mensagem: Possible exposure of secret env "GITHUB_TOKEN" in ARG
Resolucao sugerida pela ferramenta: Use secret mount if secrets are needed during image build. Use volume mount if secret files are needed during container runtime.

```
  103 | ARG GITHUB_TOKEN
```

## T0293 · alvo2 · trivy-config · MEDIUM

`dockerfile:116` · aparece em 9 rodada(s)

Regra: DS-0013 ('RUN cd ...' to change directory)
Arquivo: dockerfile
Mensagem: RUN should not be used to change directory: 'cd /app && tar -zcvf $DIST dist'. Use 'WORKDIR' statement instead.
Resolucao sugerida pela ferramenta: Use WORKDIR to change directory

```
  116 | RUN cd /app && tar -zcvf $DIST dist
```

## T0294 · alvo2 · trivy-image · CRITICAL

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.53-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Use after free in Autofill
Advisory: https://avd.aquasec.com/nvd/cve-2026-11002

## T0295 · alvo2 · trivy-image · CRITICAL

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.53-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Insufficient validation of untrusted input in Drag and Drop
Advisory: https://avd.aquasec.com/nvd/cve-2026-11029

## T0296 · alvo2 · trivy-image · CRITICAL

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.196-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: chromium-browser: Use after free in Autofill
Advisory: https://avd.aquasec.com/nvd/cve-2026-13038

## T0297 · alvo2 · trivy-image · CRITICAL

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 151.0.7922.71-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: chromium-browser: Insufficient validation of untrusted input in Dawn
Advisory: https://avd.aquasec.com/nvd/cve-2026-17651

## T0298 · alvo2 · trivy-image · CRITICAL

`libglx-mesa0@22.3.6-1+deb12u1` · aparece em 9 rodada(s)

Pacote: libglx-mesa0 22.3.6-1+deb12u1
Versao corrigida: 22.3.6-1+deb12u2
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: In Mesa before 25.3.6 and 26 before 26.0.1, out-of-bounds memory acces ...
Advisory: https://avd.aquasec.com/nvd/cve-2026-40393

## T0299 · alvo2 · trivy-image · CRITICAL

`mariadb-common@1:10.11.14-0+deb12u2` · aparece em 9 rodada(s)

Pacote: mariadb-common 1:10.11.14-0+deb12u2
Versao corrigida: 1:10.11.18-0+deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: mariadb: MariaDB server: SQL injection vulnerability via improper handling of big5 character set with mysql_real_escape_string()
Advisory: https://avd.aquasec.com/nvd/cve-2026-44172

## T0300 · alvo2 · trivy-image · CRITICAL · RETRIAGEM

`tar@7.5.11` · aparece em 9 rodada(s)

Pacote: tar 7.5.11
Versao corrigida: 7.5.19
Status na fonte: fixed
Onde esta na imagem: usr/local/lib/node_modules/npm/node_modules/tar/package.json
Titulo: tar: node-tar: Denial of Service via crafted gzip bomb
Advisory: https://avd.aquasec.com/nvd/cve-2026-59873

## T0301 · alvo2 · trivy-image · CRITICAL

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 152.0.7977.75-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: angle: Chromium: Remote code execution via out-of-bounds write in ANGLE
Advisory: https://avd.aquasec.com/nvd/cve-2026-79131

## T0302 · alvo2 · trivy-image · CRITICAL

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 152.0.7977.75-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: angle: chromium-browser: Arbitrary Code Execution via out-of-bounds write in ANGLE
Advisory: https://avd.aquasec.com/nvd/cve-2026-79138

## T0303 · alvo2 · trivy-image · CRITICAL

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 148.0.7778.215-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: angle: Out of bounds write in ANGLE
Advisory: https://avd.aquasec.com/nvd/cve-2026-9879

## T0304 · alvo2 · trivy-image · HIGH

`mariadb-server-core@1:10.11.14-0+deb12u2` · aparece em 9 rodada(s)

Pacote: mariadb-server-core 1:10.11.14-0+deb12u2
Versao corrigida: 1:10.11.18-0+deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: mariadb: MariaDB: mariadb-dump utility vulnerable to remote code execution via improper path validation
Advisory: https://avd.aquasec.com/nvd/cve-2025-13699

## T0305 · alvo2 · trivy-image · HIGH

`libncurses6@6.4-4` · aparece em 9 rodada(s)

Pacote: libncurses6 6.4-4
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: ncurses: ncurses: Buffer overflow vulnerability may lead to arbitrary code execution.
Advisory: https://avd.aquasec.com/nvd/cve-2025-69720

## T0306 · alvo2 · trivy-image · HIGH

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.53-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Insufficient validation of untrusted input in WebShare
Advisory: https://avd.aquasec.com/nvd/cve-2026-10920

## T0307 · alvo2 · trivy-image · HIGH

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.53-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Insufficient validation of untrusted input in WebShare
Advisory: https://avd.aquasec.com/nvd/cve-2026-10920

## T0308 · alvo2 · trivy-image · HIGH

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.53-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Uninitialized Use in Codecs
Advisory: https://avd.aquasec.com/nvd/cve-2026-10960

## T0309 · alvo2 · trivy-image · HIGH

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.102-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Use after free in Ozone
Advisory: https://avd.aquasec.com/nvd/cve-2026-11628

## T0310 · alvo2 · trivy-image · HIGH

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.102-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Use after free in Views
Advisory: https://avd.aquasec.com/nvd/cve-2026-11637

## T0311 · alvo2 · trivy-image · HIGH

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.102-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Use after free in WebCodecs
Advisory: https://avd.aquasec.com/nvd/cve-2026-11683

## T0312 · alvo2 · trivy-image · HIGH

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.102-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Inappropriate implementation in Passwords
Advisory: https://avd.aquasec.com/nvd/cve-2026-11695

## T0313 · alvo2 · trivy-image · HIGH

`python3.11@3.11.2-6+deb12u7` · aparece em 9 rodada(s)

Pacote: python3.11 3.11.2-6+deb12u7
Versao corrigida: (nenhuma publicada)
Status na fonte: fix_deferred
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: python: cpython: CPython: tarfile extraction filter bypass allows escaping the destination directory
Advisory: https://avd.aquasec.com/nvd/cve-2026-11940

## T0314 · alvo2 · trivy-image · HIGH

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.196-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: chromium-browser: Use after free in Digital Credentials
Advisory: https://avd.aquasec.com/nvd/cve-2026-13026

## T0315 · alvo2 · trivy-image · HIGH

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 150.0.7871.46-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Heap buffer overflow in Chromecast
Advisory: https://avd.aquasec.com/nvd/cve-2026-13798

## T0316 · alvo2 · trivy-image · HIGH · RETRIAGEM

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 150.0.7871.46-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: chromium-browser: Side-channel information leakage in Safe Browsing
Advisory: https://avd.aquasec.com/nvd/cve-2026-13809

## T0317 · alvo2 · trivy-image · HIGH

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 150.0.7871.46-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Use after free in Updater
Advisory: https://avd.aquasec.com/nvd/cve-2026-13827

## T0318 · alvo2 · trivy-image · HIGH

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 150.0.7871.46-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: angle: chromium-browser: Insufficient validation of untrusted input in ANGLE
Advisory: https://avd.aquasec.com/nvd/cve-2026-14412

## T0319 · alvo2 · trivy-image · HIGH

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 151.0.7922.71-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: chromium-browser: Race in Downloads
Advisory: https://avd.aquasec.com/nvd/cve-2026-17711

## T0320 · alvo2 · trivy-image · HIGH

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 151.0.7922.108-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Google Chrome: Sandbox escape via use-after-free in Media component
Advisory: https://avd.aquasec.com/nvd/cve-2026-19163

## T0321 · alvo2 · trivy-image · HIGH

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 151.0.7922.137-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: chromium-browser: Arbitrary code execution via use-after-free in Blink
Advisory: https://avd.aquasec.com/nvd/cve-2026-19560

## T0322 · alvo2 · trivy-image · HIGH

`stdlib@v1.26.3` · aparece em 9 rodada(s)

Pacote: stdlib v1.26.3
Versao corrigida: 1.25.12, 1.26.5, 1.27.0-rc.2
Status na fonte: fixed
Onde esta na imagem: usr/bin/cloudflared
Titulo: golang: Go os.Root: Symlink following vulnerability allows directory traversal
Advisory: https://avd.aquasec.com/nvd/cve-2026-39822

## T0323 · alvo2 · trivy-image · HIGH

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 151.0.7922.173-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Google Chrome: Arbitrary Code Execution via crafted file in Import component
Advisory: https://avd.aquasec.com/nvd/cve-2026-76018

## T0324 · alvo2 · trivy-image · HIGH

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 151.0.7922.169-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Google Chrome: Arbitrary Code Execution via Link Following
Advisory: https://avd.aquasec.com/nvd/cve-2026-76037

## T0325 · alvo2 · trivy-image · HIGH

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 151.0.7922.169-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Google Chrome: Arbitrary code execution due to a race condition in USB
Advisory: https://avd.aquasec.com/nvd/cve-2026-76044

## T0326 · alvo2 · trivy-image · HIGH

`libmount1@2.38.1-5+deb12u3` · aparece em 9 rodada(s)

Pacote: libmount1 2.38.1-5+deb12u3
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: util-linux: util-linux: nsenter --join-cgroup leaks root cgroup migration authority
Advisory: https://avd.aquasec.com/nvd/cve-2026-78408

## T0327 · alvo2 · trivy-image · HIGH

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 152.0.7977.75-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: angle: Chromium-browser: Memory disclosure via uninitialized resource in ANGLE
Advisory: https://avd.aquasec.com/nvd/cve-2026-79270

## T0328 · alvo2 · trivy-image · HIGH · RETRIAGEM

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 148.0.7778.215-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: angle: Insufficient validation of untrusted input in ANGLE
Advisory: https://avd.aquasec.com/nvd/cve-2026-9914

## T0329 · alvo2 · trivy-image · HIGH

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 148.0.7778.215-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: angle: Out of bounds read in ANGLE
Advisory: https://avd.aquasec.com/nvd/cve-2026-9928

## T0330 · alvo2 · trivy-image · HIGH

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 148.0.7778.215-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Out of bounds read in WebGL
Advisory: https://avd.aquasec.com/nvd/cve-2026-9943

## T0331 · alvo2 · trivy-image · HIGH

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 148.0.7778.215-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Insufficient validation of untrusted input in OptimizationGuide
Advisory: https://avd.aquasec.com/nvd/cve-2026-9986

## T0332 · alvo2 · trivy-image · LOW

`libnss3@2:3.87.1-1+deb12u2` · aparece em 9 rodada(s)

Pacote: libnss3 2:3.87.1-1+deb12u2
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: nss: Heap-buffer-overflow in __hash_open
Advisory: https://avd.aquasec.com/nvd/cve-2017-11696

## T0333 · alvo2 · trivy-image · LOW

`libnss3@2:3.87.1-1+deb12u2` · aparece em 9 rodada(s)

Pacote: libnss3 2:3.87.1-1+deb12u2
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: nss: Heap-buffer-overflow in __get_page
Advisory: https://avd.aquasec.com/nvd/cve-2017-11698

## T0334 · alvo2 · trivy-image · LOW

`libkrb5support0@1.20.1-2+deb12u5` · aparece em 9 rodada(s)

Pacote: libkrb5support0 1.20.1-2+deb12u5
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: krb5: integer overflow in dbentry->n_key_data in kadmin/dbutil/dump.c
Advisory: https://avd.aquasec.com/nvd/cve-2018-5709

## T0335 · alvo2 · trivy-image · LOW

`libudev1@252.39-1~deb12u2` · aparece em 9 rodada(s)

Pacote: libudev1 252.39-1~deb12u2
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: An issue was discovered in systemd 253. An attacker can truncate a sea ...
Advisory: https://avd.aquasec.com/nvd/cve-2023-31438

## T0336 · alvo2 · trivy-image · LOW

`libsystemd0@252.39-1~deb12u2` · aparece em 9 rodada(s)

Pacote: libsystemd0 252.39-1~deb12u2
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: An issue was discovered in systemd 253. An attacker can modify the con ...
Advisory: https://avd.aquasec.com/nvd/cve-2023-31439

## T0337 · alvo2 · trivy-image · LOW

`python3-certifi@2022.9.24-1` · aparece em 9 rodada(s)

Pacote: python3-certifi 2022.9.24-1
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: python-certifi: Removal of e-Tugra root certificate
Advisory: https://avd.aquasec.com/nvd/cve-2023-37920

## T0338 · alvo2 · trivy-image · LOW

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.53-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Incorrect security UI in WebUI
Advisory: https://avd.aquasec.com/nvd/cve-2026-11225

## T0339 · alvo2 · trivy-image · LOW

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.53-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Out of bounds read in Fonts
Advisory: https://avd.aquasec.com/nvd/cve-2026-11299

## T0340 · alvo2 · trivy-image · LOW

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.53-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Insufficient policy enforcement in History
Advisory: https://avd.aquasec.com/nvd/cve-2026-11309

## T0341 · alvo2 · trivy-image · LOW

`libkrb5-3@1.20.1-2+deb12u5` · aparece em 9 rodada(s)

Pacote: libkrb5-3 1.20.1-2+deb12u5
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: krb5: krb5: integer underflow in berval2tl_data() leads to heap out-of-bounds read
Advisory: https://avd.aquasec.com/nvd/cve-2026-11850

## T0342 · alvo2 · trivy-image · LOW

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 150.0.7871.46-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: chromium-browser: Insufficient data validation in Chrome for iOS
Advisory: https://avd.aquasec.com/nvd/cve-2026-14128

## T0343 · alvo2 · trivy-image · LOW

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 151.0.7922.71-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: chromium-browser: Insufficient validation of untrusted input in Printing
Advisory: https://avd.aquasec.com/nvd/cve-2026-17908

## T0344 · alvo2 · trivy-image · LOW

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 151.0.7922.71-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: chromium-browser: Insufficient policy enforcement in SVG
Advisory: https://avd.aquasec.com/nvd/cve-2026-17911

## T0345 · alvo2 · trivy-image · LOW

`python3.11@3.11.2-6+deb12u7` · aparece em 9 rodada(s)

Pacote: python3.11 3.11.2-6+deb12u7
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: python: Python: Denial of Service via super-linear regular expression work in csv.Sniffer.sniff()
Advisory: https://avd.aquasec.com/nvd/cve-2026-18503

## T0346 · alvo2 · trivy-image · LOW

`python3.11-minimal@3.11.2-6+deb12u7` · aparece em 9 rodada(s)

Pacote: python3.11-minimal 3.11.2-6+deb12u7
Versao corrigida: 3.11.2-6+deb12u8
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: cpython: CPython: Logging Bypass in Legacy .pyc File Handling
Advisory: https://avd.aquasec.com/nvd/cve-2026-2297

## T0347 · alvo2 · trivy-image · LOW

`sysvinit-utils@3.06-4` · aparece em 9 rodada(s)

Pacote: sysvinit-utils 3.06-4
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: [sysvinit: no-root option in expert installer exposes locally exploitable security flaw]
Advisory: https://security-tracker.debian.org/tracker/TEMP-0517018-A83CE6

## T0348 · alvo2 · trivy-image · MEDIUM

`perl-modules-5.36@5.36.0-7+deb12u3` · aparece em 9 rodada(s)

Pacote: perl-modules-5.36 5.36.0-7+deb12u3
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: perl-IO-Compress: perl-IO-Compress: Denial of Service via malformed DOS date in zip header
Advisory: https://avd.aquasec.com/nvd/cve-2025-15649

## T0349 · alvo2 · trivy-image · MEDIUM

`stdlib@v1.20.5` · aparece em 9 rodada(s)

Pacote: stdlib v1.20.5
Versao corrigida: 1.23.12, 1.24.6
Status na fonte: fixed
Onde esta na imagem: app/extra/healthcheck
Titulo: os/exec: Unexpected paths returned from LookPath in os/exec
Advisory: https://avd.aquasec.com/nvd/cve-2025-47906

## T0350 · alvo2 · trivy-image · MEDIUM

`stdlib@v1.20.5` · aparece em 9 rodada(s)

Pacote: stdlib v1.20.5
Versao corrigida: 1.23.12, 1.24.6
Status na fonte: fixed
Onde esta na imagem: app/extra/healthcheck
Titulo: database/sql: Postgres Scan Race Condition
Advisory: https://avd.aquasec.com/nvd/cve-2025-47907

## T0351 · alvo2 · trivy-image · MEDIUM

`libavahi-client3@0.8-10+deb12u1` · aparece em 9 rodada(s)

Pacote: libavahi-client3 0.8-10+deb12u1
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: avahi: Avahi: Denial of Service via crafted mDNS/DNS-SD announcements
Advisory: https://avd.aquasec.com/nvd/cve-2025-68468

## T0352 · alvo2 · trivy-image · MEDIUM

`libavahi-common3@0.8-10+deb12u1` · aparece em 9 rodada(s)

Pacote: libavahi-common3 0.8-10+deb12u1
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: avahi: Avahi: Denial of Service via unsolicited CNAME announcements
Advisory: https://avd.aquasec.com/nvd/cve-2025-68471

## T0353 · alvo2 · trivy-image · MEDIUM · RETRIAGEM

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.53-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Incorrect security UI in Payments
Advisory: https://avd.aquasec.com/nvd/cve-2026-11001

## T0354 · alvo2 · trivy-image · MEDIUM

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.53-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: angle: Out of bounds read in ANGLE
Advisory: https://avd.aquasec.com/nvd/cve-2026-11004

## T0355 · alvo2 · trivy-image · MEDIUM

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.53-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Insufficient policy enforcement in Actor
Advisory: https://avd.aquasec.com/nvd/cve-2026-11018

## T0356 · alvo2 · trivy-image · MEDIUM

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.53-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: angle: Use after free in ANGLE
Advisory: https://avd.aquasec.com/nvd/cve-2026-11040

## T0357 · alvo2 · trivy-image · MEDIUM

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.53-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: angle: Use after free in ANGLE
Advisory: https://avd.aquasec.com/nvd/cve-2026-11065

## T0358 · alvo2 · trivy-image · MEDIUM

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.53-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: angle: Insufficient validation of untrusted input in ANGLE
Advisory: https://avd.aquasec.com/nvd/cve-2026-11066

## T0359 · alvo2 · trivy-image · MEDIUM

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.53-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Use after free in WebGL
Advisory: https://avd.aquasec.com/nvd/cve-2026-11073

## T0360 · alvo2 · trivy-image · MEDIUM

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.53-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Insufficient validation of untrusted input in Codecs
Advisory: https://avd.aquasec.com/nvd/cve-2026-11095

## T0361 · alvo2 · trivy-image · MEDIUM

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.53-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Inappropriate implementation in Keyboard
Advisory: https://avd.aquasec.com/nvd/cve-2026-11122

## T0362 · alvo2 · trivy-image · MEDIUM

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.53-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Insufficient data validation in Media
Advisory: https://avd.aquasec.com/nvd/cve-2026-11134

## T0363 · alvo2 · trivy-image · MEDIUM

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 149.0.7827.53-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Insufficient policy enforcement in CSS
Advisory: https://avd.aquasec.com/nvd/cve-2026-11155

## T0364 · alvo2 · trivy-image · MEDIUM · RETRIAGEM

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 150.0.7871.46-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: angle: Inappropriate implementation in ANGLE
Advisory: https://avd.aquasec.com/nvd/cve-2026-13859

## T0365 · alvo2 · trivy-image · MEDIUM

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 150.0.7871.46-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Inappropriate implementation in Network
Advisory: https://avd.aquasec.com/nvd/cve-2026-13868

## T0366 · alvo2 · trivy-image · MEDIUM

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 150.0.7871.46-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Inappropriate implementation in Geolocation
Advisory: https://avd.aquasec.com/nvd/cve-2026-14002

## T0367 · alvo2 · trivy-image · MEDIUM

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 150.0.7871.46-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: Insufficient data validation in Passwords
Advisory: https://avd.aquasec.com/nvd/cve-2026-14009

## T0368 · alvo2 · trivy-image · MEDIUM · RETRIAGEM

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 150.0.7871.46-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: chromium-browser: Out of bounds read in V8
Advisory: https://avd.aquasec.com/nvd/cve-2026-14406

## T0369 · alvo2 · trivy-image · MEDIUM

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 151.0.7922.71-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: chromium-browser: Insufficient validation of untrusted input in Payments
Advisory: https://avd.aquasec.com/nvd/cve-2026-17738

## T0370 · alvo2 · trivy-image · MEDIUM

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 151.0.7922.71-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: chromium-browser: Insufficient validation of untrusted input in Extensions
Advisory: https://avd.aquasec.com/nvd/cve-2026-17806

## T0371 · alvo2 · trivy-image · MEDIUM

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 151.0.7922.71-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: chromium-browser: Insufficient policy enforcement in ServiceWorker
Advisory: https://avd.aquasec.com/nvd/cve-2026-17824

## T0372 · alvo2 · trivy-image · MEDIUM

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 151.0.7922.71-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: chromium-browser: Inappropriate implementation in Passwords
Advisory: https://avd.aquasec.com/nvd/cve-2026-17833

## T0373 · alvo2 · trivy-image · MEDIUM

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 151.0.7922.71-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: chromium-browser: Insufficient validation of untrusted input in Cast
Advisory: https://avd.aquasec.com/nvd/cve-2026-17844

## T0374 · alvo2 · trivy-image · MEDIUM

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 151.0.7922.71-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: chromium-browser: Type Confusion in Tab
Advisory: https://avd.aquasec.com/nvd/cve-2026-17866

## T0375 · alvo2 · trivy-image · MEDIUM

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 151.0.7922.71-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: chromium-browser: Use after free in TabStrip
Advisory: https://avd.aquasec.com/nvd/cve-2026-17887

## T0376 · alvo2 · trivy-image · MEDIUM

`rsync@3.2.7-1+deb12u5` · aparece em 9 rodada(s)

Pacote: rsync 3.2.7-1+deb12u5
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: rsync: rsync: Denial of Service via out-of-bounds read with crafted checksum block
Advisory: https://avd.aquasec.com/nvd/cve-2026-53792

## T0377 · alvo2 · trivy-image · MEDIUM

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 152.0.7977.75-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: chromium-browser: chromium-browser: Incorrect authorization in Downloads
Advisory: https://avd.aquasec.com/nvd/cve-2026-78898

## T0378 · alvo2 · trivy-image · MEDIUM

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 153.0.8010.52-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: Missing authorization in Browser in Google Chrome prior to 153.0.8010. ...
Advisory: https://avd.aquasec.com/nvd/cve-2026-87556

## T0379 · alvo2 · trivy-image · UNKNOWN · RETRIAGEM

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 151.0.7922.71-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: Inappropriate implementation in Chrome for iOS in Google Chrome on iOS ...
Advisory: https://avd.aquasec.com/nvd/cve-2026-17669

## T0380 · alvo2 · trivy-image · UNKNOWN

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 152.0.7977.75-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: UI misrepresentation in Browser in Google Chrome prior to 152.0.7977.6 ...
Advisory: https://avd.aquasec.com/nvd/cve-2026-78912

## T0381 · alvo2 · trivy-image · UNKNOWN

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 152.0.7977.75-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: Use after free in Sync in Google Chrome on on iOS prior to 152.0.7977. ...
Advisory: https://avd.aquasec.com/nvd/cve-2026-78964

## T0382 · alvo2 · trivy-image · UNKNOWN

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 152.0.7977.75-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: Missing authorization in BFCache in Google Chrome prior to 152.0.7977. ...
Advisory: https://avd.aquasec.com/nvd/cve-2026-78967

## T0383 · alvo2 · trivy-image · UNKNOWN

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 152.0.7977.75-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: Observable discrepancy in Network in Google Chrome prior to 152.0.7977 ...
Advisory: https://avd.aquasec.com/nvd/cve-2026-79028

## T0384 · alvo2 · trivy-image · UNKNOWN

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 152.0.7977.75-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: Improper input validation in Sync in Google Chrome prior to 152.0.7977 ...
Advisory: https://avd.aquasec.com/nvd/cve-2026-79076

## T0385 · alvo2 · trivy-image · UNKNOWN

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 152.0.7977.75-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: Improper input validation in Mobile in Google Chrome on on iOS prior t ...
Advisory: https://avd.aquasec.com/nvd/cve-2026-79105

## T0386 · alvo2 · trivy-image · UNKNOWN

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 152.0.7977.75-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: Information leak in XR in Google Chrome prior to 152.0.7977.65 allowed ...
Advisory: https://avd.aquasec.com/nvd/cve-2026-79125

## T0387 · alvo2 · trivy-image · UNKNOWN

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 152.0.7977.75-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: Incorrect authorization in Web Authentication (Passkeys & Security Key ...
Advisory: https://avd.aquasec.com/nvd/cve-2026-79178

## T0388 · alvo2 · trivy-image · UNKNOWN

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 152.0.7977.75-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: Incorrect authorization in Browser in Google Chrome on on Android prio ...
Advisory: https://avd.aquasec.com/nvd/cve-2026-79225

## T0389 · alvo2 · trivy-image · UNKNOWN

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 152.0.7977.82-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: Use after free in DevTools in Google Chrome prior to 152.0.7977.82 all ...
Advisory: https://avd.aquasec.com/nvd/cve-2026-85042

## T0390 · alvo2 · trivy-image · UNKNOWN · RETRIAGEM

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 153.0.8010.52-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: Out of bounds write in WebGL in Google Chrome on on Android prior to 1 ...
Advisory: https://avd.aquasec.com/nvd/cve-2026-87438

## T0391 · alvo2 · trivy-image · UNKNOWN · RETRIAGEM

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 153.0.8010.52-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: Improper input validation in Passwords in Google Chrome prior to 153.0 ...
Advisory: https://avd.aquasec.com/nvd/cve-2026-87590

## T0392 · alvo2 · trivy-image · UNKNOWN

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 153.0.8010.52-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: Missing authorization in SiteIsolation in Google Chrome prior to 153.0 ...
Advisory: https://avd.aquasec.com/nvd/cve-2026-87606

## T0393 · alvo2 · trivy-image · UNKNOWN

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 153.0.8010.52-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: Incorrect authorization in Sources in Google Chrome prior to 153.0.801 ...
Advisory: https://avd.aquasec.com/nvd/cve-2026-87629

## T0394 · alvo2 · trivy-image · UNKNOWN

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: 153.0.8010.52-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: Incorrect authorization in Sources in Google Chrome prior to 153.0.801 ...
Advisory: https://avd.aquasec.com/nvd/cve-2026-87629

## T0395 · alvo2 · trivy-image · UNKNOWN

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: 153.0.8010.52-1~deb12u1
Status na fonte: fixed
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: Server-side request forgery in Omnibox in Google Chrome on on Android  ...
Advisory: https://avd.aquasec.com/nvd/cve-2026-93384

## T0396 · alvo2 · trivy-image · UNKNOWN

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium 148.0.7778.178-1~deb12u1
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: Title Not Available
Advisory: https://avd.aquasec.com/nvd/cve-2026-95289

## T0397 · alvo2 · trivy-image · UNKNOWN

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: Title Not Available
Advisory: https://avd.aquasec.com/nvd/cve-2026-95328

## T0398 · alvo2 · trivy-image · UNKNOWN

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

Pacote: chromium-common 148.0.7778.178-1~deb12u1
Versao corrigida: (nenhuma publicada)
Status na fonte: affected
Onde esta na imagem: tcc-uptimekuma:7ad02b7add541c8a54400cf27ec1b09de3aedb4f (debian 12.14)
Titulo: Title Not Available
Advisory: https://avd.aquasec.com/nvd/cve-2026-95341

## T0399 · alvo2 · zap · 1

`http://localhost:3001/api/status-page/servicos/manifest.json [x-content-type-options]` · aparece em 4 rodada(s)

Alerta: X-Content-Type-Options Header Missing (plugin 10021, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/api/status-page/servicos/manifest.json
Parametro: x-content-type-options
Ataque: -
Evidencia: -
Informacao adicional: This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.

## T0400 · alvo2 · zap · 1

`http://localhost:3001/apple-touch-icon.png [x-content-type-options]` · aparece em 6 rodada(s)

Alerta: X-Content-Type-Options Header Missing (plugin 10021, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/apple-touch-icon.png
Parametro: x-content-type-options
Ataque: -
Evidencia: -
Informacao adicional: This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.

## T0401 · alvo2 · zap · 1

`http://localhost:3001/icon.svg [x-content-type-options]` · aparece em 7 rodada(s)

Alerta: X-Content-Type-Options Header Missing (plugin 10021, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/icon.svg
Parametro: x-content-type-options
Ataque: -
Evidencia: -
Informacao adicional: This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.

## T0402 · alvo2 · zap · 1

`http://localhost:3001/manifest.json [x-content-type-options]` · aparece em 1 rodada(s)

Alerta: X-Content-Type-Options Header Missing (plugin 10021, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/manifest.json
Parametro: x-content-type-options
Ataque: -
Evidencia: -
Informacao adicional: This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.

## T0403 · alvo2 · zap · 1

`http://localhost:3001/robots.txt [x-content-type-options]` · aparece em 9 rodada(s)

Alerta: X-Content-Type-Options Header Missing (plugin 10021, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/robots.txt
Parametro: x-content-type-options
Ataque: -
Evidencia: -
Informacao adicional: This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.

## T0404 · alvo2 · zap · 1

`http://localhost:3001/sitemap.xml [x-content-type-options]` · aparece em 9 rodada(s)

Alerta: X-Content-Type-Options Header Missing (plugin 10021, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/sitemap.xml
Parametro: x-content-type-options
Ataque: -
Evidencia: -
Informacao adicional: This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.

## T0405 · alvo2 · zap · 1

`http://localhost:3001/status/servicos [x-content-type-options]` · aparece em 9 rodada(s)

Alerta: X-Content-Type-Options Header Missing (plugin 10021, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/status/servicos
Parametro: x-content-type-options
Ataque: -
Evidencia: -
Informacao adicional: This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.

## T0406 · alvo2 · zap · 1

`http://localhost:3001/assets/index-BiJ2MzwC.js` · aparece em 9 rodada(s)

Alerta: Permissions Policy Header Not Set (plugin 10063, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/assets/index-BiJ2MzwC.js
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

## T0407 · alvo2 · zap · 1 · RETRIAGEM

`http://localhost:3001/sitemap.xml` · aparece em 9 rodada(s)

Alerta: Permissions Policy Header Not Set (plugin 10063, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/sitemap.xml
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

## T0408 · alvo2 · zap · 1

`http://localhost:3001/status/servicos` · aparece em 9 rodada(s)

Alerta: Permissions Policy Header Not Set (plugin 10063, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/status/servicos
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

## T0409 · alvo2 · zap · 1

`http://localhost:3001/status` · aparece em 9 rodada(s)

Alerta: Permissions Policy Header Not Set (plugin 10063, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/status
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

## T0410 · alvo2 · zap · 1

`http://localhost:3001/assets/index-BiJ2MzwC.js` · aparece em 9 rodada(s)

Alerta: Dangerous JS Functions (plugin 10110, risco 1, confianca 1, CWE-749)
Requisicao: GET http://localhost:3001/assets/index-BiJ2MzwC.js
Parametro: -
Ataque: -
Evidencia: eval(
Informacao adicional: -

## T0411 · alvo2 · zap · 1

`http://localhost:3001/assets/index-BiJ2MzwC.js` · aparece em 9 rodada(s)

Alerta: Private IP Disclosure (plugin 2, risco 1, confianca 2, CWE-497)
Requisicao: GET http://localhost:3001/assets/index-BiJ2MzwC.js
Parametro: -
Ataque: -
Evidencia: 192.168.100.1
Informacao adicional: 192.168.100.1
192.168.100.1
192.168.100.1


## T0412 · alvo2 · zap · 1

`http://localhost:3001/api/status-page/servicos/manifest.json [Cross-Origin-Resource-Policy]` · aparece em 6 rodada(s)

Alerta: Cross-Origin-Resource-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/api/status-page/servicos/manifest.json
Parametro: Cross-Origin-Resource-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0413 · alvo2 · zap · 1

`http://localhost:3001/apple-touch-icon.png [Cross-Origin-Resource-Policy]` · aparece em 5 rodada(s)

Alerta: Cross-Origin-Resource-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/apple-touch-icon.png
Parametro: Cross-Origin-Resource-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0414 · alvo2 · zap · 1

`http://localhost:3001/icon.svg [Cross-Origin-Resource-Policy]` · aparece em 7 rodada(s)

Alerta: Cross-Origin-Resource-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/icon.svg
Parametro: Cross-Origin-Resource-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0415 · alvo2 · zap · 1

`http://localhost:3001/robots.txt [Cross-Origin-Resource-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Resource-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/robots.txt
Parametro: Cross-Origin-Resource-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0416 · alvo2 · zap · 1

`http://localhost:3001/sitemap.xml [Cross-Origin-Embedder-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Embedder-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/sitemap.xml
Parametro: Cross-Origin-Embedder-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0417 · alvo2 · zap · 1 · RETRIAGEM

`http://localhost:3001/sitemap.xml [Cross-Origin-Opener-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Opener-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/sitemap.xml
Parametro: Cross-Origin-Opener-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0418 · alvo2 · zap · 1

`http://localhost:3001/sitemap.xml [Cross-Origin-Resource-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Resource-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/sitemap.xml
Parametro: Cross-Origin-Resource-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0419 · alvo2 · zap · 1

`http://localhost:3001/status/servicos [Cross-Origin-Embedder-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Embedder-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/status/servicos
Parametro: Cross-Origin-Embedder-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0420 · alvo2 · zap · 1

`http://localhost:3001/status/servicos [Cross-Origin-Opener-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Opener-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/status/servicos
Parametro: Cross-Origin-Opener-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0421 · alvo2 · zap · 1

`http://localhost:3001/status/servicos [Cross-Origin-Resource-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Resource-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/status/servicos
Parametro: Cross-Origin-Resource-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

## T0422 · alvo2 · zap · 2

`http://localhost:3001/sitemap.xml` · aparece em 9 rodada(s)

Alerta: Content Security Policy (CSP) Header Not Set (plugin 10038, risco 2, confianca 3, CWE-693)
Requisicao: GET http://localhost:3001/sitemap.xml
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

## T0423 · alvo2 · zap · 2

`http://localhost:3001/status/servicos` · aparece em 9 rodada(s)

Alerta: Content Security Policy (CSP) Header Not Set (plugin 10038, risco 2, confianca 3, CWE-693)
Requisicao: GET http://localhost:3001/status/servicos
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

## T0424 · alvo2 · zap · 2

`http://localhost:3001/status` · aparece em 9 rodada(s)

Alerta: Content Security Policy (CSP) Header Not Set (plugin 10038, risco 2, confianca 3, CWE-693)
Requisicao: GET http://localhost:3001/status
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -
