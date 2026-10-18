# Revisao da classificacao da IA (D17)

Gerado por `analise/scripts/revisao_triagem.py gerar`. Regras usadas pela IA:
`docs/TRIAGEM-REGRAS.md`. Alvos locais para conferir: `analise/scripts/subir_alvos.sh`.

Como preencher (escreva depois dos dois-pontos; dentro ou fora do negrito funciona):

- **Revisao do grupo:** `ok` aceita a proposta da IA para todos os achados do
  grupo cuja revisao individual ficar em branco.
- **Revisao:** em um achado, `ok` aceita; `VP`, `FP`, `NE` ou `IND` altera.
- **Motivo:** obrigatorio quando alterar; uma frase.

Para ver o que falta: `python3 analise/scripts/revisao_triagem.py ler`.


# Grupo: alvo1 · semgrep · code-string-concat

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0001 · proposta IA: VP

**Justificativa IA:** username vem do perfil do usuario (editavel em /profile) e e passado a eval quando casa com #{...}; injecao de codigo no servidor (desafio de SSTI)

Evidencia: alvos/juice-shop/routes/userProfile.ts:57-65 username = user.username; code = username.substring(2, ...); username = eval(code)

Como verificar: `logado no Juice Shop, definir o username como #{7*7} em http://localhost:3000/profile e ver se a pagina exibe 49`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** NE
**Motivo:** desafio desativado em container (disabledEnv: Docker); codigo segue o caminho seguro nas rodadas


---

# Grupo: alvo1 · semgrep · express-sequelize-injection

6 achado(s); proposta da IA: 2 VP, 4 FP

**Revisao do grupo:** ok

## T0002 · proposta IA: FP

**Justificativa IA:** arquivo de data/static/codefixes/ e material do desafio de codigo, lido como texto por routes/vulnCodeFixes.ts para exibicao e nunca importado nem executado

Evidencia: alvos/juice-shop/data/static/codefixes/dbSchemaChallenge_1.ts:5; routes/vulnCodeFixes.ts:9 FixesDir = data/static/codefixes (fs.readFileSync); nenhum import de codefixes/ no codigo

Como verificar: `grep -rn 'codefixes' alvos/juice-shop/routes alvos/juice-shop/server.ts alvos/juice-shop/lib (so leitura de arquivo, nenhum import)`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0003 · proposta IA: FP

**Justificativa IA:** arquivo de data/static/codefixes/ e material do desafio de codigo, lido como texto por routes/vulnCodeFixes.ts para exibicao e nunca importado nem executado

Evidencia: alvos/juice-shop/data/static/codefixes/dbSchemaChallenge_3.ts:11; routes/vulnCodeFixes.ts:9 FixesDir = data/static/codefixes (fs.readFileSync); nenhum import de codefixes/ no codigo

Como verificar: `grep -rn 'codefixes' alvos/juice-shop/routes alvos/juice-shop/server.ts alvos/juice-shop/lib (so leitura de arquivo, nenhum import)`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0004 · proposta IA: FP

**Justificativa IA:** arquivo de data/static/codefixes/ e material do desafio de codigo, lido como texto por routes/vulnCodeFixes.ts para exibicao e nunca importado nem executado

Evidencia: alvos/juice-shop/data/static/codefixes/unionSqlInjectionChallenge_1.ts:6; routes/vulnCodeFixes.ts:9 FixesDir = data/static/codefixes (fs.readFileSync); nenhum import de codefixes/ no codigo

Como verificar: `grep -rn 'codefixes' alvos/juice-shop/routes alvos/juice-shop/server.ts alvos/juice-shop/lib (so leitura de arquivo, nenhum import)`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0005 · proposta IA: FP

**Justificativa IA:** arquivo de data/static/codefixes/ e material do desafio de codigo, lido como texto por routes/vulnCodeFixes.ts para exibicao e nunca importado nem executado

Evidencia: alvos/juice-shop/data/static/codefixes/unionSqlInjectionChallenge_3.ts:10; routes/vulnCodeFixes.ts:9 FixesDir = data/static/codefixes (fs.readFileSync); nenhum import de codefixes/ no codigo

Como verificar: `grep -rn 'codefixes' alvos/juice-shop/routes alvos/juice-shop/server.ts alvos/juice-shop/lib (so leitura de arquivo, nenhum import)`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0006 · proposta IA: VP

**Justificativa IA:** req.body.email e interpolado direto no SQL bruto do login, sem parametrizacao; rota POST /rest/user/login ativa

Evidencia: alvos/juice-shop/routes/login.ts:34 sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' ...`)

Como verificar: `curl -s -X POST localhost:3000/rest/user/login -H 'Content-Type: application/json' -d '{"email":"admin@juice-sh.op'"'"'--","password":"x"}' (retorna token = login sem senha)`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0007 · proposta IA: VP

**Justificativa IA:** req.query.q e interpolado direto no SQL bruto da busca, sem parametrizacao; rota GET /rest/products/search ativa

Evidencia: alvos/juice-shop/routes/search.ts:21-23 criteria = req.query.q; sequelize.query(`... LIKE '%${criteria}%' ...`)

Como verificar: `curl -s "localhost:3000/rest/products/search?q=%27))--" (retorna todos os produtos ou erro SQL, sinal de injecao)`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · semgrep · gha-curl-pipe-shell

1 achado(s); proposta da IA: 1 NE

**Revisao do grupo:** ok

## T0008 · proposta IA: NE

**Justificativa IA:** curl https://cli-assets.heroku.com/install.sh | sh executa script remoto sem verificacao de integridade; a condicao existe, mas no CI do projeto upstream, que nao integra o artefato entregue (a imagem da aplicacao)

Evidencia: alvos/juice-shop/.github/workflows/ci.yml:359

Como verificar: `sed -n 359p alvos/juice-shop/.github/workflows/ci.yml`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · semgrep · run-shell-injection

5 achado(s); proposta da IA: 5 FP

**Revisao do grupo:** ok

## T0009 · proposta IA: FP

**Justificativa IA:** github.ref_name interpolado no run, mas o workflow so dispara em push para master/develop e workflow_dispatch, entao o valor e definido por quem tem escrita no repositorio, nao por atacante externo

Evidencia: alvos/juice-shop/.github/workflows/update-challenges-ebook.yml:22 run com ${{ github.ref_name }}; gatilho on: push branches [master, develop] e workflow_dispatch

Como verificar: `sed -n '/^on:/,/^jobs:/p' alvos/juice-shop/.github/workflows/update-challenges-ebook.yml`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0010 · proposta IA: FP

**Justificativa IA:** github.ref_name interpolado no run, mas o workflow so dispara em push para master/develop e workflow_dispatch, entao o valor e definido por quem tem escrita no repositorio, nao por atacante externo

Evidencia: alvos/juice-shop/.github/workflows/update-challenges-www-legacy.yml:27 run com ${{ github.ref_name }}; gatilho on: push branches [master, develop] e workflow_dispatch

Como verificar: `sed -n '/^on:/,/^jobs:/p' alvos/juice-shop/.github/workflows/update-challenges-www-legacy.yml`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0011 · proposta IA: FP

**Justificativa IA:** github.ref_name interpolado no run, mas o workflow so dispara em push para master/develop e workflow_dispatch, entao o valor e definido por quem tem escrita no repositorio, nao por atacante externo

Evidencia: alvos/juice-shop/.github/workflows/update-challenges-www-legacy.yml:36 run com ${{ github.ref_name }}; gatilho on: push branches [master, develop] e workflow_dispatch

Como verificar: `sed -n '/^on:/,/^jobs:/p' alvos/juice-shop/.github/workflows/update-challenges-www-legacy.yml`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0012 · proposta IA: FP

**Justificativa IA:** github.ref_name interpolado no run, mas o workflow so dispara em push para master/develop e workflow_dispatch, entao o valor e definido por quem tem escrita no repositorio, nao por atacante externo

Evidencia: alvos/juice-shop/.github/workflows/update-challenges-www.yml:27 run com ${{ github.ref_name }}; gatilho on: push branches [master, develop] e workflow_dispatch

Como verificar: `sed -n '/^on:/,/^jobs:/p' alvos/juice-shop/.github/workflows/update-challenges-www.yml`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0013 · proposta IA: FP

**Justificativa IA:** github.ref_name interpolado no run, mas o workflow so dispara em push para master/develop e workflow_dispatch, entao o valor e definido por quem tem escrita no repositorio, nao por atacante externo

Evidencia: alvos/juice-shop/.github/workflows/update-challenges-www.yml:36 run com ${{ github.ref_name }}; gatilho on: push branches [master, develop] e workflow_dispatch

Como verificar: `sed -n '/^on:/,/^jobs:/p' alvos/juice-shop/.github/workflows/update-challenges-www.yml`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · semgrep · npm-missing-minimum-release-age

2 achado(s); proposta da IA: 2 NE

**Revisao do grupo:** ok

## T0014 · proposta IA: NE

**Justificativa IA:** .npmrc nao define min-release-age, mas e endurecimento de cadeia de suprimentos; no experimento as dependencias foram congeladas por data de corte (D14)

Evidencia: alvos/juice-shop/.npmrc:1 package-lock=false, sem min-release-age; ci/alvos/juice-shop.Dockerfile npm_config_before=2026-09-23T18:27:00Z

Como verificar: `cat alvos/juice-shop/.npmrc; grep npm_config_before ci/alvos/juice-shop.Dockerfile`

<details><summary>Dados da ferramenta</summary>

`alvos/juice-shop/.npmrc:1` · aparece em 9 rodada(s)

Regra: package_managers.npm.npm-missing-minimum-release-age.npm-missing-minimum-release-age
Mensagem: This .npmrc does not set a minimum release age or sets it too low. Newly published packages can be malicious or unstable. Add `min-release-age = 7` to wait 7 days before resolving newly published package versions. Added in: v11.10 Reference: https://github.blog/changelog/2026-02-18-npm-bulk-trusted-publishing-config-and-script-security-now-generally-available/

```
>    1 | package-lock=false
```

</details>

**Revisao:** 
**Motivo:** 

## T0015 · proposta IA: NE

**Justificativa IA:** .npmrc do frontend nao define min-release-age, mas e endurecimento de cadeia de suprimentos; no experimento as dependencias foram congeladas por data de corte (D14)

Evidencia: alvos/juice-shop/frontend/.npmrc:1 package-lock=false, sem min-release-age

Como verificar: `cat alvos/juice-shop/frontend/.npmrc; grep npm_config_before ci/alvos/juice-shop.Dockerfile`

<details><summary>Dados da ferramenta</summary>

`alvos/juice-shop/frontend/.npmrc:1` · aparece em 9 rodada(s)

Regra: package_managers.npm.npm-missing-minimum-release-age.npm-missing-minimum-release-age
Mensagem: This .npmrc does not set a minimum release age or sets it too low. Newly published packages can be malicious or unstable. Add `min-release-age = 7` to wait 7 days before resolving newly published package versions. Added in: v11.10 Reference: https://github.blog/changelog/2026-02-18-npm-bulk-trusted-publishing-config-and-script-security-now-generally-available/

```
>    1 | package-lock=false
```

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · semgrep · unquoted-attribute-var

3 achado(s); proposta da IA: 2 FP, 1 NE

**Revisao do grupo:** ok

## T0016 · proposta IA: FP

**Justificativa IA:** template Angular: alt={{applicationName}} vira property binding compilado pelo Angular, nao concatenacao de HTML; nao ha como sair do atributo

Evidencia: alvos/juice-shop/frontend/src/app/navbar/navbar.component.html:17 <img ... alt={{applicationName}}>

Como verificar: `no navegador, inspecionar o <img class="logo"> em http://localhost:3000 e ver que alt recebe o texto como propriedade`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0017 · proposta IA: FP

**Justificativa IA:** template Angular: alt={{element.name}} vira property binding compilado pelo Angular, nao concatenacao de HTML; nao ha como sair do atributo

Evidencia: alvos/juice-shop/frontend/src/app/purchase-basket/purchase-basket.component.html:15 <img ... alt={{element.name}}>

Como verificar: `idem T0016, na pagina do carrinho`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0018 · proposta IA: NE

**Justificativa IA:** placeholder={{userEmail}} sem aspas existe, mas o {{ }} do Handlebars escapa sinal de igual, aspas, crase e < >, o que impede injetar atributo com valor (event handler)

Evidencia: alvos/juice-shop/views/dataErasureForm.hbs:38 placeholder={{userEmail}}; routes/dataErasure.ts:50 res.render(dataErasureForm, {userEmail: email})

Como verificar: `logado, abrir http://localhost:3000/dataerasure e ver no HTML que = e aspas do e-mail saem como entidades`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · semgrep · express-check-directory-listing

5 achado(s); proposta da IA: 4 VP, 1 NE

**Revisao do grupo:** ok

## T0019 · proposta IA: VP

**Justificativa IA:** listagem de diretorio de /infrastructure expoe o Terraform do projeto, incluindo networking.tf com chave privada RSA

Evidencia: alvos/juice-shop/server.ts:268 serveIndex(infrastructure); GET /infrastructure/ 200 lista terraform/; GET /infrastructure/terraform/networking.tf 200

Como verificar: `curl -s localhost:3000/infrastructure/terraform/ | grep -o 'title="[^"]*"'`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0020 · proposta IA: VP

**Justificativa IA:** listagem de /ftp expoe arquivos confidenciais (acquisitions.md, backups, incident-support.kdbx); desafio directoryListingChallenge

Evidencia: alvos/juice-shop/server.ts:288 serveIndex(ftp) // vuln-line directoryListingChallenge; GET /ftp/ 200

Como verificar: `curl -s localhost:3000/ftp/ | grep -o 'title="[^"]*"'`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0021 · proposta IA: NE

**Justificativa IA:** listagem de /.well-known existe, mas o diretorio so contem conteudo publico por definicao (security.txt, csaf)

Evidencia: alvos/juice-shop/server.ts:292 serveIndex(.well-known); GET /.well-known/ 200 lista csaf e security.txt

Como verificar: `curl -s localhost:3000/.well-known/ | grep -o 'title="[^"]*"'`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0022 · proposta IA: VP

**Justificativa IA:** listagem de /encryptionkeys expoe jwt.pub e premium.key, chave usada para destravar conteudo premium

Evidencia: alvos/juice-shop/server.ts:296 serveIndex(encryptionkeys); GET /encryptionkeys/ 200 lista jwt.pub e premium.key

Como verificar: `curl -s localhost:3000/encryptionkeys/ | grep -o 'title="[^"]*"'`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0023 · proposta IA: VP

**Justificativa IA:** listagem de /support/logs expoe logs de acesso da aplicacao; desafio accessLogDisclosureChallenge

Evidencia: alvos/juice-shop/server.ts:300 serveIndex(logs) // vuln-line accessLogDisclosureChallenge; GET /support/logs/ 200 lista access.log

Como verificar: `curl -s localhost:3000/support/logs/ | grep -o 'title="[^"]*"'`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · semgrep · express-open-redirect

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0024 · proposta IA: VP

**Justificativa IA:** redirect com destino do usuario; a allowlist usa includes() e e contornada colocando a URL permitida dentro de outra

Evidencia: alvos/juice-shop/routes/redirect.ts:18 res.redirect(toUrl) apos isRedirectAllowed (includes); GET /redirect?to=https://evil.example/?x=https://github.com/juice-shop/juice-shop -> 302 para evil.example

Como verificar: `curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" "localhost:3000/redirect?to=https://evil.example/?x=https://github.com/juice-shop/juice-shop"`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · semgrep · express-res-sendfile

4 achado(s); proposta da IA: 1 VP, 3 NE

**Revisao do grupo:** ok 

## T0025 · proposta IA: VP

**Justificativa IA:** nome de arquivo do usuario chega a sendFile; a restricao de extensao .md/.pdf e contornada com null byte (%2500), liberando arquivos proibidos

Evidencia: alvos/juice-shop/routes/fileServer.ts:32 res.sendFile(path.resolve(ftp/, file)); GET /ftp/package.json.bak%2500.md -> 200

Como verificar: `curl -s -o /dev/null -w "%{http_code}\n" localhost:3000/ftp/package.json.bak%2500.md`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0026 · proposta IA: NE

**Justificativa IA:** nome de arquivo do usuario chega a sendFile, mas a checagem de / impede sair de encryptionkeys/; ler arquivos do proprio diretorio e a funcao da rota

Evidencia: alvos/juice-shop/routes/keyServer.ts:13-14 if (!file.includes('/')) res.sendFile(path.resolve('encryptionkeys/', file)); GET /encryptionkeys/..%2fpackage.json -> 403

Como verificar: `curl -s -o /dev/null -w "%{http_code}\n" localhost:3000/encryptionkeys/..%2fpackage.json (403 = bloqueado)`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0027 · proposta IA: NE

**Justificativa IA:** nome de arquivo do usuario chega a sendFile, mas a checagem de / impede sair de logs/; ler arquivos do proprio diretorio e a funcao da rota

Evidencia: alvos/juice-shop/routes/logfileServer.ts:13-14 if (!file.includes('/')) res.sendFile(path.resolve('logs/', file)); GET /encryptionkeys/..%2fpackage.json -> 403

Como verificar: `curl -s -o /dev/null -w "%{http_code}\n" localhost:3000/encryptionkeys/..%2fpackage.json (403 = bloqueado)`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0028 · proposta IA: NE

**Justificativa IA:** nome de arquivo do usuario chega a sendFile, mas a checagem de / impede sair de ftp/quarantine/; ler arquivos do proprio diretorio e a funcao da rota

Evidencia: alvos/juice-shop/routes/quarantineServer.ts:13-14 if (!file.includes('/')) res.sendFile(path.resolve('ftp/quarantine/', file)); GET /encryptionkeys/..%2fpackage.json -> 403

Como verificar: `curl -s -o /dev/null -w "%{http_code}\n" localhost:3000/encryptionkeys/..%2fpackage.json (403 = bloqueado)`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · semgrep · unknown-value-in-redirect

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0029 · proposta IA: VP

**Justificativa IA:** mesma linha do T0024 por outra regra: destino do redirect vem do usuario e a allowlist e contornavel

Evidencia: alvos/juice-shop/routes/redirect.ts:18 res.redirect(toUrl); bypass com URL permitida dentro de outra -> 302 para evil.example

Como verificar: `idem T0024`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · semgrep · hardcoded-jwt-secret

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0030 · proposta IA: VP

**Justificativa IA:** jwt.sign usa privateKey embutida no codigo-fonte; quem le o codigo forja tokens RS256 validos

Evidencia: alvos/juice-shop/lib/insecurity.ts:21 const privateKey = "-----BEGIN RSA PRIVATE KEY-----..."; linha 54 jwt.sign(user, privateKey, RS256)

Como verificar: `grep -n privateKey alvos/juice-shop/lib/insecurity.ts`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · semgrep · unknown-value-with-script-tag

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0031 · proposta IA: VP

**Justificativa IA:** conteudo do arquivo de legendas e inserido sem escape dentro de <script>; com escrita do arquivo (upload zip slip do Juice Shop) vira XSS; desafio videoXssChallenge

Evidencia: alvos/juice-shop/routes/videoHandler.ts:71 replace(<script id=subtitle>, ... + subs + </script>); linha 57 solveIf(videoXssChallenge, subs.includes(</script><script>alert...))

Como verificar: `sed -n 50,72p alvos/juice-shop/routes/videoHandler.ts (subs concatenado sem escape)`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** NE
**Motivo:** desafio desativado em container (disabledEnv: Docker); codigo segue o caminho seguro nas rodadas


---

# Grupo: alvo1 · semgrep · aws-subnet-has-public-ip-address

5 achado(s); proposta da IA: 3 FP, 2 NE

**Revisao do grupo:** ok

## T0032 · proposta IA: FP

**Justificativa IA:** arquivo de data/static/codefixes/ e material do desafio de codigo, lido como texto por routes/vulnCodeFixes.ts para exibicao e nunca importado nem executado

Evidencia: alvos/juice-shop/data/static/codefixes/iacLeakedKeyChallenge_1.tf:17; routes/vulnCodeFixes.ts:9 FixesDir = data/static/codefixes (fs.readFileSync); nenhum import de codefixes/ no codigo

Como verificar: `grep -rn 'codefixes' alvos/juice-shop/routes alvos/juice-shop/server.ts alvos/juice-shop/lib (so leitura de arquivo, nenhum import)`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0033 · proposta IA: FP

**Justificativa IA:** arquivo de data/static/codefixes/ e material do desafio de codigo, lido como texto por routes/vulnCodeFixes.ts para exibicao e nunca importado nem executado

Evidencia: alvos/juice-shop/data/static/codefixes/iacLeakedKeyChallenge_2.tf:17; routes/vulnCodeFixes.ts:9 FixesDir = data/static/codefixes (fs.readFileSync); nenhum import de codefixes/ no codigo

Como verificar: `grep -rn 'codefixes' alvos/juice-shop/routes alvos/juice-shop/server.ts alvos/juice-shop/lib (so leitura de arquivo, nenhum import)`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0034 · proposta IA: FP

**Justificativa IA:** arquivo de data/static/codefixes/ e material do desafio de codigo, lido como texto por routes/vulnCodeFixes.ts para exibicao e nunca importado nem executado

Evidencia: alvos/juice-shop/data/static/codefixes/iacLeakedKeyChallenge_3_correct.tf:17; routes/vulnCodeFixes.ts:9 FixesDir = data/static/codefixes (fs.readFileSync); nenhum import de codefixes/ no codigo

Como verificar: `grep -rn 'codefixes' alvos/juice-shop/routes alvos/juice-shop/server.ts alvos/juice-shop/lib (so leitura de arquivo, nenhum import)`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0035 · proposta IA: NE

**Justificativa IA:** subnet publica com IP publico existe no Terraform, mas e o desenho esperado para subnet publica e o Terraform nao e implantado no artefato avaliado

Evidencia: alvos/juice-shop/infrastructure/terraform/networking.tf:18 resource aws_subnet public (map_public_ip_on_launch)

Como verificar: `sed -n 18,30p alvos/juice-shop/infrastructure/terraform/networking.tf`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0036 · proposta IA: NE

**Justificativa IA:** subnet publica com IP publico existe no Terraform, mas e o desenho esperado para subnet publica e o Terraform nao e implantado no artefato avaliado

Evidencia: alvos/juice-shop/terraform/networking.tf:18 resource aws_subnet public (map_public_ip_on_launch)

Como verificar: `sed -n 18,30p alvos/juice-shop/terraform/networking.tf`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · semgrep · insecure-load-balancer-tls-version

5 achado(s); proposta da IA: 3 FP, 2 NE

**Revisao do grupo:** ok

## T0037 · proposta IA: FP

**Justificativa IA:** arquivo de data/static/codefixes/ e material do desafio de codigo, lido como texto por routes/vulnCodeFixes.ts para exibicao e nunca importado nem executado

Evidencia: alvos/juice-shop/data/static/codefixes/iacLeakedKeyChallenge_1.tf:159; routes/vulnCodeFixes.ts:9 FixesDir = data/static/codefixes (fs.readFileSync); nenhum import de codefixes/ no codigo

Como verificar: `grep -rn 'codefixes' alvos/juice-shop/routes alvos/juice-shop/server.ts alvos/juice-shop/lib (so leitura de arquivo, nenhum import)`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0038 · proposta IA: FP

**Justificativa IA:** arquivo de data/static/codefixes/ e material do desafio de codigo, lido como texto por routes/vulnCodeFixes.ts para exibicao e nunca importado nem executado

Evidencia: alvos/juice-shop/data/static/codefixes/iacLeakedKeyChallenge_2.tf:159; routes/vulnCodeFixes.ts:9 FixesDir = data/static/codefixes (fs.readFileSync); nenhum import de codefixes/ no codigo

Como verificar: `grep -rn 'codefixes' alvos/juice-shop/routes alvos/juice-shop/server.ts alvos/juice-shop/lib (so leitura de arquivo, nenhum import)`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0039 · proposta IA: FP

**Justificativa IA:** arquivo de data/static/codefixes/ e material do desafio de codigo, lido como texto por routes/vulnCodeFixes.ts para exibicao e nunca importado nem executado

Evidencia: alvos/juice-shop/data/static/codefixes/iacLeakedKeyChallenge_3_correct.tf:159; routes/vulnCodeFixes.ts:9 FixesDir = data/static/codefixes (fs.readFileSync); nenhum import de codefixes/ no codigo

Como verificar: `grep -rn 'codefixes' alvos/juice-shop/routes alvos/juice-shop/server.ts alvos/juice-shop/lib (so leitura de arquivo, nenhum import)`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0040 · proposta IA: NE

**Justificativa IA:** listener HTTP sem TLS existe no Terraform, mas o Terraform nao e implantado no artefato avaliado (a aplicacao roda direto do container)

Evidencia: alvos/juice-shop/infrastructure/terraform/networking.tf:160 aws_lb_listener http port 80 protocol HTTP

Como verificar: `sed -n 155,165p alvos/juice-shop/infrastructure/terraform/networking.tf`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0041 · proposta IA: NE

**Justificativa IA:** listener HTTP sem TLS existe no Terraform, mas o Terraform nao e implantado no artefato avaliado (a aplicacao roda direto do container)

Evidencia: alvos/juice-shop/terraform/networking.tf:160 aws_lb_listener http port 80 protocol HTTP

Como verificar: `sed -n 155,165p alvos/juice-shop/terraform/networking.tf`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · semgrep · github-actions-mutable-action-tag

7 achado(s); proposta da IA: 7 NE

**Revisao do grupo:** ok

## T0042 · proposta IA: NE

**Justificativa IA:** coverallsapp/github-action@v2 por tag mutavel; a condicao existe, mas no CI do projeto upstream, que nao integra o artefato entregue (a imagem da aplicacao)

Evidencia: alvos/juice-shop/.github/workflows/ci.yml:188

Como verificar: `sed -n 188p alvos/juice-shop/.github/workflows/ci.yml`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0043 · proposta IA: NE

**Justificativa IA:** github/codeql-action/init@v3 por tag mutavel; a condicao existe, mas no CI do projeto upstream, que nao integra o artefato entregue (a imagem da aplicacao)

Evidencia: alvos/juice-shop/.github/workflows/codeql-analysis.yml:23

Como verificar: `sed -n 23p alvos/juice-shop/.github/workflows/codeql-analysis.yml`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0044 · proposta IA: NE

**Justificativa IA:** github/codeql-action/autobuild@v3 por tag mutavel; a condicao existe, mas no CI do projeto upstream, que nao integra o artefato entregue (a imagem da aplicacao)

Evidencia: alvos/juice-shop/.github/workflows/codeql-analysis.yml:34

Como verificar: `sed -n 34p alvos/juice-shop/.github/workflows/codeql-analysis.yml`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0045 · proposta IA: NE

**Justificativa IA:** github/codeql-action/analyze@v3 por tag mutavel; a condicao existe, mas no CI do projeto upstream, que nao integra o artefato entregue (a imagem da aplicacao)

Evidencia: alvos/juice-shop/.github/workflows/codeql-analysis.yml:36

Como verificar: `sed -n 36p alvos/juice-shop/.github/workflows/codeql-analysis.yml`

<details><summary>Dados da ferramenta</summary>

`alvos/juice-shop/.github/workflows/codeql-analysis.yml:36` · aparece em 9 rodada(s)

Regra: yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag
Mensagem: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

```
    33 |     - name: Autobuild
    34 |       uses: github/codeql-action/autobuild@v3
    35 |     - name: Perform CodeQL Analysis
>   36 |       uses: github/codeql-action/analyze@v3
```

</details>

**Revisao:** 
**Motivo:** 

## T0046 · proposta IA: NE

**Justificativa IA:** actions/checkout@v6 por tag mutavel; a condicao existe, mas no CI do projeto upstream, que nao integra o artefato entregue (a imagem da aplicacao)

Evidencia: alvos/juice-shop/.github/workflows/image_actions.yml:30

Como verificar: `sed -n 30p alvos/juice-shop/.github/workflows/image_actions.yml`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0047 · proposta IA: NE

**Justificativa IA:** calibreapp/image-actions@main por branch mutavel; a condicao existe, mas no CI do projeto upstream, que nao integra o artefato entregue (a imagem da aplicacao)

Evidencia: alvos/juice-shop/.github/workflows/image_actions.yml:33

Como verificar: `sed -n 33p alvos/juice-shop/.github/workflows/image_actions.yml`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0048 · proposta IA: NE

**Justificativa IA:** peter-evans/create-pull-request@v8 por tag mutavel; a condicao existe, mas no CI do projeto upstream, que nao integra o artefato entregue (a imagem da aplicacao)

Evidencia: alvos/juice-shop/.github/workflows/image_actions.yml:42

Como verificar: `sed -n 42p alvos/juice-shop/.github/workflows/image_actions.yml`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-config · DS-0026

1 achado(s); proposta da IA: 1 NE

**Revisao do grupo:** ok 

## T0049 · proposta IA: NE

**Justificativa IA:** Dockerfile do Juice Shop realmente nao define HEALTHCHECK, mas e boa pratica operacional (disponibilidade), sem impacto de seguranca exploravel

Evidencia: alvos/juice-shop/Dockerfile: nenhuma instrucao HEALTHCHECK nos dois estagios (installer e distroless)

Como verificar: `grep -n HEALTHCHECK alvos/juice-shop/Dockerfile (sem saida = ausente)`

<details><summary>Dados da ferramenta</summary>

`Dockerfile:None` · aparece em 9 rodada(s)

Regra: DS-0026 (No HEALTHCHECK defined)
Arquivo: Dockerfile
Mensagem: Add HEALTHCHECK instruction in your Dockerfile
Resolucao sugerida pela ferramenta: Add HEALTHCHECK instruction in Dockerfile

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-config · DS-0001

1 achado(s); proposta da IA: 1 NE

**Revisao do grupo:** ok

## T0050 · proposta IA: NE

**Justificativa IA:** FROM sem tag/digest existe no Dockerfile original, mas no build do experimento a imagem base e fixada por digest via --build-context (D13)

Evidencia: alvos/juice-shop/Dockerfile:22 FROM gcr.io/distroless/nodejs24-debian13; ci/perfis/alvo1-juiceshop.env ALVO_BASES fixa @sha256:b1fc3324...

Como verificar: `sed -n 22p alvos/juice-shop/Dockerfile; grep ALVO_BASES ci/perfis/alvo1-juiceshop.env`

<details><summary>Dados da ferramenta</summary>

`Dockerfile:22` · aparece em 9 rodada(s)

Regra: DS-0001 (':latest' tag used)
Arquivo: Dockerfile
Mensagem: Specify a tag in the 'FROM' statement for image 'gcr.io/distroless/nodejs24-debian13'
Resolucao sugerida pela ferramenta: Add a tag to the image in the 'FROM' statement

```
   22 | FROM gcr.io/distroless/nodejs24-debian13
```

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · jsonwebtoken

10 achado(s); proposta da IA: 10 VP

**Revisao do grupo:** ok

## T0051 · proposta IA: VP

**Justificativa IA:** jsonwebtoken 0.1.0 presente na imagem e dentro da faixa afetada (< 4.2.2)

Evidencia: /juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json version 0.1.0; CVE-2015-9235 (GHSA-c7hr-j4mj-j2w6) faixa < 4.2.2

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-c7hr-j4mj-j2w6`

<details><summary>Dados da ferramenta</summary>

`jsonwebtoken@0.1.0` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0052 · proposta IA: VP

**Justificativa IA:** jsonwebtoken 0.4.0 presente na imagem e dentro da faixa afetada (< 4.2.2)

Evidencia: /juice-shop/node_modules/jsonwebtoken/package.json version 0.4.0; CVE-2015-9235 (GHSA-c7hr-j4mj-j2w6) faixa < 4.2.2

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/jsonwebtoken/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-c7hr-j4mj-j2w6`

<details><summary>Dados da ferramenta</summary>

`jsonwebtoken@0.4.0` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0064 · proposta IA: VP

**Justificativa IA:** jsonwebtoken 0.1.0 presente na imagem e dentro da faixa afetada (<= 8.5.1)

Evidencia: /juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json version 0.1.0; CVE-2022-23539 (GHSA-8cf7-32gw-wr33) faixa <= 8.5.1

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-8cf7-32gw-wr33`

<details><summary>Dados da ferramenta</summary>

`jsonwebtoken@0.1.0` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0065 · proposta IA: VP

**Justificativa IA:** jsonwebtoken 0.4.0 presente na imagem e dentro da faixa afetada (<= 8.5.1)

Evidencia: /juice-shop/node_modules/jsonwebtoken/package.json version 0.4.0; CVE-2022-23539 (GHSA-8cf7-32gw-wr33) faixa <= 8.5.1

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/jsonwebtoken/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-8cf7-32gw-wr33`

<details><summary>Dados da ferramenta</summary>

`jsonwebtoken@0.4.0` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0096 · proposta IA: VP

**Justificativa IA:** jsonwebtoken 0.1.0 presente na imagem, abaixo da versao corrigida >=4.2.2 (advisory antigo do Node Security WG)

Evidencia: /juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json version 0.1.0; NSWG-ECO-17 corrigido em >=4.2.2

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json - | tar -xO | grep '"version"'  e comparar com a versao corrigida >=4.2.2`

<details><summary>Dados da ferramenta</summary>

`jsonwebtoken@0.1.0` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0097 · proposta IA: VP

**Justificativa IA:** jsonwebtoken 0.4.0 presente na imagem, abaixo da versao corrigida >=4.2.2 (advisory antigo do Node Security WG)

Evidencia: /juice-shop/node_modules/jsonwebtoken/package.json version 0.4.0; NSWG-ECO-17 corrigido em >=4.2.2

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/jsonwebtoken/package.json - | tar -xO | grep '"version"'  e comparar com a versao corrigida >=4.2.2`

<details><summary>Dados da ferramenta</summary>

`jsonwebtoken@0.4.0` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0118 · proposta IA: VP

**Justificativa IA:** jsonwebtoken 0.1.0 presente na imagem e dentro da faixa afetada (< 9.0.0)

Evidencia: /juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json version 0.1.0; CVE-2022-23540 (GHSA-qwph-4952-7xr6) faixa < 9.0.0

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-qwph-4952-7xr6`

<details><summary>Dados da ferramenta</summary>

`jsonwebtoken@0.1.0` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0119 · proposta IA: VP

**Justificativa IA:** jsonwebtoken 0.4.0 presente na imagem e dentro da faixa afetada (< 9.0.0)

Evidencia: /juice-shop/node_modules/jsonwebtoken/package.json version 0.4.0; CVE-2022-23540 (GHSA-qwph-4952-7xr6) faixa < 9.0.0

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/jsonwebtoken/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-qwph-4952-7xr6`

<details><summary>Dados da ferramenta</summary>

`jsonwebtoken@0.4.0` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0120 · proposta IA: VP

**Justificativa IA:** jsonwebtoken 0.1.0 presente na imagem e dentro da faixa afetada (<= 8.5.1)

Evidencia: /juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json version 0.1.0; CVE-2022-23541 (GHSA-hjrf-2m68-5959) faixa <= 8.5.1

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-hjrf-2m68-5959`

<details><summary>Dados da ferramenta</summary>

`jsonwebtoken@0.1.0` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0121 · proposta IA: VP

**Justificativa IA:** jsonwebtoken 0.4.0 presente na imagem e dentro da faixa afetada (<= 8.5.1)

Evidencia: /juice-shop/node_modules/jsonwebtoken/package.json version 0.4.0; CVE-2022-23541 (GHSA-hjrf-2m68-5959) faixa <= 8.5.1

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/jsonwebtoken/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-hjrf-2m68-5959`

<details><summary>Dados da ferramenta</summary>

`jsonwebtoken@0.4.0` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · lodash

5 achado(s); proposta da IA: 5 VP

**Revisao do grupo:** ok

## T0053 · proposta IA: VP

**Justificativa IA:** lodash 2.4.2 presente na imagem e dentro da faixa afetada (< 4.17.12)

Evidencia: /juice-shop/node_modules/sanitize-html/node_modules/lodash/package.json version 2.4.2; CVE-2019-10744 (GHSA-jf85-cpcp-j695) faixa < 4.17.12

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sanitize-html/node_modules/lodash/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-jf85-cpcp-j695`

<details><summary>Dados da ferramenta</summary>

`lodash@2.4.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0061 · proposta IA: VP

**Justificativa IA:** lodash 2.4.2 presente na imagem e dentro da faixa afetada (< 4.17.11)

Evidencia: /juice-shop/node_modules/sanitize-html/node_modules/lodash/package.json version 2.4.2; CVE-2018-16487 (GHSA-4xc9-xhrj-v574) faixa < 4.17.11

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sanitize-html/node_modules/lodash/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-4xc9-xhrj-v574`

<details><summary>Dados da ferramenta</summary>

`lodash@2.4.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0063 · proposta IA: VP

**Justificativa IA:** lodash 2.4.2 presente na imagem e dentro da faixa afetada (< 4.17.21)

Evidencia: /juice-shop/node_modules/sanitize-html/node_modules/lodash/package.json version 2.4.2; CVE-2021-23337 (GHSA-35jh-r3h4-6jhm) faixa < 4.17.21

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sanitize-html/node_modules/lodash/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-35jh-r3h4-6jhm`

<details><summary>Dados da ferramenta</summary>

`lodash@2.4.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0101 · proposta IA: VP

**Justificativa IA:** lodash 2.4.2 presente na imagem e dentro da faixa afetada (< 4.17.5)

Evidencia: /juice-shop/node_modules/sanitize-html/node_modules/lodash/package.json version 2.4.2; CVE-2018-3721 (GHSA-fvqr-27wr-82fm) faixa < 4.17.5

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sanitize-html/node_modules/lodash/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-fvqr-27wr-82fm`

<details><summary>Dados da ferramenta</summary>

`lodash@2.4.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0132 · proposta IA: VP

**Justificativa IA:** lodash 2.4.2 presente na imagem e dentro da faixa afetada (<= 4.17.23)

Evidencia: /juice-shop/node_modules/sanitize-html/node_modules/lodash/package.json version 2.4.2; CVE-2026-2950 (GHSA-f23m-r3pf-42rh) faixa <= 4.17.23

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sanitize-html/node_modules/lodash/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-f23m-r3pf-42rh`

<details><summary>Dados da ferramenta</summary>

`lodash@2.4.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · crypto-js

2 achado(s); proposta da IA: 2 VP

**Revisao do grupo:** ok

## T0054 · proposta IA: VP

**Justificativa IA:** crypto-js 3.3.0 presente na imagem e dentro da faixa afetada (< 4.2.0)

Evidencia: /juice-shop/node_modules/crypto-js/package.json version 3.3.0; CVE-2023-46233 (GHSA-xwcq-pm8m-c4vf) faixa < 4.2.0

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/crypto-js/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-xwcq-pm8m-c4vf`

<details><summary>Dados da ferramenta</summary>

`crypto-js@3.3.0` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0057 · proposta IA: VP

**Justificativa IA:** crypto-js 3.3.0 presente na imagem e dentro da faixa afetada (< 4.0.0)

Evidencia: /juice-shop/node_modules/crypto-js/package.json version 3.3.0; CVE-2026-71851 (GHSA-rg76-677x-56q9) faixa < 4.0.0

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/crypto-js/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-rg76-677x-56q9`

<details><summary>Dados da ferramenta</summary>

`crypto-js@3.3.0` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · decompress

3 achado(s); proposta da IA: 3 VP

**Revisao do grupo:** ok 

## T0055 · proposta IA: VP

**Justificativa IA:** decompress 4.2.1 presente na imagem e dentro da faixa afetada (<= 4.2.1)

Evidencia: /juice-shop/node_modules/decompress/package.json version 4.2.1; CVE-2026-53486 (GHSA-mp2f-45pm-3cg9) faixa <= 4.2.1

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/decompress/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-mp2f-45pm-3cg9`

<details><summary>Dados da ferramenta</summary>

`decompress@4.2.1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0127 · proposta IA: VP

**Justificativa IA:** decompress 4.2.1 presente na imagem e dentro da faixa afetada (<= 4.2.1)

Evidencia: /juice-shop/node_modules/decompress/package.json version 4.2.1; CVE-2026-10732 (GHSA-h39j-r5qq-r9mm) faixa <= 4.2.1

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/decompress/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-h39j-r5qq-r9mm`

<details><summary>Dados da ferramenta</summary>

`decompress@4.2.1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0134 · proposta IA: VP

**Justificativa IA:** decompress 4.2.1 presente na imagem e dentro da faixa afetada (<= 4.2.1)

Evidencia: /juice-shop/node_modules/decompress/package.json version 4.2.1; CVE-2026-39243 (GHSA-jwp9-9v96-94mx) faixa <= 4.2.1

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/decompress/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-jwp9-9v96-94mx`

<details><summary>Dados da ferramenta</summary>

`decompress@4.2.1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · tar

12 achado(s); proposta da IA: 12 VP

**Revisao do grupo:** ok

## T0056 · proposta IA: VP

**Justificativa IA:** tar 6.2.1 presente na imagem e dentro da faixa afetada (<= 7.5.18)

Evidencia: /juice-shop/node_modules/sqlite3/node_modules/tar/package.json version 6.2.1; CVE-2026-59873 (GHSA-23hp-3jrh-7fpw) faixa <= 7.5.18

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sqlite3/node_modules/tar/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-23hp-3jrh-7fpw`

<details><summary>Dados da ferramenta</summary>

`tar@6.2.1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0076 · proposta IA: VP

**Justificativa IA:** tar 6.2.1 presente na imagem e dentro da faixa afetada (<= 7.5.2)

Evidencia: /juice-shop/node_modules/sqlite3/node_modules/tar/package.json version 6.2.1; CVE-2026-23745 (GHSA-8qq5-rm4j-mr97) faixa <= 7.5.2

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sqlite3/node_modules/tar/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-8qq5-rm4j-mr97`

<details><summary>Dados da ferramenta</summary>

`tar@6.2.1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0077 · proposta IA: VP

**Justificativa IA:** tar 6.2.1 presente na imagem e dentro da faixa afetada (<= 7.5.3)

Evidencia: /juice-shop/node_modules/sqlite3/node_modules/tar/package.json version 6.2.1; CVE-2026-23950 (GHSA-r6q2-hw4h-h46w) faixa <= 7.5.3

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sqlite3/node_modules/tar/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-r6q2-hw4h-h46w`

<details><summary>Dados da ferramenta</summary>

`tar@6.2.1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0078 · proposta IA: VP

**Justificativa IA:** tar 6.2.1 presente na imagem e dentro da faixa afetada (< 7.5.7)

Evidencia: /juice-shop/node_modules/sqlite3/node_modules/tar/package.json version 6.2.1; CVE-2026-24842 (GHSA-34x7-hfp2-rc4v) faixa < 7.5.7

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sqlite3/node_modules/tar/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-34x7-hfp2-rc4v`

<details><summary>Dados da ferramenta</summary>

`tar@6.2.1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0079 · proposta IA: VP

**Justificativa IA:** tar 6.2.1 presente na imagem e dentro da faixa afetada (< 7.5.8)

Evidencia: /juice-shop/node_modules/sqlite3/node_modules/tar/package.json version 6.2.1; CVE-2026-26960 (GHSA-83g3-92jg-28cx) faixa < 7.5.8

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sqlite3/node_modules/tar/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-83g3-92jg-28cx`

<details><summary>Dados da ferramenta</summary>

`tar@6.2.1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0083 · proposta IA: VP

**Justificativa IA:** tar 6.2.1 presente na imagem e dentro da faixa afetada (<= 7.5.9)

Evidencia: /juice-shop/node_modules/sqlite3/node_modules/tar/package.json version 6.2.1; CVE-2026-29786 (GHSA-qffp-2rhf-9h96) faixa <= 7.5.9

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sqlite3/node_modules/tar/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-qffp-2rhf-9h96`

<details><summary>Dados da ferramenta</summary>

`tar@6.2.1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0084 · proposta IA: VP

**Justificativa IA:** tar 6.2.1 presente na imagem e dentro da faixa afetada (<= 7.5.10)

Evidencia: /juice-shop/node_modules/sqlite3/node_modules/tar/package.json version 6.2.1; CVE-2026-31802 (GHSA-9ppj-qmqm-q256) faixa <= 7.5.10

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sqlite3/node_modules/tar/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-9ppj-qmqm-q256`

<details><summary>Dados da ferramenta</summary>

`tar@6.2.1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0091 · proposta IA: VP

**Justificativa IA:** tar 6.2.1 presente na imagem e dentro da faixa afetada (<= 7.5.17)

Evidencia: /juice-shop/node_modules/sqlite3/node_modules/tar/package.json version 6.2.1; CVE-2026-59874 (GHSA-8x88-c5mf-7j5w) faixa <= 7.5.17

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sqlite3/node_modules/tar/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-8x88-c5mf-7j5w`

<details><summary>Dados da ferramenta</summary>

`tar@6.2.1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0093 · proposta IA: VP

**Justificativa IA:** tar 6.2.1 presente na imagem e dentro da faixa afetada (<= 7.5.20)

Evidencia: /juice-shop/node_modules/sqlite3/node_modules/tar/package.json version 6.2.1; CVE-2026-73566 (GHSA-r292-9mhp-454m) faixa <= 7.5.20

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sqlite3/node_modules/tar/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-r292-9mhp-454m`

<details><summary>Dados da ferramenta</summary>

`tar@6.2.1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0137 · proposta IA: VP

**Justificativa IA:** tar 6.2.1 presente na imagem e dentro da faixa afetada (<= 7.5.15)

Evidencia: /juice-shop/node_modules/sqlite3/node_modules/tar/package.json version 6.2.1; CVE-2026-53655 (GHSA-vmf3-w455-68vh) faixa <= 7.5.15

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sqlite3/node_modules/tar/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-vmf3-w455-68vh`

<details><summary>Dados da ferramenta</summary>

`tar@6.2.1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0139 · proposta IA: VP

**Justificativa IA:** tar 6.2.1 presente na imagem e dentro da faixa afetada (<= 7.5.17)

Evidencia: /juice-shop/node_modules/sqlite3/node_modules/tar/package.json version 6.2.1; CVE-2026-59871 (GHSA-w8wr-v893-vjvp) faixa <= 7.5.17

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sqlite3/node_modules/tar/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-w8wr-v893-vjvp`

<details><summary>Dados da ferramenta</summary>

`tar@6.2.1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0140 · proposta IA: VP

**Justificativa IA:** tar 6.2.1 presente na imagem e dentro da faixa afetada (<= 7.5.16)

Evidencia: /juice-shop/node_modules/sqlite3/node_modules/tar/package.json version 6.2.1; CVE-2026-59875 (GHSA-gvwx-54wh-qm9j) faixa <= 7.5.16

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sqlite3/node_modules/tar/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-gvwx-54wh-qm9j`

<details><summary>Dados da ferramenta</summary>

`tar@6.2.1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · marsdb

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** 

## T0058 · proposta IA: VP

**Justificativa IA:** marsdb 0.6.11 presente na imagem e dentro da faixa afetada (>= 0.0.0)

Evidencia: /juice-shop/node_modules/marsdb/package.json version 0.6.11; GHSA-5mrr-rgp6-x4gr (GHSA-5mrr-rgp6-x4gr) faixa >= 0.0.0

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/marsdb/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-5mrr-rgp6-x4gr`

<details><summary>Dados da ferramenta</summary>

`marsdb@0.6.11` · aparece em 9 rodada(s)

</details>

**Revisao: IND** 
**Motivo: todas as versoes serem afetadas me deixa desconfiado** 

---

# Grupo: alvo1 · trivy-image · jws

2 achado(s); proposta da IA: 2 VP

**Revisao do grupo:** ok 

## T0059 · proposta IA: VP

**Justificativa IA:** jws 0.2.6 presente na imagem e dentro da faixa afetada (< 3.0.0)

Evidencia: /juice-shop/node_modules/jws/package.json version 0.2.6; CVE-2016-1000223 (GHSA-gjcw-v447-2w7q) faixa < 3.0.0

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/jws/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-gjcw-v447-2w7q`

<details><summary>Dados da ferramenta</summary>

`jws@0.2.6` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0073 · proposta IA: VP

**Justificativa IA:** jws 0.2.6 presente na imagem e dentro da faixa afetada (< 3.2.3; = 4.0.0)

Evidencia: /juice-shop/node_modules/jws/package.json version 0.2.6; CVE-2025-65945 (GHSA-869p-cjfg-cm3x) faixa < 3.2.3; = 4.0.0

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/jws/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-869p-cjfg-cm3x`

<details><summary>Dados da ferramenta</summary>

`jws@0.2.6` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · moment

3 achado(s); proposta da IA: 3 VP

**Revisao do grupo:** ok

## T0060 · proposta IA: VP

**Justificativa IA:** moment 2.0.0 presente na imagem e dentro da faixa afetada (< 2.19.3)

Evidencia: /juice-shop/node_modules/express-jwt/node_modules/moment/package.json version 2.0.0; CVE-2017-18214 (GHSA-446m-mv8f-q348) faixa < 2.19.3

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/express-jwt/node_modules/moment/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-446m-mv8f-q348`

<details><summary>Dados da ferramenta</summary>

`moment@2.0.0` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0066 · proposta IA: VP

**Justificativa IA:** moment 2.0.0 presente na imagem e dentro da faixa afetada (< 2.29.2)

Evidencia: /juice-shop/node_modules/express-jwt/node_modules/moment/package.json version 2.0.0; CVE-2022-24785 (GHSA-8hfj-j24r-96c4) faixa < 2.29.2

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/express-jwt/node_modules/moment/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-8hfj-j24r-96c4`

<details><summary>Dados da ferramenta</summary>

`moment@2.0.0` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0112 · proposta IA: VP

**Justificativa IA:** moment 2.0.0 presente na imagem e dentro da faixa afetada (< 2.11.2)

Evidencia: /juice-shop/node_modules/express-jwt/node_modules/moment/package.json version 2.0.0; CVE-2016-4055 (GHSA-87vv-r9j6-g5qv) faixa < 2.11.2

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/express-jwt/node_modules/moment/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-87vv-r9j6-g5qv`

<details><summary>Dados da ferramenta</summary>

`moment@2.0.0` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · express-jwt

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0062 · proposta IA: VP

**Justificativa IA:** express-jwt 0.1.3 presente na imagem e dentro da faixa afetada (<= 5.3.3)

Evidencia: /juice-shop/node_modules/express-jwt/package.json version 0.1.3; CVE-2020-15084 (GHSA-6g6m-m6h5-w9gf) faixa <= 5.3.3

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/express-jwt/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-6g6m-m6h5-w9gf`

<details><summary>Dados da ferramenta</summary>

`express-jwt@0.1.3` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · http-cache-semantics

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0067 · proposta IA: VP

**Justificativa IA:** http-cache-semantics 3.8.1 presente na imagem e dentro da faixa afetada (< 4.1.1)

Evidencia: /juice-shop/node_modules/http-cache-semantics/package.json version 3.8.1; CVE-2022-25881 (GHSA-rc47-6667-2j5j) faixa < 4.1.1

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/http-cache-semantics/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-rc47-6667-2j5j`

<details><summary>Dados da ferramenta</summary>

`http-cache-semantics@3.8.1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · sanitize-html

9 achado(s); proposta da IA: 9 VP

**Revisao do grupo:** ok

## T0068 · proposta IA: VP

**Justificativa IA:** sanitize-html 1.4.2 presente na imagem e dentro da faixa afetada (< 2.7.1)

Evidencia: /juice-shop/node_modules/sanitize-html/package.json version 1.4.2; CVE-2022-25887 (GHSA-cgfm-xwp7-2cvr) faixa < 2.7.1

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sanitize-html/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-cgfm-xwp7-2cvr`

<details><summary>Dados da ferramenta</summary>

`sanitize-html@1.4.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0111 · proposta IA: VP

**Justificativa IA:** sanitize-html 1.4.2 presente na imagem e dentro da faixa afetada (< 1.4.3)

Evidencia: /juice-shop/node_modules/sanitize-html/package.json version 1.4.2; CVE-2016-1000237 (GHSA-3j7m-hmh3-9jmp) faixa < 1.4.3

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sanitize-html/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-3j7m-hmh3-9jmp`

<details><summary>Dados da ferramenta</summary>

`sanitize-html@1.4.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0113 · proposta IA: VP

**Justificativa IA:** sanitize-html 1.4.2 presente na imagem e dentro da faixa afetada (<= 1.11.1)

Evidencia: /juice-shop/node_modules/sanitize-html/package.json version 1.4.2; CVE-2017-16016 (GHSA-xc6g-ggrc-qq4r) faixa <= 1.11.1

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sanitize-html/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-xc6g-ggrc-qq4r`

<details><summary>Dados da ferramenta</summary>

`sanitize-html@1.4.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0114 · proposta IA: VP

**Justificativa IA:** sanitize-html 1.4.2 presente na imagem e dentro da faixa afetada (< 2.0.0-beta)

Evidencia: /juice-shop/node_modules/sanitize-html/package.json version 1.4.2; CVE-2019-25225 (GHSA-qhxp-v273-g94h) faixa < 2.0.0-beta

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sanitize-html/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-qhxp-v273-g94h`

<details><summary>Dados da ferramenta</summary>

`sanitize-html@1.4.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0116 · proposta IA: VP

**Justificativa IA:** sanitize-html 1.4.2 presente na imagem e dentro da faixa afetada (< 2.3.1)

Evidencia: /juice-shop/node_modules/sanitize-html/package.json version 1.4.2; CVE-2021-26539 (GHSA-rjqq-98f6-6j3r) faixa < 2.3.1

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sanitize-html/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-rjqq-98f6-6j3r`

<details><summary>Dados da ferramenta</summary>

`sanitize-html@1.4.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0117 · proposta IA: VP

**Justificativa IA:** sanitize-html 1.4.2 presente na imagem e dentro da faixa afetada (< 2.3.2)

Evidencia: /juice-shop/node_modules/sanitize-html/package.json version 1.4.2; CVE-2021-26540 (GHSA-mjxr-4v3x-q3m4) faixa < 2.3.2

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sanitize-html/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-mjxr-4v3x-q3m4`

<details><summary>Dados da ferramenta</summary>

`sanitize-html@1.4.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0125 · proposta IA: VP

**Justificativa IA:** sanitize-html 1.4.2 presente na imagem e dentro da faixa afetada (< 2.12.1)

Evidencia: /juice-shop/node_modules/sanitize-html/package.json version 1.4.2; CVE-2024-21501 (GHSA-rm97-x556-q36h) faixa < 2.12.1

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sanitize-html/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-rm97-x556-q36h`

<details><summary>Dados da ferramenta</summary>

`sanitize-html@1.4.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0142 · proposta IA: VP

**Justificativa IA:** sanitize-html 1.4.2 presente na imagem e dentro da faixa afetada (<= 2.17.5)

Evidencia: /juice-shop/node_modules/sanitize-html/package.json version 1.4.2; CVE-2026-63670 (GHSA-jxwj-j7wr-gfrw) faixa <= 2.17.5

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sanitize-html/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-jxwj-j7wr-gfrw`

<details><summary>Dados da ferramenta</summary>

`sanitize-html@1.4.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0153 · proposta IA: VP

**Justificativa IA:** sanitize-html 1.4.2 presente na imagem, abaixo da versao corrigida >=1.11.4 (advisory antigo do Node Security WG)

Evidencia: /juice-shop/node_modules/sanitize-html/package.json version 1.4.2; NSWG-ECO-154 corrigido em >=1.11.4

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/sanitize-html/package.json - | tar -xO | grep '"version"'  e comparar com a versao corrigida >=1.11.4`

<details><summary>Dados da ferramenta</summary>

`sanitize-html@1.4.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · ws

2 achado(s); proposta da IA: 2 VP

**Revisao do grupo:** ok

## T0069 · proposta IA: VP

**Justificativa IA:** ws 7.4.6 presente na imagem e dentro da faixa afetada (>= 2.1.0, < 5.2.4; >= 6.0.0, < 6.2.3; >= 7.0.0, < 7.5.10; >= 8.0.0, < 8.17.1)

Evidencia: /juice-shop/node_modules/ws/package.json version 7.4.6; CVE-2024-37890 (GHSA-3h5v-q93c-6h6q) faixa >= 2.1.0, < 5.2.4; >= 6.0.0, < 6.2.3; >= 7.0.0, < 7.5.10; >= 8.0.0, < 8.17.1

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/ws/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-3h5v-q93c-6h6q`

<details><summary>Dados da ferramenta</summary>

`ws@7.4.6` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0088 · proposta IA: VP

**Justificativa IA:** ws 7.4.6 presente na imagem e dentro da faixa afetada (>= 1.1.0, < 5.2.5; >= 6.0.0, < 6.2.4; >= 7.0.0, < 7.5.11; >= 8.0.0, < 8.21.0)

Evidencia: /juice-shop/node_modules/ws/package.json version 7.4.6; CVE-2026-48779 (GHSA-96hv-2xvq-fx4p) faixa >= 1.1.0, < 5.2.5; >= 6.0.0, < 6.2.4; >= 7.0.0, < 7.5.11; >= 8.0.0, < 8.21.0

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/ws/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-96hv-2xvq-fx4p`

<details><summary>Dados da ferramenta</summary>

`ws@7.4.6` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · multer

11 achado(s); proposta da IA: 11 VP

**Revisao do grupo:** ok

## T0070 · proposta IA: VP

**Justificativa IA:** multer 1.4.5-lts.2 presente na imagem e dentro da faixa afetada (< 2.0.0)

Evidencia: /juice-shop/node_modules/multer/package.json version 1.4.5-lts.2; CVE-2025-47935 (GHSA-44fp-w29j-9vj5) faixa < 2.0.0

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/multer/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-44fp-w29j-9vj5`

<details><summary>Dados da ferramenta</summary>

`multer@1.4.5-lts.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0071 · proposta IA: VP

**Justificativa IA:** multer 1.4.5-lts.2 presente na imagem e dentro da faixa afetada (>= 1.4.4-lts.1, < 2.0.0)

Evidencia: /juice-shop/node_modules/multer/package.json version 1.4.5-lts.2; CVE-2025-47944 (GHSA-4pg4-qvpc-4q3h) faixa >= 1.4.4-lts.1, < 2.0.0

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/multer/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-4pg4-qvpc-4q3h`

<details><summary>Dados da ferramenta</summary>

`multer@1.4.5-lts.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0072 · proposta IA: VP

**Justificativa IA:** multer 1.4.5-lts.2 presente na imagem e dentro da faixa afetada (>= 1.4.4-lts.1, < 2.0.1)

Evidencia: /juice-shop/node_modules/multer/package.json version 1.4.5-lts.2; CVE-2025-48997 (GHSA-g5hg-p3ph-g8qg) faixa >= 1.4.4-lts.1, < 2.0.1

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/multer/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-g5hg-p3ph-g8qg`

<details><summary>Dados da ferramenta</summary>

`multer@1.4.5-lts.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0074 · proposta IA: VP

**Justificativa IA:** multer 1.4.5-lts.2 presente na imagem e dentro da faixa afetada (>= 1.4.4-lts.1, < 2.0.2)

Evidencia: /juice-shop/node_modules/multer/package.json version 1.4.5-lts.2; CVE-2025-7338 (GHSA-fjgf-rc76-4x9p) faixa >= 1.4.4-lts.1, < 2.0.2

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/multer/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-fjgf-rc76-4x9p`

<details><summary>Dados da ferramenta</summary>

`multer@1.4.5-lts.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0075 · proposta IA: VP

**Justificativa IA:** multer 1.4.5-lts.2 presente na imagem e dentro da faixa afetada (< 2.1.0)

Evidencia: /juice-shop/node_modules/multer/package.json version 1.4.5-lts.2; CVE-2026-2359 (GHSA-v52c-386h-88mc) faixa < 2.1.0

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/multer/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-v52c-386h-88mc`

<details><summary>Dados da ferramenta</summary>

`multer@1.4.5-lts.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0085 · proposta IA: VP

**Justificativa IA:** multer 1.4.5-lts.2 presente na imagem e dentro da faixa afetada (< 2.1.0)

Evidencia: /juice-shop/node_modules/multer/package.json version 1.4.5-lts.2; CVE-2026-3304 (GHSA-xf7r-hgr6-v32p) faixa < 2.1.0

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/multer/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-xf7r-hgr6-v32p`

<details><summary>Dados da ferramenta</summary>

`multer@1.4.5-lts.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0087 · proposta IA: VP

**Justificativa IA:** multer 1.4.5-lts.2 presente na imagem e dentro da faixa afetada (< 2.1.1)

Evidencia: /juice-shop/node_modules/multer/package.json version 1.4.5-lts.2; CVE-2026-3520 (GHSA-5528-5vmv-3xc2) faixa < 2.1.1

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/multer/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-5528-5vmv-3xc2`

<details><summary>Dados da ferramenta</summary>

`multer@1.4.5-lts.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0089 · proposta IA: VP

**Justificativa IA:** multer 1.4.5-lts.2 presente na imagem e dentro da faixa afetada (>= 1.0.0, < 2.2.0; >= 3.0.0-alpha.1, < 3.0.0-alpha.2)

Evidencia: /juice-shop/node_modules/multer/package.json version 1.4.5-lts.2; CVE-2026-5079 (GHSA-72gw-mp4g-v24j) faixa >= 1.0.0, < 2.2.0; >= 3.0.0-alpha.1, < 3.0.0-alpha.2

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/multer/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-72gw-mp4g-v24j`

<details><summary>Dados da ferramenta</summary>

`multer@1.4.5-lts.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0094 · proposta IA: VP

**Justificativa IA:** multer 1.4.5-lts.2 presente na imagem e dentro da faixa afetada (< 2.3.0)

Evidencia: /juice-shop/node_modules/multer/package.json version 1.4.5-lts.2; CVE-2026-77078 (GHSA-wc9g-mqfw-jrwm) faixa < 2.3.0

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/multer/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-wc9g-mqfw-jrwm`

<details><summary>Dados da ferramenta</summary>

`multer@1.4.5-lts.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0095 · proposta IA: VP

**Justificativa IA:** multer 1.4.5-lts.2 presente na imagem e dentro da faixa afetada (< 2.3.0)

Evidencia: /juice-shop/node_modules/multer/package.json version 1.4.5-lts.2; CVE-2026-82333 (GHSA-535w-7cp7-47q4) faixa < 2.3.0

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/multer/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-535w-7cp7-47q4`

<details><summary>Dados da ferramenta</summary>

`multer@1.4.5-lts.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0110 · proposta IA: VP

**Justificativa IA:** multer 1.4.5-lts.2 presente na imagem e dentro da faixa afetada (< 2.3.0)

Evidencia: /juice-shop/node_modules/multer/package.json version 1.4.5-lts.2; CVE-2026-77063 (GHSA-qvfw-j98x-7q72) faixa < 2.3.0

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/multer/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-qvfw-j98x-7q72`

<details><summary>Dados da ferramenta</summary>

`multer@1.4.5-lts.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · minimatch

3 achado(s); proposta da IA: 3 VP

**Revisao do grupo:** ok 

## T0080 · proposta IA: VP

**Justificativa IA:** minimatch 3.0.5 presente na imagem e dentro da faixa afetada (>= 10.0.0, < 10.2.1; >= 9.0.0, < 9.0.6; >= 8.0.0, < 8.0.5; >= 7.0.0, < 7.4.7; >= 6.0.0, < 6.2.1; >= 5.0.0, < 5.1.7; >= 4.0.0, < 4.2.4; < 3.1.3)

Evidencia: /juice-shop/node_modules/replace/node_modules/minimatch/package.json version 3.0.5; CVE-2026-26996 (GHSA-3ppc-4f35-3m26) faixa >= 10.0.0, < 10.2.1; >= 9.0.0, < 9.0.6; >= 8.0.0, < 8.0.5; >= 7.0.0, < 7.4.7; >= 6.0.0, < 6.2.1; >= 5.0.0, < 5.1.7; >= 4.0.0, < 4.2.4; < 3.1.3

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/replace/node_modules/minimatch/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-3ppc-4f35-3m26`

<details><summary>Dados da ferramenta</summary>

`minimatch@3.0.5` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0081 · proposta IA: VP

**Justificativa IA:** minimatch 3.0.5 presente na imagem e dentro da faixa afetada (>= 10.0.0, < 10.2.3; >= 9.0.0, < 9.0.7; >= 8.0.0, < 8.0.6; >= 7.0.0, < 7.4.8; >= 6.0.0, < 6.2.2; >= 5.0.0, < 5.1.8; >= 4.0.0, < 4.2.5; < 3.1.3)

Evidencia: /juice-shop/node_modules/replace/node_modules/minimatch/package.json version 3.0.5; CVE-2026-27903 (GHSA-7r86-cg39-jmmj) faixa >= 10.0.0, < 10.2.3; >= 9.0.0, < 9.0.7; >= 8.0.0, < 8.0.6; >= 7.0.0, < 7.4.8; >= 6.0.0, < 6.2.2; >= 5.0.0, < 5.1.8; >= 4.0.0, < 4.2.5; < 3.1.3

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/replace/node_modules/minimatch/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-7r86-cg39-jmmj`

<details><summary>Dados da ferramenta</summary>

`minimatch@3.0.5` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0082 · proposta IA: VP

**Justificativa IA:** minimatch 3.0.5 presente na imagem e dentro da faixa afetada (>= 10.0.0, < 10.2.3; >= 9.0.0, < 9.0.7; >= 8.0.0, < 8.0.6; >= 7.0.0, < 7.4.8; >= 6.0.0, < 6.2.2; >= 5.0.0, < 5.1.8; >= 4.0.0, < 4.2.5; < 3.1.4)

Evidencia: /juice-shop/node_modules/replace/node_modules/minimatch/package.json version 3.0.5; CVE-2026-27904 (GHSA-23c5-xmqv-rm74) faixa >= 10.0.0, < 10.2.3; >= 9.0.0, < 9.0.7; >= 8.0.0, < 8.0.6; >= 7.0.0, < 7.4.8; >= 6.0.0, < 6.2.2; >= 5.0.0, < 5.1.8; >= 4.0.0, < 4.2.5; < 3.1.4

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/replace/node_modules/minimatch/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-23c5-xmqv-rm74`

<details><summary>Dados da ferramenta</summary>

`minimatch@3.0.5` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · socket.io-parser

3 achado(s); proposta da IA: 3 VP

**Revisao do grupo:** ok

## T0086 · proposta IA: VP

**Justificativa IA:** socket.io-parser 4.0.5 presente na imagem e dentro da faixa afetada (< 3.3.5; >= 3.4.0, < 3.4.4; >= 4.0.0, < 4.2.6)

Evidencia: /juice-shop/node_modules/socket.io-parser/package.json version 4.0.5; CVE-2026-33151 (GHSA-677m-j7p3-52f9) faixa < 3.3.5; >= 3.4.0, < 3.4.4; >= 4.0.0, < 4.2.6

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/socket.io-parser/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-677m-j7p3-52f9`

<details><summary>Dados da ferramenta</summary>

`socket.io-parser@4.0.5` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0092 · proposta IA: VP

**Justificativa IA:** socket.io-parser 4.0.5 presente na imagem e dentro da faixa afetada (>= 4.0.0, < 4.2.7; >= 3.4.0, < 3.4.5; < 3.3.6)

Evidencia: /juice-shop/node_modules/socket.io-parser/package.json version 4.0.5; CVE-2026-69185 (GHSA-2m8v-j782-fhvr) faixa >= 4.0.0, < 4.2.7; >= 3.4.0, < 3.4.5; < 3.3.6

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/socket.io-parser/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-2m8v-j782-fhvr`

<details><summary>Dados da ferramenta</summary>

`socket.io-parser@4.0.5` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0124 · proposta IA: VP

**Justificativa IA:** socket.io-parser 4.0.5 presente na imagem e dentro da faixa afetada (>= 3.4.0, < 3.4.3; >= 4.0.4, < 4.2.3; < 3.3.4)

Evidencia: /juice-shop/node_modules/socket.io-parser/package.json version 4.0.5; CVE-2023-32695 (GHSA-cqmj-92xf-r6r9) faixa >= 3.4.0, < 3.4.3; >= 4.0.4, < 4.2.3; < 3.3.4

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/socket.io-parser/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-cqmj-92xf-r6r9`

<details><summary>Dados da ferramenta</summary>

`socket.io-parser@4.0.5` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · engine.io

2 achado(s); proposta da IA: 2 VP

**Revisao do grupo:** ok

## T0090 · proposta IA: VP

**Justificativa IA:** engine.io 4.1.2 presente na imagem e dentro da faixa afetada (>= 4.1.0, < 6.6.7)

Evidencia: /juice-shop/node_modules/engine.io/package.json version 4.1.2; CVE-2026-59725 (GHSA-r635-g3xr-vw7x) faixa >= 4.1.0, < 6.6.7

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/engine.io/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-r635-g3xr-vw7x`

<details><summary>Dados da ferramenta</summary>

`engine.io@4.1.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0123 · proposta IA: VP

**Justificativa IA:** engine.io 4.1.2 presente na imagem e dentro da faixa afetada (< 3.6.1; >= 4.0.0, < 6.2.1)

Evidencia: /juice-shop/node_modules/engine.io/package.json version 4.1.2; CVE-2022-41940 (GHSA-r7qp-cfhv-p84w) faixa < 3.6.1; >= 4.0.0, < 6.2.1

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/engine.io/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-r7qp-cfhv-p84w`

<details><summary>Dados da ferramenta</summary>

`engine.io@4.1.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · base64url

2 achado(s); proposta da IA: 2 VP

**Revisao do grupo:** ok

## T0098 · proposta IA: VP

**Justificativa IA:** base64url 0.0.6 presente na imagem, abaixo da versao corrigida >=3.0.0 (advisory antigo do Node Security WG)

Evidencia: /juice-shop/node_modules/base64url/package.json version 0.0.6; NSWG-ECO-428 corrigido em >=3.0.0

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/base64url/package.json - | tar -xO | grep '"version"'  e comparar com a versao corrigida >=3.0.0`

<details><summary>Dados da ferramenta</summary>

`base64url@0.0.6` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0152 · proposta IA: VP

**Justificativa IA:** base64url 0.0.6 presente na imagem e dentro da faixa afetada (< 3.0.0)

Evidencia: /juice-shop/node_modules/base64url/package.json version 0.0.6; GHSA-rvg8-pwq2-xj7q (GHSA-rvg8-pwq2-xj7q) faixa < 3.0.0

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/base64url/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-rvg8-pwq2-xj7q`

<details><summary>Dados da ferramenta</summary>

`base64url@0.0.6` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · libc6

20 achado(s); proposta da IA: 13 VP, 7 NE

**Revisao do grupo:** ok

## T0099 · proposta IA: NE

**Justificativa IA:** libc6 2.41-12+deb13u4 presente na versao afetada, mas comportamento POSIX padrao, nao tratado como falha (Debian: unimportant)

Evidencia: dpkg: libc6 2.41-12+deb13u4; Debian trixie: open/unimportant; https://security-tracker.debian.org/tracker/CVE-2010-4756

Como verificar: `docker cp triagem-alvo1:/var/lib/dpkg/status.d/libc6 - | tar -xO | grep Version  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2010-4756`

<details><summary>Dados da ferramenta</summary>

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0100 · proposta IA: NE

**Justificativa IA:** libc6 2.41-12+deb13u4 presente na versao afetada, mas nao tratado como vulnerabilidade pelo glibc (Security Exceptions; Debian: unimportant)

Evidencia: dpkg: libc6 2.41-12+deb13u4; Debian trixie: open/unimportant; https://security-tracker.debian.org/tracker/CVE-2018-20796

Como verificar: `docker cp triagem-alvo1:/var/lib/dpkg/status.d/libc6 - | tar -xO | grep Version  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2018-20796`

<details><summary>Dados da ferramenta</summary>

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0102 · proposta IA: NE

**Justificativa IA:** libc6 2.41-12+deb13u4 presente na versao afetada, mas upstream nao trata como falha de seguranca (sourceware 22850; Debian: unimportant)

Evidencia: dpkg: libc6 2.41-12+deb13u4; Debian trixie: open/unimportant; https://security-tracker.debian.org/tracker/CVE-2019-1010022

Como verificar: `docker cp triagem-alvo1:/var/lib/dpkg/status.d/libc6 - | tar -xO | grep Version  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2019-1010022`

<details><summary>Dados da ferramenta</summary>

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0103 · proposta IA: NE

**Justificativa IA:** libc6 2.41-12+deb13u4 presente na versao afetada, mas upstream nao trata como falha de seguranca (sourceware 22851; Debian: unimportant)

Evidencia: dpkg: libc6 2.41-12+deb13u4; Debian trixie: open/unimportant; https://security-tracker.debian.org/tracker/CVE-2019-1010023

Como verificar: `docker cp triagem-alvo1:/var/lib/dpkg/status.d/libc6 - | tar -xO | grep Version  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2019-1010023`

<details><summary>Dados da ferramenta</summary>

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0104 · proposta IA: NE

**Justificativa IA:** libc6 2.41-12+deb13u4 presente na versao afetada, mas upstream nao trata como falha de seguranca (sourceware 22852; Debian: unimportant)

Evidencia: dpkg: libc6 2.41-12+deb13u4; Debian trixie: open/unimportant; https://security-tracker.debian.org/tracker/CVE-2019-1010024

Como verificar: `docker cp triagem-alvo1:/var/lib/dpkg/status.d/libc6 - | tar -xO | grep Version  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2019-1010024`

<details><summary>Dados da ferramenta</summary>

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0105 · proposta IA: NE

**Justificativa IA:** libc6 2.41-12+deb13u4 presente na versao afetada, mas upstream nao trata como falha de seguranca (sourceware 22853; Debian: unimportant)

Evidencia: dpkg: libc6 2.41-12+deb13u4; Debian trixie: open/unimportant; https://security-tracker.debian.org/tracker/CVE-2019-1010025

Como verificar: `docker cp triagem-alvo1:/var/lib/dpkg/status.d/libc6 - | tar -xO | grep Version  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2019-1010025`

<details><summary>Dados da ferramenta</summary>

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0106 · proposta IA: NE

**Justificativa IA:** libc6 2.41-12+deb13u4 presente na versao afetada, mas nao tratado como vulnerabilidade pelo glibc (Security Exceptions; Debian: unimportant)

Evidencia: dpkg: libc6 2.41-12+deb13u4; Debian trixie: open/unimportant; https://security-tracker.debian.org/tracker/CVE-2019-9192

Como verificar: `docker cp triagem-alvo1:/var/lib/dpkg/status.d/libc6 - | tar -xO | grep Version  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2019-9192`

<details><summary>Dados da ferramenta</summary>

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0128 · proposta IA: VP

**Justificativa IA:** libc6 2.41-12+deb13u4 presente na imagem e afetado: sem correcao no Debian trixie (status open)

Evidencia: dpkg: libc6 2.41-12+deb13u4; Debian trixie: open; https://security-tracker.debian.org/tracker/CVE-2026-18374

Como verificar: `docker cp triagem-alvo1:/var/lib/dpkg/status.d/libc6 - | tar -xO | grep Version  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-18374`

<details><summary>Dados da ferramenta</summary>

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0129 · proposta IA: VP

**Justificativa IA:** libc6 2.41-12+deb13u4 presente na imagem e afetado: sem correcao no Debian trixie (status open)

Evidencia: dpkg: libc6 2.41-12+deb13u4; Debian trixie: open; https://security-tracker.debian.org/tracker/CVE-2026-19499

Como verificar: `docker cp triagem-alvo1:/var/lib/dpkg/status.d/libc6 - | tar -xO | grep Version  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-19499`

<details><summary>Dados da ferramenta</summary>

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0130 · proposta IA: VP

**Justificativa IA:** libc6 2.41-12+deb13u4 presente na imagem e afetado: sem correcao no Debian trixie (status open)

Evidencia: dpkg: libc6 2.41-12+deb13u4; Debian trixie: open; https://security-tracker.debian.org/tracker/CVE-2026-19542

Como verificar: `docker cp triagem-alvo1:/var/lib/dpkg/status.d/libc6 - | tar -xO | grep Version  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-19542`

<details><summary>Dados da ferramenta</summary>

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0138 · proposta IA: VP

**Justificativa IA:** libc6 2.41-12+deb13u4 presente na imagem e afetado: sem correcao no Debian trixie (status open)

Evidencia: dpkg: libc6 2.41-12+deb13u4; Debian trixie: open; https://security-tracker.debian.org/tracker/CVE-2026-5435

Como verificar: `docker cp triagem-alvo1:/var/lib/dpkg/status.d/libc6 - | tar -xO | grep Version  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-5435`

<details><summary>Dados da ferramenta</summary>

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0141 · proposta IA: VP

**Justificativa IA:** libc6 2.41-12+deb13u4 presente na imagem e afetado: sem correcao no Debian trixie (status open)

Evidencia: dpkg: libc6 2.41-12+deb13u4; Debian trixie: open; https://security-tracker.debian.org/tracker/CVE-2026-6238

Como verificar: `docker cp triagem-alvo1:/var/lib/dpkg/status.d/libc6 - | tar -xO | grep Version  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-6238`

<details><summary>Dados da ferramenta</summary>

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0143 · proposta IA: VP

**Justificativa IA:** libc6 2.41-12+deb13u4 presente na imagem e afetado: sem correcao no Debian trixie (status open)

Evidencia: dpkg: libc6 2.41-12+deb13u4; Debian trixie: open; https://security-tracker.debian.org/tracker/CVE-2026-6368

Como verificar: `docker cp triagem-alvo1:/var/lib/dpkg/status.d/libc6 - | tar -xO | grep Version  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-6368`

<details><summary>Dados da ferramenta</summary>

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0144 · proposta IA: VP

**Justificativa IA:** libc6 2.41-12+deb13u4 presente na imagem e afetado: sem correcao no Debian trixie (status open)

Evidencia: dpkg: libc6 2.41-12+deb13u4; Debian trixie: open; https://security-tracker.debian.org/tracker/CVE-2026-6791

Como verificar: `docker cp triagem-alvo1:/var/lib/dpkg/status.d/libc6 - | tar -xO | grep Version  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-6791`

<details><summary>Dados da ferramenta</summary>

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0145 · proposta IA: VP

**Justificativa IA:** libc6 2.41-12+deb13u4 presente na imagem e afetado: sem correcao no Debian trixie (status open)

Evidencia: dpkg: libc6 2.41-12+deb13u4; Debian trixie: open; https://security-tracker.debian.org/tracker/CVE-2026-77117

Como verificar: `docker cp triagem-alvo1:/var/lib/dpkg/status.d/libc6 - | tar -xO | grep Version  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-77117`

<details><summary>Dados da ferramenta</summary>

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0146 · proposta IA: VP

**Justificativa IA:** libc6 2.41-12+deb13u4 presente na imagem e afetado: sem correcao no Debian trixie (status open)

Evidencia: dpkg: libc6 2.41-12+deb13u4; Debian trixie: open; https://security-tracker.debian.org/tracker/CVE-2026-80489

Como verificar: `docker cp triagem-alvo1:/var/lib/dpkg/status.d/libc6 - | tar -xO | grep Version  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-80489`

<details><summary>Dados da ferramenta</summary>

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0148 · proposta IA: VP

**Justificativa IA:** libc6 2.41-12+deb13u4 presente na imagem e afetado: sem correcao no Debian trixie (status open)

Evidencia: dpkg: libc6 2.41-12+deb13u4; Debian trixie: open; https://security-tracker.debian.org/tracker/CVE-2026-8674

Como verificar: `docker cp triagem-alvo1:/var/lib/dpkg/status.d/libc6 - | tar -xO | grep Version  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-8674`

<details><summary>Dados da ferramenta</summary>

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0149 · proposta IA: VP

**Justificativa IA:** libc6 2.41-12+deb13u4 presente na imagem e afetado: sem correcao no Debian trixie (status open)

Evidencia: dpkg: libc6 2.41-12+deb13u4; Debian trixie: open; https://security-tracker.debian.org/tracker/CVE-2026-86805

Como verificar: `docker cp triagem-alvo1:/var/lib/dpkg/status.d/libc6 - | tar -xO | grep Version  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-86805`

<details><summary>Dados da ferramenta</summary>

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0150 · proposta IA: VP

**Justificativa IA:** libc6 2.41-12+deb13u4 presente na imagem e afetado: sem correcao no Debian trixie (status open)

Evidencia: dpkg: libc6 2.41-12+deb13u4; Debian trixie: open; https://security-tracker.debian.org/tracker/CVE-2026-89092

Como verificar: `docker cp triagem-alvo1:/var/lib/dpkg/status.d/libc6 - | tar -xO | grep Version  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-89092`

<details><summary>Dados da ferramenta</summary>

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0151 · proposta IA: VP

**Justificativa IA:** libc6 2.41-12+deb13u4 presente na imagem e afetado: sem correcao no Debian trixie (status open)

Evidencia: dpkg: libc6 2.41-12+deb13u4; Debian trixie: open; https://security-tracker.debian.org/tracker/CVE-2026-95818

Como verificar: `docker cp triagem-alvo1:/var/lib/dpkg/status.d/libc6 - | tar -xO | grep Version  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-95818`

<details><summary>Dados da ferramenta</summary>

`libc6@2.41-12+deb13u4` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · cookie

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0107 · proposta IA: VP

**Justificativa IA:** cookie 0.4.2 presente na imagem e dentro da faixa afetada (< 0.7.0)

Evidencia: /juice-shop/node_modules/engine.io/node_modules/cookie/package.json version 0.4.2; CVE-2024-47764 (GHSA-pxg6-pf52-xh8x) faixa < 0.7.0

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/engine.io/node_modules/cookie/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-pxg6-pf52-xh8x`

<details><summary>Dados da ferramenta</summary>

`cookie@0.4.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · messageformat

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok 

## T0108 · proposta IA: VP

**Justificativa IA:** messageformat 2.3.0 presente na imagem e afetada: o advisory registra '< 2.3.0', mas o relato original (messageformat#452) afirma que a 2.3.0 e afetada e o mantenedor fechou como wontfix

Evidencia: /juice-shop/node_modules/messageformat/package.json version 2.3.0; CVE-2025-57349 (GHSA-xfqm-j7pc-xrfc) faixa < 2.3.0; https://github.com/messageformat/messageformat/issues/452

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/messageformat/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-xfqm-j7pc-xrfc`

<details><summary>Dados da ferramenta</summary>

`messageformat@2.3.0` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · @tootallnate/once

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:**  ok

## T0109 · proposta IA: VP

**Justificativa IA:** @tootallnate/once 1.1.2 presente na imagem e dentro da faixa afetada (>= 3.0.0, < 3.0.1; < 2.0.1)

Evidencia: /juice-shop/node_modules/@tootallnate/once/package.json version 1.1.2; CVE-2026-3449 (GHSA-vpq2-c234-7xj6) faixa >= 3.0.0, < 3.0.1; < 2.0.1

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/@tootallnate/once/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-vpq2-c234-7xj6`

<details><summary>Dados da ferramenta</summary>

`@tootallnate/once@1.1.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · notevil

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0115 · proposta IA: VP

**Justificativa IA:** notevil 1.3.3 presente na imagem e dentro da faixa afetada (<= 1.3.3)

Evidencia: /juice-shop/node_modules/notevil/package.json version 1.3.3; CVE-2021-23771 (GHSA-8g4m-cjm2-96wq) faixa <= 1.3.3

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/notevil/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-8g4m-cjm2-96wq`

<details><summary>Dados da ferramenta</summary>

`notevil@1.3.3` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · got

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0122 · proposta IA: VP

**Justificativa IA:** got 8.3.2 presente na imagem e dentro da faixa afetada (>= 12.0.0, < 12.1.0; < 11.8.5)

Evidencia: /juice-shop/node_modules/got/package.json version 8.3.2; CVE-2022-33987 (GHSA-pfrx-2q88-qq97) faixa >= 12.0.0, < 12.1.0; < 11.8.5

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/got/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-pfrx-2q88-qq97`

<details><summary>Dados da ferramenta</summary>

`got@8.3.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · socket.io

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0126 · proposta IA: VP

**Justificativa IA:** socket.io 3.1.2 presente na imagem e dentro da faixa afetada (>= 3.0.0, < 4.6.2; < 2.5.1)

Evidencia: /juice-shop/node_modules/socket.io/package.json version 3.1.2; CVE-2024-38355 (GHSA-25hc-qcg6-38wj) faixa >= 3.0.0, < 4.6.2; < 2.5.1

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/socket.io/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-25hc-qcg6-38wj`

<details><summary>Dados da ferramenta</summary>

`socket.io@3.1.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · zlib1g

2 achado(s); proposta da IA: 2 VP

**Revisao do grupo:** ok

## T0131 · proposta IA: VP

**Justificativa IA:** zlib1g 1:1.3.dfsg+really1.3.1-1+b1 presente na imagem e afetado: sem correcao no Debian trixie (status open)

Evidencia: dpkg: zlib1g 1:1.3.dfsg+really1.3.1-1+b1; Debian trixie: open; https://security-tracker.debian.org/tracker/CVE-2026-27171

Como verificar: `docker cp triagem-alvo1:/var/lib/dpkg/status.d/zlib1g - | tar -xO | grep Version  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-27171`

<details><summary>Dados da ferramenta</summary>

`zlib1g@1:1.3.dfsg+really1.3.1-1+b1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0147 · proposta IA: VP

**Justificativa IA:** zlib1g 1:1.3.dfsg+really1.3.1-1+b1 presente na imagem e afetado: sem correcao no Debian trixie (status open)

Evidencia: dpkg: zlib1g 1:1.3.dfsg+really1.3.1-1+b1; Debian trixie: open; https://security-tracker.debian.org/tracker/CVE-2026-85091

Como verificar: `docker cp triagem-alvo1:/var/lib/dpkg/status.d/zlib1g - | tar -xO | grep Version  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-85091`

<details><summary>Dados da ferramenta</summary>

`zlib1g@1:1.3.dfsg+really1.3.1-1+b1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · file-type

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0133 · proposta IA: VP

**Justificativa IA:** file-type 16.5.4 presente na imagem e dentro da faixa afetada (>= 13.0.0, < 21.3.1)

Evidencia: /juice-shop/node_modules/file-type/package.json version 16.5.4; CVE-2026-31808 (GHSA-5v7r-6r5c-r473) faixa >= 13.0.0, < 21.3.1

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/file-type/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-5v7r-6r5c-r473`

<details><summary>Dados da ferramenta</summary>

`file-type@16.5.4` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · uuid

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0135 · proposta IA: VP

**Justificativa IA:** uuid 8.3.2 presente na imagem e dentro da faixa afetada (>= 12.0.0, < 12.0.1; >= 13.0.0, < 13.0.1; < 11.1.1)

Evidencia: /juice-shop/node_modules/uuid/package.json version 8.3.2; CVE-2026-41907 (GHSA-w5hq-g745-h8pq) faixa >= 12.0.0, < 12.0.1; >= 13.0.0, < 13.0.1; < 11.1.1

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/uuid/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-w5hq-g745-h8pq`

<details><summary>Dados da ferramenta</summary>

`uuid@8.3.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-image · decode-uri-component

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0136 · proposta IA: VP

**Justificativa IA:** decode-uri-component 0.2.2 presente na imagem e dentro da faixa afetada (<= 0.4.2)

Evidencia: /juice-shop/node_modules/decode-uri-component/package.json version 0.2.2; CVE-2026-45822 (GHSA-vcc3-ghjq-m6fr) faixa <= 0.4.2

Como verificar: `docker cp triagem-alvo1:/juice-shop/node_modules/decode-uri-component/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-vcc3-ghjq-m6fr`

<details><summary>Dados da ferramenta</summary>

`decode-uri-component@0.2.2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-secret · private-key

3 achado(s); proposta da IA: 3 VP

**Revisao do grupo:** ok

## T0154 · proposta IA: VP

**Justificativa IA:** chave privada RSA valida embutida no Terraform versionado (certificado TLS do load balancer); os autores marcam a linha como vuln-line do iacLeakedKeyChallenge

Evidencia: alvos/juice-shop/infrastructure/terraform/networking.tf:171 private_key = "-----BEGIN RSA PRIVATE KEY-----..." # vuln-code-snippet vuln-line iacLeakedKeyChallenge; openssl rsa -check: RSA key ok

Como verificar: `sed -n 171p alvos/juice-shop/infrastructure/terraform/networking.tf | grep -oE -- '-----BEGIN RSA PRIVATE KEY-----.*-----END RSA PRIVATE KEY-----' | sed 's/\\n/\n/g' | openssl rsa -check -noout`

<details><summary>Dados da ferramenta</summary>

`infrastructure/terraform/networking.tf:171` · aparece em 9 rodada(s)

Regra: private-key (Asymmetric Private Key)
Arquivo: infrastructure/terraform/networking.tf

```
  171 | ----BEGIN RSA PRIVATE KEY-----**********************************************************************************************************************************
```

</details>

**Revisao:** 
**Motivo:** 

## T0155 · proposta IA: VP

**Justificativa IA:** chave privada RSA real que assina os JWT da aplicacao (jwt.sign RS256), embutida no codigo; quem a obtem forja tokens validos

Evidencia: alvos/juice-shop/lib/insecurity.ts:21 const privateKey = "-----BEGIN RSA PRIVATE KEY-----..."; linha 54 authorize = jwt.sign(user, privateKey, {algorithm: RS256}); presente em /juice-shop/build/lib/insecurity.js na imagem

Como verificar: `grep -n privateKey alvos/juice-shop/lib/insecurity.ts (uso em jwt.sign na linha 54)`

<details><summary>Dados da ferramenta</summary>

`lib/insecurity.ts:21` · aparece em 9 rodada(s)

Regra: private-key (Asymmetric Private Key)
Arquivo: lib/insecurity.ts

```
   21 | ----BEGIN RSA PRIVATE KEY-----**********************************************************************************************************************************
```

</details>

**Revisao:** 
**Motivo:** 

## T0156 · proposta IA: VP

**Justificativa IA:** copia da mesma chave privada RSA valida no segundo diretorio de Terraform, tambem marcada como vuln-line do iacLeakedKeyChallenge

Evidencia: alvos/juice-shop/terraform/networking.tf:171 private_key = "-----BEGIN RSA PRIVATE KEY-----..." # vuln-code-snippet vuln-line iacLeakedKeyChallenge; openssl rsa -check: RSA key ok

Como verificar: `sed -n 171p alvos/juice-shop/terraform/networking.tf | grep -oE -- '-----BEGIN RSA PRIVATE KEY-----.*-----END RSA PRIVATE KEY-----' | sed 's/\\n/\n/g' | openssl rsa -check -noout`

<details><summary>Dados da ferramenta</summary>

`terraform/networking.tf:171` · aparece em 9 rodada(s)

Regra: private-key (Asymmetric Private Key)
Arquivo: terraform/networking.tf

```
  171 | ----BEGIN RSA PRIVATE KEY-----**********************************************************************************************************************************
```

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · trivy-secret · jwt-token

2 achado(s); proposta da IA: 2 FP

**Revisao do grupo:** ok

## T0157 · proposta IA: FP

**Justificativa IA:** o JWT e o token de exemplo publico do jwt.io (sub 1234567890, John Doe), HS256, em teste unitario; nao e credencial e nao vale na aplicacao, que verifica RS256

Evidencia: alvos/juice-shop/frontend/src/app/app.guard.spec.ts:46 localStorage.setItem(token, eyJ...); payload {"sub":"1234567890","name":"John Doe","iat":1516239022}, header alg HS256

Como verificar: `sed -n 46p alvos/juice-shop/frontend/src/app/app.guard.spec.ts | grep -oE 'eyJ[^.]+\.[^.]+' | cut -d. -f2 | base64 -d`

<details><summary>Dados da ferramenta</summary>

`frontend/src/app/app.guard.spec.ts:46` · aparece em 9 rodada(s)

Regra: jwt-token (JWT token)
Arquivo: frontend/src/app/app.guard.spec.ts

```
   46 | ocalStorage.setItem('token', '**********************************************************************************************************************************
```

</details>

**Revisao:** 
**Motivo:** 

## T0158 · proposta IA: FP

**Justificativa IA:** JWT ficticio de teste unitario (payload so com lastLoginIp 1.2.3.4, HS256); nao e credencial e nao vale na aplicacao, que verifica RS256

Evidencia: alvos/juice-shop/frontend/src/app/last-login-ip/last-login-ip.component.spec.ts:72 localStorage.setItem(token, eyJ...); payload {"data":{"lastLoginIp":"1.2.3.4"}}, header alg HS256

Como verificar: `sed -n 72p alvos/juice-shop/frontend/src/app/last-login-ip/last-login-ip.component.spec.ts | grep -oE 'eyJ[^.]+\.[^.]+' | cut -d. -f2 | base64 -d`

<details><summary>Dados da ferramenta</summary>

`frontend/src/app/last-login-ip/last-login-ip.component.spec.ts:72` · aparece em 9 rodada(s)

Regra: jwt-token (JWT token)
Arquivo: frontend/src/app/last-login-ip/last-login-ip.component.spec.ts

```
   72 | ocalStorage.setItem('token', '*******************************************************************************************************************************')
```

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · X-Content-Type-Options Header Missing

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0159 · proposta IA: VP

**Justificativa IA:** resposta text/plain sem X-Content-Type-Options: nosniff; o navegador pode interpretar o conteudo como outro tipo (MIME sniffing)

Evidencia: GET http://localhost:3000/socket.io/?EIO=4&transport=polling&t=Q3fdxwN&sid=Z6B3l7O9IlHHNF_qAAAA -> Content-Type text/plain, sem X-Content-Type-Options (handshake novo do socket.io: EIO=4&transport=polling)

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/socket.io/?EIO=4&transport=polling" | grep -i -e "^content-type" -e "^x-content-type-options"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/socket.io/ [x-content-type-options]` · aparece em 9 rodada(s)

Alerta: X-Content-Type-Options Header Missing (plugin 10021, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/socket.io/?EIO=4&transport=polling&t=Q3fdxwN&sid=Z6B3l7O9IlHHNF_qAAAA
Parametro: x-content-type-options
Ataque: -
Evidencia: -
Informacao adicional: This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · Information Disclosure - Debug Error Messages

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** 

## T0160 · proposta IA: VP

**Justificativa IA:** a aplicacao responde erros com pagina detalhada (stack trace com caminhos internos); o 500 nesta rota ocorreu em 1 rodada e nao se reproduz, mas a condicao e verificada em outras rotas

Evidencia: GET /api/Hints/ -> 500 Internal Server Error (1 rodada); GET /ftp/coupons_2013.md.bak -> 403 com stack trace (/juice-shop/node_modules/express/lib/router/layer.js)

Como verificar: `curl -s http://localhost:3000/ftp/coupons_2013.md.bak | grep -o "/juice-shop/[^ <]*" | head -3`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/api/Hints/` · aparece em 1 rodada(s)

Alerta: Information Disclosure - Debug Error Messages (plugin 10023, risco 1, confianca 2, CWE-1295)
Requisicao: GET http://localhost:3000/api/Hints/
Parametro: -
Ataque: -
Evidencia: Internal Server Error
Informacao adicional: -

</details>

**Revisao:** IND 
**Motivo:** so apareceu em 1 rodada, possivel FP, vale uma segunda verificacao

---

# Grupo: alvo1 · zap · Deprecated Feature Policy Header Set

6 achado(s); proposta da IA: 6 NE

**Revisao do grupo:** ok

## T0161 · proposta IA: NE

**Justificativa IA:** cabecalho Feature-Policy obsoleto ainda em uso (payment self), em vez de Permissions-Policy; defesa em profundidade sem ataque direto no contexto

Evidencia: GET http://localhost:3000/chunk-DBPdFzgj.js -> Feature-Policy: payment 'self', sem Permissions-Policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/chunk-DBPdFzgj.js" | grep -i -e "^content-type" -e "^feature-policy" (sem a linha de feature-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/chunk-DBPdFzgj.js` · aparece em 9 rodada(s)

Alerta: Deprecated Feature Policy Header Set (plugin 10063, risco 1, confianca 2, CWE-16)
Requisicao: GET http://localhost:3000/chunk-DBPdFzgj.js
Parametro: -
Ataque: -
Evidencia: Feature-Policy
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0162 · proposta IA: NE

**Justificativa IA:** cabecalho Feature-Policy obsoleto ainda em uso (payment self), em vez de Permissions-Policy; defesa em profundidade sem ataque direto no contexto

Evidencia: GET http://localhost:3000/polyfills.js -> Feature-Policy: payment 'self', sem Permissions-Policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/polyfills.js" | grep -i -e "^content-type" -e "^feature-policy" (sem a linha de feature-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/polyfills.js` · aparece em 1 rodada(s)

Alerta: Deprecated Feature Policy Header Set (plugin 10063, risco 1, confianca 2, CWE-16)
Requisicao: GET http://localhost:3000/polyfills.js
Parametro: -
Ataque: -
Evidencia: Feature-Policy
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0163 · proposta IA: NE

**Justificativa IA:** cabecalho Feature-Policy obsoleto ainda em uso (payment self), em vez de Permissions-Policy; defesa em profundidade sem ataque direto no contexto

Evidencia: GET http://localhost:3000/rolldown-runtime-BoHGiXSq.js -> Feature-Policy: payment 'self', sem Permissions-Policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/rolldown-runtime-BoHGiXSq.js" | grep -i -e "^content-type" -e "^feature-policy" (sem a linha de feature-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/rolldown-runtime-BoHGiXSq.js` · aparece em 8 rodada(s)

Alerta: Deprecated Feature Policy Header Set (plugin 10063, risco 1, confianca 2, CWE-16)
Requisicao: GET http://localhost:3000/rolldown-runtime-BoHGiXSq.js
Parametro: -
Ataque: -
Evidencia: Feature-Policy
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0164 · proposta IA: NE

**Justificativa IA:** cabecalho Feature-Policy obsoleto ainda em uso (payment self), em vez de Permissions-Policy; defesa em profundidade sem ataque direto no contexto

Evidencia: GET http://localhost:3000/sitemap.xml -> Feature-Policy: payment 'self', sem Permissions-Policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/sitemap.xml" | grep -i -e "^content-type" -e "^feature-policy" (sem a linha de feature-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/sitemap.xml` · aparece em 9 rodada(s)

Alerta: Deprecated Feature Policy Header Set (plugin 10063, risco 1, confianca 2, CWE-16)
Requisicao: GET http://localhost:3000/sitemap.xml
Parametro: -
Ataque: -
Evidencia: Feature-Policy
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0165 · proposta IA: NE

**Justificativa IA:** cabecalho Feature-Policy obsoleto ainda em uso (payment self), em vez de Permissions-Policy; defesa em profundidade sem ataque direto no contexto

Evidencia: GET http://localhost:3000/ -> Feature-Policy: payment 'self', sem Permissions-Policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/" | grep -i -e "^content-type" -e "^feature-policy" (sem a linha de feature-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/` · aparece em 9 rodada(s)

Alerta: Deprecated Feature Policy Header Set (plugin 10063, risco 1, confianca 2, CWE-16)
Requisicao: GET http://localhost:3000/
Parametro: -
Ataque: -
Evidencia: Feature-Policy
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0166 · proposta IA: NE

**Justificativa IA:** cabecalho Feature-Policy obsoleto ainda em uso (payment self), em vez de Permissions-Policy; defesa em profundidade sem ataque direto no contexto

Evidencia: GET http://localhost:3000 -> Feature-Policy: payment 'self', sem Permissions-Policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000" | grep -i -e "^content-type" -e "^feature-policy" (sem a linha de feature-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000` · aparece em 9 rodada(s)

Alerta: Deprecated Feature Policy Header Set (plugin 10063, risco 1, confianca 2, CWE-16)
Requisicao: GET http://localhost:3000
Parametro: -
Ataque: -
Evidencia: Feature-Policy
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · Timestamp Disclosure - Unix

4 achado(s); proposta da IA: 4 FP

**Revisao do grupo:** ok

## T0167 · proposta IA: FP

**Justificativa IA:** o numero 1666666667 e parte da casa decimal de cores no CSS (rgb(242.8666666667, ...)), nao um timestamp

Evidencia: GET http://localhost:3000/sitemap.xml -> CSS com rgb(242.8666666667, 242.4333333333, 244.1666666667) e rgb(159.1528301887, ...)

Como verificar: `curl -s "http://localhost:3000/sitemap.xml" | grep -o ".\{20\}1666666667.\{10\}" | head -2`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/sitemap.xml` · aparece em 9 rodada(s)

Alerta: Timestamp Disclosure - Unix (plugin 10096, risco 1, confianca 1, CWE-497)
Requisicao: GET http://localhost:3000/sitemap.xml
Parametro: -
Ataque: -
Evidencia: 1666666667
Informacao adicional: 1666666667, which evaluates to: 2022-10-25 02:57:47.

</details>

**Revisao:** 
**Motivo:** 

## T0168 · proposta IA: FP

**Justificativa IA:** o numero 1528301887 e parte da casa decimal de cores no CSS (rgb(242.8666666667, ...)), nao um timestamp

Evidencia: GET http://localhost:3000/styles.css -> CSS com rgb(242.8666666667, 242.4333333333, 244.1666666667) e rgb(159.1528301887, ...)

Como verificar: `curl -s "http://localhost:3000/styles.css" | grep -o ".\{20\}1528301887.\{10\}" | head -2`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/styles.css` · aparece em 1 rodada(s)

Alerta: Timestamp Disclosure - Unix (plugin 10096, risco 1, confianca 1, CWE-497)
Requisicao: GET http://localhost:3000/styles.css
Parametro: -
Ataque: -
Evidencia: 1528301887
Informacao adicional: 1528301887, which evaluates to: 2018-06-06 16:18:07.

</details>

**Revisao:** 
**Motivo:** 

## T0169 · proposta IA: FP

**Justificativa IA:** o numero 1666666667 e parte da casa decimal de cores no CSS (rgb(242.8666666667, ...)), nao um timestamp

Evidencia: GET http://localhost:3000/ -> CSS com rgb(242.8666666667, 242.4333333333, 244.1666666667) e rgb(159.1528301887, ...)

Como verificar: `curl -s "http://localhost:3000/" | grep -o ".\{20\}1666666667.\{10\}" | head -2`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/` · aparece em 9 rodada(s)

Alerta: Timestamp Disclosure - Unix (plugin 10096, risco 1, confianca 1, CWE-497)
Requisicao: GET http://localhost:3000/
Parametro: -
Ataque: -
Evidencia: 1666666667
Informacao adicional: 1666666667, which evaluates to: 2022-10-25 02:57:47.

</details>

**Revisao:** 
**Motivo:** 

## T0170 · proposta IA: FP

**Justificativa IA:** o numero 1666666667 e parte da casa decimal de cores no CSS (rgb(242.8666666667, ...)), nao um timestamp

Evidencia: GET http://localhost:3000 -> CSS com rgb(242.8666666667, 242.4333333333, 244.1666666667) e rgb(159.1528301887, ...)

Como verificar: `curl -s "http://localhost:3000" | grep -o ".\{20\}1666666667.\{10\}" | head -2`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000` · aparece em 8 rodada(s)

Alerta: Timestamp Disclosure - Unix (plugin 10096, risco 1, confianca 1, CWE-497)
Requisicao: GET http://localhost:3000
Parametro: -
Ataque: -
Evidencia: 1666666667
Informacao adicional: 1666666667, which evaluates to: 2022-10-25 02:57:47.

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · Dangerous JS Functions

3 achado(s); proposta da IA: 2 VP, 1 FP

**Revisao do grupo:** ok

## T0171 · proposta IA: VP

**Justificativa IA:** bypassSecurityTrustHtml aplicado ao comentario dos feedbacks (dado do usuario), exibido no carrossel do About; base do XSS persistente de feedback

Evidencia: GET /about.component-*.js -> e[i].comment = this.sanitizer.bypassSecurityTrustHtml(e[i].comment)

Como verificar: `curl -s http://localhost:3000/about.component-CX4sLWGx.js | grep -o ".\{40\}bypassSecurityTrustHtml(e\[i\].comment)"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/about.component-CX4sLWGx.js` · aparece em 9 rodada(s)

Alerta: Dangerous JS Functions (plugin 10110, risco 1, confianca 1, CWE-749)
Requisicao: GET http://localhost:3000/about.component-CX4sLWGx.js
Parametro: -
Ataque: -
Evidencia: bypassSecurityTrustHtml(
Informacao adicional: -

</details>

**Revisao:** NE
**Motivo:** desafio desativado em container (disabledEnv: Docker); codigo segue o caminho seguro nas rodadas


## T0172 · proposta IA: FP

**Justificativa IA:** o trecho e a definicao do metodo bypassSecurityTrustHtml dentro do proprio Angular (DomSanitizer), nao um uso com dado do usuario

Evidencia: GET /chunk-Op3DlR8e.js -> bypassSecurityTrustHtml(t){return Id(t)} (implementacao do framework)

Como verificar: `curl -s http://localhost:3000/chunk-Op3DlR8e.js | grep -o "bypassSecurityTrustHtml(t){[^}]*}"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/chunk-Op3DlR8e.js` · aparece em 9 rodada(s)

Alerta: Dangerous JS Functions (plugin 10110, risco 1, confianca 1, CWE-749)
Requisicao: GET http://localhost:3000/chunk-Op3DlR8e.js
Parametro: -
Ataque: -
Evidencia: bypassSecurityTrustHtml(
Informacao adicional: -

</details>

**Revisao:** IND
**Motivo:** não deu para confirmar se o bypassSecurityTrustHtml recebe entrada do usuário

## T0173 · proposta IA: VP

**Justificativa IA:** bypassSecurityTrustHtml aplicado ao termo de busca vindo da URL (searchValue), que e renderizado como HTML: DOM XSS (localXssChallenge)

Evidencia: GET /main.js -> this.searchValue = this.sanitizer.bypassSecurityTrustHtml(e), com e = parametro q da busca

Como verificar: `abrir http://localhost:3000/#/search?q=<iframe src="javascript:alert(1)"> no navegador e ver o alerta`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/main.js` · aparece em 9 rodada(s)

Alerta: Dangerous JS Functions (plugin 10110, risco 1, confianca 1, CWE-749)
Requisicao: GET http://localhost:3000/main.js
Parametro: -
Ataque: -
Evidencia: bypassSecurityTrustHtml(
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · Full Path Disclosure

6 achado(s); proposta da IA: 6 VP

**Revisao do grupo:** ok

## T0174 · proposta IA: VP

**Justificativa IA:** a pagina de erro 403 traz o stack trace com caminho absoluto no servidor (/juice-shop/node_modules/express/lib/...)

Evidencia: GET http://localhost:3000/ftp/coupons_2013.md.bak -> 403 com stack trace contendo /juice-shop/node_modules/express/lib/router/layer.js

Como verificar: `curl -s "http://localhost:3000/ftp/coupons_2013.md.bak" | grep -o "/juice-shop/[^ <]*" | head -3`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/coupons_2013.md.bak` · aparece em 9 rodada(s)

Alerta: Full Path Disclosure (plugin 110009, risco 1, confianca 1, CWE-209)
Requisicao: GET http://localhost:3000/ftp/coupons_2013.md.bak
Parametro: -
Ataque: -
Evidencia: /lib/
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0175 · proposta IA: VP

**Justificativa IA:** a pagina de erro 403 traz o stack trace com caminho absoluto no servidor (/juice-shop/node_modules/express/lib/...)

Evidencia: GET http://localhost:3000/ftp/eastere.gg -> 403 com stack trace contendo /juice-shop/node_modules/express/lib/router/layer.js

Como verificar: `curl -s "http://localhost:3000/ftp/eastere.gg" | grep -o "/juice-shop/[^ <]*" | head -3`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/eastere.gg` · aparece em 9 rodada(s)

Alerta: Full Path Disclosure (plugin 110009, risco 1, confianca 1, CWE-209)
Requisicao: GET http://localhost:3000/ftp/eastere.gg
Parametro: -
Ataque: -
Evidencia: /lib/
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0176 · proposta IA: VP

**Justificativa IA:** a pagina de erro 403 traz o stack trace com caminho absoluto no servidor (/juice-shop/node_modules/express/lib/...)

Evidencia: GET http://localhost:3000/ftp/encrypt.pyc -> 403 com stack trace contendo /juice-shop/node_modules/express/lib/router/layer.js

Como verificar: `curl -s "http://localhost:3000/ftp/encrypt.pyc" | grep -o "/juice-shop/[^ <]*" | head -3`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/encrypt.pyc` · aparece em 9 rodada(s)

Alerta: Full Path Disclosure (plugin 110009, risco 1, confianca 1, CWE-209)
Requisicao: GET http://localhost:3000/ftp/encrypt.pyc
Parametro: -
Ataque: -
Evidencia: /lib/
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0177 · proposta IA: VP

**Justificativa IA:** a pagina de erro 403 traz o stack trace com caminho absoluto no servidor (/juice-shop/node_modules/express/lib/...)

Evidencia: GET http://localhost:3000/ftp/package-lock.json.bak -> 403 com stack trace contendo /juice-shop/node_modules/express/lib/router/layer.js

Como verificar: `curl -s "http://localhost:3000/ftp/package-lock.json.bak" | grep -o "/juice-shop/[^ <]*" | head -3`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/package-lock.json.bak` · aparece em 9 rodada(s)

Alerta: Full Path Disclosure (plugin 110009, risco 1, confianca 1, CWE-209)
Requisicao: GET http://localhost:3000/ftp/package-lock.json.bak
Parametro: -
Ataque: -
Evidencia: /lib/
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0178 · proposta IA: VP

**Justificativa IA:** a pagina de erro 403 traz o stack trace com caminho absoluto no servidor (/juice-shop/node_modules/express/lib/...)

Evidencia: GET http://localhost:3000/ftp/package.json.bak -> 403 com stack trace contendo /juice-shop/node_modules/express/lib/router/layer.js

Como verificar: `curl -s "http://localhost:3000/ftp/package.json.bak" | grep -o "/juice-shop/[^ <]*" | head -3`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/package.json.bak` · aparece em 9 rodada(s)

Alerta: Full Path Disclosure (plugin 110009, risco 1, confianca 1, CWE-209)
Requisicao: GET http://localhost:3000/ftp/package.json.bak
Parametro: -
Ataque: -
Evidencia: /lib/
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0179 · proposta IA: VP

**Justificativa IA:** a pagina de erro 403 traz o stack trace com caminho absoluto no servidor (/juice-shop/node_modules/express/lib/...)

Evidencia: GET http://localhost:3000/ftp/suspicious_errors.yml -> 403 com stack trace contendo /juice-shop/node_modules/express/lib/router/layer.js

Como verificar: `curl -s "http://localhost:3000/ftp/suspicious_errors.yml" | grep -o "/juice-shop/[^ <]*" | head -3`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/suspicious_errors.yml` · aparece em 9 rodada(s)

Alerta: Full Path Disclosure (plugin 110009, risco 1, confianca 1, CWE-209)
Requisicao: GET http://localhost:3000/ftp/suspicious_errors.yml
Parametro: -
Ataque: -
Evidencia: /lib/
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · Information Disclosure - Sensitive Information in Browser lo

1 achado(s); proposta da IA: 1 NE

**Revisao do grupo:** ok

## T0180 · proposta IA: NE

**Justificativa IA:** o e-mail digitado no login fica no localStorage (lembrar e-mail), legivel por XSS, mas e dado pessoal e nao credencial

Evidencia: frontend/src/app/login/login.component.ts:136 localStorage.setItem(email, this.user.email); ZAP registrou email=zaproxy@example.com

Como verificar: `no navegador, fazer login em http://localhost:3000/#/login com "lembrar" e ver Application > Local Storage`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/#/login [email]` · aparece em 1 rodada(s)

Alerta: Information Disclosure - Sensitive Information in Browser localStorage (plugin 120001, risco 1, confianca 2, CWE-359)
Requisicao: GET http://localhost:3000/#/login
Parametro: email
Ataque: -
Evidencia: -
Informacao adicional: The following data (key=value) was set which matches the pattern for email addresses: email=zaproxy@example.com
Note that alerts will only be raised once for each URL + key.

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · Private IP Disclosure

1 achado(s); proposta da IA: 1 FP

**Revisao do grupo:** ok

## T0181 · proposta IA: FP

**Justificativa IA:** 192.168.99.100:3000 e uma URI fixa da configuracao publica de OAuth (redirect para docker-machine), nao endereco da infraestrutura implantada

Evidencia: GET /rest/admin/application-configuration -> googleOauth.authorizedRedirects[] contem {"uri":"http://192.168.99.100:3000", ...}

Como verificar: `curl -s http://localhost:3000/rest/admin/application-configuration | grep -o ".\{40\}192.168.99.100.\{20\}"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/rest/admin/application-configuration` · aparece em 9 rodada(s)

Alerta: Private IP Disclosure (plugin 2, risco 1, confianca 2, CWE-497)
Requisicao: GET http://localhost:3000/rest/admin/application-configuration
Parametro: -
Ataque: -
Evidencia: 192.168.99.100:3000
Informacao adicional: 192.168.99.100:3000
192.168.99.100:4200

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · Cross Site Scripting Weakness (Persistent in JSON Response)

1 achado(s); proposta da IA: 1 FP

**Revisao do grupo:** ok

## T0182 · proposta IA: FP

**Justificativa IA:** o payload volta em resposta application/json, que o navegador nao renderiza como HTML, e as reclamacoes nao sao exibidas no frontend

Evidencia: GET /api/Complaints -> application/json com message contendo <script>; nenhum template do frontend exibe Complaint.message

Como verificar: `grep -rn "message" alvos/juice-shop/frontend/src/app/complaint/*.html (so o formulario de envio)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/api/Complaints [message]` · aparece em 1 rodada(s)

Alerta: Cross Site Scripting Weakness (Persistent in JSON Response) (plugin 40014, risco 1, confianca 1, CWE-79)
Requisicao: GET http://localhost:3000/api/Complaints
Parametro: message
Ataque: <script>alert(1);</script>
Evidencia: -
Informacao adicional: Raised with LOW confidence as the Content-Type is not HTML.

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · Cross-Origin-Embedder-Policy Header Missing or Invalid

7 achado(s); proposta da IA: 7 NE

**Revisao do grupo:** ok

## T0183 · proposta IA: NE

**Justificativa IA:** cross-origin-embedder-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3000/ftp -> text/html, sem cross-origin-embedder-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/ftp" | grep -i -e "^content-type" -e "^cross-origin-embedder-policy" (sem a linha de cross-origin-embedder-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp [Cross-Origin-Embedder-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Embedder-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/ftp
Parametro: Cross-Origin-Embedder-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0185 · proposta IA: NE

**Justificativa IA:** cross-origin-embedder-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3000/juice-shop/build/routes/fileServer.js:68:18 -> text/html, sem cross-origin-embedder-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/juice-shop/build/routes/fileServer.js:68:18" | grep -i -e "^content-type" -e "^cross-origin-embedder-policy" (sem a linha de cross-origin-embedder-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/juice-shop/build/routes/fileServer.js:68:18 [Cross-Origin-Embedder-Policy]` · aparece em 7 rodada(s)

Alerta: Cross-Origin-Embedder-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/juice-shop/build/routes/fileServer.js:68:18
Parametro: Cross-Origin-Embedder-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0187 · proposta IA: NE

**Justificativa IA:** cross-origin-embedder-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3000/juice-shop/node_modules/express/lib/router/index.js:286:9 -> text/html, sem cross-origin-embedder-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/juice-shop/node_modules/express/lib/router/index.js:286:9" | grep -i -e "^content-type" -e "^cross-origin-embedder-policy" (sem a linha de cross-origin-embedder-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/juice-shop/node_modules/express/lib/router/index.js:286:9 [Cross-Origin-Embedder-Policy]` · aparece em 1 rodada(s)

Alerta: Cross-Origin-Embedder-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/juice-shop/node_modules/express/lib/router/index.js:286:9
Parametro: Cross-Origin-Embedder-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0189 · proposta IA: NE

**Justificativa IA:** cross-origin-embedder-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5 -> text/html, sem cross-origin-embedder-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5" | grep -i -e "^content-type" -e "^cross-origin-embedder-policy" (sem a linha de cross-origin-embedder-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5 [Cross-Origin-Embedder-Policy]` · aparece em 1 rodada(s)

Alerta: Cross-Origin-Embedder-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5
Parametro: Cross-Origin-Embedder-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0191 · proposta IA: NE

**Justificativa IA:** cross-origin-embedder-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3000/sitemap.xml -> text/html, sem cross-origin-embedder-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/sitemap.xml" | grep -i -e "^content-type" -e "^cross-origin-embedder-policy" (sem a linha de cross-origin-embedder-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/sitemap.xml [Cross-Origin-Embedder-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Embedder-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/sitemap.xml
Parametro: Cross-Origin-Embedder-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0193 · proposta IA: NE

**Justificativa IA:** cross-origin-embedder-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3000/ -> text/html, sem cross-origin-embedder-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/" | grep -i -e "^content-type" -e "^cross-origin-embedder-policy" (sem a linha de cross-origin-embedder-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ [Cross-Origin-Embedder-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Embedder-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/
Parametro: Cross-Origin-Embedder-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0195 · proposta IA: NE

**Justificativa IA:** cross-origin-embedder-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3000 -> text/html, sem cross-origin-embedder-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000" | grep -i -e "^content-type" -e "^cross-origin-embedder-policy" (sem a linha de cross-origin-embedder-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000 [Cross-Origin-Embedder-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Embedder-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000
Parametro: Cross-Origin-Embedder-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · Cross-Origin-Opener-Policy Header Missing or Invalid

7 achado(s); proposta da IA: 7 NE

**Revisao do grupo:** ok

## T0184 · proposta IA: NE

**Justificativa IA:** cross-origin-opener-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3000/ftp -> text/html, sem cross-origin-opener-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/ftp" | grep -i -e "^content-type" -e "^cross-origin-opener-policy" (sem a linha de cross-origin-opener-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp [Cross-Origin-Opener-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Opener-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/ftp
Parametro: Cross-Origin-Opener-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0186 · proposta IA: NE

**Justificativa IA:** cross-origin-opener-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3000/juice-shop/build/routes/fileServer.js:68:18 -> text/html, sem cross-origin-opener-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/juice-shop/build/routes/fileServer.js:68:18" | grep -i -e "^content-type" -e "^cross-origin-opener-policy" (sem a linha de cross-origin-opener-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/juice-shop/build/routes/fileServer.js:68:18 [Cross-Origin-Opener-Policy]` · aparece em 7 rodada(s)

Alerta: Cross-Origin-Opener-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/juice-shop/build/routes/fileServer.js:68:18
Parametro: Cross-Origin-Opener-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0188 · proposta IA: NE

**Justificativa IA:** cross-origin-opener-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3000/juice-shop/node_modules/express/lib/router/index.js:286:9 -> text/html, sem cross-origin-opener-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/juice-shop/node_modules/express/lib/router/index.js:286:9" | grep -i -e "^content-type" -e "^cross-origin-opener-policy" (sem a linha de cross-origin-opener-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/juice-shop/node_modules/express/lib/router/index.js:286:9 [Cross-Origin-Opener-Policy]` · aparece em 1 rodada(s)

Alerta: Cross-Origin-Opener-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/juice-shop/node_modules/express/lib/router/index.js:286:9
Parametro: Cross-Origin-Opener-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0190 · proposta IA: NE

**Justificativa IA:** cross-origin-opener-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5 -> text/html, sem cross-origin-opener-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5" | grep -i -e "^content-type" -e "^cross-origin-opener-policy" (sem a linha de cross-origin-opener-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5 [Cross-Origin-Opener-Policy]` · aparece em 1 rodada(s)

Alerta: Cross-Origin-Opener-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5
Parametro: Cross-Origin-Opener-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0192 · proposta IA: NE

**Justificativa IA:** cross-origin-opener-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3000/sitemap.xml -> text/html, sem cross-origin-opener-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/sitemap.xml" | grep -i -e "^content-type" -e "^cross-origin-opener-policy" (sem a linha de cross-origin-opener-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/sitemap.xml [Cross-Origin-Opener-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Opener-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/sitemap.xml
Parametro: Cross-Origin-Opener-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0194 · proposta IA: NE

**Justificativa IA:** cross-origin-opener-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3000/ -> text/html, sem cross-origin-opener-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/" | grep -i -e "^content-type" -e "^cross-origin-opener-policy" (sem a linha de cross-origin-opener-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ [Cross-Origin-Opener-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Opener-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000/
Parametro: Cross-Origin-Opener-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0196 · proposta IA: NE

**Justificativa IA:** cross-origin-opener-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3000 -> text/html, sem cross-origin-opener-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000" | grep -i -e "^content-type" -e "^cross-origin-opener-policy" (sem a linha de cross-origin-opener-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000 [Cross-Origin-Opener-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Opener-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3000
Parametro: Cross-Origin-Opener-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · Missing Anti-clickjacking Header

1 achado(s); proposta da IA: 1 NE

**Revisao do grupo:** ok

## T0197 · proposta IA: NE

**Justificativa IA:** resposta do socket.io sem X-Frame-Options, mas e text/plain de transporte, nao documento HTML; protecao contra clickjacking nao se aplica

Evidencia: GET http://localhost:3000/socket.io/?EIO=4&transport=polling&t=Q3fdxwJ&sid=Z6B3l7O9IlHHNF_qAAAA (polling do socket.io) -> Content-Type text/plain

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/socket.io/?EIO=4&transport=polling" | grep -i "^content-type"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/socket.io/ [x-frame-options]` · aparece em 9 rodada(s)

Alerta: Missing Anti-clickjacking Header (plugin 10020, risco 2, confianca 2, CWE-1021)
Requisicao: POST http://localhost:3000/socket.io/?EIO=4&transport=polling&t=Q3fdxwJ&sid=Z6B3l7O9IlHHNF_qAAAA
Parametro: x-frame-options
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · Content Security Policy (CSP) Header Not Set

8 achado(s); proposta da IA: 8 VP

**Revisao do grupo:** ok

## T0198 · proposta IA: VP

**Justificativa IA:** documento HTML sem Content-Security-Policy; nao ha mitigacao de injecao de script nesta pagina (a aplicacao tem XSS conhecidos)

Evidencia: GET http://localhost:3000/ftp/coupons_2013.md.bak -> 403 text/html, sem Content-Security-Policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/ftp/coupons_2013.md.bak" | grep -i -e "^content-type" -e "^content-security-policy" (sem a linha de content-security-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/coupons_2013.md.bak` · aparece em 4 rodada(s)

Alerta: Content Security Policy (CSP) Header Not Set (plugin 10038, risco 2, confianca 3, CWE-693)
Requisicao: GET http://localhost:3000/ftp/coupons_2013.md.bak
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0199 · proposta IA: VP

**Justificativa IA:** documento HTML sem Content-Security-Policy; nao ha mitigacao de injecao de script nesta pagina (a aplicacao tem XSS conhecidos)

Evidencia: GET http://localhost:3000/ftp/eastere.gg -> 403 text/html, sem Content-Security-Policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/ftp/eastere.gg" | grep -i -e "^content-type" -e "^content-security-policy" (sem a linha de content-security-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/eastere.gg` · aparece em 4 rodada(s)

Alerta: Content Security Policy (CSP) Header Not Set (plugin 10038, risco 2, confianca 3, CWE-693)
Requisicao: GET http://localhost:3000/ftp/eastere.gg
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0200 · proposta IA: VP

**Justificativa IA:** documento HTML sem Content-Security-Policy; nao ha mitigacao de injecao de script nesta pagina (a aplicacao tem XSS conhecidos)

Evidencia: GET http://localhost:3000/ftp/encrypt.pyc -> 403 text/html, sem Content-Security-Policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/ftp/encrypt.pyc" | grep -i -e "^content-type" -e "^content-security-policy" (sem a linha de content-security-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/encrypt.pyc` · aparece em 3 rodada(s)

Alerta: Content Security Policy (CSP) Header Not Set (plugin 10038, risco 2, confianca 3, CWE-693)
Requisicao: GET http://localhost:3000/ftp/encrypt.pyc
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0201 · proposta IA: VP

**Justificativa IA:** documento HTML sem Content-Security-Policy; nao ha mitigacao de injecao de script nesta pagina (a aplicacao tem XSS conhecidos)

Evidencia: GET http://localhost:3000/ftp/package-lock.json.bak -> 403 text/html, sem Content-Security-Policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/ftp/package-lock.json.bak" | grep -i -e "^content-type" -e "^content-security-policy" (sem a linha de content-security-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/package-lock.json.bak` · aparece em 1 rodada(s)

Alerta: Content Security Policy (CSP) Header Not Set (plugin 10038, risco 2, confianca 3, CWE-693)
Requisicao: GET http://localhost:3000/ftp/package-lock.json.bak
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0202 · proposta IA: VP

**Justificativa IA:** documento HTML sem Content-Security-Policy; nao ha mitigacao de injecao de script nesta pagina (a aplicacao tem XSS conhecidos)

Evidencia: GET http://localhost:3000/ftp -> 200 text/html, sem Content-Security-Policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/ftp" | grep -i -e "^content-type" -e "^content-security-policy" (sem a linha de content-security-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp` · aparece em 6 rodada(s)

Alerta: Content Security Policy (CSP) Header Not Set (plugin 10038, risco 2, confianca 3, CWE-693)
Requisicao: GET http://localhost:3000/ftp
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0203 · proposta IA: VP

**Justificativa IA:** documento HTML sem Content-Security-Policy; nao ha mitigacao de injecao de script nesta pagina (a aplicacao tem XSS conhecidos)

Evidencia: GET http://localhost:3000/sitemap.xml -> 200 text/html, sem Content-Security-Policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/sitemap.xml" | grep -i -e "^content-type" -e "^content-security-policy" (sem a linha de content-security-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/sitemap.xml` · aparece em 9 rodada(s)

Alerta: Content Security Policy (CSP) Header Not Set (plugin 10038, risco 2, confianca 3, CWE-693)
Requisicao: GET http://localhost:3000/sitemap.xml
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0204 · proposta IA: VP

**Justificativa IA:** documento HTML sem Content-Security-Policy; nao ha mitigacao de injecao de script nesta pagina (a aplicacao tem XSS conhecidos)

Evidencia: GET http://localhost:3000/ -> 200 text/html, sem Content-Security-Policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000/" | grep -i -e "^content-type" -e "^content-security-policy" (sem a linha de content-security-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/` · aparece em 9 rodada(s)

Alerta: Content Security Policy (CSP) Header Not Set (plugin 10038, risco 2, confianca 3, CWE-693)
Requisicao: GET http://localhost:3000/
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0205 · proposta IA: VP

**Justificativa IA:** documento HTML sem Content-Security-Policy; nao ha mitigacao de injecao de script nesta pagina (a aplicacao tem XSS conhecidos)

Evidencia: GET http://localhost:3000 -> 200 text/html, sem Content-Security-Policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3000" | grep -i -e "^content-type" -e "^content-security-policy" (sem a linha de content-security-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000` · aparece em 9 rodada(s)

Alerta: Content Security Policy (CSP) Header Not Set (plugin 10038, risco 2, confianca 3, CWE-693)
Requisicao: GET http://localhost:3000
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · Backup File Disclosure

31 achado(s); proposta da IA: 31 FP

**Revisao do grupo:** ok

## T0206 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_amd_64.url -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_amd_64.url" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_amd_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_amd_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_amd_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_linux_amd_64.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_amd_64.url]

</details>

**Revisao:** 
**Motivo:** 

## T0207 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_arm_64.url -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_arm_64.url" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_arm_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_arm_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_arm_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_linux_arm_64.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_arm_64.url]

</details>

**Revisao:** 
**Motivo:** 

## T0208 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_macos_64.url -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_macos_64.url" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_macos_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_macos_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_macos_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_macos_64.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_macos_64.url]

</details>

**Revisao:** 
**Motivo:** 

## T0209 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_windows_64.exe.url -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_windows_64.exe.url" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_windows_64.exe.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_windows_64.exe.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_windows_64.exe.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_windows_64.exe.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_windows_64.exe.url]

</details>

**Revisao:** 
**Motivo:** 

## T0210 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(2) -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy%20(2)]

</details>

**Revisao:** 
**Motivo:** 

## T0211 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_amd_64.url -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_amd_64.url" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_amd_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_amd_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_amd_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_linux_amd_64.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_amd_64.url]

</details>

**Revisao:** 
**Motivo:** 

## T0212 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_arm_64.url -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_arm_64.url" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_arm_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_arm_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_arm_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_linux_arm_64.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_arm_64.url]

</details>

**Revisao:** 
**Motivo:** 

## T0213 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_macos_64.url -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_macos_64.url" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_macos_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_macos_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_macos_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_macos_64.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_macos_64.url]

</details>

**Revisao:** 
**Motivo:** 

## T0214 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_windows_64.exe.url -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_windows_64.exe.url" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_windows_64.exe.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_windows_64.exe.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_windows_64.exe.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_windows_64.exe.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_windows_64.exe.url]

</details>

**Revisao:** 
**Motivo:** 

## T0215 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(3) -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy%20(3)]

</details>

**Revisao:** 
**Motivo:** 

## T0216 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_amd_64.url -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_amd_64.url" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_amd_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_amd_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_amd_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_linux_amd_64.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_amd_64.url]

</details>

**Revisao:** 
**Motivo:** 

## T0217 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_arm_64.url -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_arm_64.url" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_arm_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_arm_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_arm_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_linux_arm_64.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_arm_64.url]

</details>

**Revisao:** 
**Motivo:** 

## T0218 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_macos_64.url -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_macos_64.url" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_macos_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_macos_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_macos_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_macos_64.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_macos_64.url]

</details>

**Revisao:** 
**Motivo:** 

## T0219 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_windows_64.exe.url -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_windows_64.exe.url" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_windows_64.exe.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_windows_64.exe.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_windows_64.exe.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_windows_64.exe.url] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy/juicy_malware_windows_64.exe.url]

</details>

**Revisao:** 
**Motivo:** 

## T0220 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine%20-%20Copy -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine%20-%20Copy" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine%20-%20Copy` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine%20-%20Copy
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine%20-%20Copy
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine%20-%20Copy]

</details>

**Revisao:** 
**Motivo:** 

## T0221 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine.backup -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine.backup" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine.backup` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine.backup
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine.backup
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine.backup]

</details>

**Revisao:** 
**Motivo:** 

## T0222 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine.bac -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine.bac" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine.bac` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine.bac
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine.bac
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine.bac]

</details>

**Revisao:** 
**Motivo:** 

## T0223 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine.bak -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine.bak" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine.bak` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine.bak
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine.bak
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine.bak]

</details>

**Revisao:** 
**Motivo:** 

## T0224 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine.jar -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine.jar" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine.jar` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine.jar
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine.jar
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine.jar]

</details>

**Revisao:** 
**Motivo:** 

## T0225 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine.log -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine.log" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine.log` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine.log
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine.log
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine.log]

</details>

**Revisao:** 
**Motivo:** 

## T0226 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine.old -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine.old" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine.old` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine.old
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine.old
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine.old]

</details>

**Revisao:** 
**Motivo:** 

## T0227 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine.swp -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine.swp" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine.swp` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine.swp
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine.swp
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine.swp]

</details>

**Revisao:** 
**Motivo:** 

## T0228 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine.tar -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine.tar" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine.tar` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine.tar
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine.tar
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine.tar]

</details>

**Revisao:** 
**Motivo:** 

## T0229 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine.zip -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine.zip" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine.zip` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine.zip
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine.zip
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine.zip]

</details>

**Revisao:** 
**Motivo:** 

## T0230 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine.~bk -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine.~bk" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine.~bk` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine.~bk
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine.~bk
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine.~bk]

</details>

**Revisao:** 
**Motivo:** 

## T0231 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantinebackup/juicy_malware_linux_amd_64.url -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantinebackup/juicy_malware_linux_amd_64.url" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantinebackup/juicy_malware_linux_amd_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantinebackup/juicy_malware_linux_amd_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantinebackup/juicy_malware_linux_amd_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_linux_amd_64.url] is available at [http://localhost:3000/ftp/quarantinebackup/juicy_malware_linux_amd_64.url]

</details>

**Revisao:** 
**Motivo:** 

## T0232 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantinebackup/juicy_malware_linux_arm_64.url -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantinebackup/juicy_malware_linux_arm_64.url" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantinebackup/juicy_malware_linux_arm_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantinebackup/juicy_malware_linux_arm_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantinebackup/juicy_malware_linux_arm_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_linux_arm_64.url] is available at [http://localhost:3000/ftp/quarantinebackup/juicy_malware_linux_arm_64.url]

</details>

**Revisao:** 
**Motivo:** 

## T0233 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantinebackup/juicy_malware_macos_64.url -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantinebackup/juicy_malware_macos_64.url" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantinebackup/juicy_malware_macos_64.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantinebackup/juicy_malware_macos_64.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantinebackup/juicy_malware_macos_64.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_macos_64.url] is available at [http://localhost:3000/ftp/quarantinebackup/juicy_malware_macos_64.url]

</details>

**Revisao:** 
**Motivo:** 

## T0234 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantinebackup/juicy_malware_windows_64.exe.url -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantinebackup/juicy_malware_windows_64.exe.url" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantinebackup/juicy_malware_windows_64.exe.url` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantinebackup/juicy_malware_windows_64.exe.url
Parametro: -
Ataque: http://localhost:3000/ftp/quarantinebackup/juicy_malware_windows_64.exe.url
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine/juicy_malware_windows_64.exe.url] is available at [http://localhost:3000/ftp/quarantinebackup/juicy_malware_windows_64.exe.url]

</details>

**Revisao:** 
**Motivo:** 

## T0235 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantinebackup -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantinebackup" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantinebackup` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantinebackup
Parametro: -
Ataque: http://localhost:3000/ftp/quarantinebackup
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantinebackup]

</details>

**Revisao:** 
**Motivo:** 

## T0236 · proposta IA: FP

**Justificativa IA:** a URL de "backup" devolve a pagina inicial da SPA (fallback do Angular), nao uma copia do recurso original; nao existe backup

Evidencia: GET http://localhost:3000/ftp/quarantine~ -> 200 9608 bytes, mesmo md5 de GET / (index.html)

Como verificar: `curl -s "http://localhost:3000/ftp/quarantine~" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/ftp/quarantine~` · aparece em 9 rodada(s)

Alerta: Backup File Disclosure (plugin 10095, risco 2, confianca 2, CWE-530)
Requisicao: GET http://localhost:3000/ftp/quarantine~
Parametro: -
Ataque: http://localhost:3000/ftp/quarantine~
Evidencia: -
Informacao adicional: A backup of [http://localhost:3000/ftp/quarantine] is available at [http://localhost:3000/ftp/quarantine~]

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · Cross-Domain Misconfiguration

8 achado(s); proposta da IA: 8 NE

**Revisao do grupo:** ok 

## T0237 · proposta IA: NE

**Justificativa IA:** Access-Control-Allow-Origin: * existe, mas em recurso publico e sem Access-Control-Allow-Credentials; outro site so le o que ja e publico

Evidencia: GET http://localhost:3000/assets/public/favicon_js.ico -> Access-Control-Allow-Origin: *, sem Access-Control-Allow-Credentials

Como verificar: `curl -s -D - -o /dev/null -H "Origin: http://evil.example" "http://localhost:3000/assets/public/favicon_js.ico" | grep -i "^access-control"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/assets/public/favicon_js.ico` · aparece em 2 rodada(s)

Alerta: Cross-Domain Misconfiguration (plugin 10098, risco 2, confianca 2, CWE-264)
Requisicao: GET http://localhost:3000/assets/public/favicon_js.ico
Parametro: -
Ataque: -
Evidencia: Access-Control-Allow-Origin: *
Informacao adicional: The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listin

</details>

**Revisao:** 
**Motivo:** 

## T0238 · proposta IA: NE

**Justificativa IA:** Access-Control-Allow-Origin: * existe, mas em recurso publico e sem Access-Control-Allow-Credentials; outro site so le o que ja e publico

Evidencia: GET http://localhost:3000/chunk-DBPdFzgj.js -> Access-Control-Allow-Origin: *, sem Access-Control-Allow-Credentials

Como verificar: `curl -s -D - -o /dev/null -H "Origin: http://evil.example" "http://localhost:3000/chunk-DBPdFzgj.js" | grep -i "^access-control"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/chunk-DBPdFzgj.js` · aparece em 2 rodada(s)

Alerta: Cross-Domain Misconfiguration (plugin 10098, risco 2, confianca 2, CWE-264)
Requisicao: GET http://localhost:3000/chunk-DBPdFzgj.js
Parametro: -
Ataque: -
Evidencia: Access-Control-Allow-Origin: *
Informacao adicional: The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listin

</details>

**Revisao:** 
**Motivo:** 

## T0239 · proposta IA: NE

**Justificativa IA:** Access-Control-Allow-Origin: * existe, mas em recurso publico e sem Access-Control-Allow-Credentials; outro site so le o que ja e publico

Evidencia: GET http://localhost:3000/robots.txt -> Access-Control-Allow-Origin: *, sem Access-Control-Allow-Credentials

Como verificar: `curl -s -D - -o /dev/null -H "Origin: http://evil.example" "http://localhost:3000/robots.txt" | grep -i "^access-control"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/robots.txt` · aparece em 9 rodada(s)

Alerta: Cross-Domain Misconfiguration (plugin 10098, risco 2, confianca 2, CWE-264)
Requisicao: GET http://localhost:3000/robots.txt
Parametro: -
Ataque: -
Evidencia: Access-Control-Allow-Origin: *
Informacao adicional: The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listin

</details>

**Revisao:** 
**Motivo:** 

## T0240 · proposta IA: NE

**Justificativa IA:** Access-Control-Allow-Origin: * existe, mas em recurso publico e sem Access-Control-Allow-Credentials; outro site so le o que ja e publico

Evidencia: GET http://localhost:3000/rolldown-runtime-BoHGiXSq.js -> Access-Control-Allow-Origin: *, sem Access-Control-Allow-Credentials

Como verificar: `curl -s -D - -o /dev/null -H "Origin: http://evil.example" "http://localhost:3000/rolldown-runtime-BoHGiXSq.js" | grep -i "^access-control"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/rolldown-runtime-BoHGiXSq.js` · aparece em 1 rodada(s)

Alerta: Cross-Domain Misconfiguration (plugin 10098, risco 2, confianca 2, CWE-264)
Requisicao: GET http://localhost:3000/rolldown-runtime-BoHGiXSq.js
Parametro: -
Ataque: -
Evidencia: Access-Control-Allow-Origin: *
Informacao adicional: The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listin

</details>

**Revisao:** 
**Motivo:** 

## T0241 · proposta IA: NE

**Justificativa IA:** Access-Control-Allow-Origin: * existe, mas em recurso publico e sem Access-Control-Allow-Credentials; outro site so le o que ja e publico

Evidencia: GET http://localhost:3000/sitemap.xml -> Access-Control-Allow-Origin: *, sem Access-Control-Allow-Credentials

Como verificar: `curl -s -D - -o /dev/null -H "Origin: http://evil.example" "http://localhost:3000/sitemap.xml" | grep -i "^access-control"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/sitemap.xml` · aparece em 9 rodada(s)

Alerta: Cross-Domain Misconfiguration (plugin 10098, risco 2, confianca 2, CWE-264)
Requisicao: GET http://localhost:3000/sitemap.xml
Parametro: -
Ataque: -
Evidencia: Access-Control-Allow-Origin: *
Informacao adicional: The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listin

</details>

**Revisao:** 
**Motivo:** 

## T0242 · proposta IA: NE

**Justificativa IA:** Access-Control-Allow-Origin: * existe, mas em recurso publico e sem Access-Control-Allow-Credentials; outro site so le o que ja e publico

Evidencia: GET http://localhost:3000/styles.css -> Access-Control-Allow-Origin: *, sem Access-Control-Allow-Credentials

Como verificar: `curl -s -D - -o /dev/null -H "Origin: http://evil.example" "http://localhost:3000/styles.css" | grep -i "^access-control"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/styles.css` · aparece em 4 rodada(s)

Alerta: Cross-Domain Misconfiguration (plugin 10098, risco 2, confianca 2, CWE-264)
Requisicao: GET http://localhost:3000/styles.css
Parametro: -
Ataque: -
Evidencia: Access-Control-Allow-Origin: *
Informacao adicional: The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listin

</details>

**Revisao:** 
**Motivo:** 

## T0243 · proposta IA: NE

**Justificativa IA:** Access-Control-Allow-Origin: * existe, mas em recurso publico e sem Access-Control-Allow-Credentials; outro site so le o que ja e publico

Evidencia: GET http://localhost:3000/ -> Access-Control-Allow-Origin: *, sem Access-Control-Allow-Credentials

Como verificar: `curl -s -D - -o /dev/null -H "Origin: http://evil.example" "http://localhost:3000/" | grep -i "^access-control"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/` · aparece em 9 rodada(s)

Alerta: Cross-Domain Misconfiguration (plugin 10098, risco 2, confianca 2, CWE-264)
Requisicao: GET http://localhost:3000/
Parametro: -
Ataque: -
Evidencia: Access-Control-Allow-Origin: *
Informacao adicional: The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listin

</details>

**Revisao:** 
**Motivo:** 

## T0244 · proposta IA: NE

**Justificativa IA:** Access-Control-Allow-Origin: * existe, mas em recurso publico e sem Access-Control-Allow-Credentials; outro site so le o que ja e publico

Evidencia: GET http://localhost:3000 -> Access-Control-Allow-Origin: *, sem Access-Control-Allow-Credentials

Como verificar: `curl -s -D - -o /dev/null -H "Origin: http://evil.example" "http://localhost:3000" | grep -i "^access-control"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000` · aparece em 9 rodada(s)

Alerta: Cross-Domain Misconfiguration (plugin 10098, risco 2, confianca 2, CWE-264)
Requisicao: GET http://localhost:3000
Parametro: -
Ataque: -
Evidencia: Access-Control-Allow-Origin: *
Informacao adicional: The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listin

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · Source Code Disclosure - SQL

1 achado(s); proposta da IA: 1 FP

**Revisao do grupo:** ok

## T0245 · proposta IA: FP

**Justificativa IA:** o texto SELECT ... e parte de uma dica sobre SQL injection em linguagem natural, no JSON de /api/Hints, nao codigo-fonte

Evidencia: GET /api/Hints/ -> data[].text contem "SELECT attack string to join the relevant data..."

Como verificar: `curl -s http://localhost:3000/api/Hints/ | grep -o "SELECT attack string.\{0,60\}"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/api/Hints/` · aparece em 1 rodada(s)

Alerta: Source Code Disclosure - SQL (plugin 10099, risco 2, confianca 2, CWE-540)
Requisicao: GET http://localhost:3000/api/Hints/
Parametro: -
Ataque: -
Evidencia: SELECT attack string to join the relevant data from any such identified system table into the original result.
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · Information Disclosure - JWT in Browser localStorage

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0246 · proposta IA: VP

**Justificativa IA:** o JWT de sessao fica no localStorage, acessivel a qualquer script da pagina; com os XSS da aplicacao, o token e roubado

Evidencia: frontend/src/app/two-factor-auth-enter/two-factor-auth-enter.component.ts:54 e payment.component.ts:233 localStorage.setItem(token, ...); ZAP registrou JWT em localStorage

Como verificar: `no navegador, logar em http://localhost:3000 e ver Application > Local Storage > token`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · Integer Overflow Error

3 achado(s); proposta da IA: 3 FP

**Revisao do grupo:** ok

## T0247 · proposta IA: FP

**Justificativa IA:** o 500 vem de validacao/consulta (produto inexistente, erro interno de chave), nao de estouro de inteiro; com zeros a requisicao retorna 200

Evidencia: POST http://localhost:3000/api/BasketItems/ ProductId=91155956979921398828... -> ProductId gigante: 500 "No such product found!"; quantity zeros: 200; UserId gigante: 500 "internal error"

Como verificar: `com token (login jim@juice-sh.op / ncc-1701), POST /api/BasketItems/ com ProductId 9115595697992139882852162954 e ver a mensagem do erro`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/api/BasketItems/ [ProductId]` · aparece em 1 rodada(s)

Alerta: Integer Overflow Error (plugin 30003, risco 2, confianca 2, CWE-190)
Requisicao: POST http://localhost:3000/api/BasketItems/
Parametro: ProductId
Ataque: 91155956979921398828521629542715942257676033
Evidencia: HTTP/1.1 500 Internal Server Error
Informacao adicional: Potential Integer Overflow. Status code changed on the input of a long string of random integers.

</details>

**Revisao:** 
**Motivo:** 

## T0248 · proposta IA: FP

**Justificativa IA:** o 500 vem de validacao/consulta (produto inexistente, erro interno de chave), nao de estouro de inteiro; com zeros a requisicao retorna 200

Evidencia: POST http://localhost:3000/api/BasketItems/ quantity=00000000000000000000... -> ProductId gigante: 500 "No such product found!"; quantity zeros: 200; UserId gigante: 500 "internal error"

Como verificar: `com token (login jim@juice-sh.op / ncc-1701), POST /api/BasketItems/ com ProductId 9115595697992139882852162954 e ver a mensagem do erro`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/api/BasketItems/ [quantity]` · aparece em 1 rodada(s)

Alerta: Integer Overflow Error (plugin 30003, risco 2, confianca 2, CWE-190)
Requisicao: POST http://localhost:3000/api/BasketItems/
Parametro: quantity
Ataque: 00000000000000000000000000000000000000000000
Evidencia: HTTP/1.1 500 Internal Server Error
Informacao adicional: Potential Integer Overflow. Status code changed on the input of a long string of zeros.

</details>

**Revisao:** 
**Motivo:** 

## T0249 · proposta IA: FP

**Justificativa IA:** o 500 vem de validacao/consulta (produto inexistente, erro interno de chave), nao de estouro de inteiro; com zeros a requisicao retorna 200

Evidencia: POST http://localhost:3000/api/Complaints/ UserId=88010430058922824764... -> ProductId gigante: 500 "No such product found!"; quantity zeros: 200; UserId gigante: 500 "internal error"

Como verificar: `com token (login jim@juice-sh.op / ncc-1701), POST /api/BasketItems/ com ProductId 9115595697992139882852162954 e ver a mensagem do erro`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/api/Complaints/ [UserId]` · aparece em 1 rodada(s)

Alerta: Integer Overflow Error (plugin 30003, risco 2, confianca 2, CWE-190)
Requisicao: POST http://localhost:3000/api/Complaints/
Parametro: UserId
Ataque: 88010430058922824764635094208566666712927343
Evidencia: HTTP/1.1 500 Internal Server Error
Informacao adicional: Potential Integer Overflow. Status code changed on the input of a long string of random integers.

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · Session ID in URL Rewrite

1 achado(s); proposta da IA: 1 NE

**Revisao do grupo:** ok

## T0250 · proposta IA: NE

**Justificativa IA:** o sid na URL e o identificador de transporte do socket.io (polling), nao a sessao autenticada da aplicacao (JWT); sem ganho de acesso

Evidencia: GET /socket.io/?EIO=4&transport=polling&sid=... ; autenticacao da aplicacao usa Authorization: Bearer <JWT>

Como verificar: `curl -s "http://localhost:3000/socket.io/?EIO=4&transport=polling" (devolve o sid do engine.io, sem dados de usuario)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/socket.io/ [sid]` · aparece em 9 rodada(s)

Alerta: Session ID in URL Rewrite (plugin 3, risco 2, confianca 3, CWE-598)
Requisicao: GET http://localhost:3000/socket.io/?EIO=4&transport=polling&t=Q3fdxwN&sid=Z6B3l7O9IlHHNF_qAAAA
Parametro: sid
Ataque: -
Evidencia: Z6B3l7O9IlHHNF_qAAAA
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · Bypassing 403

6 achado(s); proposta da IA: 6 FP

**Revisao do grupo:** ok

## T0251 · proposta IA: FP

**Justificativa IA:** o 200 em /%2e/ftp/... e a pagina inicial da SPA (fallback do Angular), nao o arquivo protegido; o bloqueio 403 nao foi contornado

Evidencia: GET http://localhost:3000/%2e/ftp/coupons_2013.md.bak -> 200 9608 bytes, mesmo md5 de GET / (index.html); GET http://localhost:3000/ftp/coupons_2013.md.bak -> 403

Como verificar: `curl -s "http://localhost:3000/%2e/ftp/coupons_2013.md.bak" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/%2e/ftp/coupons_2013.md.bak` · aparece em 9 rodada(s)

Alerta: Bypassing 403 (plugin 40038, risco 2, confianca 2, CWE-348)
Requisicao: GET http://localhost:3000/%2e/ftp/coupons_2013.md.bak
Parametro: -
Ataque: /%2e/ftp/coupons_2013.md.bak
Evidencia: -
Informacao adicional: http://localhost:3000/ftp/coupons_2013.md.bak

</details>

**Revisao:** 
**Motivo:** 

## T0252 · proposta IA: FP

**Justificativa IA:** o 200 em /%2e/ftp/... e a pagina inicial da SPA (fallback do Angular), nao o arquivo protegido; o bloqueio 403 nao foi contornado

Evidencia: GET http://localhost:3000/%2e/ftp/eastere.gg -> 200 9608 bytes, mesmo md5 de GET / (index.html); GET http://localhost:3000/ftp/eastere.gg -> 403

Como verificar: `curl -s "http://localhost:3000/%2e/ftp/eastere.gg" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/%2e/ftp/eastere.gg` · aparece em 9 rodada(s)

Alerta: Bypassing 403 (plugin 40038, risco 2, confianca 2, CWE-348)
Requisicao: GET http://localhost:3000/%2e/ftp/eastere.gg
Parametro: -
Ataque: /%2e/ftp/eastere.gg
Evidencia: -
Informacao adicional: http://localhost:3000/ftp/eastere.gg

</details>

**Revisao:** 
**Motivo:** 

## T0253 · proposta IA: FP

**Justificativa IA:** o 200 em /%2e/ftp/... e a pagina inicial da SPA (fallback do Angular), nao o arquivo protegido; o bloqueio 403 nao foi contornado

Evidencia: GET http://localhost:3000/%2e/ftp/encrypt.pyc -> 200 9608 bytes, mesmo md5 de GET / (index.html); GET http://localhost:3000/ftp/encrypt.pyc -> 403

Como verificar: `curl -s "http://localhost:3000/%2e/ftp/encrypt.pyc" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/%2e/ftp/encrypt.pyc` · aparece em 9 rodada(s)

Alerta: Bypassing 403 (plugin 40038, risco 2, confianca 2, CWE-348)
Requisicao: GET http://localhost:3000/%2e/ftp/encrypt.pyc
Parametro: -
Ataque: /%2e/ftp/encrypt.pyc
Evidencia: -
Informacao adicional: http://localhost:3000/ftp/encrypt.pyc

</details>

**Revisao:** 
**Motivo:** 

## T0254 · proposta IA: FP

**Justificativa IA:** o 200 em /%2e/ftp/... e a pagina inicial da SPA (fallback do Angular), nao o arquivo protegido; o bloqueio 403 nao foi contornado

Evidencia: GET http://localhost:3000/%2e/ftp/package-lock.json.bak -> 200 9608 bytes, mesmo md5 de GET / (index.html); GET http://localhost:3000/ftp/package-lock.json.bak -> 403

Como verificar: `curl -s "http://localhost:3000/%2e/ftp/package-lock.json.bak" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/%2e/ftp/package-lock.json.bak` · aparece em 9 rodada(s)

Alerta: Bypassing 403 (plugin 40038, risco 2, confianca 2, CWE-348)
Requisicao: GET http://localhost:3000/%2e/ftp/package-lock.json.bak
Parametro: -
Ataque: /%2e/ftp/package-lock.json.bak
Evidencia: -
Informacao adicional: http://localhost:3000/ftp/package-lock.json.bak

</details>

**Revisao:** 
**Motivo:** 

## T0255 · proposta IA: FP

**Justificativa IA:** o 200 em /%2e/ftp/... e a pagina inicial da SPA (fallback do Angular), nao o arquivo protegido; o bloqueio 403 nao foi contornado

Evidencia: GET http://localhost:3000/%2e/ftp/package.json.bak -> 200 9608 bytes, mesmo md5 de GET / (index.html); GET http://localhost:3000/ftp/package.json.bak -> 403

Como verificar: `curl -s "http://localhost:3000/%2e/ftp/package.json.bak" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/%2e/ftp/package.json.bak` · aparece em 9 rodada(s)

Alerta: Bypassing 403 (plugin 40038, risco 2, confianca 2, CWE-348)
Requisicao: GET http://localhost:3000/%2e/ftp/package.json.bak
Parametro: -
Ataque: /%2e/ftp/package.json.bak
Evidencia: -
Informacao adicional: http://localhost:3000/ftp/package.json.bak

</details>

**Revisao:** 
**Motivo:** 

## T0256 · proposta IA: FP

**Justificativa IA:** o 200 em /%2e/ftp/... e a pagina inicial da SPA (fallback do Angular), nao o arquivo protegido; o bloqueio 403 nao foi contornado

Evidencia: GET http://localhost:3000/%2e/ftp/suspicious_errors.yml -> 200 9608 bytes, mesmo md5 de GET / (index.html); GET http://localhost:3000/ftp/suspicious_errors.yml -> 403

Como verificar: `curl -s "http://localhost:3000/%2e/ftp/suspicious_errors.yml" | md5sum; curl -s http://localhost:3000/ | md5sum (iguais = SPA)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/%2e/ftp/suspicious_errors.yml` · aparece em 9 rodada(s)

Alerta: Bypassing 403 (plugin 40038, risco 2, confianca 2, CWE-348)
Requisicao: GET http://localhost:3000/%2e/ftp/suspicious_errors.yml
Parametro: -
Ataque: /%2e/ftp/suspicious_errors.yml
Evidencia: -
Informacao adicional: http://localhost:3000/ftp/suspicious_errors.yml

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · CORS Misconfiguration

9 achado(s); proposta da IA: 9 NE

**Revisao do grupo:** ok

## T0257 · proposta IA: NE

**Justificativa IA:** a API responde Access-Control-Allow-Origin: * para qualquer origem, mas sem Access-Control-Allow-Credentials e com autenticacao por cabecalho Bearer; outro site so le dados publicos

Evidencia: GET http://localhost:3000/api/Feedbacks/ com origin: http://Bxi0Qlev.com -> Access-Control-Allow-Origin: *, sem Allow-Credentials

Como verificar: `curl -s -D - -o /dev/null -H "Origin: http://evil.example" "http://localhost:3000/api/Feedbacks/" | grep -i "^access-control"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/api/Feedbacks/` · aparece em 2 rodada(s)

Alerta: CORS Misconfiguration (plugin 40040, risco 2, confianca 3, CWE-942)
Requisicao: GET http://localhost:3000/api/Feedbacks/
Parametro: -
Ataque: origin: http://Bxi0Qlev.com
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0258 · proposta IA: NE

**Justificativa IA:** a API responde Access-Control-Allow-Origin: * para qualquer origem, mas sem Access-Control-Allow-Credentials e com autenticacao por cabecalho Bearer; outro site so le dados publicos

Evidencia: GET http://localhost:3000/api/Hints/ com origin: http://iIgEjn86.com -> Access-Control-Allow-Origin: *, sem Allow-Credentials

Como verificar: `curl -s -D - -o /dev/null -H "Origin: http://evil.example" "http://localhost:3000/api/Hints/" | grep -i "^access-control"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/api/Hints/` · aparece em 1 rodada(s)

Alerta: CORS Misconfiguration (plugin 40040, risco 2, confianca 3, CWE-942)
Requisicao: GET http://localhost:3000/api/Hints/
Parametro: -
Ataque: origin: http://iIgEjn86.com
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0259 · proposta IA: NE

**Justificativa IA:** a API responde Access-Control-Allow-Origin: * para qualquer origem, mas sem Access-Control-Allow-Credentials e com autenticacao por cabecalho Bearer; outro site so le dados publicos

Evidencia: GET http://localhost:3000/api/Quantitys/ com origin: http://Bxi0Qlev.com -> Access-Control-Allow-Origin: *, sem Allow-Credentials

Como verificar: `curl -s -D - -o /dev/null -H "Origin: http://evil.example" "http://localhost:3000/api/Quantitys/" | grep -i "^access-control"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/api/Quantitys/` · aparece em 8 rodada(s)

Alerta: CORS Misconfiguration (plugin 40040, risco 2, confianca 3, CWE-942)
Requisicao: GET http://localhost:3000/api/Quantitys/
Parametro: -
Ataque: origin: http://Bxi0Qlev.com
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0260 · proposta IA: NE

**Justificativa IA:** a API responde Access-Control-Allow-Origin: * para qualquer origem, mas sem Access-Control-Allow-Credentials e com autenticacao por cabecalho Bearer; outro site so le dados publicos

Evidencia: GET http://localhost:3000/api/Recycles/ com origin: http://DbKLszGX.com -> Access-Control-Allow-Origin: *, sem Allow-Credentials

Como verificar: `curl -s -D - -o /dev/null -H "Origin: http://evil.example" "http://localhost:3000/api/Recycles/" | grep -i "^access-control"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/api/Recycles/` · aparece em 1 rodada(s)

Alerta: CORS Misconfiguration (plugin 40040, risco 2, confianca 3, CWE-942)
Requisicao: GET http://localhost:3000/api/Recycles/
Parametro: -
Ataque: origin: http://DbKLszGX.com
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0261 · proposta IA: NE

**Justificativa IA:** a API responde Access-Control-Allow-Origin: * para qualquer origem, mas sem Access-Control-Allow-Credentials e com autenticacao por cabecalho Bearer; outro site so le dados publicos

Evidencia: GET http://localhost:3000/api/SecurityQuestions/ com origin: http://Bxi0Qlev.com -> Access-Control-Allow-Origin: *, sem Allow-Credentials

Como verificar: `curl -s -D - -o /dev/null -H "Origin: http://evil.example" "http://localhost:3000/api/SecurityQuestions/" | grep -i "^access-control"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/api/SecurityQuestions/` · aparece em 7 rodada(s)

Alerta: CORS Misconfiguration (plugin 40040, risco 2, confianca 3, CWE-942)
Requisicao: GET http://localhost:3000/api/SecurityQuestions/
Parametro: -
Ataque: origin: http://Bxi0Qlev.com
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0262 · proposta IA: NE

**Justificativa IA:** a API responde Access-Control-Allow-Origin: * para qualquer origem, mas sem Access-Control-Allow-Credentials e com autenticacao por cabecalho Bearer; outro site so le dados publicos

Evidencia: POST http://localhost:3000/api/Users/ com origin: http://IamjSxHF.com -> Access-Control-Allow-Origin: *, sem Allow-Credentials

Como verificar: `curl -s -D - -o /dev/null -H "Origin: http://evil.example" "http://localhost:3000/api/Users/" | grep -i "^access-control"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/api/Users/` · aparece em 5 rodada(s)

Alerta: CORS Misconfiguration (plugin 40040, risco 2, confianca 3, CWE-942)
Requisicao: POST http://localhost:3000/api/Users/
Parametro: -
Ataque: origin: http://IamjSxHF.com
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0263 · proposta IA: NE

**Justificativa IA:** a API responde Access-Control-Allow-Origin: * para qualquer origem, mas sem Access-Control-Allow-Credentials e com autenticacao por cabecalho Bearer; outro site so le dados publicos

Evidencia: GET http://localhost:3000/rest/captcha/ com origin: http://Bxi0Qlev.com -> Access-Control-Allow-Origin: *, sem Allow-Credentials

Como verificar: `curl -s -D - -o /dev/null -H "Origin: http://evil.example" "http://localhost:3000/rest/captcha/" | grep -i "^access-control"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/rest/captcha/` · aparece em 9 rodada(s)

Alerta: CORS Misconfiguration (plugin 40040, risco 2, confianca 3, CWE-942)
Requisicao: GET http://localhost:3000/rest/captcha/
Parametro: -
Ataque: origin: http://Bxi0Qlev.com
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0264 · proposta IA: NE

**Justificativa IA:** a API responde Access-Control-Allow-Origin: * para qualquer origem, mas sem Access-Control-Allow-Credentials e com autenticacao por cabecalho Bearer; outro site so le dados publicos

Evidencia: GET http://localhost:3000/rest/memories/ com origin: http://Bxi0Qlev.com -> Access-Control-Allow-Origin: *, sem Allow-Credentials

Como verificar: `curl -s -D - -o /dev/null -H "Origin: http://evil.example" "http://localhost:3000/rest/memories/" | grep -i "^access-control"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/rest/memories/` · aparece em 9 rodada(s)

Alerta: CORS Misconfiguration (plugin 40040, risco 2, confianca 3, CWE-942)
Requisicao: GET http://localhost:3000/rest/memories/
Parametro: -
Ataque: origin: http://Bxi0Qlev.com
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0265 · proposta IA: NE

**Justificativa IA:** a API responde Access-Control-Allow-Origin: * para qualquer origem, mas sem Access-Control-Allow-Credentials e com autenticacao por cabecalho Bearer; outro site so le dados publicos

Evidencia: GET http://localhost:3000/ com origin: http://uVD1tYrp.com -> Access-Control-Allow-Origin: *, sem Allow-Credentials

Como verificar: `curl -s -D - -o /dev/null -H "Origin: http://evil.example" "http://localhost:3000/" | grep -i "^access-control"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/` · aparece em 3 rodada(s)

Alerta: CORS Misconfiguration (plugin 40040, risco 2, confianca 3, CWE-942)
Requisicao: GET http://localhost:3000/
Parametro: -
Ataque: origin: http://uVD1tYrp.com
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · Application Error Disclosure

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0266 · proposta IA: VP

**Justificativa IA:** a aplicacao responde erros com pagina detalhada (stack trace com caminhos internos); o 500 nesta rota ocorreu em 1 rodada e nao se reproduz, mas a condicao e verificada em outras rotas

Evidencia: GET /api/Hints/ -> 500 Internal Server Error (1 rodada); GET /ftp/coupons_2013.md.bak -> 403 com stack trace (/juice-shop/node_modules/express/lib/router/layer.js)

Como verificar: `curl -s http://localhost:3000/ftp/coupons_2013.md.bak | grep -o "/juice-shop/[^ <]*" | head -3`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/api/Hints/` · aparece em 1 rodada(s)

Alerta: Application Error Disclosure (plugin 90022, risco 2, confianca 2, CWE-550)
Requisicao: GET http://localhost:3000/api/Hints/
Parametro: -
Ataque: -
Evidencia: Internal Server Error
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · Off-site Redirect

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0267 · proposta IA: VP

**Justificativa IA:** o parametro to controla o Location do redirect; a allowlist usa includes() e e contornavel (ver T0268), entao o redirect aberto existe

Evidencia: GET /redirect?to=https://github.com/juice-shop/juice-shop -> 302; com https://evil.example/?x=<url permitida> -> 302 para evil.example

Como verificar: `curl -s -o /dev/null -w "%{redirect_url}\n" "http://localhost:3000/redirect?to=https://evil.example/?x=https://github.com/juice-shop/juice-shop"`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · External Redirect

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0268 · proposta IA: VP

**Justificativa IA:** redirect para dominio externo arbitrario contornando a allowlist com a URL permitida na query string

Evidencia: GET /redirect?to=https://3588080267780996708.owasp.org/?https://github.com/juice-shop/juice-shop -> Location externo

Como verificar: `curl -s -o /dev/null -w "%{redirect_url}\n" "http://localhost:3000/redirect?to=https://evil.example/?x=https://github.com/juice-shop/juice-shop"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/redirect [to]` · aparece em 9 rodada(s)

Alerta: External Redirect (plugin 20019, risco 3, confianca 2, CWE-601)
Requisicao: GET http://localhost:3000/redirect?to=https%3A%2F%2F3588080267780996708.owasp.org%2F%3Fhttps%3A%2F%2Fgithub.com%2Fjuice-shop%2Fjuice-shop
Parametro: to
Ataque: https://3588080267780996708.owasp.org/?https://github.com/juice-shop/juice-shop
Evidencia: https://3588080267780996708.owasp.org/?@@@original@@@
Informacao adicional: The response contains a redirect in its Location header which allows an external Url to be set.

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · SQL Injection

2 achado(s); proposta da IA: 2 VP

**Revisao do grupo:** ok

## T0269 · proposta IA: VP

**Justificativa IA:** aspa no parametro q quebra a consulta SQL da busca (500 com erro SQLite); injecao confirmada no codigo (routes/search.ts:23)

Evidencia: GET /rest/products/search?q='( -> 500 SQLITE_ERROR

Como verificar: `curl -s "http://localhost:3000/rest/products/search?q=%27%28" | head -c 200`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/rest/products/search [q]` · aparece em 9 rodada(s)

Alerta: SQL Injection (plugin 40018, risco 3, confianca 1, CWE-89)
Requisicao: GET http://localhost:3000/rest/products/search?q=%27%28
Parametro: q
Ataque: '(
Evidencia: HTTP/1.1 500 Internal Server Error
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0270 · proposta IA: VP

**Justificativa IA:** aspa no e-mail quebra a consulta SQL do login (500) e o payload admin@juice-sh.op'-- autentica como admin sem senha; injecao confirmada no codigo (routes/login.ts:34)

Evidencia: POST /rest/user/login email=' -> 500; email=admin@juice-sh.op'-- e senha qualquer -> 200 com authentication.token

Como verificar: `curl -s -X POST localhost:3000/rest/user/login -H 'Content-Type: application/json' -d '{"email":"admin@juice-sh.op'"'"'--","password":"x"}' | head -c 120`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/rest/user/login [email]` · aparece em 9 rodada(s)

Alerta: SQL Injection (plugin 40018, risco 3, confianca 1, CWE-89)
Requisicao: POST http://localhost:3000/rest/user/login
Parametro: email
Ataque: '
Evidencia: HTTP/1.1 500 Internal Server Error
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · SQL Injection - SQLite (Time Based)

1 achado(s); proposta da IA: 1 FP

**Revisao do grupo:** ok

## T0271 · proposta IA: FP

**Justificativa IA:** POST /api/Feedbacks usa o REST generico do Sequelize (insercao parametrizada); a diferenca de 234 ms foi variacao de tempo, nao injecao

Evidencia: server.ts:505 Feedback exposto via finale/Sequelize (create parametrizado); 1 rodada, sem reproducao

Como verificar: `grep -n "Feedback" alvos/juice-shop/server.ts (modelo exposto pelo REST generico)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/api/Feedbacks/ [comment]` · aparece em 1 rodada(s)

Alerta: SQL Injection - SQLite (Time Based) (plugin 40024, risco 3, confianca 2, CWE-89)
Requisicao: POST http://localhost:3000/api/Feedbacks/
Parametro: comment
Ataque: case randomblob(1000000) when not null then 1 else 1 end 
Evidencia: -
Informacao adicional: The query time is controllable using parameter value [case randomblob(1000000) when not null then 1 else 1 end ], which caused the request to take [234] milliseconds, parameter value [case randomblob(10000000) when not null then 1 else 1 end ], which caused the request to take [812] milliseconds, when the original unmodified query with value [ (anonymous)] took [7] milliseconds.

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo1 · zap · Source Code Disclosure - File Inclusion

3 achado(s); proposta da IA: 3 FP

**Revisao do grupo:** ok

## T0272 · proposta IA: FP

**Justificativa IA:** a diferenca de resposta vem de erro de validacao do parametro, nao de inclusao de arquivo; nenhum conteudo de arquivo do servidor e devolvido

Evidencia: POST http://localhost:3000/api/BasketItems/ BasketId -> mensagem de validacao (ex.: sort=../ -> "Sorting not allowed on given attributes")

Como verificar: `curl -s "http://localhost:3000/api/Challenges/?sort=../"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/api/BasketItems/ [BasketId]` · aparece em 1 rodada(s)

Alerta: Source Code Disclosure - File Inclusion (plugin 43, risco 3, confianca 2, CWE-541)
Requisicao: POST http://localhost:3000/api/BasketItems/
Parametro: BasketId
Ataque: -
Evidencia: -
Informacao adicional: The output for the source code filename [] differs sufficiently from that of the random parameter [lcgvzwphrtwkaqaawieumlixrewcawjmmbwfni], at [2%], compared to a threshold of [75%]

</details>

**Revisao:** 
**Motivo:** 

## T0273 · proposta IA: FP

**Justificativa IA:** a diferenca de resposta vem de erro de validacao do parametro, nao de inclusao de arquivo; nenhum conteudo de arquivo do servidor e devolvido

Evidencia: POST http://localhost:3000/api/BasketItems/ quantity -> mensagem de validacao (ex.: sort=../ -> "Sorting not allowed on given attributes")

Como verificar: `curl -s "http://localhost:3000/api/Challenges/?sort=../"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/api/BasketItems/ [quantity]` · aparece em 1 rodada(s)

Alerta: Source Code Disclosure - File Inclusion (plugin 43, risco 3, confianca 2, CWE-541)
Requisicao: POST http://localhost:3000/api/BasketItems/
Parametro: quantity
Ataque: -
Evidencia: -
Informacao adicional: The output for the source code filename [] differs sufficiently from that of the random parameter [lcgvzwphrtwkaqaawieumlixrewcawjmmbwfni], at [2%], compared to a threshold of [75%]

</details>

**Revisao:** 
**Motivo:** 

## T0274 · proposta IA: FP

**Justificativa IA:** a diferenca de resposta vem de erro de validacao do parametro, nao de inclusao de arquivo; nenhum conteudo de arquivo do servidor e devolvido

Evidencia: GET http://localhost:3000/api/Challenges/?sort=name sort -> mensagem de validacao (ex.: sort=../ -> "Sorting not allowed on given attributes")

Como verificar: `curl -s "http://localhost:3000/api/Challenges/?sort=../"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3000/api/Challenges/ [sort]` · aparece em 1 rodada(s)

Alerta: Source Code Disclosure - File Inclusion (plugin 43, risco 3, confianca 2, CWE-541)
Requisicao: GET http://localhost:3000/api/Challenges/?sort=name
Parametro: sort
Ataque: ../
Evidencia: -
Informacao adicional: The output for the source code filename [../] differs sufficiently from that of the random parameter [ldaoasdysblbicjxildwwdbpxvujlpkfvdykkn], at [75%], compared to a threshold of [75%]

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · semgrep · detect-child-process

4 achado(s); proposta da IA: 4 FP

**Revisao do grupo:** ok

## T0275 · proposta IA: FP

**Justificativa IA:** previousVersion vem de process.argv[2] (linha 83); script de release executado pelo mantenedor, sem entrada de atacante, entao nao ha injecao de comando

Evidencia: alvos/uptime-kuma/extra/release/generate-changelog.mjs:278

Como verificar: `grep -n "execSync\|exec(\|previousVersion" alvos/uptime-kuma/extra/release/generate-changelog.mjs`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0276 · proposta IA: FP

**Justificativa IA:** execSync(cmd) e wrapper chamado com comandos fixos dos scripts de release; script de release executado pelo mantenedor, sem entrada de atacante, entao nao ha injecao de comando

Evidencia: alvos/uptime-kuma/extra/release/lib.mjs:519

Como verificar: `grep -n "execSync\|exec(\|previousVersion" alvos/uptime-kuma/extra/release/lib.mjs`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0277 · proposta IA: FP

**Justificativa IA:** exec(cmd) recebe comandos git com branchName derivado da versao em RELEASE_* (ambiente do mantenedor); script de release executado pelo mantenedor, sem entrada de atacante, entao nao ha injecao de comando

Evidencia: alvos/uptime-kuma/extra/release/prepare-release.mjs:87

Como verificar: `grep -n "execSync\|exec(\|previousVersion" alvos/uptime-kuma/extra/release/prepare-release.mjs`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0278 · proposta IA: FP

**Justificativa IA:** executablePath nesse ponto e sempre a constante /usr/bin/chromium (prepareChromeExecutable, linha 120); caminhos do usuario passam por allowlist e nao chegam a esta chamada

Evidencia: alvos/uptime-kuma/server/monitor-types/real-browser-monitor-type.js:119-121 executablePath = "/usr/bin/chromium"; await installChromiumViaApt(executablePath); linha 164 execSync(executablePath + " --version")

Como verificar: `sed -n 113,135p alvos/uptime-kuma/server/monitor-types/real-browser-monitor-type.js`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · semgrep · react-insecure-request

2 achado(s); proposta da IA: 2 VP

**Revisao do grupo:** ok

## T0279 · proposta IA: VP

**Justificativa IA:** o build da imagem base baixa a lista e o .deb do apprise por HTTP sem TLS e instala com apt install ./apprise.deb, sem verificacao de assinatura; MITM no build injeta pacote

Evidencia: alvos/uptime-kuma/extra/download-apprise.mjs:10-11 baseURL = http://ftp.debian.org/...; fetch + curl do .deb; docker/debian-base.dockerfile:41-43 COPY apprise.deb e apt install ./apprise.deb

Como verificar: `sed -n 1,12p alvos/uptime-kuma/extra/download-apprise.mjs; sed -n 38,45p alvos/uptime-kuma/docker/debian-base.dockerfile`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0280 · proposta IA: VP

**Justificativa IA:** notificacao Aliyun SMS envia por HTTP sem TLS a requisicao com AccessKeyId, telefone e conteudo da mensagem; observador na rede le os dados

Evidencia: alvos/uptime-kuma/server/notification-providers/aliyun-sms.js:70-72 axios POST url http://dysmsapi.aliyuncs.com/

Como verificar: `sed -n 60,80p alvos/uptime-kuma/server/notification-providers/aliyun-sms.js`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · semgrep · gha-curl-pipe-shell

1 achado(s); proposta da IA: 1 NE

**Revisao do grupo:** ok

## T0281 · proposta IA: NE

**Justificativa IA:** curl -fsSL https://opencode.ai/install | bash executa script remoto sem verificacao de integridade; a condicao existe, mas no CI do projeto upstream, que nao integra o artefato entregue (a imagem da aplicacao)

Evidencia: alvos/uptime-kuma/.github/workflows/release.yml:135

Como verificar: `sed -n 135p alvos/uptime-kuma/.github/workflows/release.yml`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · semgrep · missing-ssl-minversion

1 achado(s); proposta da IA: 1 FP

**Revisao do grupo:** ok

## T0282 · proposta IA: FP

**Justificativa IA:** a regra aponta tls.Config sem MinVersion, mas o binario usa Go 1.20.5 e, desde o Go 1.18, o cliente ja usa TLS 1.2 como minimo padrao

Evidencia: alvos/uptime-kuma/extra/healthcheck.go:26 tls.Config{InsecureSkipVerify: true} sem MinVersion; /app/extra/healthcheck compilado com go1.20.5

Como verificar: `docker cp triagem-alvo2:/app/extra/healthcheck - | tar -xO | grep -aoE 'go1\.[0-9]+\.[0-9]+' | sort -u; ver https://go.dev/doc/go1.18#tls10`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · semgrep · direct-response-write

7 achado(s); proposta da IA: 7 FP

**Revisao do grupo:** ok

## T0283 · proposta IA: FP

**Justificativa IA:** o SVG e gerado pelo badge-maker, que escapa < > e aspas dos parametros do usuario antes de montar o XML; nao ha HTML nao escapado na resposta

Evidencia: alvos/uptime-kuma/server/routers/api-router.js:215 response.send(makeBadge(badgeValues)); GET /api/badge/1/status?label=<script>... devolve &lt;script&gt;

Como verificar: `curl -s "localhost:3001/api/badge/1/status?label=%3Cscript%3Ealert(1)%3C/script%3E" | grep -o "&lt;script&gt;"`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0284 · proposta IA: FP

**Justificativa IA:** o SVG e gerado pelo badge-maker, que escapa < > e aspas dos parametros do usuario antes de montar o XML; nao ha HTML nao escapado na resposta

Evidencia: alvos/uptime-kuma/server/routers/api-router.js:279 response.send(makeBadge(badgeValues)); GET /api/badge/1/status?label=<script>... devolve &lt;script&gt;

Como verificar: `curl -s "localhost:3001/api/badge/1/status?label=%3Cscript%3Ealert(1)%3C/script%3E" | grep -o "&lt;script&gt;"`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0285 · proposta IA: FP

**Justificativa IA:** o SVG e gerado pelo badge-maker, que escapa < > e aspas dos parametros do usuario antes de montar o XML; nao ha HTML nao escapado na resposta

Evidencia: alvos/uptime-kuma/server/routers/api-router.js:345 response.send(makeBadge(badgeValues)); GET /api/badge/1/status?label=<script>... devolve &lt;script&gt;

Como verificar: `curl -s "localhost:3001/api/badge/1/status?label=%3Cscript%3Ealert(1)%3C/script%3E" | grep -o "&lt;script&gt;"`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0286 · proposta IA: FP

**Justificativa IA:** o SVG e gerado pelo badge-maker, que escapa < > e aspas dos parametros do usuario antes de montar o XML; nao ha HTML nao escapado na resposta

Evidencia: alvos/uptime-kuma/server/routers/api-router.js:418 response.send(makeBadge(badgeValues)); GET /api/badge/1/status?label=<script>... devolve &lt;script&gt;

Como verificar: `curl -s "localhost:3001/api/badge/1/status?label=%3Cscript%3Ealert(1)%3C/script%3E" | grep -o "&lt;script&gt;"`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0287 · proposta IA: FP

**Justificativa IA:** o SVG e gerado pelo badge-maker, que escapa < > e aspas dos parametros do usuario antes de montar o XML; nao ha HTML nao escapado na resposta

Evidencia: alvos/uptime-kuma/server/routers/api-router.js:501 response.send(makeBadge(badgeValues)); GET /api/badge/1/status?label=<script>... devolve &lt;script&gt;

Como verificar: `curl -s "localhost:3001/api/badge/1/status?label=%3Cscript%3Ealert(1)%3C/script%3E" | grep -o "&lt;script&gt;"`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0288 · proposta IA: FP

**Justificativa IA:** o SVG e gerado pelo badge-maker, que escapa < > e aspas dos parametros do usuario antes de montar o XML; nao ha HTML nao escapado na resposta

Evidencia: alvos/uptime-kuma/server/routers/api-router.js:561 response.send(makeBadge(badgeValues)); GET /api/badge/1/status?label=<script>... devolve &lt;script&gt;

Como verificar: `curl -s "localhost:3001/api/badge/1/status?label=%3Cscript%3Ealert(1)%3C/script%3E" | grep -o "&lt;script&gt;"`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

## T0289 · proposta IA: FP

**Justificativa IA:** o SVG e gerado pelo badge-maker, que escapa < > e aspas dos parametros do usuario antes de montar o XML; nao ha HTML nao escapado na resposta

Evidencia: alvos/uptime-kuma/server/routers/status-page-router.js:258 response.send(makeBadge(badgeValues)); GET /api/badge/1/status?label=<script>... devolve &lt;script&gt;

Como verificar: `curl -s "localhost:3001/api/badge/1/status?label=%3Cscript%3Ealert(1)%3C/script%3E" | grep -o "&lt;script&gt;"`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · semgrep · unknown-value-with-script-tag

1 achado(s); proposta da IA: 1 FP

**Revisao do grupo:** ok

## T0290 · proposta IA: FP

**Justificativa IA:** o JSON e serializado com jsesc e isScriptContext: true, que escapa </script> e caracteres perigosos para contexto de script

Evidencia: alvos/uptime-kuma/server/model/status_page.js:196-202 escapedJSONObject = jsesc(..., {isScriptContext: true}); window.preloadData = ${escapedJSONObject}

Como verificar: `sed -n 194,204p alvos/uptime-kuma/server/model/status_page.js`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · semgrep · bypass-tls-verification

1 achado(s); proposta da IA: 1 NE

**Revisao do grupo:** ok 

## T0291 · proposta IA: NE

**Justificativa IA:** rejectUnauthorized: false existe, mas so e ativado por opcao explicita do administrador (teltonikaUnsafeTls) para roteadores com certificado autoassinado

Evidencia: alvos/uptime-kuma/server/notification-providers/teltonika.js:49-51 if (notification.teltonikaUnsafeTls) httpsAgent rejectUnauthorized false

Como verificar: `sed -n 44,54p alvos/uptime-kuma/server/notification-providers/teltonika.js`

<details><summary>Dados da ferramenta</summary>

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

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-config · DS-0031

1 achado(s); proposta da IA: 1 NE

**Revisao do grupo:** ok

## T0292 · proposta IA: NE

**Justificativa IA:** ARG GITHUB_TOKEN existe, mas no estagio upload-artifact, que nao participa do build da aplicacao (alvo usa --target release); exemplo do proprio protocolo

Evidencia: alvos/uptime-kuma/docker/dockerfile:95 FROM ... AS upload-artifact; linha 103 ARG GITHUB_TOKEN; ci/perfis/alvo2-uptimekuma.env ALVO_BUILD_TARGET=release

Como verificar: `grep -n '^FROM' alvos/uptime-kuma/docker/dockerfile; grep ALVO_BUILD_TARGET ci/perfis/alvo2-uptimekuma.env`

<details><summary>Dados da ferramenta</summary>

`dockerfile:103` · aparece em 9 rodada(s)

Regra: DS-0031 (Secrets passed via `build-args` or envs or copied secret files)
Arquivo: dockerfile
Mensagem: Possible exposure of secret env "GITHUB_TOKEN" in ARG
Resolucao sugerida pela ferramenta: Use secret mount if secrets are needed during image build. Use volume mount if secret files are needed during container runtime.

```
  103 | ARG GITHUB_TOKEN
```

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-config · DS-0013

1 achado(s); proposta da IA: 1 NE

**Revisao do grupo:** ok

## T0293 · proposta IA: NE

**Justificativa IA:** RUN cd em vez de WORKDIR e questao de estilo sem impacto de seguranca, e fica no estagio upload-artifact, fora do build da aplicacao

Evidencia: alvos/uptime-kuma/docker/dockerfile:116 RUN cd /app && tar -zcvf $DIST dist, dentro do estagio upload-artifact (linha 95)

Como verificar: `grep -n '^FROM' alvos/uptime-kuma/docker/dockerfile; sed -n 116p alvos/uptime-kuma/docker/dockerfile`

<details><summary>Dados da ferramenta</summary>

`dockerfile:116` · aparece em 9 rodada(s)

Regra: DS-0013 ('RUN cd ...' to change directory)
Arquivo: dockerfile
Mensagem: RUN should not be used to change directory: 'cd /app && tar -zcvf $DIST dist'. Use 'WORKDIR' statement instead.
Resolucao sugerida pela ferramenta: Use WORKDIR to change directory

```
  116 | RUN cd /app && tar -zcvf $DIST dist
```

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-image · chromium

34 achado(s); proposta da IA: 34 VP

**Revisao do grupo:** ok

## T0294 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.53-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.53-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-11002

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-11002`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0296 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.196-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.196-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-13038

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-13038`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0303 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 148.0.7778.215-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 148.0.7778.215-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-9879

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-9879`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0307 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.53-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.53-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-10920

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-10920`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0308 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.53-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.53-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-10960

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-10960`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0311 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.102-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.102-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-11683

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-11683`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0315 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 150.0.7871.46-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 150.0.7871.46-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-13798

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-13798`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0317 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 150.0.7871.46-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 150.0.7871.46-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-13827

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-13827`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0319 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 151.0.7922.71-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 151.0.7922.71-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-17711

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-17711`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0320 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 151.0.7922.108-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 151.0.7922.108-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-19163

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-19163`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0325 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 151.0.7922.169-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 151.0.7922.169-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-76044

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-76044`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0328 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 148.0.7778.215-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 148.0.7778.215-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-9914

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-9914`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0339 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.53-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.53-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-11299

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-11299`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0340 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.53-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.53-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-11309

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-11309`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0342 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 150.0.7871.46-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 150.0.7871.46-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-14128

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-14128`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0353 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.53-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.53-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-11001

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-11001`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0358 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.53-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.53-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-11066

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-11066`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0361 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.53-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.53-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-11122

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-11122`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0366 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 150.0.7871.46-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 150.0.7871.46-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-14002

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-14002`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0367 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 150.0.7871.46-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 150.0.7871.46-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-14009

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-14009`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0369 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 151.0.7922.71-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 151.0.7922.71-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-17738

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-17738`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0370 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 151.0.7922.71-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 151.0.7922.71-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-17806

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-17806`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0374 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 151.0.7922.71-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 151.0.7922.71-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-17866

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-17866`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0377 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 152.0.7977.75-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 152.0.7977.75-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-78898

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-78898`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0378 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 153.0.8010.52-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 153.0.8010.52-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-87556

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-87556`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0379 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 151.0.7922.71-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 151.0.7922.71-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-17669

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-17669`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0381 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 152.0.7977.75-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 152.0.7977.75-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-78964

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-78964`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0382 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 152.0.7977.75-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 152.0.7977.75-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-78967

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-78967`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0386 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 152.0.7977.75-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 152.0.7977.75-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-79125

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-79125`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0387 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 152.0.7977.75-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 152.0.7977.75-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-79178

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-79178`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0388 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 152.0.7977.75-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 152.0.7977.75-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-79225

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-79225`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0390 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 153.0.8010.52-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 153.0.8010.52-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-87438

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-87438`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0394 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 153.0.8010.52-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 153.0.8010.52-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-87629

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-87629`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0396 · proposta IA: VP

**Justificativa IA:** chromium 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 154.0.8037.57-1, posterior a instalada

Evidencia: dpkg: chromium 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 154.0.8037.57-1; https://security-tracker.debian.org/tracker/CVE-2026-95289

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-95289`

<details><summary>Dados da ferramenta</summary>

`chromium@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-image · chromium-common

47 achado(s); proposta da IA: 47 VP

**Revisao do grupo:** ok

## T0295 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.53-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.53-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-11029

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-11029`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0297 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 151.0.7922.71-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 151.0.7922.71-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-17651

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-17651`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0301 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 152.0.7977.75-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 152.0.7977.75-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-79131

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-79131`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0302 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 152.0.7977.75-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 152.0.7977.75-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-79138

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-79138`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0306 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.53-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.53-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-10920

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-10920`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0309 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.102-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.102-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-11628

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-11628`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0310 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.102-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.102-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-11637

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-11637`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0312 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.102-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.102-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-11695

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-11695`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0314 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.196-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.196-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-13026

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-13026`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0316 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 150.0.7871.46-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 150.0.7871.46-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-13809

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-13809`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0318 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 150.0.7871.46-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 150.0.7871.46-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-14412

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-14412`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0321 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 151.0.7922.137-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 151.0.7922.137-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-19560

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-19560`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0323 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 151.0.7922.173-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 151.0.7922.173-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-76018

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-76018`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0324 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 151.0.7922.169-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 151.0.7922.169-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-76037

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-76037`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0327 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 152.0.7977.75-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 152.0.7977.75-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-79270

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-79270`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0329 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 148.0.7778.215-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 148.0.7778.215-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-9928

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-9928`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0330 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 148.0.7778.215-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 148.0.7778.215-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-9943

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-9943`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0331 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 148.0.7778.215-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 148.0.7778.215-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-9986

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-9986`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0338 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.53-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.53-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-11225

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-11225`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0343 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 151.0.7922.71-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 151.0.7922.71-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-17908

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-17908`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0344 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 151.0.7922.71-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 151.0.7922.71-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-17911

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-17911`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0354 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.53-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.53-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-11004

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-11004`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0355 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.53-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.53-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-11018

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-11018`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0356 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.53-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.53-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-11040

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-11040`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0357 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.53-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.53-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-11065

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-11065`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0359 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.53-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.53-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-11073

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-11073`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0360 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.53-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.53-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-11095

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-11095`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0362 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.53-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.53-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-11134

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-11134`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0363 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 149.0.7827.53-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 149.0.7827.53-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-11155

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-11155`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0364 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 150.0.7871.46-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 150.0.7871.46-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-13859

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-13859`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0365 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 150.0.7871.46-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 150.0.7871.46-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-13868

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-13868`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0368 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 150.0.7871.46-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 150.0.7871.46-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-14406

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-14406`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0371 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 151.0.7922.71-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 151.0.7922.71-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-17824

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-17824`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0372 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 151.0.7922.71-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 151.0.7922.71-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-17833

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-17833`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0373 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 151.0.7922.71-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 151.0.7922.71-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-17844

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-17844`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0375 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 151.0.7922.71-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 151.0.7922.71-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-17887

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-17887`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0380 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 152.0.7977.75-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 152.0.7977.75-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-78912

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-78912`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0383 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 152.0.7977.75-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 152.0.7977.75-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-79028

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-79028`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0384 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 152.0.7977.75-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 152.0.7977.75-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-79076

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-79076`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0385 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 152.0.7977.75-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 152.0.7977.75-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-79105

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-79105`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0389 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 152.0.7977.82-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 152.0.7977.82-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-85042

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-85042`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0391 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 153.0.8010.52-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 153.0.8010.52-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-87590

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-87590`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0392 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 153.0.8010.52-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 153.0.8010.52-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-87606

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-87606`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0393 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 153.0.8010.52-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 153.0.8010.52-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-87629

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-87629`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0395 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 153.0.8010.52-1~deb12u1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 153.0.8010.52-1~deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-93384

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-93384`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0397 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 154.0.8037.57-1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 154.0.8037.57-1; https://security-tracker.debian.org/tracker/CVE-2026-95328

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-95328`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0398 · proposta IA: VP

**Justificativa IA:** chromium-common 148.0.7778.178-1~deb12u1 presente na imagem e afetado: corrigido no Debian em 154.0.8037.57-1, posterior a instalada

Evidencia: dpkg: chromium-common 148.0.7778.178-1~deb12u1; Debian bookworm: resolved, corrigido em 154.0.8037.57-1; https://security-tracker.debian.org/tracker/CVE-2026-95341

Como verificar: `docker exec triagem-alvo2 dpkg-query -W chromium-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-95341`

<details><summary>Dados da ferramenta</summary>

`chromium-common@148.0.7778.178-1~deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-image · libglx-mesa0

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0298 · proposta IA: VP

**Justificativa IA:** libglx-mesa0 22.3.6-1+deb12u1 presente na imagem e afetado: corrigido no Debian em 22.3.6-1+deb12u2, posterior a instalada

Evidencia: dpkg: libglx-mesa0 22.3.6-1+deb12u1; Debian bookworm: resolved, corrigido em 22.3.6-1+deb12u2; https://security-tracker.debian.org/tracker/CVE-2026-40393

Como verificar: `docker exec triagem-alvo2 dpkg-query -W libglx-mesa0  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-40393`

<details><summary>Dados da ferramenta</summary>

`libglx-mesa0@22.3.6-1+deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-image · mariadb-common

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0299 · proposta IA: VP

**Justificativa IA:** mariadb-common 1:10.11.14-0+deb12u2 presente na imagem e afetado: corrigido no Debian em 1:10.11.18-0+deb12u1, posterior a instalada

Evidencia: dpkg: mariadb-common 1:10.11.14-0+deb12u2; Debian bookworm: resolved, corrigido em 1:10.11.18-0+deb12u1; https://security-tracker.debian.org/tracker/CVE-2026-44172

Como verificar: `docker exec triagem-alvo2 dpkg-query -W mariadb-common  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-44172`

<details><summary>Dados da ferramenta</summary>

`mariadb-common@1:10.11.14-0+deb12u2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-image · tar

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0300 · proposta IA: VP

**Justificativa IA:** tar 7.5.11 presente na imagem e dentro da faixa afetada (<= 7.5.18)

Evidencia: /usr/local/lib/node_modules/npm/node_modules/tar/package.json version 7.5.11; CVE-2026-59873 (GHSA-23hp-3jrh-7fpw) faixa <= 7.5.18

Como verificar: `docker cp triagem-alvo2:/usr/local/lib/node_modules/npm/node_modules/tar/package.json - | tar -xO | grep '"version"'  e comparar com https://github.com/advisories/GHSA-23hp-3jrh-7fpw`

<details><summary>Dados da ferramenta</summary>

`tar@7.5.11` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-image · mariadb-server-core

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0304 · proposta IA: VP

**Justificativa IA:** mariadb-server-core 1:10.11.14-0+deb12u2 presente na imagem e afetado: corrigido no Debian em 1:10.11.18-0+deb12u1, posterior a instalada

Evidencia: dpkg: mariadb-server-core 1:10.11.14-0+deb12u2; Debian bookworm: resolved, corrigido em 1:10.11.18-0+deb12u1; https://security-tracker.debian.org/tracker/CVE-2025-13699

Como verificar: `docker exec triagem-alvo2 dpkg-query -W mariadb-server-core  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2025-13699`

<details><summary>Dados da ferramenta</summary>

`mariadb-server-core@1:10.11.14-0+deb12u2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-image · libncurses6

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0305 · proposta IA: VP

**Justificativa IA:** libncurses6 6.4-4 presente na imagem e afetado: sem correcao no Debian bookworm (status open)

Evidencia: dpkg: libncurses6 6.4-4; Debian bookworm: open; https://security-tracker.debian.org/tracker/CVE-2025-69720

Como verificar: `docker exec triagem-alvo2 dpkg-query -W libncurses6  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2025-69720`

<details><summary>Dados da ferramenta</summary>

`libncurses6@6.4-4` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-image · python3.11

2 achado(s); proposta da IA: 2 VP

**Revisao do grupo:** ok

## T0313 · proposta IA: VP

**Justificativa IA:** python3.11 3.11.2-6+deb12u7 presente na imagem e afetado: sem correcao no Debian bookworm (status open)

Evidencia: dpkg: python3.11 3.11.2-6+deb12u7; Debian bookworm: open; https://security-tracker.debian.org/tracker/CVE-2026-11940

Como verificar: `docker exec triagem-alvo2 dpkg-query -W python3.11  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-11940`

<details><summary>Dados da ferramenta</summary>

`python3.11@3.11.2-6+deb12u7` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0345 · proposta IA: VP

**Justificativa IA:** python3.11 3.11.2-6+deb12u7 presente na imagem e afetado: sem correcao no Debian bookworm (status open)

Evidencia: dpkg: python3.11 3.11.2-6+deb12u7; Debian bookworm: open; https://security-tracker.debian.org/tracker/CVE-2026-18503

Como verificar: `docker exec triagem-alvo2 dpkg-query -W python3.11  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-18503`

<details><summary>Dados da ferramenta</summary>

`python3.11@3.11.2-6+deb12u7` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-image · stdlib

3 achado(s); proposta da IA: 3 VP

**Revisao do grupo:** ok

## T0322 · proposta IA: VP

**Justificativa IA:** binario Go /usr/bin/cloudflared compilado com Go 1.26.3, dentro da faixa afetada (corrigido em 1.25.12, 1.26.5, 1.27.0-rc.2)

Evidencia: /usr/bin/cloudflared: string go1.26.3 no binario; Go Vulnerability DB para CVE-2026-39822

Como verificar: `docker cp triagem-alvo2:/usr/bin/cloudflared - | tar -xO | grep -aoE 'go1\.[0-9]+\.[0-9]+' | sort -u  e comparar com https://pkg.go.dev/vuln/ (busca CVE-2026-39822)`

<details><summary>Dados da ferramenta</summary>

`stdlib@v1.26.3` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0349 · proposta IA: VP

**Justificativa IA:** binario Go /app/extra/healthcheck compilado com Go 1.20.5, dentro da faixa afetada (corrigido em 1.23.12, 1.24.6)

Evidencia: /app/extra/healthcheck: string go1.20.5 no binario; Go Vulnerability DB para CVE-2025-47906

Como verificar: `docker cp triagem-alvo2:/app/extra/healthcheck - | tar -xO | grep -aoE 'go1\.[0-9]+\.[0-9]+' | sort -u  e comparar com https://pkg.go.dev/vuln/ (busca CVE-2025-47906)`

<details><summary>Dados da ferramenta</summary>

`stdlib@v1.20.5` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0350 · proposta IA: VP

**Justificativa IA:** binario Go /app/extra/healthcheck compilado com Go 1.20.5, dentro da faixa afetada (corrigido em 1.23.12, 1.24.6)

Evidencia: /app/extra/healthcheck: string go1.20.5 no binario; Go Vulnerability DB para CVE-2025-47907

Como verificar: `docker cp triagem-alvo2:/app/extra/healthcheck - | tar -xO | grep -aoE 'go1\.[0-9]+\.[0-9]+' | sort -u  e comparar com https://pkg.go.dev/vuln/ (busca CVE-2025-47907)`

<details><summary>Dados da ferramenta</summary>

`stdlib@v1.20.5` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-image · libmount1

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0326 · proposta IA: VP

**Justificativa IA:** libmount1 2.38.1-5+deb12u3 presente na imagem e afetado: sem correcao no Debian bookworm (status open)

Evidencia: dpkg: libmount1 2.38.1-5+deb12u3; Debian bookworm: open; https://security-tracker.debian.org/tracker/CVE-2026-78408

Como verificar: `docker exec triagem-alvo2 dpkg-query -W libmount1  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-78408`

<details><summary>Dados da ferramenta</summary>

`libmount1@2.38.1-5+deb12u3` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-image · libnss3

2 achado(s); proposta da IA: 2 NE

**Revisao do grupo:** ok

## T0332 · proposta IA: NE

**Justificativa IA:** libnss3 2:3.87.1-1+deb12u2 presente na versao afetada, mas exige acesso local para forjar arquivos DBM do NSS (Debian: unimportant)

Evidencia: dpkg: libnss3 2:3.87.1-1+deb12u2; Debian bookworm: open/unimportant; https://security-tracker.debian.org/tracker/CVE-2017-11696

Como verificar: `docker exec triagem-alvo2 dpkg-query -W libnss3  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2017-11696`

<details><summary>Dados da ferramenta</summary>

`libnss3@2:3.87.1-1+deb12u2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

## T0333 · proposta IA: NE

**Justificativa IA:** libnss3 2:3.87.1-1+deb12u2 presente na versao afetada, mas exige acesso local para forjar arquivos DBM do NSS (Debian: unimportant)

Evidencia: dpkg: libnss3 2:3.87.1-1+deb12u2; Debian bookworm: open/unimportant; https://security-tracker.debian.org/tracker/CVE-2017-11698

Como verificar: `docker exec triagem-alvo2 dpkg-query -W libnss3  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2017-11698`

<details><summary>Dados da ferramenta</summary>

`libnss3@2:3.87.1-1+deb12u2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-image · libkrb5support0

1 achado(s); proposta da IA: 1 NE

**Revisao do grupo:** ok

## T0334 · proposta IA: NE

**Justificativa IA:** libkrb5support0 1.20.1-2+deb12u5 presente na versao afetada, mas caminho de codigo so roda com entrada confiavel (Debian: unimportant, non-issue)

Evidencia: dpkg: libkrb5support0 1.20.1-2+deb12u5; Debian bookworm: open/unimportant; https://security-tracker.debian.org/tracker/CVE-2018-5709

Como verificar: `docker exec triagem-alvo2 dpkg-query -W libkrb5support0  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2018-5709`

<details><summary>Dados da ferramenta</summary>

`libkrb5support0@1.20.1-2+deb12u5` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-image · libudev1

1 achado(s); proposta da IA: 1 NE

**Revisao do grupo:** ok

## T0335 · proposta IA: NE

**Justificativa IA:** libudev1 252.39-1~deb12u2 presente na versao afetada, mas contestado pelo upstream do systemd; selagem de log do journald nao usada no container (Debian: unimportant)

Evidencia: dpkg: libudev1 252.39-1~deb12u2; Debian bookworm: open/unimportant; https://security-tracker.debian.org/tracker/CVE-2023-31438

Como verificar: `docker exec triagem-alvo2 dpkg-query -W libudev1  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2023-31438`

<details><summary>Dados da ferramenta</summary>

`libudev1@252.39-1~deb12u2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-image · libsystemd0

1 achado(s); proposta da IA: 1 NE

**Revisao do grupo:** ok

## T0336 · proposta IA: NE

**Justificativa IA:** libsystemd0 252.39-1~deb12u2 presente na versao afetada, mas contestado pelo upstream do systemd; selagem de log do journald nao usada no container (Debian: unimportant)

Evidencia: dpkg: libsystemd0 252.39-1~deb12u2; Debian bookworm: open/unimportant; https://security-tracker.debian.org/tracker/CVE-2023-31439

Como verificar: `docker exec triagem-alvo2 dpkg-query -W libsystemd0  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2023-31439`

<details><summary>Dados da ferramenta</summary>

`libsystemd0@252.39-1~deb12u2` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-image · python3-certifi

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0337 · proposta IA: VP

**Justificativa IA:** Debian marca unimportant porque o certifi usa o repositorio do sistema, mas nesta imagem o ca-certificates 20230311+deb12u1 ainda confia nas 3 raizes E-Tugra

Evidencia: certifi.where() = /etc/ssl/certs/ca-certificates.crt; /etc/ca-certificates.conf habilita mozilla/E-Tugra_*.crt (3 raizes); certificado E-Tugra RSA v3 presente no bundle

Como verificar: `docker exec triagem-alvo2 sh -c 'python3 -c "import certifi;print(certifi.where())"; ls /etc/ssl/certs | grep -i tugra'`

<details><summary>Dados da ferramenta</summary>

`python3-certifi@2022.9.24-1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-image · libkrb5-3

1 achado(s); proposta da IA: 1 NE

**Revisao do grupo:** ok

## T0341 · proposta IA: NE

**Justificativa IA:** libkrb5-3 1.20.1-2+deb12u5 presente na versao afetada, mas sem impacto de seguranca, nao cruza fronteira de seguranca (krb5 #9206; Debian: unimportant)

Evidencia: dpkg: libkrb5-3 1.20.1-2+deb12u5; Debian bookworm: open/unimportant; https://security-tracker.debian.org/tracker/CVE-2026-11850

Como verificar: `docker exec triagem-alvo2 dpkg-query -W libkrb5-3  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-11850`

<details><summary>Dados da ferramenta</summary>

`libkrb5-3@1.20.1-2+deb12u5` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-image · python3.11-minimal

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0346 · proposta IA: VP

**Justificativa IA:** python3.11-minimal 3.11.2-6+deb12u7 presente na imagem e afetado: corrigido no Debian em 3.11.2-6+deb12u8, posterior a instalada

Evidencia: dpkg: python3.11-minimal 3.11.2-6+deb12u7; Debian bookworm: resolved, corrigido em 3.11.2-6+deb12u8; https://security-tracker.debian.org/tracker/CVE-2026-2297

Como verificar: `docker exec triagem-alvo2 dpkg-query -W python3.11-minimal  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-2297`

<details><summary>Dados da ferramenta</summary>

`python3.11-minimal@3.11.2-6+deb12u7` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-image · sysvinit-utils

1 achado(s); proposta da IA: 1 NE

**Revisao do grupo:** ok

## T0347 · proposta IA: NE

**Justificativa IA:** sysvinit-utils 3.06-4 presente na versao afetada, mas exige acesso local a maquina; sem CVE atribuido (Debian: unimportant)

Evidencia: dpkg: sysvinit-utils 3.06-4; Debian bookworm: open/unimportant; https://security-tracker.debian.org/tracker/TEMP-0517018-A83CE6

Como verificar: `docker exec triagem-alvo2 dpkg-query -W sysvinit-utils  e conferir o status em https://security-tracker.debian.org/tracker/TEMP-0517018-A83CE6`

<details><summary>Dados da ferramenta</summary>

`sysvinit-utils@3.06-4` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-image · perl-modules-5.36

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0348 · proposta IA: VP

**Justificativa IA:** perl-modules-5.36 5.36.0-7+deb12u3 presente na imagem e afetado: sem correcao no Debian bookworm (status open)

Evidencia: dpkg: perl-modules-5.36 5.36.0-7+deb12u3; Debian bookworm: open; https://security-tracker.debian.org/tracker/CVE-2025-15649

Como verificar: `docker exec triagem-alvo2 dpkg-query -W perl-modules-5.36  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2025-15649`

<details><summary>Dados da ferramenta</summary>

`perl-modules-5.36@5.36.0-7+deb12u3` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-image · libavahi-client3

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0351 · proposta IA: VP

**Justificativa IA:** libavahi-client3 0.8-10+deb12u1 presente na imagem e afetado: sem correcao no Debian bookworm (status open)

Evidencia: dpkg: libavahi-client3 0.8-10+deb12u1; Debian bookworm: open; https://security-tracker.debian.org/tracker/CVE-2025-68468

Como verificar: `docker exec triagem-alvo2 dpkg-query -W libavahi-client3  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2025-68468`

<details><summary>Dados da ferramenta</summary>

`libavahi-client3@0.8-10+deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-image · libavahi-common3

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0352 · proposta IA: VP

**Justificativa IA:** libavahi-common3 0.8-10+deb12u1 presente na imagem e afetado: sem correcao no Debian bookworm (status open)

Evidencia: dpkg: libavahi-common3 0.8-10+deb12u1; Debian bookworm: open; https://security-tracker.debian.org/tracker/CVE-2025-68471

Como verificar: `docker exec triagem-alvo2 dpkg-query -W libavahi-common3  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2025-68471`

<details><summary>Dados da ferramenta</summary>

`libavahi-common3@0.8-10+deb12u1` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · trivy-image · rsync

1 achado(s); proposta da IA: 1 VP

**Revisao do grupo:** ok

## T0376 · proposta IA: VP

**Justificativa IA:** rsync 3.2.7-1+deb12u5 presente na imagem e afetado: sem correcao no Debian bookworm (status open)

Evidencia: dpkg: rsync 3.2.7-1+deb12u5; Debian bookworm: open; https://security-tracker.debian.org/tracker/CVE-2026-53792

Como verificar: `docker exec triagem-alvo2 dpkg-query -W rsync  e conferir o status em https://security-tracker.debian.org/tracker/CVE-2026-53792`

<details><summary>Dados da ferramenta</summary>

`rsync@3.2.7-1+deb12u5` · aparece em 9 rodada(s)

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · zap · X-Content-Type-Options Header Missing

7 achado(s); proposta da IA: 7 VP

**Revisao do grupo:** ok

## T0399 · proposta IA: VP

**Justificativa IA:** resposta application/json sem X-Content-Type-Options: nosniff; o navegador pode interpretar o conteudo como outro tipo (MIME sniffing)

Evidencia: GET http://localhost:3001/api/status-page/servicos/manifest.json -> Content-Type application/json, sem X-Content-Type-Options

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/api/status-page/servicos/manifest.json" | grep -i -e "^content-type" -e "^x-content-type-options" (sem a linha de x-content-type-options = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/api/status-page/servicos/manifest.json [x-content-type-options]` · aparece em 4 rodada(s)

Alerta: X-Content-Type-Options Header Missing (plugin 10021, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/api/status-page/servicos/manifest.json
Parametro: x-content-type-options
Ataque: -
Evidencia: -
Informacao adicional: This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.

</details>

**Revisao:** 
**Motivo:** 

## T0400 · proposta IA: VP

**Justificativa IA:** resposta image/png sem X-Content-Type-Options: nosniff; o navegador pode interpretar o conteudo como outro tipo (MIME sniffing)

Evidencia: GET http://localhost:3001/apple-touch-icon.png -> Content-Type image/png, sem X-Content-Type-Options

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/apple-touch-icon.png" | grep -i -e "^content-type" -e "^x-content-type-options" (sem a linha de x-content-type-options = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/apple-touch-icon.png [x-content-type-options]` · aparece em 6 rodada(s)

Alerta: X-Content-Type-Options Header Missing (plugin 10021, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/apple-touch-icon.png
Parametro: x-content-type-options
Ataque: -
Evidencia: -
Informacao adicional: This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.

</details>

**Revisao:** 
**Motivo:** 

## T0401 · proposta IA: VP

**Justificativa IA:** resposta image/svg+xml sem X-Content-Type-Options: nosniff; o navegador pode interpretar o conteudo como outro tipo (MIME sniffing)

Evidencia: GET http://localhost:3001/icon.svg -> Content-Type image/svg+xml, sem X-Content-Type-Options

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/icon.svg" | grep -i -e "^content-type" -e "^x-content-type-options" (sem a linha de x-content-type-options = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/icon.svg [x-content-type-options]` · aparece em 7 rodada(s)

Alerta: X-Content-Type-Options Header Missing (plugin 10021, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/icon.svg
Parametro: x-content-type-options
Ataque: -
Evidencia: -
Informacao adicional: This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.

</details>

**Revisao:** 
**Motivo:** 

## T0402 · proposta IA: VP

**Justificativa IA:** resposta application/json sem X-Content-Type-Options: nosniff; o navegador pode interpretar o conteudo como outro tipo (MIME sniffing)

Evidencia: GET http://localhost:3001/manifest.json -> Content-Type application/json, sem X-Content-Type-Options

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/manifest.json" | grep -i -e "^content-type" -e "^x-content-type-options" (sem a linha de x-content-type-options = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/manifest.json [x-content-type-options]` · aparece em 1 rodada(s)

Alerta: X-Content-Type-Options Header Missing (plugin 10021, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/manifest.json
Parametro: x-content-type-options
Ataque: -
Evidencia: -
Informacao adicional: This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.

</details>

**Revisao:** 
**Motivo:** 

## T0403 · proposta IA: VP

**Justificativa IA:** resposta text/plain sem X-Content-Type-Options: nosniff; o navegador pode interpretar o conteudo como outro tipo (MIME sniffing)

Evidencia: GET http://localhost:3001/robots.txt -> Content-Type text/plain, sem X-Content-Type-Options

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/robots.txt" | grep -i -e "^content-type" -e "^x-content-type-options" (sem a linha de x-content-type-options = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/robots.txt [x-content-type-options]` · aparece em 9 rodada(s)

Alerta: X-Content-Type-Options Header Missing (plugin 10021, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/robots.txt
Parametro: x-content-type-options
Ataque: -
Evidencia: -
Informacao adicional: This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.

</details>

**Revisao:** 
**Motivo:** 

## T0404 · proposta IA: VP

**Justificativa IA:** resposta text/html sem X-Content-Type-Options: nosniff; o navegador pode interpretar o conteudo como outro tipo (MIME sniffing)

Evidencia: GET http://localhost:3001/sitemap.xml -> Content-Type text/html, sem X-Content-Type-Options

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/sitemap.xml" | grep -i -e "^content-type" -e "^x-content-type-options" (sem a linha de x-content-type-options = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/sitemap.xml [x-content-type-options]` · aparece em 9 rodada(s)

Alerta: X-Content-Type-Options Header Missing (plugin 10021, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/sitemap.xml
Parametro: x-content-type-options
Ataque: -
Evidencia: -
Informacao adicional: This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.

</details>

**Revisao:** 
**Motivo:** 

## T0405 · proposta IA: VP

**Justificativa IA:** resposta text/html sem X-Content-Type-Options: nosniff; o navegador pode interpretar o conteudo como outro tipo (MIME sniffing)

Evidencia: GET http://localhost:3001/status/servicos -> Content-Type text/html, sem X-Content-Type-Options

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/status/servicos" | grep -i -e "^content-type" -e "^x-content-type-options" (sem a linha de x-content-type-options = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/status/servicos [x-content-type-options]` · aparece em 9 rodada(s)

Alerta: X-Content-Type-Options Header Missing (plugin 10021, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/status/servicos
Parametro: x-content-type-options
Ataque: -
Evidencia: -
Informacao adicional: This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · zap · Permissions Policy Header Not Set

4 achado(s); proposta da IA: 4 NE

**Revisao do grupo:** ok

## T0406 · proposta IA: NE

**Justificativa IA:** permissions-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3001/assets/index-BiJ2MzwC.js -> application/javascript, sem permissions-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/assets/index-BiJ2MzwC.js" | grep -i -e "^content-type" -e "^permissions-policy" (sem a linha de permissions-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/assets/index-BiJ2MzwC.js` · aparece em 9 rodada(s)

Alerta: Permissions Policy Header Not Set (plugin 10063, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/assets/index-BiJ2MzwC.js
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0407 · proposta IA: NE

**Justificativa IA:** permissions-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3001/sitemap.xml -> text/html, sem permissions-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/sitemap.xml" | grep -i -e "^content-type" -e "^permissions-policy" (sem a linha de permissions-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/sitemap.xml` · aparece em 9 rodada(s)

Alerta: Permissions Policy Header Not Set (plugin 10063, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/sitemap.xml
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0408 · proposta IA: NE

**Justificativa IA:** permissions-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3001/status/servicos -> text/html, sem permissions-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/status/servicos" | grep -i -e "^content-type" -e "^permissions-policy" (sem a linha de permissions-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/status/servicos` · aparece em 9 rodada(s)

Alerta: Permissions Policy Header Not Set (plugin 10063, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/status/servicos
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0409 · proposta IA: NE

**Justificativa IA:** permissions-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3001/status -> text/html, sem permissions-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/status" | grep -i -e "^content-type" -e "^permissions-policy" (sem a linha de permissions-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/status` · aparece em 9 rodada(s)

Alerta: Permissions Policy Header Not Set (plugin 10063, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/status
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · zap · Dangerous JS Functions

1 achado(s); proposta da IA: 1 FP

**Revisao do grupo:** ok

## T0410 · proposta IA: FP

**Justificativa IA:** o eval no bundle e de um polyfill que avalia string constante ("(async function* () {})") para detectar suporte do navegador; sem dado do usuario

Evidencia: GET /assets/index-BiJ2MzwC.js -> oe.eval("(async function* () {})")

Como verificar: `curl -s http://localhost:3001/assets/index-BiJ2MzwC.js | grep -o ".\{30\}eval(.\{30\}"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/assets/index-BiJ2MzwC.js` · aparece em 9 rodada(s)

Alerta: Dangerous JS Functions (plugin 10110, risco 1, confianca 1, CWE-749)
Requisicao: GET http://localhost:3001/assets/index-BiJ2MzwC.js
Parametro: -
Ataque: -
Evidencia: eval(
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · zap · Private IP Disclosure

1 achado(s); proposta da IA: 1 FP

**Revisao do grupo:** ok

## T0411 · proposta IA: FP

**Justificativa IA:** 192.168.100.1 e o texto de exemplo (placeholder) do campo de URL da notificacao Teltonika, nao endereco da infraestrutura

Evidencia: GET /assets/index-BiJ2MzwC.js -> placeholder:"192.168.100.1" no formulario teltonikaUrl

Como verificar: `curl -s http://localhost:3001/assets/index-BiJ2MzwC.js | grep -o ".\{40\}192.168.100.1.\{10\}"`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/assets/index-BiJ2MzwC.js` · aparece em 9 rodada(s)

Alerta: Private IP Disclosure (plugin 2, risco 1, confianca 2, CWE-497)
Requisicao: GET http://localhost:3001/assets/index-BiJ2MzwC.js
Parametro: -
Ataque: -
Evidencia: 192.168.100.1
Informacao adicional: 192.168.100.1
192.168.100.1
192.168.100.1

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · zap · Cross-Origin-Resource-Policy Header Missing or Invalid

6 achado(s); proposta da IA: 6 NE

**Revisao do grupo:** ok

## T0412 · proposta IA: NE

**Justificativa IA:** cross-origin-resource-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3001/api/status-page/servicos/manifest.json -> application/json, sem cross-origin-resource-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/api/status-page/servicos/manifest.json" | grep -i -e "^content-type" -e "^cross-origin-resource-policy" (sem a linha de cross-origin-resource-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/api/status-page/servicos/manifest.json [Cross-Origin-Resource-Policy]` · aparece em 6 rodada(s)

Alerta: Cross-Origin-Resource-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/api/status-page/servicos/manifest.json
Parametro: Cross-Origin-Resource-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0413 · proposta IA: NE

**Justificativa IA:** cross-origin-resource-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3001/apple-touch-icon.png -> image/png, sem cross-origin-resource-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/apple-touch-icon.png" | grep -i -e "^content-type" -e "^cross-origin-resource-policy" (sem a linha de cross-origin-resource-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/apple-touch-icon.png [Cross-Origin-Resource-Policy]` · aparece em 5 rodada(s)

Alerta: Cross-Origin-Resource-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/apple-touch-icon.png
Parametro: Cross-Origin-Resource-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0414 · proposta IA: NE

**Justificativa IA:** cross-origin-resource-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3001/icon.svg -> image/svg+xml, sem cross-origin-resource-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/icon.svg" | grep -i -e "^content-type" -e "^cross-origin-resource-policy" (sem a linha de cross-origin-resource-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/icon.svg [Cross-Origin-Resource-Policy]` · aparece em 7 rodada(s)

Alerta: Cross-Origin-Resource-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/icon.svg
Parametro: Cross-Origin-Resource-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0415 · proposta IA: NE

**Justificativa IA:** cross-origin-resource-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3001/robots.txt -> text/plain, sem cross-origin-resource-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/robots.txt" | grep -i -e "^content-type" -e "^cross-origin-resource-policy" (sem a linha de cross-origin-resource-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/robots.txt [Cross-Origin-Resource-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Resource-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/robots.txt
Parametro: Cross-Origin-Resource-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0418 · proposta IA: NE

**Justificativa IA:** cross-origin-resource-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3001/sitemap.xml -> text/html, sem cross-origin-resource-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/sitemap.xml" | grep -i -e "^content-type" -e "^cross-origin-resource-policy" (sem a linha de cross-origin-resource-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/sitemap.xml [Cross-Origin-Resource-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Resource-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/sitemap.xml
Parametro: Cross-Origin-Resource-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0421 · proposta IA: NE

**Justificativa IA:** cross-origin-resource-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3001/status/servicos -> text/html, sem cross-origin-resource-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/status/servicos" | grep -i -e "^content-type" -e "^cross-origin-resource-policy" (sem a linha de cross-origin-resource-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/status/servicos [Cross-Origin-Resource-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Resource-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/status/servicos
Parametro: Cross-Origin-Resource-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · zap · Cross-Origin-Embedder-Policy Header Missing or Invalid

2 achado(s); proposta da IA: 2 NE

**Revisao do grupo:** ok

## T0416 · proposta IA: NE

**Justificativa IA:** cross-origin-embedder-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3001/sitemap.xml -> text/html, sem cross-origin-embedder-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/sitemap.xml" | grep -i -e "^content-type" -e "^cross-origin-embedder-policy" (sem a linha de cross-origin-embedder-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/sitemap.xml [Cross-Origin-Embedder-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Embedder-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/sitemap.xml
Parametro: Cross-Origin-Embedder-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0419 · proposta IA: NE

**Justificativa IA:** cross-origin-embedder-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3001/status/servicos -> text/html, sem cross-origin-embedder-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/status/servicos" | grep -i -e "^content-type" -e "^cross-origin-embedder-policy" (sem a linha de cross-origin-embedder-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/status/servicos [Cross-Origin-Embedder-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Embedder-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/status/servicos
Parametro: Cross-Origin-Embedder-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · zap · Cross-Origin-Opener-Policy Header Missing or Invalid

2 achado(s); proposta da IA: 2 NE

**Revisao do grupo:** ok

## T0417 · proposta IA: NE

**Justificativa IA:** cross-origin-opener-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3001/sitemap.xml -> text/html, sem cross-origin-opener-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/sitemap.xml" | grep -i -e "^content-type" -e "^cross-origin-opener-policy" (sem a linha de cross-origin-opener-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/sitemap.xml [Cross-Origin-Opener-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Opener-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/sitemap.xml
Parametro: Cross-Origin-Opener-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0420 · proposta IA: NE

**Justificativa IA:** cross-origin-opener-policy ausente, mas e cabecalho de isolamento/restricao de recursos do navegador (defesa em profundidade); sem ataque direto no contexto, a aplicacao nao depende de isolamento cross-origin

Evidencia: GET http://localhost:3001/status/servicos -> text/html, sem cross-origin-opener-policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/status/servicos" | grep -i -e "^content-type" -e "^cross-origin-opener-policy" (sem a linha de cross-origin-opener-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/status/servicos [Cross-Origin-Opener-Policy]` · aparece em 9 rodada(s)

Alerta: Cross-Origin-Opener-Policy Header Missing or Invalid (plugin 90004, risco 1, confianca 2, CWE-693)
Requisicao: GET http://localhost:3001/status/servicos
Parametro: Cross-Origin-Opener-Policy
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

---

# Grupo: alvo2 · zap · Content Security Policy (CSP) Header Not Set

3 achado(s); proposta da IA: 3 VP

**Revisao do grupo:** ok

## T0422 · proposta IA: VP

**Justificativa IA:** documento HTML sem Content-Security-Policy; nao ha mitigacao de injecao de script nesta pagina

Evidencia: GET http://localhost:3001/sitemap.xml -> 200 text/html, sem Content-Security-Policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/sitemap.xml" | grep -i -e "^content-type" -e "^content-security-policy" (sem a linha de content-security-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/sitemap.xml` · aparece em 9 rodada(s)

Alerta: Content Security Policy (CSP) Header Not Set (plugin 10038, risco 2, confianca 3, CWE-693)
Requisicao: GET http://localhost:3001/sitemap.xml
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0423 · proposta IA: VP

**Justificativa IA:** documento HTML sem Content-Security-Policy; nao ha mitigacao de injecao de script nesta pagina

Evidencia: GET http://localhost:3001/status/servicos -> 200 text/html, sem Content-Security-Policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/status/servicos" | grep -i -e "^content-type" -e "^content-security-policy" (sem a linha de content-security-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/status/servicos` · aparece em 9 rodada(s)

Alerta: Content Security Policy (CSP) Header Not Set (plugin 10038, risco 2, confianca 3, CWE-693)
Requisicao: GET http://localhost:3001/status/servicos
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

## T0424 · proposta IA: VP

**Justificativa IA:** documento HTML sem Content-Security-Policy; nao ha mitigacao de injecao de script nesta pagina

Evidencia: GET http://localhost:3001/status -> 404 text/html, sem Content-Security-Policy

Como verificar: `curl -s -D - -o /dev/null "http://localhost:3001/status" | grep -i -e "^content-type" -e "^content-security-policy" (sem a linha de content-security-policy = ausente)`

<details><summary>Dados da ferramenta</summary>

`http://localhost:3001/status` · aparece em 9 rodada(s)

Alerta: Content Security Policy (CSP) Header Not Set (plugin 10038, risco 2, confianca 3, CWE-693)
Requisicao: GET http://localhost:3001/status
Parametro: -
Ataque: -
Evidencia: -
Informacao adicional: -

</details>

**Revisao:** 
**Motivo:** 

---
