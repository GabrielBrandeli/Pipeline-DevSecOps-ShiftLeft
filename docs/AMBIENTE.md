# Ambiente Experimental

Ultima atualizacao: 2026-09-05

Este documento registra todos os parametros fixados do experimento. Ele e a
fonte de dados para o quadro da secao 3.1.3 do TCC e para a checklist de
reprodutibilidade.

---

## 1. Estacao de trabalho (desenvolvimento)

| Item | Valor |
|---|---|
| Sistema hospedeiro | Windows 11, build 26200.9168 |
| Camada de virtualizacao | WSL2 |
| Distribuicao | Ubuntu 24.04.4 LTS |
| Kernel | Linux 6.6.87.2-microsoft-standard-WSL2 x86_64 |
| Docker | Docker Desktop 4.89.0, integracao WSL habilitada |
| Data da coleta | 2026-09-05T03:23:08Z |

## 2. Versoes das ferramentas (local)

| Ferramenta | Versao | Origem |
|---|---|---|
| git | 2.43.0 | apt |
| Node.js | 22.23.2 | nvm |
| npm | 10.9.8 | nvm |
| Docker Engine | 29.8.0 | Docker Desktop |
| Python | 3.12.3 | apt |
| GitHub CLI | 2.100.0 | apt |
| Semgrep | 1.176.1 | pip/pipx |
| Trivy | 0.71.2 | apt (repositorio oficial Aqua) |
| jq | 1.7 | apt |
---

## 3. Aplicacoes-alvo

| | Alvo 1 | Alvo 2 |
|---|---|---|
| Nome | OWASP Juice Shop | Uptime Kuma |
| Repositorio | github.com/juice-shop/juice-shop | github.com/louislam/uptime-kuma |
| Tag fixada | v20.2.0 | 2.5.3 |
| Commit (SHA) | 5658473cf8814459bf89000ce373b20ed0b4eb37 | 1f0755fb044fe08e99fccde6722062fb2bf6c8f4 |
| Data do release | 2026-08-10T14:43:31+02:00 | 2026-08-22T17:15:57+08:00 |
| Licenca | MIT | MIT |
| Stack | Node.js / TypeScript / Angular | Node.js / Vue |
| Porta | 3000 | 3001 |
| Caminho de health check | / | / |
| Ground truth disponivel | Sim (`data/static/challenges.yml`) | Nao |

### 3.1 Particularidades de build

Os dois alvos exigem procedimentos de build diferentes. As diferencas estao
isoladas nos arquivos de perfil em `ci/perfis/` e sao aplicadas de forma
identica nas configuracoes de linha de base e de intervencao, nao interferindo
na medicao de sobrecarga.

| Aspecto | Alvo 1 | Alvo 2 |
|---|---|---|
| Caminho do Dockerfile | `alvos/juice-shop/Dockerfile` | `alvos/uptime-kuma/docker/dockerfile` |
| Estagio de build (`--target`) | nao se aplica | `release` |
| Pre-build fora do Docker | nao | `npm ci && npm run build` |
| Imagem base | `gcr.io/distroless/nodejs24-debian13` | `louislam/uptime-kuma:base2` (Debian) |
| Origem da imagem base | construida no pipeline (multi-stage a partir de `node:24`) | herdada pronta do Docker Hub |
| Node.js em execucao | 24 | 22.22.3 |

Notas relevantes:

1. **Estagio de build do alvo 2.** O `dockerfile` do Uptime Kuma define oito
   estagios. O ultimo (`upload-artifact`) e infraestrutura de release do
   projeto e falha fora do CI dos mantenedores. O estagio da aplicacao e
   `release` (linha 29), e o `--target release` e obrigatorio.

2. **Pre-build do alvo 2.** O estagio `build` executa `npm ci --omit=dev`, sem
   as dependencias de desenvolvimento, e portanto sem o Vite. O diretorio
   `dist/` precisa ser gerado no host antes do `docker build` e entra pelo
   contexto. Sem isso o container sobe mas responde com erro
   `Cannot find 'dist/index.html'`.

3. **Consequencia para o SCA.** Apos o pre-build, existem `node_modules/` e
   `dist/` na arvore do alvo 2. O `trivy fs` e executado com
   `--skip-dirs node_modules,dist` em **ambos os alvos**, para preservar a
   comparabilidade. O `npm ci` completo instala dependencias de
   desenvolvimento que nao chegam a imagem final; a diferenca entre o conjunto
   de achados do `trivy fs` e do `trivy image` e reportada como resultado.

4. **Escopo do `trivy config` no alvo 2.** O diretorio `docker/` contem tres
   dockerfiles (`dockerfile`, `debian-base.dockerfile`,
   `builder-go.dockerfile`) e ha ainda `test/test-radius.dockerfile`. Varrer
   todos inflaria a contagem de IaC e quebraria a comparabilidade com o alvo 1,
   que possui um unico Dockerfile. A varredura e restrita ao dockerfile de
   producao por `--file-patterns "dockerfile:docker/dockerfile"`.

5. **Assimetria de imagem base.** O alvo 1 usa imagem distroless, com
   superficie minima de pacotes de sistema operacional; o alvo 2 usa base
   Debian completa herdada do registro. Espera-se diferenca acentuada no
   volume de achados de sistema operacional entre os dois, o que constitui
   resultado e nao ruido experimental.

---

## 4. Ambiente de execucao da esteira (CI)   [preencher em S2]

| Item | Valor |
|---|---|
| Plataforma | GitHub Actions, runners hospedados |
| Imagem do runner | ubuntu-24.04 (versao fixada, nunca `ubuntu-latest`) |
| Recursos | 2 vCPU, 7 GB RAM, 14 GB SSD |
| Repositorio | github.com/GabrielBrandeli/Pipeline-DevSecOps-ShiftLeft |
| Visibilidade | Publico (minutos de Actions ilimitados) |
| Retencao de artefatos | 90 dias |
| Dependabot / CodeQL | Desabilitados (evitam varreduras paralelas que contaminam o experimento) |
| Cache de camadas Docker | PREENCHER (decidir em S2; se habilitado, deve valer para os dois alvos e as duas configuracoes) |

## 5. Actions fixadas por SHA   [preencher em S2/S3]

Todas as actions de terceiros sao fixadas por SHA completo de commit, nunca por
tag. Tags sao mutaveis e o `aquasecurity/trivy-action` sofreu comprometimento
de cadeia de suprimentos em marco de 2026.

| Action | Versao | SHA de commit |
|---|---|---|
| actions/checkout | | |
| actions/upload-artifact | | |
| actions/download-artifact | | |
| aquasecurity/setup-trivy | | |
| zaproxy/action-full-scan | | |

## 6. Configuracao das ferramentas de seguranca   [preencher em S3/S4]

### Semgrep (SAST)
- Versao no CI:
- Conjuntos de regras: `p/owasp-top-ten`, `p/javascript`, `p/security-audit`, `p/secrets`
- Comando: `semgrep scan \
  --config p/owasp-top-ten --config p/javascript \
  --config p/security-audit --config p/secrets \
  --json --output /tmp/smoke/sg-uptime-kuma.json \
  --metrics=off --timeout 300 \
  --exclude node_modules --exclude dist \
  alvos/uptime-kuma`
- Justificativa de `scan` em vez de `ci`: `semgrep ci` realiza varredura
  diferencial em relacao a um commit-base e e orientado a plataforma comercial.
  O experimento exige varredura completa e deterministica em todas as execucoes.

### Trivy (SCA e IaC)
- Versao no CI:
- Data da base de vulnerabilidades:
- Cache habilitado:
- Varreduras: `fs` (vuln, secret), `image` (vuln), `config`
- `--exit-code 0` em todas: a decisao de bloqueio e delegada ao
  `ci/quality_gate.py`, porque a flag `--severity` filtra pelo rotulo de
  severidade e nao pela pontuacao numerica CVSS exigida pelo criterio.

### OWASP ZAP (DAST)
- Imagem: `ghcr.io/zaproxy/zaproxy:stable`
- Digest (sha256): ghcr.io/zaproxy/zaproxy@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef
- Modo: full scan
- Limites: `-m 5 -T 20`
- Autenticado:
- Escrita de issues: desabilitada (`allow_issue_writing: false`)
- Estado inicial do alvo 2: PREENCHER (o Uptime Kuma exibe tela de configuracao
  inicial; decidir entre fixture de banco pre-populado ou varredura nao
  autenticada, e registrar)

## 7. Criterio de Quality Gate

- Versao do CVSS: 3.1 (Base Score)
- Limiar: 7.0, criterio `>=`
- Precedencia de fonte: NVD, GHSA, Red Hat, fallback por rotulo
- Regra de equivalencia: `ci/regras/equivalencia.yaml`, versao 1.0
- Modos: `enforce`, `audit`
- Escopos: `sca_only` (padrao), `all_tools`

---

## 8. Teste de fumaca

### 8.1 Parte 1: build e subida (concluida em 05/09/2026)

| Verificacao | Alvo 1 | Alvo 2 |
|---|---|---|
| Sobe em container unico | Sim | Sim |
| Pre-build no host (s) | nao se aplica | ~135 (npm ci ~120 + vite 14,9) |
| Build Docker a frio (s) | 292 | 147 |
| Build Docker com cache (s) | nao medido | 20,5 |
| Tempo ate responder ao health check (s) | ~6 | ~4 |
| Criterio de build < 15 min | Atendido | Atendido |

Observacoes registradas:

- O primeiro health check do alvo 1 falhou por ausencia de espera ativa: o
  `curl` foi executado imediatamente apos o `docker run`, antes de a aplicacao
  subir. Isso confirma a necessidade do laco de espera obrigatorio antes do
  estagio de DAST. Sem ele, o ZAP varreria uma aplicacao ainda nao disponivel e
  reportaria ausencia de alertas sem qualquer sinal de erro.
- O `npm ci` do alvo 2 reportou, via `npm audit`, 54 vulnerabilidades
  (3 criticas, 25 altas, 24 moderadas, 2 baixas). Isso afasta o risco R3
  (alvo sem achados) e antecipa que o Quality Gate tera achados a bloquear no
  alvo 2. O numero e registrado tambem como ponto de comparacao com o Trivy no
  Capitulo 4, ja que `npm audit` e Trivy consultam bases distintas.
- O BuildKit acusou `SecretsUsedInArgOrEnv` na linha 103 do dockerfile do
  alvo 2 (`ARG GITHUB_TOKEN`), ma configuracao mapeavel a OWASP A05. O achado
  esta em estagio nao utilizado no build da aplicacao (`upload-artifact`), o
  que o torna candidato a classificacao "nao exploravel" no protocolo de
  triagem.

### 8.2 Parte 2: varreduras (concluida em 05/09/2026)

| Verificacao | Alvo 1 | Alvo 2 |
|---|---|---|
| Semgrep: tempo de parede (s) | 56 | 11 |
| Semgrep: arquivos varridos | 1027 | 722 |
| Semgrep: regras efetivamente executadas | 246 | 563 |
| Semgrep: arquivos pulados por .semgrepignore | 156 | 53 |
| Semgrep: total de achados | 48 | 17 |
| Semgrep: ERROR / WARNING / MEDIUM | 13 / 33 / 2 | 7 / 10 / 0 |
| Semgrep: achados que atendem a regra D3 | 13 | 3 |
| Trivy image: total | 100 | 5290 |
| Trivy image: CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN | 8 / 38 / 43 / 11 / 0 | 150 / 1547 / 1721 / 988 / 884 |
| Trivy image: os-pkgs / lang-pkgs | 20 / 80 | 5097 / 193 |
| Trivy image: pacotes de SO na base | 14 (Debian 13.6) | 401 (Debian 12.14) |
| Trivy image: deduplicado por D6 | nao medido | 5288 |
| Trivy config: misconfiguracoes no Dockerfile | 2 | 2 |
| Achados com CVSS v3 >= 7,0 | 47 | 2239 |
| Achados sem score V3 (fallback por rotulo) | 9 | 1083 |
| Fallback com rotulo CRITICAL / HIGH | a medir | 3 / 7 |
| Quality Gate dispararia | Sim | Sim |

Observacoes registradas na parte 2:

- **Assimetria de imagem base.** O alvo 1 (distroless, 14 pacotes de SO)
  apresentou 20 achados de sistema operacional; o alvo 2 (Debian completo
  herdado do registro, 401 pacotes) apresentou 5097, razao de aproximadamente
  255 vezes. Os achados de dependencia da aplicacao sao da mesma ordem de
  grandeza nos dois (80 e 193). O volume e determinado pela imagem base, nao
  pelo codigo da aplicacao.

- **Fallback de pontuacao.** No alvo 2, 1083 achados (20,5% do total) nao
  possuem pontuacao CVSS v3 em nenhuma das fontes consultadas. Destes, 3 sao
  rotulados CRITICAL e 7 HIGH, e portanto disparam o gate exclusivamente pela
  regra de fallback definida em D2. Sem essa regra o gate deixaria passar 3
  vulnerabilidades criticas.

- **Aviso do Trivy sobre severidades de terceiros.** A ferramenta emitiu
  `Using severities from other vendors for some vulnerabilities`, confirmando
  empiricamente a necessidade da ordem de precedencia de fontes definida em D2.

- **Filtragem da regra D3.** No alvo 1, os 13 achados ERROR do Semgrep atendem
  ao criterio de confianca; no alvo 2, apenas 3 dos 7. A regra de dois eixos
  filtra de forma diferenciada entre os alvos.

- **Semgrep e paralelismo.** Tempo de parede de 56 s no alvo 1 contra 2m42s de
  tempo de CPU, indicando paralelizacao em multiplos nucleos. Os runners do
  GitHub dispoem de 2 vCPU, portanto o tempo no ambiente de CI sera superior ao
  medido localmente. O valor local nao deve ser extrapolado para o orcamento
  das execucoes experimentais.
---

## 9. Execucao experimental   [preencher em S5]

| Item | Valor |
|---|---|
| Periodo das rodadas | |
| Repeticoes por configuracao (n) | 10 |
| Execucoes descartadas (aquecimento) | 1 por configuracao |
| Concorrencia maxima por lote | 4 |
| Semente aleatoria da amostragem de triagem | |
| Tag de congelamento do repositorio | v1.0-tcc |