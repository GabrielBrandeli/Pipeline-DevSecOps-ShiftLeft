# Decisoes Metodologicas

Registro das decisoes que definem o desenho experimental. Cada uma foi fechada
com o orientador e tem contrapartida no Capitulo 3 do TCC.

Data de fechamento de D1 a D8: 04/09/2026. D9: 05/09/2026. D10 e D11: 14/09/2026.
Revisao de D11: 23/09/2026. D12 a D16 e revisao de D7: 27/09/2026.

---

## Quadro-resumo

| ID | Decisao | Valor adotado |
|---|---|---|
| D1 | Segunda aplicacao-alvo | Uptime Kuma (`louislam/uptime-kuma`), tag 2.5.3, Node.js + Vue, SQLite, MIT |
| D2 | Versao do CVSS | CVSS v3.1 Base Score, precedencia NVD, GHSA, Red Hat, fallback por rotulo |
| D3 | Regra de equivalencia entre ferramentas | Ver detalhamento abaixo e `ci/regras/equivalencia.yaml` |
| D4 | Modos de execucao | `enforce` (bloqueante) e `audit` (observatorio), mesmo codigo de decisao |
| D5 | Repeticoes e tratamento estatistico | n = 10, descarte da primeira, intercalacao, mediana e IQR, Mann-Whitney U (alfa = 0,05), delta de Cliff, duas metricas de tempo |
| D6 | Unidade de contagem de alertas | Tupla especifica por ferramenta, com reporte bruto e deduplicado |
| D7 | Protocolo de triagem manual | Adotado, com amostragem estratificada e dupla triagem cega no tempo; parametros fixados e revisao pelo orientador retirada (revisado em 27/09/2026) |
| D8 | Arquitetura de repositorio | Monorepo com submodulos Git |
| D9 | Fonte de dados do SCA | `trivy image` como fonte unica; `trivy fs` restrito a `--scanners secret` |
| D10 | Versionamento de dados brutos | CSV para dados processados; JSON bruto comprimido em gzip para evidencia |
| D11 | Estado inicial do Alvo 2 para o DAST | Fixture com admin pre-provisionado e status page publica; ZAP sem autenticacao nos dois alvos (revisado em 23/09/2026) |
| D12 | Spider AJAX do ZAP | Ligado em todas as rodadas; teto da varredura ativa elevado de 30 para 60 min |
| D13 | Imagens base dos alvos | Fixadas por digest via `--build-context`, sem alterar os submodulos |
| D14 | Dependencias npm do Juice Shop | Resolvidas com data de corte (`npm_config_before=2026-09-23T18:27:00Z`), revisado em 27/09/2026 apos o build quebrar |
| D15 | Regras do Semgrep | Pacotes copiados para `ci/regras/semgrep/`, em vez de baixados do registro |
| D16 | Escopo do relatorio do ZAP | Apenas o site do alvo entra na contagem e no gate |

---

## D1. Segunda aplicacao-alvo

**Motivacao.** Requisito do orientador: avaliar a esteira tambem sobre uma
aplicacao cujas vulnerabilidades nao sejam conhecidas de antemao, ampliando a
validade externa do experimento.

**Escolhida:** Uptime Kuma, tag 2.5.3.

**Criterios atendidos:** codigo aberto sob licenca permissiva; stack Node.js,
o que mantem a linguagem como variavel de controle em relacao ao alvo 1;
possui Dockerfile; aplicacao web com interface HTTP; repositorio ativo; porte
medio; ausencia de catalogo publico de vulnerabilidades intencionais; sobe em
container unico com banco embutido, sem dependencia de servico externo.

**Consequencia metodologica.** Sem ground truth nao existe denominador para
revocacao nem para falsos negativos. As metricas aplicaveis a cada alvo sao
distintas e estao declaradas no Capitulo 3.

| Metrica | Alvo 1 | Alvo 2 |
|---|---|---|
| Sobrecarga de tempo | Sim | Sim |
| Volume de alertas | Sim | Sim |
| Precisao (pos-triagem) | Sim | Sim |
| Revocacao | Sim | Nao aplicavel |
| Falsos negativos | Sim | Nao aplicavel |
| Comportamento do gate | Sim | Sim |
| Complementaridade entre ferramentas | Sim | Sim |

---

## D2. Versao do CVSS

**Adotado:** CVSS v3.1 Base Score.

**Justificativa.** Tres razoes. Primeira, e a versao presente de forma
praticamente universal nas bases consultadas pelo Trivy (NVD, GHSA,
distribuicoes), enquanto boa parte dos CVE mais antigos nao possui vetor v4.0,
o que introduziria vies de cobertura. Segunda, e a versao da qual o proprio
Trivy deriva o rotulo de severidade, garantindo coerencia entre o criterio
numerico e o rotulo exibido. Terceira, ha divergencia documentada entre as duas
versoes: um mesmo CVE pode ser classificado como Critico em v3.1 e Baixo em
v4.0, e essa divergencia e tratada como limitacao de padronizacao do
ecossistema na discussao do Capitulo 5.

**Ordem de precedencia de fonte de pontuacao:**

1. `CVSS.nvd.V3Score`
2. `CVSS.ghsa.V3Score`
3. `CVSS.redhat.V3Score`
4. Fallback por rotulo: CRITICAL = 9,0; HIGH = 7,0; MEDIUM = 4,0; LOW = 0,1;
   UNKNOWN = 0,0

A quantidade de achados que recai no fallback e registrada e reportada, por
medir a completude das bases de pontuacao consultadas.

---

## D3. Regra de equivalencia operacional

**Problema.** O criterio de bloqueio do trabalho e CVSS v3.1 maior ou igual a
7,0, aplicavel literalmente apenas ao SCA. Semgrep emite `ERROR`, `WARNING` e
`INFO` com metadados de confianca; OWASP ZAP emite `riskcode` e `confidence`.
Nenhum dos dois emite pontuacao CVSS.

**Principio adotado.** A equivalencia e construida sobre dois eixos
simultaneos: a severidade nativa da ferramenta e o grau de confianca que ela
propria atribui ao achado. Exigir os dois eixos e justificavel porque a faixa
Alta do CVSS pressupoe impacto real, e nao impacto potencial sob suposicao nao
verificada.

| Ferramenta | Metrica nativa | Criterio de bloqueio |
|---|---|---|
| Semgrep (SAST) | `severity` e `metadata.confidence` | `severity == ERROR` e `confidence` em {HIGH, MEDIUM} |
| Trivy (SCA) | CVSS v3.1 Base Score | `score >= 7.0` (criterio literal) |
| OWASP ZAP (DAST) | `riskcode` e `confidence` | `riskcode == 3` (High) e `confidence >= 2` (Media ou superior) |

Convencao para confianca ausente no Semgrep: tratada como MEDIUM.

**Escopos do gate.** Duas variantes sao executadas e comparadas:
`sca_only`, fiel ao modelo logico aprovado em TCC 1, e `all_tools`, ampliado.
A diferenca na taxa de bloqueio entre os dois escopos e reportada como
resultado.

**Limitacao.** A equivalencia e uma construcao deste trabalho, nao um
mapeamento normalizado por FIRST ou OWASP. E reprodutivel, por estar versionada
e ser deterministica, mas constitui ameaca a validade de construto: dois
achados equiparados por vias diferentes nao sao necessariamente comparaveis em
impacto real. Declarada no Capitulo 5.

---

## D4. Modos de execucao

**Problema.** O Juice Shop possui numerosas dependencias com CVSS maior ou
igual a 7,0. Com o gate ativo, a esteira aborta no estagio de SCA e o DAST
nunca executa, deixando o objetivo especifico correspondente sem evidencia.

| Modo | Comportamento | Finalidade |
|---|---|---|
| `enforce` | Gate aborta a esteira com codigo de saida diferente de zero | Validar o comportamento real do Shift-Left |
| `audit` | Gate registra a decisao que teria tomado, retorna codigo zero e a esteira prossegue | Coletar dados completos de todos os estagios |

Os dois modos usam o mesmo codigo de decisao; a unica diferenca e o codigo de
saida final. Isso garante que a decisao medida em modo observatorio e identica
a que seria tomada em modo bloqueante.

**Fundamento.** O Shift-Left protege a producao ao bloquear cedo, mas o
bloqueio impede a medicao do que viria depois. O modo observatorio e o
instrumento de medicao; o modo bloqueante e o objeto medido.

---

## D5. Repeticoes e tratamento estatistico

- n = 10 execucoes por configuracao. Configuracoes: {alvo 1, alvo 2} x
  {baseline, devsecops-audit}, mais as execucoes em modo `enforce`.
- Descarte da primeira execucao de cada configuracao, por aquecimento de cache
  de imagem e de base do Trivy. O descarte e documentado.
- Intercalacao de baseline e intervencao no mesmo periodo do dia, de modo que a
  variacao de infraestrutura afete os dois grupos igualmente.
- Concorrencia maxima de 4 execucoes por lote, para evitar contencao de
  infraestrutura que distorceria os tempos.
- Reporte de mediana e intervalo interquartil, e nao media e desvio padrao,
  por os tempos de CI nao seguirem distribuicao normal.
- Teste de hipotese: Mann-Whitney U, alfa = 0,05.
- Tamanho de efeito: delta de Cliff.
- Registro de `runner_name` e horario UTC de cada execucao, para inspecao de
  valores atipicos.

**Duas metricas de tempo, reportadas separadamente:**

| Metrica | Definicao | Pergunta que responde |
|---|---|---|
| Tempo de parede | Duracao do inicio ao fim da execucao | Quanto o desenvolvedor espera |
| Minutos faturaveis | Soma das duracoes dos jobs | Qual o custo computacional |

---

## D6. Unidade de contagem de alertas

Chave de deduplicacao por ferramenta:

| Ferramenta | Chave |
|---|---|
| Semgrep | (`check_id`, `path`, `start.line`) |
| Trivy | (`VulnerabilityID`, `PkgName`, `InstalledVersion`) |
| OWASP ZAP | (`pluginid`, URI normalizada, `param`) |

Sao reportados sempre dois numeros: total bruto e total apos deduplicacao. A
razao entre eles mede o ruido de repeticao enfrentado pela equipe de
desenvolvimento e e reportada como resultado.

---

## D7. Protocolo de triagem manual

Adotado integralmente. Detalhamento em `docs/PROTOCOLO-TRIAGEM.md`.

### D7, revisao de 27/09/2026

- Parametros de amostragem fixados em `analise/scripts/amostrar_triagem.py`:
  censo ate 150 achados distintos por (alvo, fonte); acima disso, 100 achados
  estratificados por severidade, minimo de 10 por estrato; semente 20260927.
- Populacao: uniao dos achados distintos das rodadas AUD validas (sem AUD-01).
- Alertas informativos do ZAP (riskcode 0) fora da precisao.
- Revisao por amostragem pelo orientador retirada: o orientador nao tem
  familiaridade tecnica com as ferramentas. Fica a retriagem cega (30
  achados, sorteados junto com a amostra) e a limitacao de avaliador unico.

Elementos centrais: amostragem aleatoria estratificada por severidade e
ferramenta com semente fixada; quatro categorias de classificacao (verdadeiro
positivo, falso positivo, nao exploravel, indeterminado) definidas antes da
inspecao dos dados; evidencia registrada por achado; dupla triagem cega no
tempo sobre subamostra, com reporte de concordancia intra-avaliador.

---

## D8. Arquitetura de repositorio

**Adotado:** monorepo com as aplicacoes-alvo referenciadas como submodulos Git,
em vez de tres repositorios separados com forks dos alvos.

| Aspecto | Forks separados | Monorepo com submodulos |
|---|---|---|
| Fixacao de commit do alvo | Manual | Automatica, pelo mecanismo de submodulo |
| Reprodutibilidade | Estado espalhado em tres historicos | Um commit captura tudo |
| Workflows nativos do alvo | Disparam junto, poluindo o experimento | Nao disparam |
| Workflow unico com matriz de alvos | Codigo duplicado | Direto |
| Realismo | Maior | Menor, mitigavel por declaracao |

**Limitacao e mitigacao.** Em cenario real a esteira reside no repositorio da
propria aplicacao. Aqui reside em repositorio orquestrador. Isso nao afeta
nenhuma variavel de resposta: a operacao de checkout dos submodulos e identica
nas configuracoes de linha de base e de intervencao, cancelando-se na medicao
de sobrecarga; e as tres ferramentas operam sobre o codigo e sobre a aplicacao
em execucao, indiferentes a origem do diretorio. Declarado em nota de rodape no
Capitulo 3.

## D9. Fonte de dados do SCA

**Adotado:** `trivy image` como unica fonte de dados de vulnerabilidades de
dependencia. O `trivy fs` e mantido apenas para `--scanners secret`.

**Motivacao.** No teste de fumaca, o `trivy fs` retornou 60 achados no alvo 2 e
zero no alvo 1. A causa foi identificada: o Juice Shop v20.2.0 nao possui
`package-lock.json`, e sem lockfile o Trivy nao dispoe de versoes resolvidas
para consultar (`Number of language-specific files num=0`). O alvo 2, por
exigir pre-build, possui `node_modules` e lockfile na arvore. A assimetria e de
estado do sistema de arquivos, nao de postura de seguranca: o `trivy image`
encontra 80 achados de dependencia (`lang-pkgs`) no alvo 1.

**Justificativa metodologica.** O `trivy image` inspeciona as dependencias
efetivamente instaladas no artefato entregue, e nao a declaracao de intencao do
lockfile. E mais fiel ao que chega a producao, e simetrico entre os dois alvos,
que ambos produzem imagem, e elimina a dependencia do estado da arvore de
arquivos, que difere entre eles por causa do pre-build do alvo 2.

**Consequencia.** A comparacao entre `trivy fs` e `trivy image` prevista no
plano original (vulnerabilidades no repositorio contra vulnerabilidades no
artefato) e abandonada. Registrada como trabalho futuro no Capitulo 5.

---

## D10. Estrategia de versionamento dos dados brutos

**Motivacao.** O `trivy image` do alvo 2 sozinho produziu 16 MB de JSON em uma
unica execucao de validacao (14/09/2026). Com as 40 ou mais execucoes
experimentais previstas para a S5, versionar o achado bruto sem qualquer
tratamento inflaria o repositorio rapidamente.

**Adotado:** dois formatos, para dois propositos que nao se substituem.

| Dado | Formato | Proposito |
|---|---|---|
| Processado (`achados.csv`, `tempos.csv`, `triagem.csv`) | Texto simples, deduplicado por D6 | Insumo das analises estatisticas do Capitulo 4 |
| Bruto (JSON original de Trivy, Semgrep, ZAP) | Comprimido em `gzip` (`*.json.gz`) | Evidencia auditavel exigida pela checklist de reprodutibilidade (secao 14 do plano de acao); permite reprocessamento caso o esquema de normalizacao mude |

`gate-decision.json` e `jobs.json` permanecem descomprimidos, por serem
pequenos e servirem como trilha de auditoria diretamente legivel no
historico do git.

**Justificativa.** CSV e JSON bruto atendem propositos diferentes. Descartar o
bruto em favor apenas do CSV quebraria o item da checklist de reprodutibilidade
que exige os dados brutos disponiveis, alem de impedir reprocessamento caso um
erro seja encontrado depois na normalizacao. Comprimir o bruto preserva a
integridade da evidencia a um custo de espaco muito menor, pela alta
redundancia estrutural do JSON.

**Consequencia.** Os scripts de coleta (`baixar_run.sh`) e de normalizacao
(`normalizar_achados.py`) precisam descomprimir antes de ler.

---

## D11. Estado inicial do Alvo 2 para o DAST

**Problema.** O Uptime Kuma nao possui estado persistente entre execucoes: a
cada `docker run`, o SQLite e criado vazio e a aplicacao exibe um assistente de
configuracao inicial (criacao do usuario administrador). Sem intervencao, esse
seria o unico conteudo que o ZAP encontraria em **todas** as rodadas de DAST do
alvo 2, o que inviabilizaria a deteccao (risco R3) e tornaria as ~20 execucoes
de DAST previstas para o alvo 2 indistinguiveis entre si.

**Adotado:** fixture do banco SQLite (`kuma.db`) com um usuario administrador
pre-provisionado, versionada em `ci/fixtures/uptime-kuma/`, copiada para dentro
do container antes da subida em toda execucao (baseline e DevSecOps, para nao
contaminar a medicao de sobrecarga). O ZAP roda **autenticado** no alvo 2,
com as credenciais fixas da fixture.

**Assimetria declarada com o alvo 1.** O alvo 1 (Juice Shop) mantem a
varredura **nao autenticada**, conforme a secao 3.4 do plano original: sua
superficie publica ja e suficiente para a maior parte dos desafios OWASP
catalogados. A assimetria entre os alvos nao e inconsistencia metodologica: e
consequencia direta da natureza de cada aplicacao. Uma aplicacao de e-commerce
vulneravel expõe catalogo, busca e comentarios sem login; um painel de
monitoramento privado, por definicao, nao expõe nada de util sem autenticacao.
Isso sera declarado explicitamente no Capitulo 3, com nota de rodape.

**Consequencia.** A criacao da fixture e a configuracao de autenticacao do ZAP
(`ZAP_AUTH_HEADER` ou script de login) ficam no escopo da S4 (staging + DAST).
As credenciais fixas (usuario e senha de teste, sem qualquer relacao com
segredo real) serao registradas em `docs/AMBIENTE.md`.

### D11, revisao de 23/09/2026

**Decisao revisada:** a fixture e mantida e ampliada com a superficie publica
padrao do produto; o ZAP passa a rodar **sem autenticacao nos dois alvos**,
eliminando a assimetria da versao original.

**Motivo 1: a autenticacao nao amplia a superficie HTTP.** Na implementacao
verificou-se que o painel do Uptime Kuma trafega inteiramente por socket.io; o
JWT so e usado nesse canal. A unica rota HTTP que exige autenticacao e
`/metrics` (Basic Auth). O ZAP realiza apenas analise passiva de mensagens
WebSocket; varredura ativa desse canal nao existe no modo automatizado.

**Motivo 2: a autenticacao por header contamina a medicao.** Com o header
`Authorization: Basic` injetado, a regra passiva 10105 do ZAP
(Authentication Credentials Captured, riskcode 3, confidence 2) disparou em
todas as requisicoes, inclusive a arquivos estaticos. E um alerta High criado
pela propria instrumentacao do experimento, e nao pela aplicacao, e que pela
regra D3 bloquearia o gate no escopo `all_tools` em toda rodada do alvo 2.

**Ampliacao da fixture.** Alem do administrador, a fixture recebe, pelos
mesmos eventos de socket.io da interface: um monitor do tipo push (so recebe
requisicoes, sem trafego de saida), uma status page publicada contendo esse
monitor e a pagina inicial apontando para ela. E a superficie que uma
instalacao real expoe publicamente. Script: `ci/fixtures/uptime-kuma/popular.js`.

**Evidencia (varreduras locais, mesma configuracao do CI, sem spider AJAX):**

| Configuracao | URLs alcancadas | Tipos de alerta | Instancias | Alertas High | Tempo (s) |
|---|---|---|---|---|---|
| Fixture so com admin + Basic Auth | 11 | 18 | 61 | 1 (10105, artefato do header) | 249 |
| Fixture ampliada + Basic Auth | 16 | 18 | 66 | 1 (10105, artefato do header) | 412 |

Rotas alcancadas apenas com a fixture ampliada: `/status`, `/status/servicos`,
`/api/status-page/servicos/manifest.json`. As rotas de API carregadas por
JavaScript (`/api/status-page/servicos`, `/api/status-page/heartbeat/servicos`)
nao sao alcancadas pelo spider tradicional; sua cobertura depende do spider
AJAX, avaliado em etapa posterior.

**Alternativas descartadas.** (a) Autenticacao pelo navegador com spider
AJAX: custo alto e ganho restrito a analise passiva de WebSocket. (b) Remover
o DAST do alvo 2: enfraqueceria o objetivo especifico de DAST e a analise de
complementaridade.

**Ameaca a validade.** A superficie publica e configurada pelo pesquisador.
Mitigacao: apenas funcionalidades padrao do produto, configuracao minima,
versionada e identica em todas as execucoes (baseline e DevSecOps).

**Resultado para o Capitulo 5.** Um DAST baseado em HTTP nao alcanca a
logica de aplicacoes construidas sobre WebSocket: limite estrutural da tecnica,
medido pela superficie alcancada em cada alvo.

---

## D12. Spider AJAX do ZAP nas rodadas experimentais

**Adotado:** spider AJAX (`-j`) ligado em todas as rodadas (`zap_ajax` passa a
ter padrao `true`) e teto da varredura ativa (`scanner.maxScanDurationInMins`)
elevado de 30 para 60 minutos.

**Evidencia (execucoes 35902561486, sem AJAX, e 35905208031, com AJAX, ambas
audit/all_tools, 23/09/2026):**

| Juice Shop | Sem AJAX | Com AJAX |
|---|---|---|
| Tipos de alerta (so o alvo, ver D16) | 20 | 23 |
| Alertas High | 0 | 3 (SQL Injection, External Redirect, Off-site Redirect) |
| Disparadores do gate (DAST) | 0 | 2 (a SQLi veio com confidence 1) |
| Desafios resolvidos pelo scan | 2 | 3 |
| Duracao do job staging+DAST | 583 s | 2273 s |

No Uptime Kuma o efeito foi minimo: uma rota a mais
(`/api/status-page/heartbeat/servicos`), um alerta Info a mais, 323 s para 346 s.

**Justificativa.** O Juice Shop e uma SPA Angular; sem navegador o spider
tradicional enxerga pouco da aplicacao e o DAST fica restrito a cabecalhos e
configuracao (A05). A analise de complementaridade e a contribuicao do DAST ao
gate no escopo `all_tools` seriam artefato da configuracao, e nao da tecnica.

**Motivo do teto de 60 min.** Com AJAX, o DAST durou ~37 min, coerente com a
varredura ativa atingindo o teto de 30 min: quatro tipos de alerta presentes
sem AJAX desapareceram (Backup File Disclosure, Bypassing 403, CORS
Misconfiguration, User Agent Fuzzer) e as URIs com alerta cairam de 63 para 42.
Com o corte, o resultado passaria a depender de ate onde a varredura chegou.
**Pendente:** execucao de teste com o novo teto, para confirmar que a
varredura termina antes dele e que os alertas perdidos voltam.

**Custo.** Estimado em 45 a 60 min de DAST por rodada no Juice Shop; dentro do
limite de 6 h por job e sem custo em repositorio publico. A sobrecarga medida
passa a ser dominada pelo DAST no alvo 1, o que deve ser declarado no Cap. 4.

---

## D13. Fixacao das imagens base dos alvos

**Problema.** Os Dockerfiles dos alvos (submodulos) usam tags mutaveis:
`node:24` e `gcr.io/distroless/nodejs24-debian13` no alvo 1;
`louislam/uptime-kuma:base2` (tambem via `ARG BASE_IMAGE`) e
`louislam/uptime-kuma:builder-go` no alvo 2. Contradiz a regra de nao usar
referencias moveis (Cap. 3) e permitiria que o volume de achados de SO mudasse
entre rodadas por troca silenciosa da imagem base.

**Adotado:** variavel `ALVO_BASES` em `ci/perfis/*.env`, convertida no passo de
build em `--build-context <nome>=docker-image://<nome>@sha256:...`. O BuildKit
substitui o `FROM` correspondente pela imagem fixada, sem editar o submodulo.
O passo de build tem texto identico em `00-baseline.yml` e `01-devsecops.yml`.

**Verificacao (27/09/2026).** As camadas das imagens de runtime nos digests
fixados (13 camadas do `base2`, 22 do distroless) coincidem com o prefixo de
`Metadata.DiffIDs` do `trivy image` nas tres execucoes de validacao (14 e
23/09). A fixacao nao altera nada do que ja foi medido. A substituicao por
`--build-context` foi testada localmente para `FROM node:24` e para
`FROM $BASE_IMAGE`.

**Limitacao remanescente (tratada em D14).** O Juice Shop declara
`package-lock=false` no `.npmrc`: o `npm install` do build resolve as faixas de
versao do `package.json` no momento da execucao. Dependencias podem mudar entre
rodadas (os `lang-pkgs` do `trivy image` passaram de 80 em 05/09 para 81 em
23/09). Decisao em aberto: aceitar e medir (o `trivy image` registra as versoes
instaladas de cada rodada) ou injetar lockfile, o que altera o alvo.

---

## D14. Dependencias npm do Juice Shop sem lockfile

**REVISADA no mesmo dia; ver "D14, revisao" abaixo. O texto a seguir e a decisao original.**

**Problema.** O `.npmrc` do Juice Shop declara `package-lock=false`: o
`npm install` do build resolve as faixas de versao do `package.json` no momento
da execucao. Uma versao nova publicada no meio das rodadas muda o conjunto de
dependencias da imagem, e com ele os achados de SCA, sem mudanca no alvo.

**Adotado (decisao do pesquisador, 27/09/2026):** manter o build como o
projeto o define, sem injetar lockfile. As rodadas ocorrem em janela curta
(outubro de 2026) e a variacao esperada e pequena (de 80 para 81 pacotes de
linguagem entre 05/09 e 23/09).

**Mitigacao.** A variacao nao e escondida, e medida: o `trivy image` de cada
rodada lista pacote e versao instalados (`PkgName`, `InstalledVersion`), e a
analise reporta quantas rodadas tiveram conjunto de dependencias diferente da
primeira rodada valida. Rodadas com conjunto diferente continuam validas para
tempo; na eficacia de SCA, a diferenca e reportada.

**Por que nao injetar lockfile.** Altera o alvo (o artefato avaliado deixaria
de ser o que o projeto distribui) e exigiria escolher um instante de
resolucao, o que tambem e arbitrario.

---

## D15. Fixacao dos pacotes de regras do Semgrep

**Problema.** `--config p/<pacote>` baixa a versao corrente do registro a cada
execucao. O conteudo dos pacotes muda sem aviso (nao ha versao nem digest), o
que contradiz a regra de nao usar referencias moveis e poderia alterar o
numero de achados de SAST durante as rodadas sem mudanca no alvo.

**Adotado:** copia dos quatro pacotes em `ci/regras/semgrep/`, com origem e
SHA-256 registrados em `ci/regras/semgrep/README.md`. O workflow passa os
arquivos locais ao `--config`. Efeito colateral: sem download de regras, sai
tambem uma fonte de variacao de rede do tempo medido do SAST.

**Verificacao (27/09/2026).** Com Semgrep 1.176.1, a copia local produz os
mesmos achados que o registro nos dois alvos (48 e 17), identicos em regra,
arquivo, linha, severidade e confianca, e iguais aos do CI de 23/09.

**Consequencia.** Regras locais recebem o prefixo `ci.regras.semgrep.` no
`check_id`; o `quality_gate.py` remove o prefixo para manter as chaves de D6
(cenario E7-12).

---

## D16. Escopo do relatorio do ZAP

**Problema (identificado em 27/09/2026).** Com o spider AJAX, o navegador segue
links externos da aplicacao e o relatorio do ZAP passa a trazer alertas
passivos de outros dominios. Na execucao 35905208031 (Juice Shop, com AJAX),
14 alertas eram de dominios do GitHub (github.com, githubassets.com). O
`quality_gate.py` somava todos os sites: o total de DAST do alvo 1 aparecia
como 110 quando o do alvo era 79, e um alerta High em site de terceiro
bloquearia o gate no escopo `all_tools`.

**Adotado:** o gate recebe `--zap-alvo http://localhost:<porta>` e considera
apenas esse site; a quantidade descartada fica em `zap_alertas_fora_do_alvo`
no `gate-decision`. A normalizacao aplica o mesmo filtro. Cenario E7-11.

**Numeros corrigidos da comparacao de D12 (apenas o site do alvo).** Juice
Shop sem AJAX / com AJAX: tipos de alerta 20 / 23 (e nao 37); instancias
deduplicadas 115 / 79; URIs com alerta 63 / 28. Os tres alertas High sao do
proprio alvo. A queda de URIs com alerta reforca a hipotese de corte da
varredura ativa que motivou o teto de 60 min.

**Nota.** O filtro atua na analise. O ZAP ainda visita os dominios externos
com o navegador (apenas trafego de navegacao, analisado passivamente); a
varredura ativa da acao ja fica restrita ao alvo.

### D14, revisao de 27/09/2026 (forcada pela quebra do build)

**Fato.** Na execucao de teste 36337852503 (27/09/2026), o build do Juice
Shop falhou dentro do `npm install --omit=dev`: `Missing metafile:
dist/frontend/stats.json` na geracao de SBOM do frontend. Causa: o
`@angular/build` 22.2.0 foi publicado em 23/09/2026 21:37 UTC, depois da
ultima execucao bem-sucedida (35905208031, 18:50 UTC), e o `^22.0.1` do
`frontend/package.json` passou a resolve-lo. O risco descrito acima se
materializou em quatro dias: nao apenas mudar achados, mas impedir o build.

**Adotado:** data de corte na resolucao das dependencias, com
`ENV npm_config_before=2026-09-23T18:27:00Z` em uma copia do Dockerfile do alvo
(`ci/alvos/juice-shop.Dockerfile`, uma linha a mais), apontada pelo perfil.
A data e o inicio da execucao de validacao 35902561486.

**Verificacao.** Build local com a copia: sucesso; as 81 vulnerabilidades de
dependencia do `trivy image` sao identicas as da execucao 35902561486. O
conjunto de dependencias fica congelado para todas as rodadas, o que tambem
elimina a variacao que a decisao original apenas media.

**Por que data de corte e nao lockfile.** O `package-lock=false` do projeto
faz o npm ignorar lockfiles; injetar um exigiria alterar tambem o `.npmrc`.
A data de corte e uma linha, nao altera arquivos do submodulo e e
auditavel (a data explica o conjunto resolvido).

**Consequencia para o texto.** O Cap. 3 declara que o Juice Shop e construido
com as dependencias resolvidas na data de corte, como ajuste de
reprodutibilidade, e nao mais com a resolucao corrente.

**Achado lateral: falha de um alvo derruba a esteira dos dois.** Na mesma
execucao de teste, a AUD (36337862032) parou nos dois alvos, embora so o build
do alvo 1 tenha falhado: o `needs` do GitHub Actions espera todas as pernas da
matriz do job anterior. Na linha de base, o job unico com matriz nao tem esse
acoplamento. Consequencia: falha de build ou de SAST em um alvo invalida a
rodada inteira (os dois alvos); a falha de DAST, no ultimo job, afeta so o
proprio alvo. Registrado no roteiro de rodadas.
