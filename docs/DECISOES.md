# Decisoes Metodologicas

Registro das decisoes que definem o desenho experimental. Cada uma foi fechada
com o orientador e tem contrapartida no Capitulo 3 do TCC.

Data de fechamento de D1 a D8: 04/09/2026.

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
| D7 | Protocolo de triagem manual | Adotado, com amostragem estratificada e dupla triagem cega no tempo |
| D8 | Arquitetura de repositorio | Monorepo com submodulos Git |

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