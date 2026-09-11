# Plano de Ação TCC 2

## Implementação de uma Esteira DevSecOps: Avaliação da Abordagem Shift-Left na Automação de Testes de Segurança em CI/CD

**Aluno:** Gabriel Brandeli Ramos
**Orientador:** Prof. Dr. Alan Gavioli
**Data-base do plano:** 04/09/2026
**Referências de entrada:** TCC 1 (versão pós-correção de banca), apresentação `tcc1.pptx`, relatório de reunião de 31/08/2026

---

# 0. Diagnóstico: o que existe e o que falta

## 0.1 O que já está pronto e não precisa ser refeito

| Item | Situação |
|---|---|
| Capítulos 1, 2 e 3 escritos e revisados | Completo, corrigido conforme banca |
| Referencial teórico (CI/CD, Shift-Left, DevSecOps, SAST/DAST/SCA, OWASP, maturidade, CVSS, contêineres) | Completo |
| Trabalhos relacionados (10 obras) + Quadro 5 com posicionamento | Completo |
| Escolha das ferramentas (Semgrep, Trivy, OWASP ZAP) | Definida |
| Alvo 1 (OWASP Juice Shop) | Definido |
| Infraestrutura (GitHub Actions, Ubuntu LTS, 2 vCPU, 7 GB RAM, 14 GB SSD) | Definida |
| Desenho experimental de alto nível (baseline vs. intervenção) | Definido |
| Fluxograma lógico do pipeline (Figura 5) | Definido |

## 0.2 O que falta e é bloqueante

1. Definição do **segundo alvo** (pedido do professor), com perfil de vulnerabilidades desconhecido.
2. Resolução da **versão do CVSS** usada no Quality Gate (o texto cita v4.0, o slide diz v3.1, o Trivy usa v3.x para o rótulo).
3. Definição da **regra de bloqueio para SAST e DAST**, que não produzem CVSS.
4. Definição do **modo de execução** da esteira (bloqueante vs. observatório), sem o qual o DAST nunca executa no Juice Shop.
5. Definição do **número de repetições** e do **tratamento estatístico**.
6. Definição da **unidade de contagem de alertas** (o que conta como "um achado").
7. Definição do **protocolo de triagem manual** para o alvo sem ground truth.

## 0.3 O que falta e é execução

- Construção dos repositórios e workflows.
- Execução das rodadas experimentais.
- Scripts de parsing e análise.
- Capítulos 4 (Resultados) e 5 (Discussão e Conclusão).
- Atualização do Capítulo 3 para refletir as decisões acima.
- Nova apresentação de defesa (TCC 2).

---

# 1. Decisões pendentes, com recomendação técnica

Estas sete decisões devem ser fechadas com o orientador na primeira ou segunda reunião de sexta-feira. Cada uma altera o Capítulo 3.

## D1. Segundo alvo experimental

**Requisito do professor:** aplicação cujas vulnerabilidades não sejam conhecidas de antemão, para aumentar a validade experimental.

**Critérios de seleção (todos obrigatórios):**

| Critério | Justificativa |
|---|---|
| Código aberto, licença permissiva | Publicação e reprodutibilidade |
| Stack Node.js / JavaScript | Reaproveita as regras do Semgrep e o ecossistema npm do Trivy, mantendo a stack como variável de controle |
| Possui `Dockerfile` no repositório | Necessário para o estágio de Build e para `trivy image` / `trivy config` |
| Aplicação web com interface HTTP acessível | Necessário para o DAST |
| Repositório ativo (commits nos últimos 6 meses) | Evita que o resultado seja um artefato de abandono do projeto |
| Porte médio (aprox. 20 mil a 150 mil linhas) | Grande demais estoura o tempo do runner; pequeno demais não gera achados |
| Sem lista pública de vulnerabilidades intencionais | É exatamente isso que caracteriza o "perfil desconhecido" |
| Sobe sem dependência de serviço externo (banco embutido ou container único) | O runner do GitHub é efêmero |

**Candidatos recomendados (validar contra a checklist acima antes de fechar):**

| Candidato | Stack | Observação |
|---|---|---|
| **Uptime Kuma** (`louislam/uptime-kuma`) | Node.js + Vue, SQLite, MIT | Recomendado. Sobe em container único, sem dependências externas, ativo (v2.5.0), porte adequado. Requer Node.js >= 20. |
| Etherpad Lite | Node.js | Viável, porém com plugins e estado mais complexo |
| NodeBB | Node.js | Exige Redis ou MongoDB, o que complica o staging no runner |
| Strapi | Node.js/TS | Porte grande, tempo de build alto |

**Recomendação:** Uptime Kuma. Registrar no Capítulo 3 a justificativa da escolha item a item, contra os critérios acima, e fixar o commit exato (`git rev-parse HEAD`) como variável de controle.

**Consequência metodológica crítica que precisa estar escrita no Capítulo 3:** sem ground truth, não existe denominador para o cálculo de recall (revocação) nem para falsos negativos. No alvo 2, as métricas possíveis são:

- Volume de alertas por ferramenta e por severidade.
- **Precisão** (após triagem manual), que exige o protocolo da seção 9.
- Sobreposição e complementaridade entre as três ferramentas.
- Comportamento do Quality Gate em um cenário não controlado.

Isso não enfraquece o trabalho. Pelo contrário, é o que aproxima o experimento de um cenário real e permite responder à pergunta de pesquisa fora do ambiente artificialmente vulnerável. Mas precisa estar declarado, e não implícito.

---

## D2. Versão do CVSS no Quality Gate

**Problema:** o Capítulo 2 cita FIRST (2024), que é a especificação **CVSS v4.0**. O slide 10 diz **v3.1**. O Trivy retorna o score v4.0 no JSON quando disponível, mas o campo `Severity` continua sendo derivado de CVSS v3.x. Existe divergência real e documentada: um mesmo CVE pode ser Crítico em v3.1 e Baixo em v4.0.

**Recomendação:** adotar **CVSS v3.1 Base Score** como métrica do gate, pelos seguintes motivos, todos citáveis:

1. É a versão presente de forma praticamente universal nas bases consultadas pelo Trivy (NVD, GHSA, distribuições).
2. É a versão da qual o próprio Trivy deriva o rótulo de severidade, garantindo coerência entre o gate numérico e o rótulo exibido.
3. A adoção do v4.0 introduziria um viés de cobertura, já que boa parte dos CVEs mais antigos não possui vetor v4.0.

**Ações:**
- Corrigir o texto do Capítulo 2 (seção 2.4.3) para citar a especificação v3.1 do FIRST como norma operacional adotada, mantendo a menção ao v4.0 como evolução do padrão.
- Adicionar a referência da especificação v3.1 ao `main.bib`.
- Documentar no Capítulo 3 a **ordem de precedência de fontes de score**, que é uma decisão metodológica e não um detalhe de implementação:

```
1. CVSS.nvd.V3Score
2. CVSS.ghsa.V3Score
3. CVSS.redhat.V3Score
4. (fallback) mapeamento do rótulo Severity → limite inferior da faixa
   CRITICAL → 9.0 | HIGH → 7.0 | MEDIUM → 4.0 | LOW → 0.1
```

- Registrar quantos achados caíram no fallback. Esse número é resultado publicável (mede a completude das bases de score).
- Levar a divergência v3.1 vs. v4.0 para a discussão do Capítulo 5 como limitação de padronização do ecossistema.

---

## D3. Regra de bloqueio para SAST e DAST

**Problema:** o critério "CVSS ≥ 7.0" só é aplicável ao Trivy. Semgrep emite `ERROR` / `WARNING` / `INFO` com metadados de `confidence`, `impact` e mapeamento OWASP/CWE. ZAP emite `High` / `Medium` / `Low` / `Informational` com `confidence`. Nenhum dos dois emite pontuação CVSS.

**Recomendação:** declarar uma **regra de equivalência operacional** explícita, em quadro próprio no Capítulo 3, e assumi-la como limitação no Capítulo 5.

| Ferramenta | Métrica nativa | Critério de bloqueio adotado | Equivalência declarada |
|---|---|---|---|
| Semgrep (SAST) | `severity` + `metadata.confidence` | `severity == ERROR` **e** `confidence in {HIGH, MEDIUM}` | Equiparado a CVSS ≥ 7.0 |
| Trivy (SCA) | CVSS v3.1 Base Score | `score >= 7.0` | Critério primário e literal |
| OWASP ZAP (DAST) | `riskcode` + `confidence` | `riskcode == 3` (High) **e** `confidence >= 2` (Medium) | Equiparado a CVSS ≥ 7.0 |

**Alternativa mais conservadora, se o orientador preferir aderência estrita ao texto do TCC 1:** manter o gate **exclusivamente no estágio de SCA**, exatamente como a Figura 5 já mostra, e tratar SAST e DAST como estágios **informativos e mensurados, porém não bloqueantes**. Isso é defensável, simplifica a análise e é fiel ao que já foi aprovado na banca de TCC 1.

**Recomendação final:** implementar as duas variantes (o custo marginal é baixo, é uma variável de ambiente no workflow) e reportar ambas no Capítulo 4. Isso vira um resultado próprio: quanto o escopo do gate altera a taxa de bloqueio da esteira.

---

## D4. Modos de execução (decisão que salva o experimento)

**Problema crítico:** o Juice Shop possui dezenas de dependências com CVSS ≥ 7.0. Com o gate ativo, a esteira **aborta no SCA e o DAST nunca executa**. Sem tratar isso, não existem dados de DAST no alvo 1, e o objetivo específico OE4 fica sem evidência.

**Solução:** definir dois modos de execução, ambos documentados no Capítulo 3.

| Modo | Configuração | Finalidade | Dado que produz |
|---|---|---|---|
| **Modo Bloqueante** (`GATE_MODE=enforce`) | Gate aborta a esteira com `exit code != 0` | Validar o comportamento real do Shift-Left | Ponto de parada, tempo até a falha, achado que causou o bloqueio |
| **Modo Observatório** (`GATE_MODE=audit`) | Gate registra a decisão que **teria** tomado, mas retorna `exit 0` e a esteira prossegue | Coletar dados completos de todos os estágios | Tempos completos, achados de SAST + SCA + DAST, base para as métricas de eficácia |

Ambos os modos usam o **mesmo código de decisão**. A única diferença é o código de saída final. Isso precisa estar explícito, porque garante que a decisão medida no modo observatório é idêntica à que seria tomada no modo bloqueante.

Essa distinção também resolve elegantemente uma tensão conceitual do trabalho: o Shift-Left protege a produção ao bloquear cedo, mas o bloqueio cedo impede a medição do que viria depois. O modo observatório é o instrumento de medição; o modo bloqueante é o objeto medido.

---

## D5. Repetições e tratamento estatístico

**Problema:** runners hospedados do GitHub têm variância relevante de desempenho (recursos compartilhados, latência de rede, estado de cache). Uma única execução por configuração não sustenta afirmação sobre overhead.

**Recomendação:**

- **n = 10 execuções por configuração.** Configurações: {Alvo 1, Alvo 2} × {Baseline, DevSecOps-audit} = 4 configurações × 10 = 40 execuções, mais as execuções do modo bloqueante para validação do gate.
- **Descartar a primeira execução de cada configuração** (aquecimento de cache de imagem e de base do Trivy), documentando o descarte.
- **Intercalar** as execuções de baseline e de intervenção no mesmo período do dia, para que variação de infraestrutura afete os dois grupos igualmente. Não rodar todos os baselines na segunda e todas as intervenções na sexta.
- Reportar **mediana e intervalo interquartil**, não média e desvio padrão. Tempos de CI não são normalmente distribuídos.
- Teste de hipótese: **Mann-Whitney U** (não paramétrico, amostras independentes), α = 0,05.
- Tamanho de efeito: **delta de Cliff**, que é a medida apropriada para o Mann-Whitney e é o que realmente responde "o overhead importa na prática".
- Registrar também o `runner_name` e o horário UTC de cada execução, para permitir inspeção posterior de outliers.

Distinguir e reportar separadamente duas métricas de tempo, porque elas respondem a perguntas diferentes:

- **Tempo de parede (wall-clock):** duração do início ao fim da execução. É o que o desenvolvedor espera.
- **Minutos faturáveis (soma das durações dos jobs):** é o custo computacional. Diverge do anterior quando há jobs paralelos.

---

## D6. Unidade de contagem de alertas

**Problema:** "o Trivy encontrou 340 vulnerabilidades" pode significar 340 CVEs distintos ou 40 CVEs repetidos em 8 pacotes. Sem definição, os números do Capítulo 4 não são interpretáveis nem comparáveis com a literatura.

**Recomendação:** definir a unidade como uma tupla e aplicar deduplicação explícita.

| Ferramenta | Unidade de contagem (chave de deduplicação) |
|---|---|
| Semgrep | (`check_id`, `path`, `start.line`) |
| Trivy | (`VulnerabilityID`, `PkgName`, `InstalledVersion`) |
| ZAP | (`pluginid`, `uri` normalizada, `param`) |

Reportar sempre **dois números**: total bruto de alertas e total após deduplicação. A razão entre eles é, por si só, um resultado (mede o ruído de repetição que a equipe de desenvolvimento enfrenta).

---

## D7. Protocolo de triagem manual

Necessário para calcular precisão no alvo 2 e para classificar falsos positivos no alvo 1. Detalhado na seção 9.

---

# 2. Arquitetura de repositórios e artefatos

## 2.1 Estrutura recomendada: três repositórios públicos

Repositórios **públicos** são obrigatórios nesta escolha, porque o GitHub Actions oferece minutos ilimitados para repositórios públicos. Repositório privado no plano gratuito tem cota mensal limitada, o que inviabilizaria 40+ execuções.

```
github.com/<usuario>/
├── tcc-alvo1-juiceshop/        # fork do OWASP Juice Shop, commit fixado
│   ├── .github/workflows/
│   │   ├── 00-baseline.yml
│   │   ├── 01-devsecops.yml
│   │   └── 02-gate-validation.yml
│   ├── .zap/rules.tsv
│   ├── .zap/plan.yaml
│   └── ci/ (scripts do gate e de normalização)
│
├── tcc-alvo2-<nome>/           # fork do segundo alvo, mesma estrutura
│   └── (idêntica)
│
└── tcc-devsecops-analise/      # repositório de análise e dados
    ├── dados/
    │   ├── brutos/<alvo>/<run_id>/{semgrep.json,trivy.json,zap.json,jobs.json}
    │   └── processados/{achados.csv,tempos.csv,triagem.csv}
    ├── scripts/
    │   ├── coletar_tempos.py
    │   ├── normalizar_achados.py
    │   ├── ground_truth_juiceshop.py
    │   └── analise_estatistica.py
    ├── notebooks/analise.ipynb
    ├── figuras/            # saída em PDF/PNG para o LaTeX
    └── tabelas/            # saída em .tex para o Overleaf
```

**Vantagem dessa separação:** os repositórios-alvo permanecem o mais próximos possível do upstream (só se acrescenta `.github/workflows` e `ci/`), o que preserva a validade do experimento. Toda a lógica de análise fica isolada e versionada à parte.

## 2.2 Fixação de versões (variáveis de controle)

Criar no repositório de análise um arquivo `AMBIENTE.md` registrando, e replicá-lo como quadro no Capítulo 3:

```yaml
alvo1_commit:        <sha do Juice Shop>
alvo1_versao:        v<x.y.z>
alvo2_commit:        <sha>
alvo2_versao:        v<x.y.z>
runner:              ubuntu-24.04   # NÃO usar ubuntu-latest
semgrep_versao:      <x.y.z>
semgrep_rulesets:    p/owasp-top-ten, p/javascript, p/security-audit, p/secrets
trivy_versao:        <x.y.z>
trivy_db_data:       <data da base baixada>
zap_imagem:          ghcr.io/zaproxy/zaproxy:stable (digest sha256:...)
docker_versao:       <x.y.z>
periodo_execucao:    <datas>
```

**Regra inegociável:** nunca usar `ubuntu-latest`, `@master`, `@main` ou `:latest`. Isso destrói a reprodutibilidade e é a primeira coisa que uma banca técnica pergunta.

**Regra de segurança:** fixar todas as GitHub Actions de terceiros por **SHA completo de commit**, não por tag. O `aquasecurity/trivy-action` sofreu comprometimento de cadeia de suprimentos em março de 2026, e tags são mutáveis. Exemplo:

```yaml
uses: aquasecurity/trivy-action@<sha40>  # v0.3x.x
```

Esse fato é excelente material para o Capítulo 5: a própria esteira de segurança é superfície de ataque, o que dialoga diretamente com o item A08 do OWASP Top 10 (Falhas na Integridade de Software e Dados) já descrito no seu Capítulo 2.

---

# 3. Ferramentas: obtenção, uso e saída

Todas as ferramentas são gratuitas e de código aberto. **Nenhuma exige conta paga ou token comercial.** Isso precisa estar dito no Capítulo 3, porque é parte da reprodutibilidade.

## 3.1 GitHub Actions

- **Obtenção:** conta GitHub gratuita. Repositório público. Sem custo.
- **Uso:** arquivos YAML em `.github/workflows/`.
- **Runner:** `ubuntu-24.04`, 2 vCPU / 7 GB RAM / 14 GB SSD (confere com o Capítulo 3 já escrito).
- **API para coleta de tempos:**
  `GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs`
  retorna `jobs[].steps[].started_at` e `completed_at` com precisão de segundo. Essa é a fonte de dados de tempo, muito superior a cronometragem manual com `date` dentro do script.
- **CLI:** `gh` (GitHub CLI), já pré-instalado nos runners e instalável localmente.

## 3.2 Semgrep (SAST)

- **Obtenção:** `pip install semgrep`, ou imagem `semgrep/semgrep` (Docker), ou `brew install semgrep`. Community Edition, sem token.
- **Regras:** Semgrep Registry, prefixo `p/`. Conjunto recomendado para JavaScript/Node.js:
  - `p/owasp-top-ten` (alinhamento direto com o OE2 do seu trabalho)
  - `p/javascript`
  - `p/security-audit`
  - `p/secrets`
- **Comando recomendado (coleta completa, sem bloquear):**

```bash
semgrep scan \
  --config p/owasp-top-ten \
  --config p/javascript \
  --config p/security-audit \
  --config p/secrets \
  --json --output semgrep.json \
  --sarif --output semgrep.sarif \
  --metrics=off \
  --error=false \
  --timeout 300
```

- **Por que `semgrep scan` e não `semgrep ci`:** `semgrep ci` faz varredura diferencial (só o que mudou desde o commit-base) e é orientado à plataforma comercial. Para um experimento, é preciso a varredura **completa e determinística** do código inteiro em todas as execuções. Use `scan`.
- **Saída relevante no JSON:** `results[].check_id`, `.path`, `.start.line`, `.extra.severity`, `.extra.metadata.owasp`, `.extra.metadata.cwe`, `.extra.metadata.confidence`.
- **Atenção:** `--metrics=off` evita telemetria e reduz variação de rede no tempo medido.

## 3.3 Trivy (SCA)

- **Obtenção:** binário via `aquasecurity/setup-trivy`, imagem `aquasec/trivy`, ou `apt`/`brew`. Sem custo.
- **Três varreduras distintas, que atendem a três seções diferentes do seu TCC:**

| Comando | Alvo | Seção do TCC que atende |
|---|---|---|
| `trivy fs --scanners vuln,secret .` | Dependências npm no código-fonte | 2.3.3 (SCA) |
| `trivy image <img>` | Imagem Docker construída (SO base + libs) | 2.5 (contêineres) |
| `trivy config .` | `Dockerfile` e arquivos IaC | 2.5 (IaC/Shift-Left na infraestrutura) |

Rodar as três é o que fecha o argumento da seção 2.5 do seu referencial, que hoje está teoricamente desenvolvida mas sem contrapartida experimental. Isso é uma lacuna que a banca pode apontar.

- **Comando recomendado:**

```bash
trivy image \
  --format json --output trivy-image.json \
  --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
  --exit-code 0 \
  --scanners vuln,secret \
  --timeout 15m \
  <imagem>
```

- **Ponto crítico:** usar `--exit-code 0` e **aplicar o gate em um passo separado**, com script próprio que lê o JSON. Motivo: a flag `--severity` do Trivy filtra pelo **rótulo** de severidade, não pela **pontuação numérica** CVSS. Seu critério é numérico (≥ 7.0). Delegar o gate ao `--severity HIGH,CRITICAL` seria implementar um critério diferente do que o TCC declara. Essa distinção precisa estar escrita no Capítulo 3.
- **Campo de score no JSON:** `Results[].Vulnerabilities[].CVSS.<fonte>.V3Score`, com `<fonte>` em `nvd`, `ghsa`, `redhat`, entre outros. Daí a necessidade da ordem de precedência definida em D2.
- **Cache da base de dados:** o Trivy baixa a base de vulnerabilidades do registro OCI. Para reduzir variação de tempo e evitar limite de requisições, usar `cache: true` no `setup-trivy` e o cache de actions. **Documentar se o cache está ativo**, porque ele afeta diretamente a medição de overhead.

## 3.4 OWASP ZAP (DAST)

- **Obtenção:** imagem `ghcr.io/zaproxy/zaproxy:stable` ou actions oficiais.
- **Actions disponíveis (organização `zaproxy`, verificada pelo GitHub):**

| Action | Versão atual | Comportamento |
|---|---|---|
| `zaproxy/action-baseline` | v0.15.0 | Varredura passiva (spider + análise passiva). Rápida, 1 a 5 min. |
| `zaproxy/action-full-scan` | atual | Spider + spider AJAX + **varredura ativa**. Ataca de fato. Pode levar 30 a 60+ min. |
| `zaproxy/action-api-scan` | atual | Para APIs com OpenAPI/SOAP |
| `zaproxy/action-af` | atual | Executa planos do **Automation Framework** (YAML) |

- **Recomendação:** usar `action-full-scan` com **limites de tempo explícitos**, ou migrar para `action-af` com um plano YAML versionado. O plano YAML é superior para o TCC, porque o plano fica no repositório como artefato reprodutível e citável.
- **Parâmetros obrigatórios de controle:**
  - `-m <minutos>` limita o spider.
  - `-T <minutos>` limita o tempo total.
  - `allow_issue_writing: false` (por padrão a action abre e mantém issues no repositório, o que polui o experimento).
  - `cmd_options: '-J zap.json'` para saída JSON além do HTML/MD.
- **Não determinismo:** o spider do ZAP não visita as páginas na mesma ordem em toda execução, e o spider AJAX depende de temporização de navegador. Isso significa que **o ZAP produzirá contagens ligeiramente diferentes entre execuções**. Isso não é um defeito do experimento, é uma característica da técnica, e deve ser: (a) medido, reportando a variação entre as n execuções; (b) discutido no Capítulo 5 como limitação intrínseca do DAST automatizado, o que dialoga diretamente com Seid et al. (2025) e Rosa et al. (2024), já citados no seu Capítulo 2.
- **Autenticação:** o Juice Shop tem áreas acessíveis apenas autenticado. Sem autenticação, o ZAP cobre só a superfície pública, o que subestima a detecção. Definir e documentar: rodar autenticado (via `ZAP_AUTH_HEADER` com token JWT obtido previamente) ou não autenticado. **Recomendação:** rodar não autenticado no experimento principal (mais simples, determinístico e reprodutível) e registrar como limitação, ou rodar uma execução adicional autenticada como análise complementar.
- **Campos do JSON:** `site[].alerts[].pluginid`, `.alert`, `.riskcode`, `.confidence`, `.instances[].uri`, `.instances[].param`, `.cweid`, `.wascid`.

## 3.5 Docker

- Pré-instalado nos runners do GitHub.
- Uso: `docker build` no estágio de Build; `docker run -d` no estágio de Staging.
- **Healthcheck obrigatório** antes do DAST. Sem espera ativa, o ZAP varre uma aplicação que ainda não subiu e reporta zero alertas, o que é um falso resultado silencioso e destruiria uma rodada inteira sem aviso.

```bash
for i in $(seq 1 60); do
  curl -sf http://localhost:3000 >/dev/null && break
  sleep 2
done
```

## 3.6 Ferramentas de análise (máquina local)

- Python 3.11+, `pandas`, `scipy`, `matplotlib`, `jupyter`.
- `jq` para inspeção rápida dos JSON.
- `gh` CLI para baixar artefatos e consultar a API de jobs.

```bash
python -m venv .venv && source .venv/bin/activate
pip install pandas scipy matplotlib jupyter
```

---

# 4. Alvos experimentais

## 4.1 Alvo 1: OWASP Juice Shop (ground truth conhecido)

**Função no experimento:** linha de base controlada. Permite calcular **revocação** (recall) e **falsos negativos**, porque as falhas são documentadas.

**Problema do Quadro 6 atual:** ele lista apenas 5 vulnerabilidades-alvo. Isso é pouco para sustentar uma taxa de detecção com significado estatístico. Um recall calculado sobre n=5 é frágil.

**Solução recomendada:** ampliar o ground truth usando o arquivo `data/static/challenges.yml` do próprio repositório do Juice Shop, que cataloga aproximadamente uma centena de desafios, cada um com categoria, dificuldade e descrição. É uma fonte oficial, versionada e citável.

**Passo essencial para não gerar um resultado injusto:** nem todo desafio do Juice Shop é detectável por varredura automatizada. Muitos dependem de lógica de negócio, o que é precisamente o ponto levantado por Seid et al. (2025) no seu referencial. Portanto, construir a tabela de ground truth com **classificação prévia de detectabilidade**:

| Coluna | Conteúdo |
|---|---|
| `id_desafio` | Identificador do `challenges.yml` |
| `categoria_owasp` | A01 a A10 |
| `descricao` | Resumo |
| `detectavel_sast` | Sim / Não / Parcial |
| `detectavel_sca` | Sim / Não / Parcial |
| `detectavel_dast` | Sim / Não / Parcial |
| `justificativa` | Por que sim ou não |

Essa classificação deve ser feita **antes de rodar as ferramentas** e registrada com data. Classificar depois de ver os resultados é viés de confirmação, e é o tipo de coisa que uma banca atenta detecta.

Com isso, o recall passa a ser calculado sobre o denominador correto:

```
Recall_ferramenta = TP_ferramenta / |{desafios detectáveis por aquela ferramenta}|
```

E o conjunto de desafios **não detectáveis** vira, ele próprio, um resultado importante: quantifica o teto da automação e sustenta empiricamente o argumento de que a esteira automatizada não substitui análise humana.

**Manter o Quadro 6 existente** como recorte ilustrativo no Capítulo 3, e apresentar a tabela completa como apêndice.

## 4.2 Alvo 2: aplicação com perfil desconhecido

**Função no experimento:** validade externa. Responde à pergunta "isto funciona fora de uma aplicação feita de propósito para ser encontrada?".

**Métricas aplicáveis:** volume de achados, precisão pós-triagem, sobreposição entre ferramentas, comportamento do gate, overhead. **Não aplicáveis:** recall e falsos negativos.

**Redação necessária no Capítulo 3:** um parágrafo explicando por que a ausência de ground truth é uma escolha deliberada de desenho e não uma deficiência, e listando exatamente quais métricas se aplicam a cada alvo. Um quadro comparativo resolve isso de forma limpa.

| Métrica | Alvo 1 (Juice Shop) | Alvo 2 (perfil desconhecido) |
|---|---|---|
| Overhead de tempo | Sim | Sim |
| Volume de alertas | Sim | Sim |
| Precisão (pós-triagem) | Sim | Sim |
| Revocação (recall) | Sim | Não aplicável |
| Falsos negativos | Sim | Não aplicável |
| Comportamento do gate | Sim | Sim |
| Complementaridade entre ferramentas | Sim | Sim |

---

# 5. Desenho experimental consolidado

## 5.1 Variáveis (revisão do que já está no Capítulo 3)

**Variável de estímulo:** presença e configuração da esteira DevSecOps.
Níveis: `baseline` (sem segurança) | `devsecops-audit` | `devsecops-enforce`.

**Variáveis de resposta:**
1. Tempo de parede total (s)
2. Minutos faturáveis (s)
3. Tempo por estágio (s)
4. Overhead absoluto (s) e relativo (%)
5. Contagem de alertas bruta e deduplicada, por ferramenta e severidade
6. Verdadeiros positivos, falsos positivos, precisão
7. Revocação e falsos negativos (somente alvo 1)
8. Decisão do gate e estágio de parada
9. Taxa de achados sem score CVSS (fallback)

**Variáveis de controle:**
- Commit fixado de cada alvo
- Imagem do runner (`ubuntu-24.04`)
- Versões fixadas de Semgrep, Trivy, ZAP, Docker
- Conjunto de regras fixado
- Configuração padrão de cada scanner, salvo os desvios documentados
- Período de execução

**Fatores de confusão a mitigar e documentar:**
- Estado de cache (imagem Docker, base do Trivy, `node_modules`)
- Variação de desempenho do runner compartilhado
- Latência de rede no download de regras e de bases
- Não determinismo do spider do ZAP

## 5.2 Matriz de execuções

| # | Alvo | Configuração | n | Finalidade |
|---|---|---|---|---|
| E1 | Juice Shop | baseline | 10 | Linha de base de tempo |
| E2 | Juice Shop | devsecops-audit | 10 | Overhead + eficácia completa |
| E3 | Juice Shop | devsecops-enforce | 5 | Validação do gate (esperado: bloqueio) |
| E4 | Alvo 2 | baseline | 10 | Linha de base de tempo |
| E5 | Alvo 2 | devsecops-audit | 10 | Overhead + eficácia |
| E6 | Alvo 2 | devsecops-enforce | 5 | Validação do gate |
| E7 | Juice Shop | gate-fixture | 3 | Prova de corretude do gate (ver 5.3) |

Total aproximado: 53 execuções. Descartando a primeira de cada bloco: 46 válidas.

## 5.3 Experimento de validação do gate (E7)

Um gate que bloqueia não prova que o gate funciona: pode estar bloqueando por qualquer motivo. É preciso demonstrar **corretude nos dois sentidos**, com um cenário construído:

| Cenário | Construção | Resultado esperado |
|---|---|---|
| **Positivo controlado** | Fixar uma dependência com CVE de CVSS conhecido ≥ 7.0 | Gate bloqueia, e o relatório aponta exatamente aquele CVE |
| **Negativo controlado** | Ambiente sem nenhum achado ≥ 7.0 (via `.trivyignore` documentado ou imagem base mínima) | Gate aprova, esteira segue até o DAST |
| **Limite** | Achado com score exatamente 7.0 | Gate bloqueia (critério é `>=`, não `>`) |

Este experimento é curto, barato e vale uma seção inteira do Capítulo 4. É a diferença entre "eu implementei um gate" e "eu demonstrei que o gate implementa o critério declarado".

---

# 6. Os workflows

## 6.1 W0: Baseline (`00-baseline.yml`)

Representa a esteira sem segurança. Deve conter **exatamente** os mesmos estágios não relacionados a segurança do W1, nem um a mais nem um a menos. Qualquer assimetria contamina a medição de overhead.

```yaml
name: 00-baseline
on:
  workflow_dispatch:
    inputs:
      rodada: { description: 'Identificador da rodada', required: true }

jobs:
  build-deploy:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<sha>
      - name: Build da imagem Docker
        run: docker build -t alvo:${{ github.sha }} .
      - name: Staging (subir aplicação)
        run: |
          docker run -d --name alvo -p 3000:3000 alvo:${{ github.sha }}
          for i in $(seq 1 60); do
            curl -sf http://localhost:3000 >/dev/null && exit 0
            sleep 2
          done
          echo "Aplicação não respondeu"; exit 1
```

## 6.2 W1: Esteira DevSecOps (`01-devsecops.yml`)

Estrutura de jobs, refletindo a Figura 5 do TCC:

```
sast (Semgrep)
  └─> build (Docker)
        └─> sca (Trivy: fs + image + config)
              └─> quality-gate (script de decisão CVSS)
                    └─> staging-dast (deploy + ZAP no mesmo job)
```

**Observação de arquitetura importante:** o deploy e o DAST **precisam estar no mesmo job**. Jobs do GitHub Actions rodam em runners distintos e não compartilham processos em execução. Um container subido no job A não existe no job B. A Figura 5 mostra `Staging/Deploy` e `DAST` como caixas separadas, o que é correto no plano lógico, mas na implementação são um único job. Vale uma nota de rodapé no Capítulo 3 explicando essa diferença entre modelo lógico e implementação.

Esqueleto:

```yaml
name: 01-devsecops
on:
  workflow_dispatch:
    inputs:
      rodada: { required: true }
      gate_mode:
        type: choice
        options: [audit, enforce]
        default: audit
      gate_scope:
        type: choice
        options: [sca-only, all-tools]
        default: sca-only

env:
  GATE_MODE: ${{ inputs.gate_mode }}
  GATE_SCOPE: ${{ inputs.gate_scope }}
  CVSS_LIMIAR: '7.0'

jobs:
  sast:
    runs-on: ubuntu-24.04
    container: semgrep/semgrep:<versao-fixada>
    steps:
      - uses: actions/checkout@<sha>
      - name: Semgrep
        run: |
          semgrep scan \
            --config p/owasp-top-ten --config p/javascript \
            --config p/security-audit --config p/secrets \
            --json --output semgrep.json \
            --metrics=off --error=false --timeout 300
      - uses: actions/upload-artifact@<sha>
        with: { name: semgrep-${{ inputs.rodada }}, path: semgrep.json }

  build:
    needs: sast
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<sha>
      - run: docker build -t alvo:${{ github.sha }} .
      - run: docker save alvo:${{ github.sha }} -o imagem.tar
      - uses: actions/upload-artifact@<sha>
        with: { name: imagem-${{ inputs.rodada }}, path: imagem.tar }

  sca:
    needs: build
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<sha>
      - uses: actions/download-artifact@<sha>
        with: { name: imagem-${{ inputs.rodada }} }
      - run: docker load -i imagem.tar
      - uses: aquasecurity/setup-trivy@<sha>
        with: { version: v<x.y.z>, cache: true }
      - name: Trivy - dependencias (fs)
        run: trivy fs --scanners vuln,secret --format json -o trivy-fs.json --exit-code 0 .
      - name: Trivy - imagem
        run: trivy image --scanners vuln --format json -o trivy-image.json --exit-code 0 alvo:${{ github.sha }}
      - name: Trivy - IaC (Dockerfile)
        run: trivy config --format json -o trivy-config.json --exit-code 0 .
      - uses: actions/upload-artifact@<sha>
        with: { name: trivy-${{ inputs.rodada }}, path: trivy-*.json }

  quality-gate:
    needs: sca
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<sha>
      - uses: actions/download-artifact@<sha>
      - name: Avaliar Quality Gate
        run: python ci/quality_gate.py --limiar $CVSS_LIMIAR --modo $GATE_MODE --escopo $GATE_SCOPE

  staging-dast:
    needs: quality-gate
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<sha>
      - uses: actions/download-artifact@<sha>
        with: { name: imagem-${{ inputs.rodada }} }
      - run: docker load -i imagem.tar
      - name: Staging
        run: |
          docker run -d --name alvo -p 3000:3000 alvo:${{ github.sha }}
          for i in $(seq 1 60); do curl -sf http://localhost:3000 >/dev/null && break; sleep 2; done
      - name: OWASP ZAP - full scan
        uses: zaproxy/action-full-scan@<sha>   # v0.x
        with:
          target: 'http://localhost:3000'
          docker_name: 'ghcr.io/zaproxy/zaproxy:stable'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-J zap.json -m 5 -T 20 -a'
          allow_issue_writing: false
          artifact_name: zap-${{ inputs.rodada }}
```

## 6.3 O script do Quality Gate (`ci/quality_gate.py`)

Este script é o **coração do trabalho** e merece ser reproduzido (ou ter seu pseudocódigo reproduzido) no Capítulo 3 ou em apêndice. Responsabilidades:

1. Ler `trivy-fs.json`, `trivy-image.json`, `trivy-config.json` e, se `escopo == all-tools`, também `semgrep.json` e `zap.json`.
2. Para cada achado do Trivy, extrair o score seguindo a **ordem de precedência de D2**, registrando qual fonte foi usada.
3. Deduplicar conforme a chave de D6.
4. Aplicar o critério: bloqueia se existe achado com score ≥ limiar (ou, no escopo ampliado, se atende às equivalências de D3).
5. Emitir `gate-decision.json` com: decisão, motivo, lista de achados que dispararam, contagem por faixa de severidade, quantidade de fallbacks.
6. Emitir resumo no `$GITHUB_STEP_SUMMARY` (fica visível na interface e rende boa captura de tela para o Capítulo 4).
7. Retornar `exit 1` **somente** se `modo == enforce`. Em `audit`, retorna 0 mas grava a mesma decisão.

Pseudocódigo da extração de score:

```python
FONTES = ["nvd", "ghsa", "redhat"]
MAPA_ROTULO = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 0.1, "UNKNOWN": 0.0}

def score_cvss(vuln):
    cvss = vuln.get("CVSS", {}) or {}
    for fonte in FONTES:
        v = (cvss.get(fonte) or {}).get("V3Score")
        if v is not None:
            return float(v), fonte
    return MAPA_ROTULO.get(vuln.get("Severity", "UNKNOWN"), 0.0), "fallback_rotulo"
```

## 6.4 W2: Validação do gate (`02-gate-validation.yml`)

Workflow curto que executa apenas os cenários de E7 (seção 5.3), com fixtures versionados.

---

# 7. Coleta de dados

## 7.1 Tempos

Após cada execução, capturar via API:

```bash
gh api repos/$OWNER/$REPO/actions/runs/$RUN_ID/jobs \
  > dados/brutos/$ALVO/$RUN_ID/jobs.json
```

O script `coletar_tempos.py` converte isso em `tempos.csv`:

| coluna | descrição |
|---|---|
| `run_id`, `rodada`, `alvo`, `config` | identificação |
| `job`, `step` | estágio |
| `inicio_utc`, `fim_utc`, `duracao_s` | tempo |
| `conclusao` | success / failure / skipped |
| `runner_name` | para inspeção de outliers |

## 7.2 Achados

Baixar artefatos:

```bash
gh run download $RUN_ID -D dados/brutos/$ALVO/$RUN_ID/
```

O script `normalizar_achados.py` converte os três formatos distintos em um esquema único `achados.csv`:

| coluna | descrição |
|---|---|
| `run_id`, `alvo`, `config` | identificação |
| `ferramenta` | semgrep / trivy / zap |
| `id_achado` | check_id, VulnerabilityID ou pluginid |
| `local` | arquivo:linha, pacote@versão ou URI |
| `severidade_nativa` | rótulo original |
| `cvss_v3` | score, quando aplicável |
| `fonte_score` | nvd / ghsa / redhat / fallback |
| `owasp` | categoria mapeada |
| `cwe` | quando disponível |
| `chave_dedup` | conforme D6 |
| `dispara_gate` | booleano |

Ter um esquema único é o que torna possível a análise de complementaridade entre ferramentas (seção 8.4), que é um dos diferenciais que você declarou no Quadro 5.

---

# 8. Métricas e fórmulas

## 8.1 Impacto operacional

```
Overhead_absoluto = mediana(T_devsecops) - mediana(T_baseline)
Overhead_relativo = Overhead_absoluto / mediana(T_baseline) × 100
```

Reportar decomposto por estágio, para responder "de onde vem o custo". A expectativa (a confirmar) é que o DAST domine o custo, o que sustenta uma diretriz prática: SAST e SCA cabem em cada commit, DAST não.

## 8.2 Eficácia (alvo 1)

```
Precisao  = VP / (VP + FP)
Revocacao = VP / (VP + FN)     [denominador: apenas achados detectáveis]
F1        = 2 × (Precisao × Revocacao) / (Precisao + Revocacao)
Taxa_FP   = FP / (VP + FP)
```

## 8.3 Eficácia (alvo 2)

Apenas precisão pós-triagem, volume e distribuição por severidade e categoria OWASP.

## 8.4 Complementaridade entre ferramentas

Análise de sobreposição (diagrama de Venn ou matriz), respondendo: quantas categorias OWASP foram cobertas **exclusivamente** por cada ferramenta?

Este é o resultado que dialoga diretamente com Rosa et al. (2024), que concluiu que nenhuma ferramenta isolada basta. Seu trabalho pode confirmar ou refutar isso em um arranjo diferente (três categorias distintas de ferramenta, e não apenas vários DAST). É provavelmente a contribuição mais forte disponível.

## 8.5 Comportamento do gate

- Taxa de bloqueio por configuração.
- Estágio médio de parada.
- Tempo até o bloqueio (relevante: quanto mais cedo o bloqueio, mais barato o ciclo de feedback, o que é exatamente a tese do Shift-Left e da Regra de 10 de Myers citada no seu Capítulo 2).
- Corretude nos cenários controlados de E7.

---

# 9. Protocolo de triagem manual

Necessário para separar VP de FP. Sem protocolo escrito, a triagem é opinião e a banca pode contestá-la.

**Procedimento:**

1. **Amostragem.** Se o volume de achados for grande (provável no Juice Shop), triar amostra aleatória estratificada por severidade e ferramenta, com `random.seed` fixado e documentado. Definir tamanho de amostra e reportar intervalo de confiança da precisão estimada. Se o volume for gerenciável (< 200 achados), triar tudo.

2. **Critérios de classificação, definidos antes de olhar os dados:**

| Classificação | Critério |
|---|---|
| **Verdadeiro positivo** | A condição apontada existe no código ou na aplicação e é explorável, ou a dependência vulnerável está de fato presente e na versão afetada |
| **Falso positivo** | A condição apontada não existe, ou o caminho de código é inalcançável, ou a regra casou com um padrão sintaticamente semelhante mas semanticamente distinto |
| **Não explorável** | A condição existe mas está mitigada pelo contexto (categoria separada, não somada aos FP; reportar à parte) |
| **Indeterminado** | Não foi possível decidir com o esforço definido (registrar e reportar) |

3. **Evidência obrigatória.** Cada classificação registra: trecho de código ou requisição, justificativa em uma frase, e data. Sem evidência registrada, a triagem não é auditável.

4. **Confiabilidade.** O ideal metodológico é dois avaliadores independentes com cálculo de concordância (Kappa de Cohen). Em TCC individual isso é inviável. Alternativas defensáveis, em ordem de preferência:
   - Pedir ao orientador que triе uma subamostra (20 a 30 achados) e reportar a concordância.
   - Realizar **dupla triagem cega no tempo**: triar tudo, esperar duas semanas, retriar uma subamostra sem consultar a primeira classificação, e reportar a concordância intra-avaliador.
   - No mínimo, declarar explicitamente a triagem como de avaliador único e listar isso nas ameaças à validade.

5. **Saída:** `triagem.csv` com `id_achado`, `classificacao`, `justificativa`, `evidencia`, `avaliador`, `data`.

---

# 10. Ajustes necessários no texto já escrito

Estes ajustes decorrem das decisões D1 a D7 e devem ser feitos de forma cirúrgica, sem reescrita dos capítulos.

## 10.1 Capítulo 2

| Local | Ajuste |
|---|---|
| Seção 2.4.3 | Explicitar a versão do CVSS adotada operacionalmente (v3.1) e mencionar a v4.0 como evolução do padrão. Adicionar entrada correspondente no `main.bib`. |
| Quadro 4 | Verificar coerência: a coluna "Ação Recomendada" distingue Alta (quebra condicional) de Crítica (quebra imediata), enquanto o gate implementado é binário em 7.0. Adicionar nota de rodapé esclarecendo que o quadro apresenta a classificação conceitual do padrão e que o critério implementado é binário. |
| Seção 2.5 | Nenhum ajuste, mas garantir que o `trivy config` implementado seja referenciado no Capítulo 3 como a contrapartida experimental desta seção. |

## 10.2 Capítulo 3

Ajustes maiores. Estrutura proposta revisada:

```
3.1 Materiais
  3.1.1 Cenário de Avaliação e Perfil de Ameaças
    3.1.1.1 Alvo 1: OWASP Juice Shop            [existente, ampliar ground truth]
    3.1.1.2 Alvo 2: <nome>                      [NOVO]
    3.1.1.3 Métricas aplicáveis a cada alvo     [NOVO, quadro comparativo]
  3.1.2 Ambiente de Execução e Infraestrutura Virtual   [existente]
  3.1.3 Versões e Fixação do Ambiente           [NOVO, quadro de versões]

3.2 Métodos
  3.2.1 Metodologia Experimental                [revisar: n, repetições, estatística]
  3.2.2 Modelagem Lógica do Pipeline            [existente + nota sobre deploy/DAST no mesmo job]
  3.2.3 Critério de Quality Gate                [NOVO: precedência CVSS + equivalências SAST/DAST]
  3.2.4 Modos de Execução                       [NOVO: enforce vs audit]
  3.2.5 Coleta e Análise de Dados               [revisar: unidade de contagem, protocolo de triagem]
  3.2.6 Ameaças à Validade                      [NOVO, ou mover para o Cap. 5]
```

Convenções de escrita a manter (conforme padrão já estabelecido no trabalho):
- Toda afirmação atribuída a autor e ano.
- Distinção CVE (identificador, MITRE) vs. CVSS (pontuação, FIRST) preservada.
- SSRF permanece no referencial teórico, mas não entra entre as vulnerabilidades testadas.
- `\gls{}` com atenção aos `\glsunset` anteriores ao Capítulo 2 (expansões em títulos e primeiras ocorrências continuam hardcoded).
- Especificador `[H]` em todas as tabelas e figuras.
- Aspas padrão do LaTeX, sem `\enquote{}`.
- Sem travessões duplos; usar vírgulas ou parênteses.
- Referências cruzadas com os rótulos reais dos arquivos-fonte.
- Corrigir a inconsistência SSDLC (glossário) vs. S-SDLC (Lista de Abreviaturas) na raiz do glossário.
- Figuras geradas com auxílio de IA citadas como "Elaborado com auxílio de [ferramenta] (ano), adaptado de [fonte]", com entrada ABNT correspondente.

---

# 11. Estrutura dos Capítulos 4 e 5

## Capítulo 4: Resultados

```
4.1 Implementação da Esteira
    4.1.1 Estrutura dos repositórios e workflows
    4.1.2 Configuração final de cada ferramenta
    4.1.3 Implementação do Quality Gate      [trecho de código ou pseudocódigo]
    Figura: captura da execução no GitHub Actions
    Figura: grafo de dependências dos jobs

4.2 Validação Funcional do Quality Gate
    Quadro: cenários E7 (positivo, negativo, limite) e resultados
    Figura: captura do bloqueio da esteira

4.3 Impacto Operacional
    Tabela: mediana e IQR de tempo por configuração e por alvo
    Tabela: decomposição por estágio
    Figura: boxplot baseline vs. devsecops (por alvo)
    Tabela: overhead absoluto e relativo, p-valor, delta de Cliff

4.4 Eficácia de Detecção no Alvo 1 (Juice Shop)
    Tabela: achados por ferramenta e severidade (bruto e deduplicado)
    Tabela: matriz de confusão contra o ground truth
    Tabela: precisão, revocação, F1, taxa de FP por ferramenta
    Tabela: desafios não detectáveis por automação

4.5 Eficácia de Detecção no Alvo 2
    Tabela: achados por ferramenta e severidade
    Tabela: resultado da triagem e precisão estimada
    Figura: distribuição por categoria OWASP

4.6 Complementaridade entre SAST, SCA e DAST
    Figura: sobreposição de cobertura
    Tabela: categorias OWASP cobertas exclusivamente por cada ferramenta

4.7 Síntese dos Resultados
    Quadro consolidando os achados por objetivo específico
```

## Capítulo 5: Discussão e Conclusão

```
5.1 Discussão dos Resultados
    5.1.1 O custo real do Shift-Left        [responde à pergunta de pesquisa]
    5.1.2 Falsos positivos e fadiga de alertas
    5.1.3 O teto da automação               [dialoga com Seid et al., 2025]
    5.1.4 O gate como instrumento de decisão

5.2 Comparação com os Trabalhos Relacionados
    Retomar o Quadro 5 e confrontar seus números com Putra e Kabetta (2022),
    Nikolov e Aleksieva-Petrova (2023), Rosa et al. (2024) e Seid et al. (2025)

5.3 Diretrizes Propostas
    ATENÇÃO: esta é a entrega do OBJETIVO GERAL do trabalho.
    Apresentar como quadro numerado (D1..Dn), cada diretriz com:
    enunciado, evidência empírica que a sustenta, e condição de aplicabilidade.
    Sem esta seção, o objetivo geral fica sem entregável explícito.

5.4 Ameaças à Validade
    Interna: variação do runner, cache, não determinismo do ZAP, triagem única
    Externa: dois alvos, stack única (Node.js), plataforma única (GitHub Actions)
    Construto: equivalência de severidade entre ferramentas, unidade de contagem
    Conclusão: n=10, teste não paramétrico

5.5 Conclusão

5.6 Trabalhos Futuros
    IAST, análise com autenticação, múltiplas stacks, comparação entre
    plataformas de CI, uso de IA na triagem (retomando Abdiukov, 2024)
```

**Alerta:** a seção 5.3 é a mais importante do trabalho e a mais fácil de esquecer. Seu objetivo geral é "propor diretrizes". Se o Capítulo 4 traz números e o Capítulo 5 traz apenas discussão, o objetivo geral não foi cumprido formalmente. As diretrizes precisam existir como artefato identificável, numerado e derivado das evidências.

---

# 12. Cronograma

Reuniões presenciais às sextas-feiras pela manhã, conforme definido em 31/08. Cada sprint fecha com um entregável verificável para a reunião. O cronograma abaixo assume 12 semanas a partir de 05/09/2026 e precisa ser ancorado na data real de entrega e defesa.

| Sprint | Sexta | Entregável para a reunião | Frente escrita em paralelo |
|---|---|---|---|
| S1 | 05/09 | Decisões D1 a D7 fechadas com o orientador. Segundo alvo escolhido e justificado. | Rascunho da nova seção 3.1.1.2 |
| S2 | 12/09 | Repositórios criados. W0 (baseline) rodando nos dois alvos. Versões fixadas em `AMBIENTE.md`. | Seção 3.1.3 (quadro de versões) |
| S3 | 19/09 | Jobs de SAST e Build funcionando. `semgrep.json` sendo produzido e arquivado. | Seção 4.1.1 e 4.1.2 |
| S4 | 26/09 | Job de SCA com as três varreduras do Trivy. `quality_gate.py` implementado nos dois modos. | Seção 3.2.3 e 3.2.4 |
| S5 | 03/10 | Job de Staging + DAST funcionando. Esteira completa executa fim a fim em modo audit. | Seção 4.1.3 |
| S6 | 10/10 | E7 executado. Gate validado nos três cenários. Ground truth do Juice Shop classificado por detectabilidade (antes das rodadas). | Seção 4.2 |
| S7 | 17/10 | Rodadas E1 a E6 executadas (40 execuções). Dados brutos arquivados. | Revisão do Cap. 3 completa |
| S8 | 24/10 | Scripts de parsing prontos. `tempos.csv` e `achados.csv` gerados. Análise de overhead concluída. | Seção 4.3 |
| S9 | 31/10 | Triagem manual concluída. `triagem.csv` fechado. Subamostra triada pelo orientador. | Seção 4.4 e 4.5 |
| S10 | 07/11 | Análise de complementaridade e estatística inferencial. Todas as figuras e tabelas geradas. | Seção 4.6 e 4.7. Capítulo 4 fechado. |
| S11 | 14/11 | Capítulo 5 completo, com ênfase nas diretrizes (5.3). | Capítulo 5 |
| S12 | 21/11 | Revisão integral, resumo, abstract, apêndices. Documento fechado para revisão do orientador. | Revisão final |
| S13 | 28/11 | Apresentação de defesa construída e ensaiada. | Slides |

**Ajuste pelas 2 semanas perdidas:** a compressão está concentrada em S2 a S5, onde a construção da esteira acontece. A alavanca de recuperação é começar o Capítulo 4 (seções 4.1 e 4.2) já em S3, escrevendo a implementação enquanto ela é feita, e não depois. Documentar durante a construção custa quase nada; reconstituir depois custa uma semana.

---

# 13. Riscos e mitigações

O relatório de reunião registra que riscos foram discutidos. Esta tabela pode ser levada diretamente à próxima reunião e, em versão resumida, ao Capítulo 5.

| # | Risco | Prob. | Impacto | Mitigação |
|---|---|---|---|---|
| R1 | Varredura completa do ZAP excede o tempo do job (limite de 6h) e derruba rodadas | Média | Alto | Limitar com `-m 5 -T 20`; medir o tempo antes de rodar as 10 repetições; ter o baseline scan como plano B documentado |
| R2 | Gate bloqueia sempre no Juice Shop e não há dados de DAST | **Alta** | **Alto** | Modo observatório (D4). Risco já mitigado por desenho. |
| R3 | Segundo alvo produz zero ou pouquíssimos achados, esvaziando a análise | Média | Alto | Validar com uma varredura local **antes** de fechar a escolha do alvo. Ter um segundo candidato de reserva. |
| R4 | Limite de requisições ou indisponibilidade da base do Trivy | Média | Médio | Cache habilitado; autenticar o pull; espaçar as execuções |
| R5 | Variância do runner mascara o efeito de overhead | Média | Médio | n=10, intercalação, estatística não paramétrica, registro do `runner_name` |
| R6 | Não determinismo do ZAP gera contagens inconsistentes | **Alta** | Médio | Medir e reportar a variação como resultado; discutir como limitação intrínseca do DAST |
| R7 | Volume de achados torna a triagem manual inviável no prazo | Média | Alto | Amostragem estratificada com semente fixa e IC reportado; definir o tamanho da amostra já em S6 |
| R8 | Comprometimento ou mudança quebrando actions de terceiros | Baixa | Alto | Fixação por SHA (incidente real com `trivy-action` em março de 2026) |
| R9 | Segundo alvo exige serviços externos (banco, cache) que não sobem no runner | Média | Médio | Critério de seleção já exclui isso; validar em S1 |
| R10 | Atraso residual do cronograma | Média | Alto | Escrita em paralelo desde S3; capítulos 4.1 e 4.2 escritos durante a construção |
| R11 | Perda de dados brutos entre execuções | Baixa | Alto | Artefatos versionados no repositório de análise imediatamente após cada rodada; não confiar na retenção de artefatos do GitHub (padrão de 90 dias) |

---

# 14. Checklist de reprodutibilidade

Um leitor deveria conseguir reproduzir o experimento com o que está publicado. Verificar antes de fechar o documento:

- [ ] Commits exatos dos dois alvos registrados
- [ ] Versões exatas de Semgrep, Trivy, ZAP, Docker e imagem do runner registradas
- [ ] Conjunto de regras do Semgrep listado
- [ ] Plano do ZAP (`.zap/plan.yaml` ou `rules.tsv`) publicado
- [ ] Workflows completos publicados ou em apêndice
- [ ] `quality_gate.py` publicado ou em pseudocódigo no texto
- [ ] Ordem de precedência de fontes de score CVSS declarada
- [ ] Unidade de contagem e regra de deduplicação declaradas
- [ ] Regra de equivalência de severidade entre ferramentas declarada
- [ ] Modos de execução declarados
- [ ] n, critério de descarte e teste estatístico declarados
- [ ] Protocolo de triagem e critérios de classificação declarados
- [ ] Ground truth do alvo 1 publicado como apêndice, com data de classificação anterior às rodadas
- [ ] Dados brutos e processados disponíveis (repositório público ou apêndice digital)
- [ ] Período de execução informado

---

# 15. Primeiras ações concretas (esta semana)

Em ordem, sem depender de nada:

1. **Escolher e validar o segundo alvo.** Clonar o candidato, rodar `semgrep scan` e `trivy fs` localmente, e verificar se há achados suficientes e se ele sobe em container único. Isso responde a R3 e R9 antes que virem problema.
2. **Criar os três repositórios** e fixar os commits dos alvos.
3. **Escrever o W0 (baseline)** e rodá-lo uma vez em cada alvo. É o workflow mais simples e destrava a medição de tempo.
4. **Levar as sete decisões (D1 a D7) para a reunião de sexta**, com a recomendação de cada uma, para fechar todas de uma vez em vez de decidi-las aos poucos ao longo do semestre.
5. **Iniciar o `AMBIENTE.md`**, que depois vira quadro no Capítulo 3.
