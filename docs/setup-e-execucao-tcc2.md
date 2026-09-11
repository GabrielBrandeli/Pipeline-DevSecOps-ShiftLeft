# Setup e Execução: Esteira DevSecOps TCC 2

**Repositório:** `github.com/GabrielBrandeli/Pipeline-DevSecOps-ShiftLeft` (público, 1 commit)
**Prazo:** entrega do escrito e do projeto em **03/11/2026** (8 semanas e meia a partir de 04/09/2026)
**Decisões fechadas:** D1 a D7 conforme respostas de 04/09/2026

---

# PARTE I: DECISÕES CONSOLIDADAS

Registrar estas decisões em `docs/DECISOES.md` no repositório, com data. Elas viram texto do Capítulo 3.

| ID | Decisão | Valor adotado |
|---|---|---|
| D1 | Segundo alvo | Uptime Kuma (`louislam/uptime-kuma`), Node.js + Vue, SQLite, MIT |
| D2 | Versão do CVSS | CVSS v3.1 Base Score, com precedência NVD → GHSA → RedHat → fallback por rótulo |
| D3 | Regra de equivalência | Definida na Parte II desta seção |
| D4 | Modos de execução | `enforce` (bloqueante) e `audit` (observatório), mesmo código de decisão |
| D5 | Repetições e estatística | n = 10, descarte da primeira, intercalação, mediana + IQR, Mann-Whitney U (α = 0,05), delta de Cliff. Duas métricas de tempo: parede e faturável |
| D6 | Unidade de contagem | Tupla por ferramenta, com reporte bruto e deduplicado |
| D7 | Protocolo de triagem | Adotado, com amostragem estratificada e dupla triagem cega no tempo |
| **D8** | **Arquitetura de repositório** | **Monorepo com submódulos** (revisão do plano original, ver Parte III) |

---

## Parte II: Regra de Equivalência Operacional (D3, versão final)

Esta é a regra que resolve o fato de que Semgrep e ZAP não emitem CVSS. Ela deve ser materializada em `ci/regras/equivalencia.yaml`, versionada, e reproduzida como quadro no Capítulo 3.

### Princípio norteador

O critério de bloqueio do trabalho é **CVSS v3.1 ≥ 7,0**, aplicado literalmente ao SCA. Para SAST e DAST, adota-se uma equivalência operacional construída sobre **dois eixos simultâneos**: a severidade nativa da ferramenta e o grau de confiança que ela própria atribui ao achado. Exigir os dois eixos, e não apenas a severidade, é o que reduz o efeito de fadiga de alertas discutido no Capítulo 2, e é justificável academicamente: a faixa "Alta" do CVSS pressupõe impacto real, não impacto potencial sob suposição não verificada.

### Regra formal

```yaml
# ci/regras/equivalencia.yaml
versao: "1.0"
data: "2026-09-05"
cvss_versao: "3.1"
limiar_cvss: 7.0

sca:
  ferramenta: trivy
  criterio: literal
  regra: "score_cvss_v31 >= 7.0"
  precedencia_fonte: [nvd, ghsa, redhat]
  fallback_rotulo:          # usado apenas se nenhuma fonte fornecer V3Score
    CRITICAL: 9.0
    HIGH:     7.0
    MEDIUM:   4.0
    LOW:      0.1
    UNKNOWN:  0.0

sast:
  ferramenta: semgrep
  criterio: equivalencia
  regra: "severity == 'ERROR' AND confidence in ['HIGH', 'MEDIUM']"
  campos:
    severity:   "extra.severity"
    confidence: "extra.metadata.confidence"
  confidence_ausente: tratar_como_MEDIUM   # decisão documentada
  justificativa: >
    ERROR e a categoria mais alta do Semgrep e indica violacao de seguranca
    com impacto direto. A exigencia de confianca nao-baixa evita equiparar
    a CVSS >= 7.0 achados que a propria ferramenta sinaliza como incertos.

dast:
  ferramenta: owasp_zap
  criterio: equivalencia
  regra: "riskcode == 3 AND confidence >= 2"
  escalas:
    riskcode:   {0: Informational, 1: Low, 2: Medium, 3: High}
    confidence: {0: Falso Positivo, 1: Baixa, 2: Media, 3: Alta, 4: Confirmada}
  justificativa: >
    riskcode 3 (High) e a maior severidade emitida pelo ZAP.
    confidence >= 2 (Media ou superior) exclui achados de baixa confianca,
    que sao a principal fonte de falso positivo em varredura ativa.

escopo_do_gate:
  sca_only:  [sca]                 # fiel a Figura 5 do TCC 1
  all_tools: [sast, sca, dast]     # variante ampliada
  padrao: sca_only
```

### Como isso é reportado no Capítulo 4

Rodar **as duas variantes de escopo** e comparar. A diferença entre a taxa de bloqueio em `sca_only` e em `all_tools` é um resultado próprio: mede quanto a escolha do escopo do gate, e não do limiar, determina o comportamento da esteira. Nenhum dos trabalhos relacionados do seu Quadro 5 faz essa separação.

### Limitação a declarar no Capítulo 5

A equivalência é uma construção deste trabalho, não um mapeamento normalizado por FIRST ou OWASP. Ela é reprodutível (está versionada e é determinística), mas é uma **ameaça à validade de construto**: dois achados equiparados a "CVSS ≥ 7,0" por vias diferentes não são necessariamente comparáveis em impacto real. Declarar isso explicitamente é o que torna a decisão defensável.

---

## Parte III: Arquitetura de repositório revisada (D8)

O plano original previa três repositórios. Com o repositório já criado, a arquitetura superior é **monorepo com submódulos Git**.

### Justificativa

| Aspecto | Três repositórios (forks) | Monorepo com submódulos |
|---|---|---|
| Fixação de commit do alvo | Manual, documentada em texto | Automática, é o próprio mecanismo do submódulo |
| Reprodutibilidade | Estado espalhado em três históricos | Um commit captura tudo |
| Workflows nativos do alvo | Disparam junto com os seus, poluindo o experimento | Não disparam |
| Workflow único com matriz de alvos | Impossível, código duplicado | Direto |
| Dados, scripts e esteira juntos | Não | Sim |
| Realismo (esteira vive no repo da app) | Maior | Menor, mitigável |

### A limitação e como tratá-la no texto

Em um cenário real, a esteira vive no repositório da própria aplicação. Aqui ela vive em um repositório orquestrador que referencia os alvos. **Isso não afeta nenhuma variável de resposta**: o `checkout` dos submódulos acontece de forma idêntica no baseline e na intervenção, portanto se cancela na medição de overhead; e Semgrep, Trivy e ZAP operam sobre o código e a aplicação em execução, indiferentes à origem do diretório.

Redação sugerida para nota de rodapé no Capítulo 3:

> A esteira foi implementada em repositório orquestrador que referencia as aplicações-alvo como submódulos Git, e não replicada no repositório de cada aplicação. Essa escolha garante que um único commit do repositório do experimento capture integralmente o estado das aplicações, dos workflows, dos scripts e dos dados coletados, favorecendo a reprodutibilidade. A operação de checkout dos submódulos é idêntica nas configurações de linha de base e de intervenção, não interferindo na medição de sobrecarga.

### Estrutura de diretórios

```
Pipeline-DevSecOps-ShiftLeft/
├── .github/
│   └── workflows/
│       ├── 00-baseline.yml            # W0: build + staging, sem seguranca
│       ├── 01-devsecops.yml           # W1: esteira completa
│       └── 02-gate-validation.yml     # W2: cenarios E7
├── alvos/
│   ├── juice-shop/                    # submodulo, tag fixada
│   └── uptime-kuma/                   # submodulo, tag fixada
├── ci/
│   ├── quality_gate.py                # coracao do trabalho
│   ├── regras/
│   │   └── equivalencia.yaml
│   └── perfis/
│       ├── alvo1-juiceshop.env
│       └── alvo2-uptimekuma.env
├── zap/
│   ├── rules.tsv
│   ├── plan-alvo1.yaml
│   └── plan-alvo2.yaml
├── analise/
│   ├── requirements.txt
│   ├── scripts/
│   │   ├── coletar_tempos.py
│   │   ├── normalizar_achados.py
│   │   ├── ground_truth_juiceshop.py
│   │   └── analise_estatistica.py
│   └── notebooks/
│       └── analise.ipynb
├── dados/
│   ├── brutos/<alvo>/<run_id>/        # semgrep.json, trivy-*.json, zap.json, jobs.json
│   └── processados/                   # tempos.csv, achados.csv, triagem.csv
├── docs/
│   ├── DECISOES.md
│   ├── AMBIENTE.md
│   ├── GROUND-TRUTH.md
│   └── PROTOCOLO-TRIAGEM.md
├── saidas/
│   ├── figuras/                       # PDF/PNG para o Overleaf
│   └── tabelas/                       # .tex para o Overleaf
├── .gitmodules
├── .gitignore
└── README.md
```

### Perfis por alvo

O que muda entre os dois alvos fica isolado em arquivos de perfil, e o workflow vira único, com matriz. Isso evita duplicar YAML.

```bash
# ci/perfis/alvo1-juiceshop.env
ALVO_ID=alvo1
ALVO_NOME=juice-shop
ALVO_CAMINHO=alvos/juice-shop
ALVO_PORTA=3000
ALVO_HEALTH=/
ALVO_IMAGEM=tcc-juiceshop
ALVO_TEM_GROUND_TRUTH=true
```

```bash
# ci/perfis/alvo2-uptimekuma.env
ALVO_ID=alvo2
ALVO_NOME=uptime-kuma
ALVO_CAMINHO=alvos/uptime-kuma
ALVO_PORTA=3001
ALVO_HEALTH=/
ALVO_IMAGEM=tcc-uptimekuma
ALVO_TEM_GROUND_TRUTH=false
```

---

# PARTE IV: AMBIENTE LOCAL

## 1. Sistema operacional

**Se estiver no Windows:** instalar **WSL2 com Ubuntu 24.04** e fazer todo o trabalho de linha de comando dentro dele. Motivo: o runner do GitHub é Ubuntu 24.04. Trabalhar em Windows nativo introduz diferenças de terminação de linha, de permissões de arquivo e de comportamento do Docker que geram divergências entre o que funciona local e o que funciona no CI, e você não tem 8 semanas para depurar isso.

```powershell
# PowerShell como Administrador
wsl --install -d Ubuntu-24.04
wsl --set-default-version 2
# reiniciar, criar usuario e senha do Ubuntu
```

**Se já estiver no Linux:** seguir direto.

**Regra importante:** manter o repositório dentro do sistema de arquivos do Linux (`~/tcc/...`), nunca em `/mnt/c/...`. Docker e Node ficam lentíssimos atravessando a fronteira de sistema de arquivos do WSL.

## 2. Ferramentas a instalar

Todas gratuitas. Nenhuma exige conta paga.

### 2.1 Básico do sistema

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential curl wget git jq unzip ca-certificates gnupg lsb-release
```

### 2.2 Git

```bash
git config --global user.name "Gabriel Brandeli"
git config --global user.email "<seu-email-do-github>"
git config --global init.defaultBranch main
git config --global core.autocrlf input
```

### 2.3 Node.js 22 LTS (via nvm)

Necessário para rodar os alvos localmente durante os testes de fumaça. O Uptime Kuma exige Node >= 20.4; o Juice Shop também roda em 20/22. Usar nvm em vez do apt permite trocar de versão se um alvo exigir.

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/master/install.sh | bash
source ~/.bashrc
nvm install 22
nvm alias default 22
node -v && npm -v
```

### 2.4 Docker

**No WSL2:** instalar o **Docker Desktop no Windows** e habilitar a integração com o WSL (Settings → Resources → WSL Integration → marcar Ubuntu-24.04). É o caminho com menos atrito.

**No Linux nativo:**

```bash
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER    # relogar depois disso
```

### 2.5 Python 3.11+ e ambiente virtual

Usado só para os scripts de análise, não no pipeline.

```bash
sudo apt install -y python3 python3-pip python3-venv
python3 --version
```

### 2.6 GitHub CLI (`gh`)

Essencial: é como você vai baixar os artefatos e os tempos de execução da API.

```bash
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
  | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
  | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update && sudo apt install -y gh
gh auth login          # escolher GitHub.com, HTTPS, autenticar pelo navegador
```

### 2.7 Semgrep

```bash
python3 -m pip install --user semgrep
# ou, se o pip reclamar de ambiente gerenciado:
pipx install semgrep
semgrep --version
```

### 2.8 Trivy

```bash
sudo install -m 0755 -d /etc/apt/keyrings
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
  | gpg --dearmor | sudo tee /etc/apt/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" \
  | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt update && sudo apt install -y trivy
trivy --version
```

### 2.9 OWASP ZAP

**Não instalar nada.** O ZAP roda exclusivamente via container, tanto local quanto no CI. Isso garante que a versão usada é a mesma nos dois ambientes.

```bash
docker pull ghcr.io/zaproxy/zaproxy:stable
```

Anotar o digest, que é o que fixa a versão de verdade:

```bash
docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/zaproxy/zaproxy:stable
```

### 2.10 Opcional: `act` (rodar workflows localmente)

Permite testar o YAML sem consumir uma execução do GitHub. Útil na fase de construção, **inútil para medir tempo** (o hardware é outro). Use só para depurar sintaxe e lógica.

```bash
curl -s https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash -s -- -b /usr/local/bin
act --version
```

## 3. Verificação do ambiente

Rodar tudo de uma vez e conferir que nenhuma linha falha:

```bash
echo "--- versoes ---"
git --version
node -v
npm -v
docker --version
docker compose version
python3 --version
gh --version
semgrep --version
trivy --version
jq --version
echo "--- docker funcional ---"
docker run --rm hello-world
echo "--- gh autenticado ---"
gh auth status
```

| Ferramenta | Versão mínima esperada |
|---|---|
| git | 2.40+ |
| node | 22.x |
| docker | 26+ |
| python3 | 3.11+ |
| gh | 2.4x+ |
| semgrep | 1.x atual |
| trivy | 0.6x/0.7x atual |

Registrar as versões exatas obtidas em `docs/AMBIENTE.md`. Esse arquivo vira quadro na seção 3.1.3 do TCC.

---

# PARTE V: BOOTSTRAP DO REPOSITÓRIO

Sequência completa, de cima para baixo. Executar dentro do WSL/Linux.

## 1. Clonar e criar a estrutura

```bash
mkdir -p ~/tcc && cd ~/tcc
git clone https://github.com/GabrielBrandeli/Pipeline-DevSecOps-ShiftLeft.git
cd Pipeline-DevSecOps-ShiftLeft

mkdir -p .github/workflows
mkdir -p alvos
mkdir -p ci/regras ci/perfis
mkdir -p zap
mkdir -p analise/scripts analise/notebooks
mkdir -p dados/brutos dados/processados
mkdir -p docs
mkdir -p saidas/figuras saidas/tabelas

# manter diretorios vazios no git
find dados saidas -type d -exec touch {}/.gitkeep \;
```

## 2. `.gitignore`

```bash
cat > .gitignore <<'EOF'
# Python
__pycache__/
*.py[cod]
.venv/
.ipynb_checkpoints/

# Node
node_modules/

# Artefatos temporarios locais
*.tar
*.log
tmp/

# NAO ignorar dados: eles sao parte do resultado do TCC
!dados/**
EOF
```

Atenção ao último ponto: os dados brutos e processados **devem ser versionados**. Eles são o resultado do trabalho e a base da reprodutibilidade. A retenção padrão de artefatos do GitHub Actions é de 90 dias; se você não baixar e commitar, perde.

## 3. Adicionar os alvos como submódulos

```bash
# Alvo 1: OWASP Juice Shop
git submodule add https://github.com/juice-shop/juice-shop.git alvos/juice-shop
cd alvos/juice-shop
git tag --sort=-v:refname | head -5        # escolher a ultima tag estavel
git checkout tags/<TAG_ESCOLHIDA>
git rev-parse HEAD                          # ANOTAR este SHA
cd ../..

# Alvo 2: Uptime Kuma
git submodule add https://github.com/louislam/uptime-kuma.git alvos/uptime-kuma
cd alvos/uptime-kuma
git tag --sort=-v:refname | head -5
git checkout tags/<TAG_ESCOLHIDA>
git rev-parse HEAD                          # ANOTAR este SHA
cd ../..

git add .gitmodules alvos
git commit -m "chore: adiciona alvos experimentais como submodulos fixados"
git push
```

**Regra crítica:** escolher **tags de release**, não a `main`. A `main` se move e destrói a reprodutibilidade. Anotar as duas tags e os dois SHAs em `docs/AMBIENTE.md` imediatamente.

Para clonar o repositório completo depois (você ou a banca):

```bash
git clone --recurse-submodules https://github.com/GabrielBrandeli/Pipeline-DevSecOps-ShiftLeft.git
```

## 4. Ambiente Python de análise

```bash
cat > analise/requirements.txt <<'EOF'
pandas>=2.2
scipy>=1.13
matplotlib>=3.9
jupyter>=1.1
pyyaml>=6.0
tabulate>=0.9
EOF

python3 -m venv .venv
source .venv/bin/activate
pip install -r analise/requirements.txt
```

## 5. Configuração do repositório no GitHub

- Settings → Actions → General → **Workflow permissions: Read and write** (necessário para escrever artefatos e o step summary).
- Settings → Actions → General → **Artifact retention: 90 days** (máximo do plano gratuito). Mesmo assim, baixe os dados logo após cada rodada.
- Confirmar que o repositório está **público** (já está). Isso garante minutos ilimitados de Actions.
- Não habilitar Dependabot nem CodeQL. Eles disparariam varreduras paralelas que contaminam o experimento e consomem recursos do runner.

---

# PARTE VI: TESTE DE FUMAÇA (fazer ANTES de escrever qualquer workflow)

Este passo responde aos riscos R3 (alvo 2 sem achados) e R9 (alvo 2 não sobe em container único), que são os únicos capazes de invalidar a escolha do alvo. Fazer **nesta semana**, antes de qualquer outra coisa.

## 1. Os alvos sobem?

```bash
# Juice Shop
docker build -t tcc-juiceshop ./alvos/juice-shop
docker run -d --name js -p 3000:3000 tcc-juiceshop
curl -sf http://localhost:3000 >/dev/null && echo "OK juice-shop"
docker rm -f js

# Uptime Kuma
docker build -t tcc-uptimekuma ./alvos/uptime-kuma
docker run -d --name uk -p 3001:3001 tcc-uptimekuma
curl -sf http://localhost:3001 >/dev/null && echo "OK uptime-kuma"
docker rm -f uk
```

**Cronometrar cada build.** Se o build do Uptime Kuma passar de 15 minutos, isso pressiona o orçamento de tempo das 40 execuções e precisa ser considerado.

## 2. Há achados suficientes no alvo 2?

```bash
# SAST
semgrep scan \
  --config p/owasp-top-ten --config p/javascript \
  --config p/security-audit --config p/secrets \
  --json --output /tmp/sg-uk.json --metrics=off --error=false \
  alvos/uptime-kuma

jq '[.results[]] | length' /tmp/sg-uk.json
jq '[.results[].extra.severity] | group_by(.) | map({sev: .[0], n: length})' /tmp/sg-uk.json

# SCA (dependencias)
trivy fs --scanners vuln,secret --format json -o /tmp/tv-uk.json --exit-code 0 alvos/uptime-kuma
jq '[.Results[]?.Vulnerabilities[]?] | length' /tmp/tv-uk.json
jq '[.Results[]?.Vulnerabilities[]?.Severity] | group_by(.) | map({sev: .[0], n: length})' /tmp/tv-uk.json

# SCA (imagem)
trivy image --format json -o /tmp/tv-uk-img.json --exit-code 0 tcc-uptimekuma
jq '[.Results[]?.Vulnerabilities[]?] | length' /tmp/tv-uk-img.json

# IaC (Dockerfile)
trivy config --format json -o /tmp/tv-uk-cfg.json --exit-code 0 alvos/uptime-kuma
```

## 3. Critério de aceitação do alvo 2

| Verificação | Critério | Se falhar |
|---|---|---|
| Sobe em container único | `curl` responde | Trocar de alvo (Etherpad Lite) |
| Build < 15 min | cronômetro | Aceitável até 20 min, acima disso reavaliar |
| Semgrep | ≥ 20 achados totais | Ampliar rulesets antes de descartar o alvo |
| Trivy fs + image | ≥ 30 achados, com pelo menos alguns HIGH/CRITICAL | Se zero HIGH, o gate nunca dispara e o alvo perde utilidade |
| ZAP alcança a interface | página carrega em `localhost:3001` | Verificar se exige setup inicial (ver abaixo) |

**Ponto de atenção específico do Uptime Kuma:** na primeira execução ele exibe uma tela de configuração inicial (criação do usuário administrador). Verificar se o ZAP consegue rastrear algo útil nesse estado. Se a superfície pública for pobre demais, duas saídas, ambas documentáveis: (a) pré-popular o banco SQLite com um usuário e versionar esse arquivo de fixture; (b) rodar o ZAP autenticado. A opção (a) é mais simples e mais determinística. Decidir isso já em S1 e registrar.

## 4. Registrar os resultados

Anotar os números do teste de fumaça em `docs/AMBIENTE.md`. Eles justificam formalmente a escolha do alvo no Capítulo 3, e é exatamente o tipo de evidência que a banca pergunta ("por que essa aplicação?").

---

# PARTE VII: VS CODE

## 1. Abrir o projeto

**No WSL:** instalar o VS Code no Windows e a extensão **WSL**. Depois:

```bash
cd ~/tcc/Pipeline-DevSecOps-ShiftLeft
code .
```

O VS Code abre conectado ao WSL (canto inferior esquerdo mostra `WSL: Ubuntu-24.04`). Se não mostrar isso, você está editando de fora e vai ter problemas.

## 2. Extensões

| Extensão | ID | Para quê |
|---|---|---|
| WSL | `ms-vscode-remote.remote-wsl` | Obrigatória no Windows |
| GitHub Actions | `github.vscode-github-actions` | Autocompletar e validar o YAML dos workflows, ver execuções na IDE |
| Docker | `ms-azuretools.vscode-docker` | Gerenciar imagens e containers |
| Python | `ms-python.python` | Scripts de análise |
| Jupyter | `ms-toolsai.jupyter` | Notebook de análise |
| YAML | `redhat.vscode-yaml` | Validação de schema |
| GitLens | `eamodio.gitlens` | Navegar histórico e submódulos |
| LaTeX Workshop | `james-yu.latex-workshop` | Opcional, se quiser editar o TCC local em vez do Overleaf |

Instalação em bloco:

```bash
for ext in ms-vscode-remote.remote-wsl github.vscode-github-actions \
  ms-azuretools.vscode-docker ms-python.python ms-toolsai.jupyter \
  redhat.vscode-yaml eamodio.gitlens; do
  code --install-extension $ext
done
```

## 3. `.vscode/settings.json`

```json
{
  "python.defaultInterpreterPath": ".venv/bin/python",
  "files.eol": "\n",
  "files.trimTrailingWhitespace": true,
  "yaml.schemas": {
    "https://json.schemastore.org/github-workflow.json": ".github/workflows/*.yml"
  },
  "git.detectSubmodules": true,
  "search.exclude": {
    "alvos/**": true,
    "dados/brutos/**": true
  }
}
```

O `search.exclude` importa mais do que parece: sem ele, toda busca no projeto vasculha o código inteiro dos dois alvos e fica inutilizável.

## 4. `.vscode/tasks.json` (atalhos úteis)

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Baixar dados da ultima execucao",
      "type": "shell",
      "command": "bash analise/scripts/baixar_run.sh ${input:runId}"
    },
    {
      "label": "Normalizar achados",
      "type": "shell",
      "command": ".venv/bin/python analise/scripts/normalizar_achados.py"
    },
    {
      "label": "Analise estatistica",
      "type": "shell",
      "command": ".venv/bin/python analise/scripts/analise_estatistica.py"
    }
  ],
  "inputs": [
    { "id": "runId", "type": "promptString", "description": "run_id do GitHub Actions" }
  ]
}
```

---

# PARTE VIII: CRONOGRAMA REVISADO (8 semanas, entrega 03/11/2026)

O prazo é 3 semanas menor que o do plano original. A compressão vem de três lugares: escrita em paralelo desde a primeira semana, ground truth restrito a um subconjunto justificado, e triagem por amostragem em vez de censo.

| Sprint | Sexta | Entregável técnico | Entregável escrito |
|---|---|---|---|
| **S1** | 05/09 | Ambiente instalado e verificado. Repo estruturado, submódulos fixados. **Teste de fumaça dos dois alvos concluído.** `equivalencia.yaml` e `DECISOES.md` commitados. | Seções 3.1.1.2 (alvo 2), 3.1.1.3 (métricas por alvo), 3.1.3 (versões) |
| **S2** | 12/09 | `00-baseline.yml` rodando nos dois alvos. Job de SAST funcionando. Coleta de tempos via API validada. | Seções 3.2.3 (gate), 3.2.4 (modos), nota de rodapé D8 |
| **S3** | 19/09 | Build + SCA (3 varreduras do Trivy). `quality_gate.py` completo, nos dois modos e nos dois escopos. | Seção 4.1 (implementação), escrita durante a construção |
| **S4** | 26/09 | Staging + DAST. **Esteira completa fim a fim em modo audit nos dois alvos.** E7 (validação do gate) executado. | Seção 4.2 (validação do gate). Capítulo 3 revisado e fechado |
| **S5** | 03/10 | Ground truth do Juice Shop classificado por detectabilidade (datado, antes das rodadas). **Rodadas E1 a E6 executadas: 40 execuções.** Dados baixados e commitados. | Apêndice do ground truth |
| **S6** | 10/10 | Scripts de parsing. `tempos.csv` e `achados.csv`. Análise de overhead, Mann-Whitney, delta de Cliff. Figuras de tempo geradas. | Seção 4.3 (impacto operacional) |
| **S7** | 17/10 | Triagem manual da amostra concluída. Precisão calculada. Análise de complementaridade. Todas as figuras e tabelas geradas. | Seções 4.4, 4.5, 4.6, 4.7. **Capítulo 4 fechado** |
| **S8** | 24/10 | Retriagem cega da subamostra (concordância intra-avaliador). Congelamento do repositório, tag `v1.0-tcc`. | **Capítulo 5 completo**, com ênfase nas diretrizes (5.3) |
| **S9** | 31/10 | Verificação da checklist de reprodutibilidade. README final do repositório. | Revisão integral, resumo, abstract, apêndices, sumário |
| **Entrega** | **03/11** | Repositório público e citável | Documento final |

## Caminho crítico

**S4 → S5 é o gargalo.** Se a esteira não estiver rodando fim a fim até 26/09, as 40 execuções não cabem no prazo e todo o Capítulo 4 desaba. Tratar S1 a S4 como inegociáveis.

Três alavancas de contingência, em ordem de uso:

1. **Reduzir n de 10 para 7.** Perde-se pouco poder estatístico com Mann-Whitney; declarar no texto.
2. **Restringir o ground truth** aos desafios do Juice Shop das categorias OWASP já cobertas no Quadro 6 e adjacentes, em vez do catálogo completo. Justificar o recorte.
3. **Reduzir a amostra de triagem** e ampliar o intervalo de confiança reportado.

Nenhuma das três compromete a validade se for declarada. O que compromete é chegar em 31/10 sem dados.

## Paralelismo que economiza dias

As 40 execuções não precisam ser sequenciais. O plano gratuito do GitHub permite execuções concorrentes em repositórios públicos, e cada rodada pode ser disparada por `workflow_dispatch` com um identificador diferente. Em S5, dispare em lotes e deixe rodando. O que consome seu tempo é o download e a organização dos dados, não a espera.

Mas atenção a uma armadilha experimental: rodar 20 execuções simultâneas pode gerar contenção de infraestrutura no lado do GitHub e distorcer os tempos. **Rodar em lotes de no máximo 4 concorrentes**, e sempre intercalando baseline e intervenção dentro do mesmo lote, conforme D5.

---

# PARTE IX: PRÓXIMOS PASSOS IMEDIATOS

Ordem exata, sem dependências entre si até o item 5:

1. Instalar WSL2 (se Windows) e todas as ferramentas da Parte IV.
2. Rodar o bloco de verificação de ambiente e registrar as versões em `docs/AMBIENTE.md`.
3. Executar o bootstrap da Parte V (estrutura, submódulos, gitignore, venv).
4. **Executar o teste de fumaça da Parte VI e me enviar os números.** É o que confirma ou derruba a escolha do Uptime Kuma. Nada mais depende disso, mas tudo depois depende.
5. Commitar `ci/regras/equivalencia.yaml` e `docs/DECISOES.md`.
6. Levar para a reunião de sexta: a arquitetura D8 (monorepo com submódulos), a regra de equivalência, o cronograma de 8 semanas com o caminho crítico marcado, e os números do teste de fumaça.

---

# PARTE X: O QUE PRECISO DE VOCÊ PARA AS ALTERAÇÕES NO LATEX

As mudanças no Capítulo 2 e no Capítulo 3 são cirúrgicas e dependem dos rótulos, comandos de glossário e estrutura de seções reais dos seus arquivos. Escrever sem ver o fonte produziria referências cruzadas quebradas e `\gls{}` incorretos.

Envie:

| Arquivo | Para quê |
|---|---|
| `cap-referencial.tex` (ou o nome real do Capítulo 2) | Ajuste da seção 2.4.3 (versão do CVSS) e nota no Quadro 4 |
| `cap-metodologia.tex` | Inserção de 3.1.1.2, 3.1.1.3, 3.1.3, 3.2.3, 3.2.4; revisão de 3.2.1 e 3.2.5 |
| `main.bib` | Adição da referência da especificação CVSS v3.1 e da referência do Uptime Kuma |

Com esses três arquivos eu devolvo os blocos prontos para colar no Overleaf, com os rótulos reais, o `[H]` nos flutuantes, sem `\enquote{}`, sem travessões duplos, e com cada afirmação nova atribuída a autor e ano.
