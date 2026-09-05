# Ground Truth: OWASP Juice Shop v20.2.0

Este documento define o conjunto de referencia usado para calcular revocacao
e falsos negativos no alvo 1. Ele nao se aplica ao alvo 2 (Uptime Kuma), que
por definicao nao possui ground truth.

**Regra critica de integridade metodologica:** toda a classificacao de
detectabilidade descrita na secao 3 deve ser concluida e datada **antes** da
execucao das varreduras experimentais (E1 a E6). Classificar apos observar os
resultados constitui vies de confirmacao.

Data de conclusao da classificacao: PREENCHER
Responsavel: Gabriel Brandeli Ramos
Revisao por amostragem pelo orientador: PREENCHER

---

## 1. Fonte

O catalogo oficial de desafios do Juice Shop, versionado no proprio
repositorio da aplicacao:

```
alvos/juice-shop/data/static/challenges.yml
```

Cada entrada traz nome, descricao, dificuldade e categoria. E fonte oficial,
versionada e citavel, superior ao recorte de cinco vulnerabilidades do Quadro 6
do TCC 1, que e mantido no Capitulo 3 apenas como recorte ilustrativo. O
catalogo completo entra como apendice.

Extracao:

```bash
python analise/scripts/ground_truth_juiceshop.py \
  --entrada alvos/juice-shop/data/static/challenges.yml \
  --saida dados/processados/ground_truth.csv
```

---

## 2. Por que o denominador precisa ser filtrado

Nem todo desafio do Juice Shop e detectavel por varredura automatizada. Muitos
dependem de logica de negocio, encadeamento de passos ou conhecimento de
contexto, e nenhuma das tres ferramentas empregadas os encontraria por
construcao, e nao por deficiencia.

Calcular revocacao sobre o catalogo completo produziria um numero
artificialmente baixo e metodologicamente incorreto. O denominador correto e:

```
Revocacao_ferramenta = VP_ferramenta / |{desafios detectaveis por aquela ferramenta}|
```

O subconjunto de desafios classificados como nao detectaveis por nenhuma das
tres ferramentas e, por si so, um resultado: quantifica o teto da automacao e
sustenta empiricamente o argumento de que a esteira nao substitui analise
humana, dialogando com Seid et al. (2025).

---

## 3. Esquema da tabela de classificacao

Arquivo: `dados/processados/ground_truth.csv`

| Coluna | Conteudo |
|---|---|
| `id_desafio` | Identificador do `challenges.yml` |
| `nome` | Nome do desafio |
| `categoria_owasp` | A01 a A10 |
| `dificuldade` | 1 a 6, conforme o catalogo |
| `descricao` | Resumo |
| `detectavel_sast` | Sim / Nao / Parcial |
| `detectavel_sca` | Sim / Nao / Parcial |
| `detectavel_dast` | Sim / Nao / Parcial |
| `justificativa_detectabilidade` | Uma frase por decisao |
| `excluido` | Sim / Nao |
| `motivo_exclusao` | Ver secao 4 |
| `data_classificacao` | ISO 8601 |

### Criterios de classificacao de detectabilidade

Definidos antes da inspecao dos dados.

| Valor | Criterio |
|---|---|
| **Sim** | A falha se manifesta em padrao de codigo, em dependencia declarada ou em resposta HTTP observavel, e esta dentro do escopo declarado das regras ou plugins empregados |
| **Parcial** | A ferramenta pode sinalizar um indicio relacionado, mas nao a falha especifica, ou depende de configuracao adicional nao adotada |
| **Nao** | A falha depende de logica de negocio, de encadeamento de acoes, de conhecimento de contexto, ou de dependencia externa indisponivel |

No calculo de revocacao, apenas desafios classificados como **Sim** compoem o
denominador. Os classificados como **Parcial** sao reportados a parte, sem
integrar o denominador principal, e a decisao e declarada no Capitulo 3.

---

## 4. Exclusoes por dependencia externa indisponivel

Registrado em 05/09/2026, a partir dos avisos emitidos pela aplicacao na
inicializacao do container (`docker logs js`).

Estes desafios nao funcionam no ambiente experimental por dependerem de
servicos externos nao providos. A exclusao decorre de indisponibilidade de
dependencia, **nao de falha das ferramentas de seguranca**, e por isso os
desafios sao removidos do denominador de revocacao. Sem esse registro, eles
contariam indevidamente como falsos negativos.

### 4.1 Dependencia de API Web3 (`ALCHEMY_API_KEY` ausente)

Aviso registrado: a variavel de ambiente nao esta presente e os desafios
correspondentes nao funcionam como pretendido.

| Desafio | Situacao |
|---|---|
| Mint the Honey Pot | Excluido |
| Wallet Depletion | Excluido |

### 4.2 Dependencia de API de LLM (`http://localhost:11434/v1` inacessivel)

Aviso registrado: o dominio nao e alcancavel e os desafios correspondentes nao
funcionam como pretendido.

| Desafio | Situacao |
|---|---|
| Chatbot Prompt Injection | Excluido |
| Greedy Chatbot Manipulation | Excluido |
| AI Debugging | Excluido |
| System Prompt Extraction | Excluido |

### 4.3 Total

Seis desafios excluidos por dependencia externa. Registrar no Capitulo 3, na
descricao do cenario de avaliacao, e reportar o denominador final na secao 4.4
do Capitulo 4.

**Decisao de nao provisionar as dependencias.** Prover chave da API Alchemy e
um servico de LLM local introduziria variabilidade de rede e de latencia entre
execucoes, comprometendo a medicao de tempo, alem de custo e de dependencia de
servico de terceiros fora do controle do experimento. A exclusao e a opcao mais
conservadora e esta declarada.

---

## 5. Verificacoes antes de fechar o ground truth

- [ ] `challenges.yml` extraido da tag v20.2.0, e nao de outra versao
- [ ] Total de desafios do catalogo registrado
- [ ] Todos os desafios classificados nos tres eixos de detectabilidade
- [ ] Justificativa preenchida para cada classificacao
- [ ] Seis exclusoes da secao 4 marcadas com motivo
- [ ] Denominador final calculado por ferramenta
- [ ] Data de conclusao anterior a data da primeira execucao experimental
- [ ] Subamostra revisada pelo orientador, com concordancia registrada
- [ ] Arquivo commitado e referenciado no apendice do TCC

---

## 6. Denominadores finais   [preencher ao concluir]

| | Total no catalogo | Excluidos | Detectaveis (Sim) | Parciais |
|---|---|---|---|---|
| SAST (Semgrep) | | 6 | | |
| SCA (Trivy) | | 6 | | |
| DAST (OWASP ZAP) | | 6 | | |
| Nao detectavel por nenhuma ferramenta | | | | |