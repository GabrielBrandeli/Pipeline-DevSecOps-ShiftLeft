# Ground Truth: OWASP Juice Shop v20.2.0

Este documento define o conjunto de referencia usado para calcular revocacao
e falsos negativos no alvo 1. Ele nao se aplica ao alvo 2 (Uptime Kuma), que
por definicao nao possui ground truth.

**Regra critica de integridade metodologica:** toda a classificacao de
detectabilidade descrita na secao 3 deve ser concluida e datada **antes** da
execucao das varreduras experimentais (E1 a E6). Classificar apos observar os
resultados constitui vies de confirmacao.

Proposta de classificacao: 27/09/2026, elaborada com auxilio de IA (Claude),
a pedido do pesquisador (ver secao 3.2).
Data de conclusao da classificacao: 27/09/2026 (revisao integral pelo pesquisador)
Responsavel: Gabriel Brandeli Ramos
Revisao por amostragem pelo orientador: nao realizada. O orientador nao tem
familiaridade tecnica com as ferramentas; a classificacao foi revisada
integralmente pelo pesquisador. Declarado como limitacao no Capitulo 5.

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

Extracao e geracao da tabela:

```bash
python analise/scripts/ground_truth_juiceshop.py \
  --classificacao analise/ground_truth/classificacao-juiceshop.yaml \
  --saida dados/processados/ground_truth.csv
```

O script confere que o submodulo esta na tag v20.2.0, aplica as exclusoes da
secao 4, recusa gerar a tabela se algum desafio incluido estiver sem
classificacao e imprime os denominadores da secao 6. A classificacao em si
(julgamento) fica no YAML; o script so faz a parte mecanica.

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
| `local_esperado` | Arquivo e/ou rota onde um achado precisa apontar para contar como deteccao |
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

### 3.1 Regras de decisao por ferramenta

Aplicacao dos criterios acima ao escopo exato de cada ferramenta, como
configurada no experimento. As regras usam apenas informacao a priori.

**SAST (Semgrep, p/owasp-top-ten, p/javascript, p/security-audit, p/secrets,
sem node_modules e dist).**
- Sim: o codigo vulneravel esta no repositorio do alvo e existe regra nos
  quatro pacotes para aquela construcao (ex.: `express-sequelize-injection`,
  `angular-bypasssecuritytrust`, `express-open-redirect`,
  `express-check-directory-listing`, deteccao de chave privada em p/secrets).
- Parcial: ha regra para a classe, mas nao para a API usada, ou a regra aponta
  um indicio relacionado e nao a falha (ex.: SSRF com `fetch`, envio de
  arquivo sem o contorno por byte nulo).
- Nao: falha em conteudo de dados, logica de negocio ou autorizacao, em
  biblioteca de terceiros, ou sem regra nos pacotes (ex.: md5, NoSQL no
  MarsDB, que nao tem regra).

**SCA (estagio do Trivy: `image` vuln, `fs` secret, `config` do Dockerfile).**
- Sim: CVE ou advisory publicado para pacote instalado na imagem, ou segredo
  no repositorio em formato reconhecido pelas regras embutidas (chave privada).
- Parcial: o Trivy detectaria com uma varredura nao adotada (ex.: imagem
  referenciada em docker-compose) ou aponta o componente, mas o desafio pede
  outra coisa.
- Nao: typosquatting, pacote ausente da versao avaliada, segredo sem formato
  reconhecido.

**DAST (ZAP full scan, spider AJAX, sem autenticacao, regras padrao + alfa).**
- Sim: a falha aparece na resposta HTTP a sondagem generica em rota publica
  alcancavel pelo spider, e ha regra padrao para a classe (SQL Injection, XSS
  baseado em DOM, Directory Browsing, External Redirect, Application Error
  Disclosure).
- Parcial: ha regra para a classe, mas a rota exige autenticacao, nao e
  referenciada pela aplicacao, ou a regra depende de configuracao nao adotada
  (servidor de callback para SSRF).
- Nao: logica de negocio, autorizacao, OSINT, criptoanalise, forca bruta.

Varios desafios compartilham a mesma falha (ex.: cinco desafios exploram a
mesma injecao SQL do login). Cada desafio e contado, mas a correspondencia usa
o `local_esperado`: um unico achado no login conta como deteccao dos cinco. A
analise deve reportar tambem o numero de falhas distintas, para nao inflar a
revocacao.

### 3.2 Como a proposta foi elaborada

A pedido do pesquisador, a proposta de classificacao foi elaborada com auxilio
de IA (Claude, 27/09/2026), seguindo as regras da secao 3.1 e usando apenas:
o catalogo `challenges.yml`; o codigo-fonte do alvo, inclusive as marcacoes
`vuln-code-snippet` que o proprio projeto usa para indicar a linha vulneravel
de cada desafio; a lista de regras dos quatro pacotes do Semgrep; as versoes
das dependencias no `package.json`; e o escopo configurado de cada ferramenta.

**Ameaca a validade declarada.** A proposta foi feita depois das execucoes de
validacao de 14 e 23/09, cujos resumos eram conhecidos (por exemplo, que o ZAP
resolveu os desafios Confidential Document, Error Handling e Allowlist
Bypass). Os arquivos de resultado nao foram consultados para decidir nenhum
item, e os tres desafios citados receberam a mesma regra aplicada aos demais.
Mitigacoes: regras escritas antes da classificacao, justificativa e local
esperado por item, revisao integral pelo pesquisador e subamostra revisada
pelo orientador. Execucoes de validacao nao sao rodadas experimentais e seus
dados nao entram nas metricas.

---

## 4. Exclusoes

### 4.0 Desafios desativados em container (18)

Identificado em 27/09/2026. Com `challenges.safetyMode: auto` (padrao em
`config/default.yml`), o Juice Shop desativa, quando detecta que roda em
container, os desafios marcados com `disabledEnv: [Docker]` no catalogo (os
da categoria Danger Zone: XSS persistido, XXE, RCE, NoSQL DoS, SSTi, leitura e
escrita de arquivos, entre outros). O experimento sempre roda em container, e
esses desafios nao existem no ambiente. A exclusao e aplicada automaticamente
pelo script a partir do campo `disabledEnv`.

Alterar o `safetyMode` para habilitar esses desafios mudaria o alvo e exporia o
runner a cargas destrutivas (DoS, RCE); a exclusao e a opcao conservadora.

### 4.1 a 4.2 Dependencia externa indisponivel (6)

Registrado em 05/09/2026, a partir dos avisos emitidos pela aplicacao na
inicializacao do container (`docker logs js`).

Estes desafios nao funcionam no ambiente experimental por dependerem de
servicos externos nao providos. A exclusao decorre de indisponibilidade de
dependencia, **nao de falha das ferramentas de seguranca**, e por isso os
desafios sao removidos do denominador de revocacao. Sem esse registro, eles
contariam indevidamente como falsos negativos.

#### Dependencia de API Web3 (`ALCHEMY_API_KEY` ausente)

Aviso registrado: a variavel de ambiente nao esta presente e os desafios
correspondentes nao funcionam como pretendido.

| Desafio | Situacao |
|---|---|
| Mint the Honey Pot | Excluido |
| Wallet Depletion | Excluido |

#### Dependencia de API de LLM (`http://localhost:11434/v1` inacessivel)

Aviso registrado: o dominio nao e alcancavel e os desafios correspondentes nao
funcionam como pretendido.

| Desafio | Situacao |
|---|---|
| Chatbot Prompt Injection | Excluido |
| Greedy Chatbot Manipulation | Excluido |
| AI Debugging | Excluido |
| System Prompt Extraction | Excluido |

### 4.3 Total

24 desafios excluidos: 18 desativados em container e 6 por dependencia externa. Registrar no Capitulo 3, na
descricao do cenario de avaliacao, e reportar o denominador final na secao 4.4
do Capitulo 4.

**Decisao de nao provisionar as dependencias.** Prover chave da API Alchemy e
um servico de LLM local introduziria variabilidade de rede e de latencia entre
execucoes, comprometendo a medicao de tempo, alem de custo e de dependencia de
servico de terceiros fora do controle do experimento. A exclusao e a opcao mais
conservadora e esta declarada.

---

## 5. Verificacoes antes de fechar o ground truth

- [x] `challenges.yml` extraido da tag v20.2.0 (conferido pelo script)
- [x] Total de desafios do catalogo registrado (116)
- [x] Todos os desafios classificados nos tres eixos de detectabilidade (proposta)
- [x] Justificativa preenchida para cada classificacao (proposta)
- [x] 24 exclusoes da secao 4 marcadas com motivo
- [x] Denominador final calculado por ferramenta (proposta, secao 6)
- [x] Proposta revisada integralmente pelo pesquisador, com `revisado_em` preenchido no YAML (27/09/2026)
- [x] Data de conclusao anterior a data da primeira execucao experimental
- [ ] ~~Subamostra revisada pelo orientador~~: nao realizada, ver cabecalho
- [ ] Controle de alteracoes: mudancas apos a primeira rodada registradas em `alteracoes` no YAML
- [ ] Arquivo commitado e referenciado no apendice do TCC

---

## 6. Denominadores   [revisados em 27/09/2026]

| | Total no catalogo | Excluidos | Classificados | Detectaveis (Sim) | Parciais |
|---|---|---|---|---|---|
| SAST (Semgrep) | 116 | 24 | 92 | 15 | 7 |
| SCA (Trivy) | 116 | 24 | 92 | 4 | 2 |
| DAST (OWASP ZAP) | 116 | 24 | 92 | 13 | 11 |
| Nao detectavel por nenhuma ferramenta | | | | 62 | |

Detectaveis (Sim) por ao menos uma ferramenta: 19 desafios.
---

## 7. Controle de alteracoes

A classificacao foi congelada em 27/09/2026. O pesquisador indicou que ela pode
ser corrigida se algum problema aparecer. Para isso nao se converter em vies de
confirmacao (ajustar o denominador ao que a ferramenta encontrou), toda
alteracao posterior a primeira rodada:

1. e registrada na lista `alteracoes` do YAML, com data, desafio, valores antes
   e depois, motivo e se foi feita antes ou depois de observar resultados;
2. so e aceita se o motivo for um erro de fato na classificacao (ex.: a rota
   exige autenticacao e isso foi ignorado), nunca "a ferramenta encontrou" ou
   "a ferramenta nao encontrou";
3. e reportada no Cap. 4, com a revocacao calculada nas duas versoes.
