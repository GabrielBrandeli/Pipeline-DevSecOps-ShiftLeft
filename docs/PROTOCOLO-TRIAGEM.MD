# Protocolo de Triagem Manual

Procedimento para separar verdadeiros positivos de falsos positivos nos
achados das tres ferramentas, nos dois alvos. Sem protocolo escrito e
anterior a inspecao dos dados, a triagem e opiniao e nao sustenta o calculo
de precisao.

Versao: 1.1
Data de definicao: 27/09/2026 (anterior as rodadas experimentais e a qualquer triagem)
Avaliador: Gabriel Brandeli Ramos

---

## 1. Escopo

| Alvo | Uso da triagem |
|---|---|
| Juice Shop | Classificar falsos positivos e compor a matriz de confusao junto ao ground truth |
| Uptime Kuma | Unica via de calculo de precisao, ja que nao ha ground truth |

---

## 2. Amostragem

Implementada em `analise/scripts/amostrar_triagem.py`; os parametros abaixo
estao fixados no script e nao mudam depois das rodadas.

**Populacao.** Achados distintos (chave de deduplicacao D6) observados nas
rodadas validas do modo observatorio (AUD-02 a AUD-10; AUD-01 e aquecimento e
rodadas invalidadas pela verificacao de integridade do DAST ficam fora), por
alvo e fonte: `semgrep`, `trivy-image`, `trivy-secret`, `trivy-config`, `zap`.
Um achado que aparece em varias rodadas e triado uma vez; a coluna
`rodadas_em_que_aparece` registra em quantas apareceu.

**Fora da populacao:** alertas informativos do ZAP (`riskcode` 0). Nao afirmam
vulnerabilidade, e classifica-los como VP ou FP nao tem sentido. Sao contados
no volume de alertas e reportados a parte.

**Regra por (alvo, fonte).** Ate 150 achados distintos: censo. Acima disso:
amostra aleatoria estratificada por severidade nativa, com 100 achados
alocados proporcionalmente e minimo de 10 por estrato; estratos com ate 10
achados sao triados integralmente. Na pratica, so o `trivy-image` do alvo 2
(cerca de 6.100 achados, base Debian completa) deve cair em amostragem.

**Semente aleatoria:** `20260927`, fixada no script e registrada no
`AMBIENTE.md`, secao 9. O sorteio e deterministico: a mesma entrada produz a
mesma amostra.

**Peso amostral.** Cada linha de `triagem.csv` traz `peso_amostral = N_h/n_h`,
usado no estimador estratificado da precisao e no intervalo de confianca de
95%.

**Estimativa de volume** (simulada sobre os dados das execucoes de validacao,
27/09/2026): cerca de 410 achados a triar, sendo ~105 do `trivy-image` do alvo
2 (amostra) e o restante em censo. Achados de SCA sao os mais rapidos
(conferir pacote e versao instalados contra a faixa afetada).

**Reporte obrigatorio:** tamanho da amostra por estrato
(`triagem-amostra.csv`), fracao amostral e intervalo de confianca de 95% da
precisao estimada.

## 3. Categorias de classificacao

Definidas antes de qualquer inspecao dos dados.

| Categoria | Criterio |
|---|---|
| **Verdadeiro positivo (VP)** | A condicao apontada existe no codigo ou na aplicacao e e explotavel, ou a dependencia vulneravel esta de fato presente e na versao afetada |
| **Falso positivo (FP)** | A condicao apontada nao existe, ou o caminho de codigo e inalcancavel, ou a regra casou com padrao sintaticamente semelhante mas semanticamente distinto |
| **Nao exploravel (NE)** | A condicao existe, porem esta mitigada pelo contexto ou reside em componente que nao integra o artefato entregue |
| **Indeterminado (IND)** | Nao foi possivel decidir dentro do esforco definido |

### Tratamento no calculo

```
Precisao = VP / (VP + FP)
```

Achados **NE** e **IND** sao reportados separadamente e **nao integram** o
denominador da precisao. Somar NE aos falsos positivos penalizaria injustamente
a ferramenta, que identificou corretamente a condicao; somar aos verdadeiros
positivos superestimaria a utilidade pratica do achado. A separacao e declarada
no Capitulo 3 e a proporcao de NE e reportada como resultado, por medir a
distancia entre deteccao correta e relevancia operacional.

### Exemplo ja identificado

O achado `SecretsUsedInArgOrEnv` na linha 103 do
`alvos/uptime-kuma/docker/dockerfile` (`ARG GITHUB_TOKEN`) e tecnicamente
correto, mas reside no estagio `upload-artifact`, que nao participa do build da
aplicacao. Classificacao: **NE**.

---

## 4. Esforco maximo por achado

Limite de 10 minutos por achado. Alcancado o limite sem decisao, classificar
como **IND** e registrar o que ficou em aberto. O limite existe para que a
triagem seja conclusivel no prazo e para que a fadiga do avaliador nao se
converta em classificacoes arbitrarias nas ultimas horas de trabalho.

---

## 5. Evidencia obrigatoria

Cada classificacao registra:

| Campo | Conteudo |
|---|---|
| `id_achado` | Chave de deduplicacao conforme D6 |
| `ferramenta` | semgrep / trivy / zap |
| `alvo` | alvo1 / alvo2 |
| `severidade_nativa` | Rotulo original |
| `classificacao` | VP / FP / NE / IND |
| `justificativa` | Uma frase |
| `evidencia` | Trecho de codigo com caminho e linha, ou requisicao e resposta HTTP |
| `avaliador` | Iniciais |
| `data` | ISO 8601 |
| `rodada_triagem` | 1 (primeira) ou 2 (retriagem cega) |

Saida: `dados/processados/triagem.csv`

Sem evidencia registrada a triagem nao e auditavel, e uma banca pode
legitimamente contestar qualquer numero derivado dela.

---

## 6. Confiabilidade da classificacao

O ideal metodologico e dois avaliadores independentes com calculo de Kappa de
Cohen, inviavel em trabalho individual. Adotam-se, em conjunto:

**6.1 Revisao por amostragem pelo orientador: nao adotada (27/09/2026).** O
orientador nao tem familiaridade tecnica com as ferramentas, e uma
concordancia medida nessas condicoes nao teria valor como verificacao. A
confiabilidade fica a cargo da retriagem cega (6.2), e a limitacao de avaliador
unico e declarada (6.3).

**6.2 Dupla triagem cega no tempo.** Concluida a triagem completa, aguardar no
minimo duas semanas e reclassificar uma subamostra de 30 achados sem consultar
a classificacao anterior. A subamostra ja e sorteada junto com a amostra
(coluna `retriagem` de `triagem.csv`), para nao depender das classificacoes da
rodada 1. Reportar a concordancia intra-avaliador. Esta e a
verificacao que mede estabilidade do criterio ao longo do tempo, e por isso a
janela de duas semanas precisa caber no cronograma: com entrega em 03/11/2026,
a primeira triagem precisa terminar ate cerca de 16/10 para a retriagem
ocorrer a partir de 30/10.

**6.3 Declaracao de limitacao.** Independentemente do resultado das duas
verificacoes acima, o Capitulo 5 declara a triagem como de avaliador unico
entre as ameacas a validade interna.

---

## 7. Ordem de execucao

1. `normalizar_achados.py` sobre o lote `experimento` (gera `achados.csv`)
2. `amostrar_triagem.py` (gera `triagem.csv` e `triagem-amostra.csv`)
3. Commitar `triagem.csv` ainda vazio, como registro da amostra sorteada
3a. `contexto_triagem.py`: acrescenta a coluna `link` e gera
    `triagem-contexto.md` com o que cada ferramenta registrou e o trecho de
    codigo, sem sugerir classificacao (29/09/2026)
4. Triar (rodada 1), registrando evidencia por achado
5. Calcular precisao com intervalo de confianca
7. Aguardar duas semanas
8. Retriar subamostra as cegas (rodada 2) e registrar concordancia
9. Commitar `triagem.csv`

---

## 8. Verificacoes finais

- [x] Protocolo datado antes da primeira triagem (27/09/2026)
- [x] Semente aleatoria registrada e nunca alterada (20260927)
- [ ] Todo achado triado possui evidencia
- [ ] NE e IND reportados separadamente e fora do denominador
- [ ] Intervalo de confianca calculado quando houve amostragem
- [ ] ~~Concordancia com o orientador registrada~~: nao adotada (secao 6.1)
- [ ] Concordancia intra-avaliador registrada
- [ ] Limitacao de avaliador unico declarada no Capitulo 5