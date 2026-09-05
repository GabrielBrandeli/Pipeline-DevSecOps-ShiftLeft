# Protocolo de Triagem Manual

Procedimento para separar verdadeiros positivos de falsos positivos nos
achados das tres ferramentas, nos dois alvos. Sem protocolo escrito e
anterior a inspecao dos dados, a triagem e opiniao e nao sustenta o calculo
de precisao.

Versao: 1.0
Data de definicao: PREENCHER (deve ser anterior a primeira triagem)
Avaliador: Gabriel Brandeli Ramos

---

## 1. Escopo

| Alvo | Uso da triagem |
|---|---|
| Juice Shop | Classificar falsos positivos e compor a matriz de confusao junto ao ground truth |
| Uptime Kuma | Unica via de calculo de precisao, ja que nao ha ground truth |

---

## 2. Amostragem

Se o volume total de achados deduplicados for menor que 200, triar o conjunto
completo (censo). Acima disso, aplicar amostragem aleatoria estratificada.

**Estratos:** cruzamento de ferramenta (Semgrep, Trivy, ZAP) e severidade
nativa. A estratificacao evita que o volume do SCA, tipicamente muito maior,
domine a amostra e mascare o comportamento das demais ferramentas.

**Alocacao:** proporcional ao tamanho do estrato, com minimo de 10 achados por
estrato nao vazio. Estratos com menos de 10 achados sao triados integralmente.

**Semente aleatoria:** fixada e registrada no `AMBIENTE.md`, secao 9.

```python
random.seed(SEMENTE)   # valor registrado, nunca alterado apos o inicio
```

**Reporte obrigatorio:** tamanho da amostra por estrato, fracao amostral, e
intervalo de confianca de 95% da precisao estimada. Precisao sem intervalo de
confianca, em amostra, e um numero sem significado inferencial.

---

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

**6.1 Revisao por amostragem pelo orientador.** Subamostra de 20 a 30 achados
classificada independentemente pelo orientador. Reportar percentual de
concordancia.

**6.2 Dupla triagem cega no tempo.** Concluida a triagem completa, aguardar no
minimo duas semanas e reclassificar uma subamostra de 30 achados sem consultar
a classificacao anterior. Reportar a concordancia intra-avaliador. Esta e a
verificacao que mede estabilidade do criterio ao longo do tempo, e por isso a
janela de duas semanas precisa caber no cronograma: primeira triagem em S7,
retriagem em S8.

**6.3 Declaracao de limitacao.** Independentemente do resultado das duas
verificacoes acima, o Capitulo 5 declara a triagem como de avaliador unico
entre as ameacas a validade interna.

---

## 7. Ordem de execucao

1. Consolidar `achados.csv` com todos os achados deduplicados
2. Calcular estratos e tamanhos de amostra
3. Sortear com semente fixada e registrar a semente
4. Triar (rodada 1), registrando evidencia por achado
5. Enviar subamostra ao orientador e registrar concordancia
6. Calcular precisao com intervalo de confianca
7. Aguardar duas semanas
8. Retriar subamostra as cegas (rodada 2) e registrar concordancia
9. Commitar `triagem.csv`

---

## 8. Verificacoes finais

- [ ] Protocolo datado antes da primeira triagem
- [ ] Semente aleatoria registrada e nunca alterada
- [ ] Todo achado triado possui evidencia
- [ ] NE e IND reportados separadamente e fora do denominador
- [ ] Intervalo de confianca calculado quando houve amostragem
- [ ] Concordancia com o orientador registrada
- [ ] Concordancia intra-avaliador registrada
- [ ] Limitacao de avaliador unico declarada no Capitulo 5