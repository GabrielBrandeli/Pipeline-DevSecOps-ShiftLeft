# Roteiro das rodadas experimentais

Passo a passo para executar o experimento e processar os dados. Decisoes em
`docs/DECISOES.md`; parametros em `docs/AMBIENTE.md`.

## 0. Antes de comecar

- [ ] `git status` limpo e `main` local igual a `origin/main` (o `rodadas.py`
      recusa comecar se nao estiver).
- [ ] Execucao de teste `analise/rodadas/plano-teste.yaml` concluida e conferida
      (secao 5).
- [ ] Ground truth revisado (`analise/ground_truth/classificacao-juiceshop.yaml`,
      `revisado_em` preenchido).
- [ ] Nenhuma alteracao na esteira entre a primeira e a ultima rodada. Qualquer
      mudanca obrigatoria invalida as rodadas anteriores e precisa ser
      registrada em `DECISOES.md`.

## 1. Executar

```bash
source .venv/bin/activate
nohup python analise/scripts/rodadas.py executar analise/rodadas/plano-experimento.yaml \
  > dados/brutos/experimento-rodadas.log 2>&1 &
```

- Dispara as 25 execucoes na ordem do plano (BASE e AUD intercaladas, uma ENF
  a cada dois pares), com no maximo 4 em andamento.
- Cada execucao concluida e arquivada em `dados/brutos/experimento/<run_id>/`
  pelo `baixar_run.sh`.
- Pode ser interrompido (Ctrl+C, queda da maquina) e executado de novo: retoma
  de onde parou, sem disparar a mesma rodada duas vezes.
- Duracao estimada: cerca de 3 h 30 (simulacao do plano com os tempos da
  execucao de teste: AUD ~61 min, dominada pelo DAST do Juice Shop; ENF ~7 min;
  BASE ~3 min; 4 execucoes simultaneas). Com filas do GitHub, prever 4 a 5 h.

Acompanhar: `python analise/scripts/rodadas.py status analise/rodadas/plano-experimento.yaml`.

## 2. Falhas

| Situacao | O que fazer |
|---|---|
| ENF terminou em `failure` | Esperado: o gate bloqueante falha por desenho. |
| ENF terminou em `success` | Revisar: o gate deveria ter bloqueado. |
| BASE ou AUD em `failure` no passo "Verificar que o alvo sobreviveu ao DAST" | Rodada invalida (alvo caiu). Manter o registro, excluir da analise, adicionar ao plano uma repeticao com novo id (ex.: `AUD-04R`) e rodar de novo. |
| BASE ou AUD em `failure` por infraestrutura (download, rede, runner) | Mesmo procedimento: registrar, excluir, repetir com sufixo `R`. |

Toda exclusao e toda repeticao entram na secao 9 do `AMBIENTE.md`, com o
motivo.

Atencao ao acoplamento da matriz: no `01-devsecops.yml`, cada job espera as
duas pernas (alvos) do job anterior. Falha de SAST, build ou SCA em um alvo
interrompe a esteira nos dois, e a rodada inteira e repetida. Falha no DAST
(ultimo job) afeta so o proprio alvo.

## 3. Processar

```bash
python analise/scripts/coletar_tempos.py dados/brutos/experimento
python analise/scripts/normalizar_achados.py dados/brutos/experimento
python analise/scripts/amostrar_triagem.py dados/processados/achados.csv \
  --excluir-rodadas AUD-01            # + rodadas invalidadas, se houver
git add dados/ && git commit          # registra a amostra antes de triar
```

Saidas em `dados/processados/`: `tempos.csv`, `tempos-execucao.csv`,
`achados.csv`, `achados-contagem.csv`, `triagem.csv`, `triagem-amostra.csv`.

## 4. Depois das rodadas

- Preencher o periodo das rodadas no `AMBIENTE.md` (secao 9) e no quadro de
  versoes do Cap. 3.
- Criar a tag de congelamento `v1.0-tcc`.
- Triagem conforme `docs/PROTOCOLO-TRIAGEM.MD`.

## 5. Conferencia da execucao de teste (concluida em 27/09/2026)

Plano `analise/rodadas/plano-teste.yaml`, lote `dados/brutos/teste-pre-rodadas/`.
Conferir:

- E7 com 12 cenarios `ok`.
- Build dos dois alvos com `--build-context` (logs do passo "Build da imagem
  Docker" mostram `[context ...]` com os digests).
- SAST com regras locais: 48 achados no alvo 1 e 17 no alvo 2.
- DAST do Juice Shop terminando antes do teto de 60 min da varredura ativa.
- `gate-decision-final-alvo1.json` com `zap_alertas_fora_do_alvo` preenchido.
- TESTE-ENF-01 com o job de Quality Gate em `failure` e DAST pulado.

**Resultado (27/09/2026, commit e590af7).** Primeira tentativa: E7 12/12,
build do alvo 1 quebrado pelo `@angular/build` 22.2.0 (motivou D14 revisado).
Segunda tentativa, todos os itens conferidos:

| Rodada | Execucao | Resultado |
|---|---|---|
| TESTE-GV-01 | 36337843239 | E7 com 12/12 cenarios ok |
| TESTE-BASE-02 | 36338635355 | Sucesso nos dois alvos (153 s e 113 s) |
| TESTE-AUD-02 | 36338644737 | Esteira completa nos dois alvos; alvos no ar apos o DAST; SAST 48 e 17 com regras locais; ZAP do alvo 1 em 52,7 min (abaixo do teto); 10 alertas externos descartados; gate bloqueado nos dois alvos |
| TESTE-ENF-02 | 36338655400 | Gate em failure nos dois alvos e DAST pulado, como previsto |

Durante o teste o orquestrador caiu por falha de rede (corrigido: tolera
falhas transitorias) e o `coletar_tempos.py` lia o nome do workflow do campo
errado com o run-name (corrigido: usa o `path`).
