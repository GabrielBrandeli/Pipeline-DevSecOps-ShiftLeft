# OWASP ZAP (DAST): onde esta a configuracao

Esta pasta nao contem arquivo de regras (`rules.tsv`) nem plano do Automation
Framework (`plan.yaml`). **Isso e intencional**: o ZAP roda com a configuracao
padrao da ferramenta, e todos os parametros do experimento ficam no proprio
workflow. O plano de acao original previa arquivos aqui; a decisao de nao
usa-los esta registrada em `docs/AMBIENTE.md` (secao 6).

## Por que configuracao padrao

As "configuracoes padrao internas de cada ferramenta" sao variavel de controle
do experimento (Cap. 3). Um `rules.tsv` que ignorasse ou rebaixasse regras
seria uma escolha do pesquisador sobre o que o ZAP pode encontrar, e
enviesaria as metricas de deteccao. O mesmo vale para Semgrep e Trivy, que
tambem rodam com as regras e politicas padrao.

## Onde cada parametro esta definido

Tudo em `.github/workflows/01-devsecops.yml`, job `staging-dast`:

| Parametro | Valor | Onde |
|---|---|---|
| Acao | `zaproxy/action-full-scan` v0.13.0, fixada por SHA | passo `OWASP ZAP: full scan` |
| Imagem do ZAP | `ghcr.io/zaproxy/zaproxy@sha256:781a2bda...` | `docker_name` do mesmo passo |
| Tipo de varredura | Full scan (spider + varredura ativa) | acao |
| Spider tradicional e AJAX | `-m 5` (5 min cada) | passo `Montar opcoes do ZAP` |
| Spider AJAX | `-j`, ligado por padrao (D12); input `zap_ajax` | idem |
| Espera do scan passivo | `-T 10` (nao limita a varredura ativa) | idem |
| Teto da varredura ativa | `scanner.maxScanDurationInMins=60` (D12) | idem |
| Regras alfa | incluidas (`-a`) | idem |
| Autenticacao | nenhuma, nos dois alvos (D11 revisado) | ausencia de `ZAP_AUTH_*` |
| Abertura de issues | desabilitada (`allow_issue_writing: false`) | acao |
| Falha da acao | desabilitada (`fail_action: false`); decisao e do `ci/quality_gate.py` | acao |

## Saidas por rodada

| Arquivo | Conteudo |
|---|---|
| `zap-<alvo>.json` | Relatorio JSON do ZAP (`report_json.json` renomeado), entrada do gate e da normalizacao |
| `dast-integridade-<alvo>.json` | Estado do alvo apos o DAST, `zap_ajax` e opcoes usadas; rodada invalida se o alvo caiu |
| `app-log-<alvo>.txt` | Log da aplicacao durante a varredura (desafios resolvidos do Juice Shop aparecem aqui) |

Os tres ficam no artefato `zap-<perfil>-<rodada>` e sao arquivados por
`analise/scripts/baixar_run.sh`. O artefato `zap-relatorios-*` (HTML/MD gerado
pela acao) e redundante com o JSON e nao e arquivado.

## Regras aplicadas sobre a saida

- Deduplicacao (D6): `(pluginid, URI sem query string, param)`.
- Criterio de bloqueio (D3): `riskcode == 3` e `confidence >= 2`
  (`ci/regras/equivalencia.yaml`).
