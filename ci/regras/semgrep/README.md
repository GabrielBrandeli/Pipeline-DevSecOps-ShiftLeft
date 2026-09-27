# Pacotes de regras do Semgrep fixados (D15)

Copia local dos quatro pacotes do registro usados no SAST. A esteira le estes
arquivos em vez de `--config p/<pacote>`, que baixaria a versao corrente do
registro a cada execucao: o conteudo dos pacotes muda sem aviso, e uma regra
nova ou removida no meio das rodadas alteraria o numero de achados sem
nenhuma mudanca no alvo.

| Arquivo | Origem | Regras | SHA-256 |
|---|---|---|---|
| `owasp-top-ten.yml` | https://semgrep.dev/c/p/owasp-top-ten | 560 | `370bbfbbb8ea4037c0099cd056cf99d3ba27b650cb7d4520f87067616cbb3ac6` |
| `javascript.yml` | https://semgrep.dev/c/p/javascript | 74 | `e65e8449157ef5d587f2c2a0c17ed388910ca90336e514d27941ccd25543cf4e` |
| `security-audit.yml` | https://semgrep.dev/c/p/security-audit | 225 | `b109a039df712f30c6d3e25e1e8358053fd0f1c91b92d0e8d2871cd141fe602f` |
| `secrets.yml` | https://semgrep.dev/c/p/secrets | 52 | `2a68fbe96f88bdabcfe95c22b2d89d30416d7e213326c5050e5b78543f2f79aa` (ver alteracao abaixo; original `139b35ad...cf5c6518`) |

Baixados em 27/09/2026. As regras incluem todas as linguagens; o Semgrep so
aplica as que correspondem aos arquivos varridos.

## Equivalencia com o registro (verificada em 27/09/2026)

Semgrep 1.176.1, mesmo comando do CI, local:

| Alvo | Registro (`p/...`) | Copia local | CI 23/09 (registro) |
|---|---|---|---|
| Juice Shop | 48 | 48 | 48 |
| Uptime Kuma | 17 | 17 | 17 |

Os conjuntos (regra, arquivo, linha, severidade, confianca) sao identicos
entre registro e copia local, depois de removido o prefixo descrito abaixo.

## Unica alteracao em relacao ao registro

Na regra `generic.secrets.security.detected-slack-webhook` do `secrets.yml`, a
exclusao do exemplo de documentacao

    - pattern-not: https://hooks.slack.com/services/T00000000/B00000000/XXXX...X  (24 X)

foi reescrita como

    - pattern-not-regex: https://hooks\.slack\.com/services/T0{8}/B0{8}/X{24}

Motivo: o push protection do GitHub bloqueou o commit por identificar o
exemplo como webhook do Slack (falso positivo: e o placeholder que a propria
regra exclui). A forma em regex exclui exatamente o mesmo texto sem conte-lo
literalmente. Verificado em 27/09/2026: o placeholder continua excluido, um
webhook no formato real continua detectado, e os achados nos dois alvos nao
mudam. SHA-256 do arquivo original do registro:
`139b35ad3442bc83d1f0864db82fa4fdc7e1f1ee4b5ac872bfbeb604c82c6518`.

## Prefixo do check_id

Regras lidas de arquivo local recebem o caminho do diretorio como prefixo:
`ci.regras.semgrep.javascript.express...` em vez de `javascript.express...`.
O `ci/quality_gate.py` (e a normalizacao) remove o prefixo, para que as
chaves de deduplicacao (D6) continuem iguais as do registro e as das
execucoes de validacao. Cenario E7-12.

## Atualizar

Nao atualizar durante as rodadas. Fora delas:
`curl -sSfL https://semgrep.dev/c/p/<pacote> -o ci/regras/semgrep/<pacote>.yml`,
atualizar a tabela e registrar em `docs/DECISOES.md`.
