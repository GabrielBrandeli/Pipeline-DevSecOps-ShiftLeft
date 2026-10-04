# Regras de decisao da triagem assistida por IA

Complemento da secao 3 do PROTOCOLO-TRIAGEM (versao 1.2, D17). As categorias
continuam as do protocolo; aqui ficam as regras aplicadas a casos recorrentes,
para que achados semelhantes recebam a mesma classificacao. Definidas durante a
classificacao da IA em 03/10/2026, antes da comparacao com a triagem cega do
autor. Saida: `dados/processados/triagem-ia.csv` (coluna `como_verificar` traz o
comando ou passo para conferir cada achado).

Ordem de perguntas usada em todos os achados:

1. A condicao apontada existe? Nao: **FP**.
2. O codigo, pacote ou resposta faz parte da aplicacao em execucao? Codigo que
   nunca executa: **FP**. Fora do artefato entregue: **NE**.
3. Algo no contexto impede a exploracao? Sim: **NE**. Nao: **VP**.

## Verificacao feita

- **SCA:** presenca e versao conferidas na imagem das rodadas (`package.json`
  em `node_modules`, `dpkg` / `status.d`, versao do Go embutida no binario);
  faixa afetada conferida em fonte independente do Trivy: GitHub Advisory
  Database (npm), Go Vulnerability Database (stdlib) e Debian Security Tracker
  (pacotes do sistema).
- **DAST:** cada alerta reproduzido com `curl` contra as mesmas imagens das
  rodadas (`analise/scripts/subir_alvos.sh`).
- **SAST e segredos:** leitura do codigo e, quando possivel, exploracao na
  aplicacao rodando.

## Regras por tipo

| Caso | Classificacao | Motivo |
|---|---|---|
| Pacote presente na versao afetada | VP | Criterio de SCA do protocolo; nao se exige alcancabilidade |
| Pacote afetado com status `unimportant` no Debian, contestado pelo upstream ou sem impacto de seguranca | NE | Condicao existe na versao, mas os mantenedores nao a tratam como vulnerabilidade no contexto |
| Idem, mas a condicao se confirma na imagem (python3-certifi e raizes E-Tugra) | VP | A verificacao na imagem prevalece sobre o rotulo |
| Codigo em `juice-shop/data/static/codefixes/` | FP | Material do desafio de codigo, lido como texto e nunca executado |
| Terraform do Juice Shop (configuracao de rede) | NE | Nao e implantado no artefato avaliado |
| Segredo valido no Terraform ou no codigo | VP | A exposicao ocorre no proprio repositorio (e, no Juice Shop, tambem por `/infrastructure`) |
| Token de exemplo em teste unitario | FP | Nao e credencial |
| Workflows de CI do projeto upstream (`.github/workflows`) | NE se a condicao existe, FP se o valor nao e controlavel por atacante | CI nao integra o artefato entregue |
| Scripts de release com entrada do mantenedor | FP | Nao ha entrada de atacante, logo nao ha injecao |
| Estagio de Dockerfile fora do `--target` do build | NE | Exemplo do proprio protocolo |
| Boa pratica sem impacto de seguranca (HEALTHCHECK, `RUN cd`, `min-release-age`) | NE | Condicao existe, impacto nao |
| Dado do usuario escapado por biblioteca no caminho (badge-maker, jsesc, Angular) | FP | A condicao alegada, dado nao escapado na saida, nao existe |
| Mitigacao parcial ou opt-in do administrador (Handlebars sem aspas, TLS desligavel por opcao) | NE | Condicao existe, contexto impede exploracao direta |
| Resposta 200 que e a pagina inicial da SPA (fallback do Angular) | FP | Backup, bypass de 403 e afins nao existem; o md5 e o da pagina inicial |
| Numero, IP ou funcao que so casa com o padrao (casa decimal de CSS, placeholder, definicao do framework, `eval` de constante) | FP | Padrao sintatico sem o significado alegado |
| `Access-Control-Allow-Origin: *` sem credenciais | NE | Outro site so le o que ja e publico |

## Cabecalhos de seguranca (ZAP)

| Situacao | Classificacao |
|---|---|
| Cabecalho presente | FP |
| `X-Content-Type-Options` ausente, qualquer resposta | VP |
| CSP ou anti-clickjacking ausente em documento HTML | VP |
| CSP ou anti-clickjacking ausente em resposta que nao e HTML | NE |
| COOP, COEP, CORP, Permissions-Policy ausentes, ou Feature-Policy obsoleto | NE (defesa em profundidade, sem ataque direto no contexto) |

**Criterio confirmado pelo autor (04/10/2026).** Na triagem cega o autor havia
classificado como VP casos deste tipo (cabecalhos de isolamento, CORS `*` em
recurso publico, `curl | bash` no CI do upstream), o que explica 7 das 12
divergencias com a IA. Apos a comparacao, o autor adotou NE para esses casos.
A triagem cega permanece como registrada; o Kappa reflete a divergencia de
criterio, e nenhuma divergencia foi entre VP e FP.

## Alerta nao reproduzido

Quando o alerta ocorreu em poucas rodadas e nao se reproduz, mas a condicao e
verificada em outra rota da mesma aplicacao (paginas de erro com stack trace),
a classificacao segue a condicao verificada e a justificativa registra a nao
reproducao (T0160, T0266).

## Regra acrescentada na revisao (04/10/2026)

**Codigo do Juice Shop condicionado a desafio desativado em container.** Os 18
desafios com `disabledEnv: Docker` (`data/static/challenges.yml`) ficam
desligados nas rodadas, e o codigo protegido por
`utils.isChallengeEnabled(...)` segue o caminho seguro. Achado cuja exploracao
depende desse codigo: **NE** (a condicao existe no codigo, mas o contexto de
execucao a desativa). Mesmo criterio da exclusao desses desafios no ground
truth. A IA nao aplicou a regra na classificacao inicial; o autor identificou o
problema ao verificar o T0001 (o username `#{7*7}` aparece literal no perfil),
e os casos afetados foram corrigidos na revisao: T0001 (usernameXssChallenge),
T0031 (videoXss, depende de fileWriteChallenge) e T0171 (feedback sanitizado com
`sanitizeSecure` quando persistedXssFeedbackChallenge esta desligado).
