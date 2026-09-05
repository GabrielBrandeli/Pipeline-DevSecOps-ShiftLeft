# Contexto do projeto

TCC 2 de Ciencia da Computacao, UTFPR Medianeira. Esteira DevSecOps com
avaliacao da abordagem Shift-Left. Orientador: Prof. Dr. Alan Gavioli.
Entrega: 03/11/2026.

Leia sempre antes de trabalhar:
- docs/DECISOES.md      (D1 a D9, decisoes metodologicas fechadas)
- docs/AMBIENTE.md      (versoes fixadas e resultados do teste de fumaca)
- ci/regras/equivalencia.yaml
- ci/perfis/*.env

## Regras do projeto

- Fixar todas as GitHub Actions por SHA completo de commit, nunca por tag.
- Nunca usar ubuntu-latest, @master, @main ou :latest.
- Qualquer etapa nao relacionada a seguranca deve existir de forma identica no
  baseline e na esteira DevSecOps, sob pena de invalidar a medicao de overhead.
- Trivy sempre com --exit-code 0; a decisao de bloqueio e do ci/quality_gate.py.
- Alteracoes cirurgicas e minimas, nunca reescritas completas de arquivo.

## Escrita (LaTeX no Overleaf, ABNT)

- Toda afirmacao atribuida a autor e ano.
- Especificador [H] em tabelas e figuras.
- Aspas padrao do LaTeX, sem \enquote{}.
- Sem travessoes duplos; usar virgulas ou parenteses.