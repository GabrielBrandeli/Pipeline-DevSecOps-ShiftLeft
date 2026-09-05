<!-- .claude/skills/latex-abnt-tcc/SKILL.md -->
---
name: latex-abnt-tcc
description: Convencoes de LaTeX e ABNT do TCC sobre esteira DevSecOps. Use ao escrever, revisar ou editar qualquer conteudo dos capitulos, ao gerar tabelas, quadros, figuras ou referencias bibliograficas, e ao produzir trechos .tex para colar no Overleaf.
---

# Convencoes de escrita do TCC

O documento vive no Overleaf, em portugues, formatado em ABNT. Os arquivos-fonte
nao estao neste repositorio: os trechos gerados sao para colagem manual.

## Regras inegociaveis

- Toda afirmacao atribuida a autor e ano. Nenhuma afirmacao orfa.
- Nunca inventar referencia. Se a fonte for incerta, omitir a afirmacao.
- Especificador `[H]` em todas as tabelas e figuras, para evitar que o
  flutuante apareca depois do texto que o referencia.
- Aspas padrao do LaTeX (``texto''), nunca `\enquote{}`. O pacote csquotes
  nao esta carregado.
- Sem travessoes duplos (`---`). Usar virgulas ou parenteses.
- Referencias cruzadas apenas com rotulos que existem de fato nos arquivos.
  Nunca inventar rotulo nem usar marcador generico.
- Alteracoes cirurgicas e minimas. Nunca reescrever um capitulo inteiro quando
  o pedido e um ajuste pontual.
- Antes e depois de editar, verificar explicitamente contra o texto de
  referencia fornecido pelo usuario.

## Glossario

O sistema usa `\gls{}`, mas ha chamadas `\glsunset` que consomem os acronimos
antes do Capitulo 2. Consequencia pratica: expansoes por extenso em titulos e
em primeiras ocorrencias no corpo precisam ser escritas manualmente, nao
delegadas ao `\gls{}`.

Inconsistencia conhecida e ainda nao corrigida na raiz: "SSDLC" no glossario
contra "S-SDLC" na Lista de Abreviaturas.

## Precisao terminologica

- CVE e identificador de vulnerabilidade, mantido pela MITRE.
- CVSS e sistema de pontuacao de severidade, mantido pelo FIRST.
  Nunca tratar os dois como sinonimos.
- A versao adotada no trabalho e CVSS v3.1 (ver docs/DECISOES.md, D2).
- O criterio implementado do Quality Gate e binario em 7,0. A classificacao
  conceitual "Alta" (7,0 a 8,9) e "Critica" (9,0 a 10,0) e usada apenas em
  exposicao teorica e nao deve ser confundida com o criterio implementado.
- SSRF (OWASP A10) consta do referencial teorico, mas nao esta entre as
  vulnerabilidades testadas experimentalmente. Preservar essa distincao.

## Figuras geradas com auxilio de IA

Citar como: "Elaborado com auxilio de [ferramenta] (ano), adaptado de [fonte]",
com entrada ABNT correspondente da ferramenta no