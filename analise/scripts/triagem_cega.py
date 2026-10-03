#!/usr/bin/env python3
"""Triagem cega do autor sobre a subamostra de concordancia (D17).

Uso:
    python analise/scripts/triagem_cega.py gerar   # cria o arquivo de preenchimento
    python analise/scripts/triagem_cega.py ler     # valida e exporta o CSV

`gerar` copia de triagem-contexto.md os blocos dos 30 achados marcados com
`retriagem = sim` em triagem.csv e acrescenta, a cada um, os campos que o
avaliador preenche. Nada da classificacao assistida por IA entra no arquivo.
Nao sobrescreve um arquivo ja existente.

`ler` le as respostas, aponta campos vazios ou invalidos e grava
triagem-cega-gbr.csv (id_triagem, classificacao, justificativa, evidencia,
avaliador, data, exposto). `exposto = sim` marca os achados cuja classificacao
foi discutida com a IA antes da triagem cega (ver D17); eles ficam fora do
Kappa principal.
"""
import csv
import re
import sys
from datetime import date
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
PROC = RAIZ / "dados" / "processados"
TRIAGEM = PROC / "triagem.csv"
CONTEXTO = PROC / "triagem-contexto.md"
SAIDA_MD = PROC / "triagem-cega-gbr.md"
SAIDA_CSV = PROC / "triagem-cega-gbr.csv"
AVALIADOR = "GBR"
CATEGORIAS = {"VP", "FP", "NE", "IND"}
# Classificacao ou criterio discutido em conversa com a IA em 03/10/2026,
# antes da triagem cega: T0007 e T0051 (exemplos com classificacao) e T0038
# (arquivo em data/static/codefixes/, criterio discutido no exemplo T0002).
EXPOSTOS = {"T0007", "T0038", "T0051"}
CAMPOS = ("Classificacao", "Justificativa", "Evidencia")

INSTRUCOES = """# Triagem cega do autor (subamostra de concordancia, D17)

Gerado por `analise/scripts/triagem_cega.py gerar`. Contem apenas os dados das
ferramentas e do codigo, iguais aos de `triagem-contexto.md`.

Como preencher, para cada achado:

- **Classificacao:** VP, FP, NE ou IND (PROTOCOLO-TRIAGEM, secao 3)
- **Justificativa:** uma frase
- **Evidencia:** caminho e linha do codigo, versao instalada contra a faixa
  afetada, ou requisicao e resposta HTTP

Escreva depois dos dois-pontos, na mesma linha. Limite de 10 minutos por
achado; passou disso, IND e o que ficou em aberto na justificativa.
Nao abra `triagem-ia.csv` nem converse com a IA sobre estes achados ate
terminar. Para conferir o que falta: `python analise/scripts/triagem_cega.py ler`.

"""


def ids_subamostra():
    with open(TRIAGEM, encoding="utf-8") as f:
        return [r["id_triagem"] for r in csv.DictReader(f) if r.get("retriagem") == "sim"]


def blocos(texto):
    """id_triagem -> bloco markdown, a partir de cabecalhos '## Txxxx'."""
    partes = re.split(r"(?m)^(?=## T\d{4} )", texto)
    return {p[3:8]: p.rstrip() for p in partes if p.startswith("## T")}


def gerar():
    if SAIDA_MD.exists():
        sys.exit(f"{SAIDA_MD.name} ja existe; apague-o manualmente para gerar de novo.")
    ctx = blocos(CONTEXTO.read_text(encoding="utf-8"))
    ids = ids_subamostra()
    saida = [INSTRUCOES]
    for i in ids:
        bloco = ctx[i].replace(" · RETRIAGEM", "")
        saida.append(f"{bloco}\n\n" + "\n".join(f"**{c}:** " for c in CAMPOS) + "\n\n---\n")
    SAIDA_MD.write_text("\n".join(saida), encoding="utf-8")
    print(f"{len(ids)} achados em {SAIDA_MD}")


def ler():
    resp = {}
    for i, bloco in blocos(SAIDA_MD.read_text(encoding="utf-8")).items():
        resp[i] = {c: (re.search(rf"(?m)^\*\*{c}:\*\*[ \t]*(.*)$", bloco) or [None, ""])[1].strip()
                   for c in CAMPOS}
    linhas, pendentes = [], []
    for i in ids_subamostra():
        r = resp.get(i, dict.fromkeys(CAMPOS, ""))
        r["Classificacao"] = r["Classificacao"].upper()
        problemas = [c for c in CAMPOS if not r[c]]
        if r["Classificacao"] and r["Classificacao"] not in CATEGORIAS:
            problemas.append(f"classificacao '{r['Classificacao']}' invalida")
        if problemas:
            pendentes.append(f"{i}: {', '.join(problemas)}")
            continue
        linhas.append({"id_triagem": i, "classificacao": r["Classificacao"],
                       "justificativa": r["Justificativa"], "evidencia": r["Evidencia"],
                       "avaliador": AVALIADOR, "data": date.today().isoformat(),
                       "exposto": "sim" if i in EXPOSTOS else ""})

    anteriores = {}
    if SAIDA_CSV.exists():
        with open(SAIDA_CSV, encoding="utf-8") as f:
            anteriores = {r["id_triagem"]: r for r in csv.DictReader(f)}
    for l in linhas:  # preserva a data da primeira resposta
        a = anteriores.get(l["id_triagem"])
        if a and all(a[k] == l[k] for k in ("classificacao", "justificativa", "evidencia")):
            l["data"] = a["data"]

    with open(SAIDA_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(linhas[0]) if linhas else ["id_triagem"],
                           lineterminator="\n")
        w.writeheader()
        w.writerows(linhas)
    print(f"{len(linhas)} de {len(linhas) + len(pendentes)} completos -> {SAIDA_CSV.name}")
    for p in pendentes:
        print(f"  pendente {p}")


if __name__ == "__main__":
    {"gerar": gerar, "ler": ler}.get(sys.argv[1] if len(sys.argv) > 1 else "", lambda: sys.exit(__doc__))()
