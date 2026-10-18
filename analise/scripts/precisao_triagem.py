#!/usr/bin/env python3
"""Precisao por alvo e fonte, a partir da classificacao final da triagem (D7, D17).

Uso:
    python analise/scripts/precisao_triagem.py

Le triagem.csv (classificacao final do autor) e revisao-gbr.csv, e escreve
dados/processados/resultados/precisao.csv com uma linha por (alvo, fonte):
contagens de VP, FP, NE e IND, precisao VP / (VP + FP) e intervalo de
confianca de 95%.

- Grupos em censo: a precisao e exata para a populacao; o intervalo de Wilson
  e reportado so como referencia de incerteza para alvos semelhantes.
- Grupo amostrado (trivy-image do alvo 2): estimador de razao estratificado,
  sum(N_h * VP_h / n_h) / sum(N_h * (VP_h + FP_h) / n_h), com intervalo de
  Wilson sobre o tamanho efetivo de Kish, que cobre o caso de FP = 0 (em que
  a variancia linearizada do estimador de razao e zero).

NE e IND ficam fora do denominador (protocolo, secao 3) e sao reportados como
proporcao do total triado. Imprime tambem a taxa de alteracao na revisao.
"""
import csv
import math
from collections import defaultdict
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
PROC = RAIZ / "dados" / "processados"
TRIAGEM = PROC / "triagem.csv"
REVISAO = PROC / "revisao-gbr.csv"
SAIDA = PROC / "resultados" / "precisao.csv"
Z = 1.959964


def wilson(p, n):
    if n == 0:
        return float("nan"), float("nan")
    centro = (p + Z * Z / (2 * n)) / (1 + Z * Z / n)
    meia = Z * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n)) / (1 + Z * Z / n)
    return max(0.0, centro - meia), min(1.0, centro + meia)


def main():
    linhas = list(csv.DictReader(open(TRIAGEM, encoding="utf-8")))
    grupos = defaultdict(list)
    for l in linhas:
        grupos[(l["alvo"], l["fonte"])].append(l)

    saida = []
    for (alvo, fonte), itens in sorted(grupos.items()):
        cont = defaultdict(int)
        for l in itens:
            cont[l["classificacao"]] += 1
        pesos = [float(l["peso_amostral"]) for l in itens]
        amostrado = any(w != 1.0 for w in pesos)
        julgados = [l for l in itens if l["classificacao"] in ("VP", "FP")]
        if amostrado:
            w = [float(l["peso_amostral"]) for l in julgados]
            vp = sum(wi for wi, l in zip(w, julgados) if l["classificacao"] == "VP")
            p = vp / sum(w) if w else float("nan")
            n_ic = sum(w) ** 2 / sum(wi * wi for wi in w) if w else 0
        else:
            p = cont["VP"] / len(julgados) if julgados else float("nan")
            n_ic = len(julgados)
        lo, hi = wilson(p, n_ic)
        total = len(itens)
        saida.append({
            "alvo": alvo, "fonte": fonte,
            "modo": "amostra estratificada" if amostrado else "censo",
            "triados": total, "VP": cont["VP"], "FP": cont["FP"],
            "NE": cont["NE"], "IND": cont["IND"],
            "precisao": round(p, 4), "ic95_inf": round(lo, 4), "ic95_sup": round(hi, 4),
            "n_ic": round(n_ic, 1),
            "prop_NE": round(cont["NE"] / total, 4), "prop_IND": round(cont["IND"] / total, 4),
        })

    SAIDA.parent.mkdir(parents=True, exist_ok=True)
    with open(SAIDA, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(saida[0]))
        w.writeheader()
        w.writerows(saida)
    for s in saida:
        print(f"{s['alvo']:6} {s['fonte']:13} {s['modo']:22} VP={s['VP']:3} FP={s['FP']:3} "
              f"NE={s['NE']:3} IND={s['IND']} precisao={s['precisao']:.3f} "
              f"[{s['ic95_inf']:.3f}; {s['ic95_sup']:.3f}]")

    rev = list(csv.DictReader(open(REVISAO, encoding="utf-8")))
    alteradas = sum(r["alterada"] == "sim" for r in rev)
    print(f"revisao: {alteradas} de {len(rev)} alteradas ({alteradas / len(rev):.1%})")
    print(f"-> {SAIDA.relative_to(RAIZ)}")


if __name__ == "__main__":
    main()
