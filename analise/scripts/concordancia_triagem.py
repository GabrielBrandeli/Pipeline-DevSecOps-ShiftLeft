#!/usr/bin/env python3
"""Concordancia entre a triagem cega do autor e a classificacao da IA (D17).

Uso:
    python3 analise/scripts/concordancia_triagem.py

Le triagem-cega-gbr.csv (autor, 30 achados) e triagem-ia.csv (IA, 424) e
reporta, para os 27 achados nao expostos (principal) e para os 30
(sensibilidade): concordancia observada, Kappa de Cohen com IC 95% por
bootstrap (10.000 reamostragens, semente 20260927), matriz de confusao e
lista de divergencias. Reporta tambem a concordancia restrita aos achados que
os dois classificaram como VP ou FP, unicos que entram na precisao.
"""
import collections
import csv
import random
from pathlib import Path

PROC = Path(__file__).resolve().parents[2] / "dados" / "processados"
CATS = ["VP", "FP", "NE", "IND"]
SEMENTE = 20260927


def ler(nome):
    with open(PROC / nome, encoding="utf-8") as f:
        return {r["id_triagem"]: r for r in csv.DictReader(f)}


def kappa(pares):
    n = len(pares)
    po = sum(a == b for a, b in pares) / n
    ca, cb = collections.Counter(a for a, _ in pares), collections.Counter(b for _, b in pares)
    pe = sum(ca[c] * cb[c] for c in CATS) / n / n
    return po, (po - pe) / (1 - pe) if pe < 1 else float("nan")


def ic_bootstrap(pares, b=10000):
    rng = random.Random(SEMENTE)
    ks = sorted(k for k in (kappa([rng.choice(pares) for _ in pares])[1] for _ in range(b)) if k == k)
    return ks[int(0.025 * len(ks))], ks[int(0.975 * len(ks))]


def main():
    autor, ia = ler("triagem-cega-gbr.csv"), ler("triagem-ia.csv")
    todos = sorted(autor)
    limpos = [i for i in todos if autor[i]["exposto"] != "sim"]
    for nome, ids in (("27 nao expostos (principal)", limpos), ("30 (sensibilidade)", todos)):
        pares = [(autor[i]["classificacao"], ia[i]["classificacao"]) for i in ids]
        po, k = kappa(pares)
        lo, hi = ic_bootstrap(pares)
        vpfp = [(a, b) for a, b in pares if a in ("VP", "FP") and b in ("VP", "FP")]
        print(f"{nome}: n={len(ids)} concordancia={po:.1%} kappa={k:.3f} IC95%=[{lo:.3f}; {hi:.3f}]"
              f" | ambos VP/FP: {sum(a == b for a, b in vpfp)}/{len(vpfp)} iguais")

    print("\nMatriz, 27 nao expostos (linhas = autor, colunas = IA)")
    m = collections.Counter((autor[i]["classificacao"], ia[i]["classificacao"]) for i in limpos)
    print("     " + "".join(f"{c:>5}" for c in CATS))
    for a in CATS:
        print(f"{a:>4} " + "".join(f"{m[(a, b)]:>5}" for b in CATS))

    print("\nDivergencias")
    for i in todos:
        if autor[i]["classificacao"] != ia[i]["classificacao"]:
            print(f"{i} {ia[i]['fonte']:<12} autor={autor[i]['classificacao']:<3} IA={ia[i]['classificacao']:<3}"
                  f"{' exposto' if autor[i]['exposto'] else ''}  {ia[i]['local'][:60]}")


if __name__ == "__main__":
    main()
