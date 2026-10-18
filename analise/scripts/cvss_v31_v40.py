#!/usr/bin/env python3
"""Divergencia entre CVSS v3.1 e v4.0 nos achados do Trivy na imagem (D2).

Uso:
    python3 analise/scripts/cvss_v31_v40.py

Le o trivy-image de uma rodada AUD valida (o Trivy deu os mesmos achados nas
nove rodadas) e, para cada achado distinto (VulnerabilityID, PkgName,
InstalledVersion), toma a pontuacao v3.1 e a v4.0 pela mesma ordem de
precedencia do gate (nvd, ghsa, redhat). Escreve
dados/processados/resultados/cvss-v31-v40.csv com, por alvo: achados, achados
com v4.0, achados com as duas versoes, quantos mudam de faixa qualitativa e
quantos cruzam o limiar de 7,0 em cada sentido.
"""
import csv
import gzip
import json
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
RODADA = RAIZ / "dados" / "brutos" / "experimento" / "36475797081"   # AUD-02
SAIDA = RAIZ / "dados" / "processados" / "resultados" / "cvss-v31-v40.csv"
FONTES = ["nvd", "ghsa", "redhat"]
LIMIAR = 7.0


def faixa(s):
    if s == 0:
        return "Nenhuma"
    return "Baixa" if s < 4 else "Media" if s < 7 else "Alta" if s < 9 else "Critica"


def pontuacao(cvss, campo):
    for f in FONTES:
        v = (cvss.get(f) or {}).get(campo)
        if v is not None:
            return float(v)
    return None


def main():
    linhas = []
    for alvo in ("alvo1", "alvo2"):
        rel = json.load(gzip.open(RODADA / f"trivy-image-{alvo}.json.gz"))
        vistos = {}
        for res in rel.get("Results") or []:
            for v in res.get("Vulnerabilities") or []:
                chave = (v["VulnerabilityID"], v["PkgName"], v["InstalledVersion"])
                if chave not in vistos:
                    c = v.get("CVSS") or {}
                    vistos[chave] = (pontuacao(c, "V3Score"), pontuacao(c, "V40Score"))
        com_v4 = [p for p in vistos.values() if p[1] is not None]
        ambos = [p for p in com_v4 if p[0] is not None]
        linhas.append({
            "alvo": alvo,
            "achados": len(vistos),
            "com_v40": len(com_v4),
            "com_as_duas": len(ambos),
            "mudam_de_faixa": sum(faixa(a) != faixa(b) for a, b in ambos),
            "passam_a_bloquear_em_v40": sum(a < LIMIAR <= b for a, b in ambos),
            "deixam_de_bloquear_em_v40": sum(b < LIMIAR <= a for a, b in ambos),
        })
    SAIDA.parent.mkdir(parents=True, exist_ok=True)
    with open(SAIDA, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(linhas[0]))
        w.writeheader()
        w.writerows(linhas)
    for l in linhas:
        print(l)
    print(f"-> {SAIDA.relative_to(RAIZ)}")


if __name__ == "__main__":
    main()
