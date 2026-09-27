#!/usr/bin/env python3
"""Sorteia os achados a triar (docs/PROTOCOLO-TRIAGEM.MD, secao 2).

Uso:
    python analise/scripts/amostrar_triagem.py dados/processados/achados.csv \
        --saida dados/processados/triagem.csv \
        --resumo dados/processados/triagem-amostra.csv

Populacao: achados distintos (chave de deduplicacao D6) observados nas rodadas
validas do modo observatorio, por alvo e fonte. Por padrao exclui a rodada de
aquecimento AUD-01 (D5). Entram semgrep, trivy-image, trivy-secret,
trivy-config e zap. Alertas informativos do ZAP (riskcode 0) ficam fora: nao
afirmam vulnerabilidade, e classifica-los como verdadeiro ou falso positivo nao
tem sentido. Continuam contados no volume de alertas.

Regra de amostragem, por (alvo, fonte):
- ate LIMITE_CENSO achados distintos: censo (todos sao triados);
- acima disso: amostra estratificada por severidade nativa, com TAMANHO_AMOSTRA
  achados alocados proporcionalmente e minimo de MINIMO_ESTRATO por estrato;
  estratos menores que o minimo sao triados integralmente.

A semente e fixa (SEMENTE) e o sorteio e deterministico: mesma entrada, mesma
amostra. Cada linha traz o peso amostral (N_h / n_h), usado no estimador
estratificado da precisao e do seu intervalo de confianca.

Tambem marca a subamostra da retriagem cega (secao 6.2), sorteada agora com a
mesma semente, para que a escolha nao dependa das classificacoes da rodada 1.
"""
import argparse
import csv
import random
from collections import defaultdict
from pathlib import Path

SEMENTE = 20260927
LIMITE_CENSO = 150
TAMANHO_AMOSTRA = 100
MINIMO_ESTRATO = 10
TAMANHO_RETRIAGEM = 30
FONTES = ("semgrep", "trivy-image", "trivy-secret", "trivy-config", "zap")

CAMPOS = ["id_triagem", "alvo", "ferramenta", "fonte", "estrato", "peso_amostral",
          "id_achado", "chave_dedup", "titulo", "local", "severidade_nativa", "confianca",
          "cvss_v3", "owasp", "rodadas_em_que_aparece", "retriagem",
          "classificacao", "justificativa", "evidencia", "avaliador", "data", "rodada_triagem"]


def alocar(tamanhos, total, minimo):
    """Alocacao proporcional com minimo por estrato (maior resto)."""
    fixos = {h: n for h, n in tamanhos.items() if n <= minimo}
    resto = {h: n for h, n in tamanhos.items() if n > minimo}
    livre = max(total - sum(fixos.values()), minimo * len(resto))
    soma = sum(resto.values())
    base = {h: max(minimo, int(livre * n / soma)) for h, n in resto.items()}
    fracoes = sorted(resto, key=lambda h: (livre * resto[h] / soma) - int(livre * resto[h] / soma),
                     reverse=True)
    i = 0
    while sum(base.values()) < livre and fracoes:
        h = fracoes[i % len(fracoes)]
        if base[h] < resto[h]:
            base[h] += 1
        i += 1
    return {**fixos, **{h: min(n, resto[h]) for h, n in base.items()}}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("achados", type=Path)
    ap.add_argument("--config", default="devsecops-audit")
    ap.add_argument("--excluir-rodadas", default="AUD-01",
                    help="rodadas fora da populacao, separadas por virgula (aquecimento, invalidas)")
    ap.add_argument("--saida", type=Path, default=Path("dados/processados/triagem.csv"))
    ap.add_argument("--resumo", type=Path, default=Path("dados/processados/triagem-amostra.csv"))
    args = ap.parse_args()
    excluir = {r.strip() for r in args.excluir_rodadas.split(",") if r.strip()}

    populacao, rodadas = {}, defaultdict(set)
    with open(args.achados, encoding="utf-8") as f:
        for a in csv.DictReader(f):
            if a["config"] != args.config or a["rodada"] in excluir or a["fonte"] not in FONTES:
                continue
            if a["fonte"] == "zap" and a["severidade_nativa"] == "0":
                continue
            chave = (a["alvo"], a["fonte"], a["chave_dedup"])
            populacao.setdefault(chave, a)
            rodadas[chave].add(a["rodada"] or a["run_id"])

    grupos = defaultdict(lambda: defaultdict(list))
    for (alvo, fonte, chave), a in sorted(populacao.items()):
        grupos[(alvo, fonte)][a["severidade_nativa"] or "(vazio)"].append((chave, a))

    rng = random.Random(SEMENTE)
    selecionados, resumo = [], []
    for (alvo, fonte) in sorted(grupos):
        estratos = grupos[(alvo, fonte)]
        tamanhos = {h: len(v) for h, v in estratos.items()}
        total = sum(tamanhos.values())
        censo = total <= LIMITE_CENSO
        n_h = tamanhos if censo else alocar(tamanhos, TAMANHO_AMOSTRA, MINIMO_ESTRATO)
        for h in sorted(estratos):
            itens = estratos[h]
            escolhidos = itens if n_h[h] >= len(itens) else rng.sample(itens, n_h[h])
            peso = round(len(itens) / len(escolhidos), 4)
            resumo.append({"alvo": alvo, "fonte": fonte, "estrato": h, "populacao": len(itens),
                           "amostra": len(escolhidos), "fracao": round(len(escolhidos) / len(itens), 4),
                           "modo": "censo" if censo else "amostra estratificada"})
            for chave, a in sorted(escolhidos):
                selecionados.append((alvo, fonte, h, peso, chave, a))

    ids_retriagem = set(rng.sample(range(len(selecionados)), min(TAMANHO_RETRIAGEM, len(selecionados))))
    args.saida.parent.mkdir(parents=True, exist_ok=True)
    with open(args.saida, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CAMPOS, lineterminator="\n")
        w.writeheader()
        for i, (alvo, fonte, h, peso, chave, a) in enumerate(selecionados):
            w.writerow({"id_triagem": f"T{i + 1:04d}", "alvo": alvo, "ferramenta": a["ferramenta"],
                        "fonte": fonte, "estrato": h, "peso_amostral": peso,
                        "id_achado": a["id_achado"], "chave_dedup": chave, "titulo": a["titulo"],
                        "local": a["local"], "severidade_nativa": a["severidade_nativa"],
                        "confianca": a["confianca"], "cvss_v3": a["cvss_v3"], "owasp": a["owasp"],
                        "rodadas_em_que_aparece": len(rodadas[(alvo, fonte, chave)]),
                        "retriagem": "sim" if i in ids_retriagem else "",
                        "rodada_triagem": 1})
    with open(args.resumo, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["alvo", "fonte", "estrato", "populacao", "amostra",
                                          "fracao", "modo"], lineterminator="\n")
        w.writeheader()
        w.writerows(resumo)

    por_grupo = defaultdict(lambda: [0, 0])
    for r in resumo:
        por_grupo[(r["alvo"], r["fonte"])][0] += r["populacao"]
        por_grupo[(r["alvo"], r["fonte"])][1] += r["amostra"]
    print(f"Semente {SEMENTE}; populacao de {args.config}, sem {sorted(excluir) or 'nenhuma'}")
    for (alvo, fonte), (pop, amo) in sorted(por_grupo.items()):
        print(f"  {alvo} {fonte:<13} populacao {pop:>5}  a triar {amo:>4}")
    print(f"Total a triar: {len(selecionados)} (retriagem cega: {len(ids_retriagem)})")


if __name__ == "__main__":
    main()
