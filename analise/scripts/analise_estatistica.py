#!/usr/bin/env python3
"""Tabelas de resultado do experimento (Cap. 4).

Uso:
    python analise/scripts/analise_estatistica.py

Le os arquivos de dados/processados/ gerados por coletar_tempos.py,
normalizar_achados.py e revocacao_juiceshop.py, e os gate-decision de
dados/brutos/experimento/. Escreve em dados/processados/resultados/:

sobrecarga.csv        mediana e IQR por configuracao, sobrecarga absoluta e
                      relativa, Mann-Whitney U (bilateral) e delta de Cliff
estagios.csv          duracao por job (mediana, minimo, maximo)
achados.csv           volume bruto e deduplicado, disparadores, por fonte
gate.csv              decisoes do gate por modo, escopo e etapa
pontuacao.csv         origem da pontuacao CVSS dos achados de SCA
revocacao.csv         revocacao por ferramenta (por rodada, uniao, falhas)
complementaridade.csv categorias OWASP 2021 alcancadas por cada ferramenta

Descarta as rodadas de aquecimento (sufixo -01), conforme D5.
"""
import csv
import glob
import json
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import mannwhitneyu

RAIZ = Path(__file__).resolve().parents[2]
PROC = RAIZ / "dados" / "processados"
SAIDA = PROC / "resultados"
LOTE = RAIZ / "dados" / "brutos" / "experimento"
AQUECIMENTO = "-01"


def cliff(a, b):
    a, b = np.asarray(a, float), np.asarray(b, float)
    return ((a[:, None] > b).sum() - (a[:, None] < b).sum()) / (len(a) * len(b))


def validas(df):
    return df[~df.rodada.astype(str).str.endswith(AQUECIMENTO)]


def sobrecarga():
    t = validas(pd.read_csv(PROC / "tempos-execucao.csv"))
    linhas = []
    for alvo in sorted(t.alvo.dropna().unique()):
        base = t[(t.alvo == alvo) & (t.config == "baseline")]
        for config in ("devsecops-audit", "devsecops-enforce"):
            trat = t[(t.alvo == alvo) & (t.config == config)]
            for metrica in ("tempo_parede_s", "soma_jobs_s", "minutos_faturaveis"):
                b, x = base[metrica], trat[metrica]
                u = mannwhitneyu(x, b, alternative="two-sided")
                mb, mx = np.median(b), np.median(x)
                linhas.append({
                    "alvo": alvo, "config": config, "metrica": metrica,
                    "n_base": len(b), "n_trat": len(x),
                    "base_mediana": mb, "base_q1": b.quantile(.25), "base_q3": b.quantile(.75),
                    "trat_mediana": mx, "trat_q1": x.quantile(.25), "trat_q3": x.quantile(.75),
                    "trat_min": x.min(), "trat_max": x.max(),
                    "sobrecarga_abs": mx - mb, "sobrecarga_rel_pct": round((mx - mb) / mb * 100, 1),
                    "mann_whitney_u": u.statistic, "p_valor": u.pvalue,
                    "delta_cliff": round(cliff(x, b), 3)})
    return pd.DataFrame(linhas)


def estagios():
    j = validas(pd.read_csv(PROC / "tempos.csv"))
    j = j[(j.nivel == "job") & (j.conclusao != "skipped")]
    j = j.assign(estagio=j.job.str.split(" (", regex=False).str[0])
    return (j.groupby(["alvo", "config", "estagio"]).duracao_s
             .agg(mediana="median", minimo="min", maximo="max", n="size").reset_index())


def achados():
    c = validas(pd.read_csv(PROC / "achados-contagem.csv"))
    c = c[c.config == "devsecops-audit"]
    return (c.groupby(["alvo", "fonte"])
             .agg(bruto_mediana=("bruto", "median"), dedup_mediana=("deduplicado", "median"),
                  dedup_min=("deduplicado", "min"), dedup_max=("deduplicado", "max"),
                  dedup_cv=("deduplicado", lambda s: round(s.std() / s.mean(), 4) if s.mean() else 0),
                  razao_bruto_dedup=("razao_bruto_dedup", "median"),
                  disparadores_mediana=("disparadores", "median"),
                  disparadores_min=("disparadores", "min"), disparadores_max=("disparadores", "max"),
                  fora_do_alvo_mediana=("fora_do_alvo", "median"))
             .reset_index())


def gate():
    rodadas = {r["run_id"]: r["rodada"] for r in csv.DictReader(open(LOTE / "rodadas.csv"))}
    linhas = []
    for f in glob.glob(str(LOTE / "*" / "gate-decision*.json")):
        caminho = Path(f)
        d = json.loads(caminho.read_text(encoding="utf-8"))
        linhas.append({"rodada": rodadas[caminho.parent.name], "modo": d["modo"], "escopo": d["escopo"],
                       "etapa": "pos-DAST" if "final" in caminho.name else "pre-deploy",
                       "alvo": caminho.stem.rsplit("-", 1)[1], "bloqueado": d["decisao"] == "bloqueado",
                       **{f"disp_{k}": v["disparadores"] for k, v in d["por_ferramenta"].items()}})
    g = validas(pd.DataFrame(linhas))
    res = (g.groupby(["modo", "escopo", "etapa", "alvo"])
            .agg(execucoes=("bloqueado", "size"), bloqueadas=("bloqueado", "sum")).reset_index())
    # Nas rodadas audit/all_tools, a decisao de cada escopo e de cada ferramenta
    # isolada e derivavel dos disparadores (mesmo codigo, D4).
    aud = g[(g.modo == "audit") & (g.etapa == "pos-DAST")]
    extra = []
    for alvo, s in aud.groupby("alvo"):
        for ferr in ("trivy", "semgrep", "zap"):
            extra.append({"modo": "audit (derivado)", "escopo": f"so {ferr}", "etapa": "pos-DAST",
                          "alvo": alvo, "execucoes": len(s), "bloqueadas": int((s[f"disp_{ferr}"] > 0).sum())})
    return pd.concat([res, pd.DataFrame(extra)], ignore_index=True)


def pontuacao():
    a = validas(pd.read_csv(PROC / "achados.csv", low_memory=False,
                            usecols=["rodada", "config", "alvo", "fonte", "fonte_score", "dispara_gate"]))
    a = a[(a.config == "devsecops-audit") & (a.fonte == "trivy-image")]
    n_rod = a.rodada.nunique()
    t = (a.groupby(["alvo", "fonte_score"])
          .agg(achados_por_rodada=("rodada", "size"),
               disparadores_por_rodada=("dispara_gate", lambda s: (s == "sim").sum()))
          .reset_index())
    t[["achados_por_rodada", "disparadores_por_rodada"]] /= n_rod
    t["proporcao"] = t.achados_por_rodada / t.groupby("alvo").achados_por_rodada.transform("sum")
    return t.round(4)


def revocacao():
    d = pd.read_csv(PROC / "deteccao-juiceshop.csv")
    linhas = []
    for eixo in ("sast", "sca", "dast"):
        sim = d[(d.eixo == eixo) & (d.classificacao == "Sim")]
        par = d[(d.eixo == eixo) & (d.classificacao == "Parcial")]
        den = sim.id_desafio.nunique()
        por_rodada = sim.groupby("rodada").detectado.sum()
        uniao = sim.groupby("id_desafio").detectado.any()
        falhas = sim.groupby("falha").detectado.any()
        linhas.append({"ferramenta": eixo, "denominador": den,
                       "detectados_mediana": por_rodada.median(), "detectados_min": por_rodada.min(),
                       "detectados_max": por_rodada.max(),
                       "revocacao_mediana": round(por_rodada.median() / den, 3) if den else None,
                       "detectados_uniao": int(uniao.sum()),
                       "falhas_distintas": len(falhas), "falhas_detectadas": int(falhas.sum()),
                       "parciais": par.id_desafio.nunique(),
                       "parciais_sinalizados": int(par.groupby("id_desafio").detectado.any().sum()),
                       "nao_detectados": ";".join(sorted(uniao[~uniao].index))})
    todos = d[d.classificacao == "Sim"].groupby("id_desafio").detectado.any()
    linhas.append({"ferramenta": "qualquer", "denominador": len(todos),
                   "detectados_uniao": int(todos.sum()),
                   "nao_detectados": ";".join(sorted(todos[~todos].index))})
    return pd.DataFrame(linhas)


def complementaridade():
    a = validas(pd.read_csv(PROC / "achados.csv", low_memory=False,
                            usecols=["rodada", "config", "alvo", "fonte", "owasp", "severidade_nativa"]))
    a = a[(a.config == "devsecops-audit") & a.owasp.notna()]
    a = a[~((a.fonte == "zap") & (a.severidade_nativa.astype(str) == "0"))]   # informativos fora
    a = a.assign(ferramenta=a.fonte.map({"semgrep": "SAST", "trivy-image": "SCA", "trivy-secret": "SCA",
                                         "trivy-config": "SCA", "zap": "DAST"}))
    m = (a.groupby(["alvo", "owasp", "ferramenta"]).size().unstack(fill_value=0) > 0).reset_index()
    for f in ("SAST", "SCA", "DAST"):
        if f not in m:
            m[f] = False
    m["exclusiva_de"] = m.apply(lambda r: next((f for f in ("SAST", "SCA", "DAST") if r[f] and
                                                 sum(r[g] for g in ("SAST", "SCA", "DAST")) == 1), ""), axis=1)
    return m


def main():
    SAIDA.mkdir(parents=True, exist_ok=True)
    for nome, funcao in (("sobrecarga", sobrecarga), ("estagios", estagios), ("achados", achados),
                         ("gate", gate), ("pontuacao", pontuacao), ("revocacao", revocacao),
                         ("complementaridade", complementaridade)):
        df = funcao()
        df.to_csv(SAIDA / f"{nome}.csv", index=False)
        print(f"{SAIDA / nome}.csv: {len(df)} linhas")


if __name__ == "__main__":
    main()
