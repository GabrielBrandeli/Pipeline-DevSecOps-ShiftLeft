#!/usr/bin/env python3
"""Normaliza os relatorios das tres ferramentas em um esquema unico (D6).

Uso:
    python analise/scripts/normalizar_achados.py dados/brutos/experimento \
        --saida dados/processados/achados.csv \
        --contagem dados/processados/achados-contagem.csv

achados.csv          um achado deduplicado por linha, por (execucao, alvo, fonte)
achados-contagem.csv total bruto e deduplicado por (execucao, alvo, fonte), cuja
                     razao mede o ruido de repeticao (Cap. 3)

Regras identicas as do gate, importadas de ci/quality_gate.py: precedencia de
pontuacao CVSS (D2), criterio de bloqueio (D3), chaves de deduplicacao (D6),
prefixo das regras locais do Semgrep (D15) e restricao ao site do alvo no
ZAP (D16).

Categoria OWASP Top 10:2021:
- Semgrep: metadado owasp da propria regra (entrada :2021); na falta, pelo CWE.
- Trivy image: A06 (componente vulneravel, por definicao da categoria).
- Trivy config (Dockerfile): A05.
- Trivy secret e ZAP: pelo CWE, com a tabela oficial do OWASP em
  analise/ground_truth/owasp2021-cwe.csv e, para tres CWEs frequentes no ZAP
  que o OWASP nao lista, o complemento do autor em owasp2021-cwe-complemento.csv.
A coluna owasp_origem registra de onde veio cada categoria (regra, definicao,
oficial, autor). Alertas sem categoria ficam vazios (em geral informativos).
"""
import argparse
import csv
import gzip
import json
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RAIZ / "ci"))
import quality_gate as qg  # noqa: E402

PORTAS = {"alvo1": 3000, "alvo2": 3001}
CAMPOS = ["run_id", "rodada", "config", "alvo", "ferramenta", "fonte", "id_achado", "titulo",
          "local", "severidade_nativa", "confianca", "cvss_v3", "fonte_score", "cwe", "owasp",
          "owasp_origem", "chave_dedup", "ocorrencias", "dispara_gate"]
CAMPOS_CONTAGEM = ["run_id", "rodada", "config", "alvo", "ferramenta", "fonte", "bruto",
                   "deduplicado", "razao_bruto_dedup", "disparadores", "fora_do_alvo"]


def ler(dir_run, nome):
    for caminho in (dir_run / f"{nome}.json.gz", dir_run / f"{nome}.json"):
        if caminho.exists():
            abrir = gzip.open if caminho.suffix == ".gz" else open
            with abrir(caminho, "rt", encoding="utf-8") as f:
                return json.load(f)
    return None


class TabelaCWE(dict):
    """cwe -> categoria; origem[cwe] = 'oficial' ou 'autor'."""


def tabela_cwe():
    tabela = TabelaCWE()
    tabela.origem = {}
    for arquivo, origem in (("owasp2021-cwe-complemento.csv", "autor"), ("owasp2021-cwe.csv", "oficial")):
        with open(RAIZ / "analise/ground_truth" / arquivo, encoding="utf-8") as f:
            for linha in csv.DictReader(f):
                tabela[linha["cwe"]] = linha["categoria_owasp_2021"]
                tabela.origem[linha["cwe"]] = origem
    return tabela


def por_cwe(cwe_owasp, cwe):
    return cwe_owasp.get(cwe, ""), cwe_owasp.origem.get(cwe, "")


def primeiro_cwe(valores):
    for v in valores or []:
        m = re.search(r"CWE-(\d+)", str(v))
        if m:
            return f"CWE-{m.group(1)}"
    return ""


def meta_execucao(dir_run):
    rodada, config = "", ""
    run_json = dir_run / "run.json"
    if run_json.exists():
        run = json.loads(run_json.read_text(encoding="utf-8"))
        partes = run.get("display_title", "").split()
        rodada = partes[1] if len(partes) > 1 else ""
        m = re.search(r"\[(\w+),", run.get("display_title", ""))
        wf = Path(run.get("path", "")).stem or run.get("name", "")
        config = ("baseline" if wf.startswith("00") else
                  f"devsecops-{m.group(1)}" if m else wf)
    return rodada, config


def agrupar(itens, chave):
    """Deduplica mantendo a primeira ocorrencia e contando as repeticoes."""
    vistos, ordem = Counter(), {}
    for it in itens:
        k = chave(it)
        vistos[k] += 1
        ordem.setdefault(k, it)
    return [(k, ordem[k], vistos[k]) for k in ordem], len(itens)


def normalizar_run(dir_run, regras, cwe_owasp):
    limiar = float(regras["limiar_cvss"])
    fallback = regras["sca"]["fallback_rotulo"]
    rodada, config = meta_execucao(dir_run)
    linhas, contagens = [], []
    base_run = {"run_id": dir_run.name, "rodada": rodada, "config": config}

    for alvo, porta in PORTAS.items():
        base = dict(base_run, alvo=alvo)

        def registrar(ferramenta, fonte, grupos, bruto, montar, fora=0):
            disparos = 0
            for chave, item, n in grupos:
                linha = dict(base, ferramenta=ferramenta, fonte=fonte,
                             chave_dedup="|".join(str(c) for c in chave), ocorrencias=n)
                linha.update(montar(item))
                disparos += linha.get("dispara_gate") == "sim"
                linhas.append(linha)
            contagens.append(dict(base, ferramenta=ferramenta, fonte=fonte, bruto=bruto,
                                  deduplicado=len(grupos),
                                  razao_bruto_dedup=round(bruto / len(grupos), 3) if grupos else "",
                                  disparadores=disparos if fonte in ("semgrep", "trivy-image", "zap") else "",
                                  fora_do_alvo=fora))

        semgrep = ler(dir_run, f"semgrep-{alvo}")
        if semgrep is not None:
            itens = semgrep.get("results") or []

            def id_regra(r):
                cid = r.get("check_id") or ""
                return cid[len(qg.PREFIXO_REGRAS_LOCAIS):] if cid.startswith(qg.PREFIXO_REGRAS_LOCAIS) else cid

            grupos, bruto = agrupar(itens, lambda r: (id_regra(r), r.get("path"),
                                                      (r.get("start") or {}).get("line")))

            def montar_semgrep(r):
                extra = r.get("extra") or {}
                meta = extra.get("metadata") or {}
                sev, conf = extra.get("severity"), meta.get("confidence", "MEDIUM")
                owasp = next((re.match(r"(A\d{2}):2021", o).group(1) for o in (meta.get("owasp") or [])
                              if re.match(r"A\d{2}:2021", str(o))), "")
                cwe = primeiro_cwe(meta.get("cwe") if isinstance(meta.get("cwe"), list) else [meta.get("cwe")])
                return {"id_achado": id_regra(r), "titulo": (extra.get("message") or "")[:200],
                        "local": f"{r.get('path')}:{(r.get('start') or {}).get('line')}",
                        "severidade_nativa": sev, "confianca": conf, "cwe": cwe,
                        "owasp": owasp or por_cwe(cwe_owasp, cwe)[0],
                        "owasp_origem": "regra" if owasp else por_cwe(cwe_owasp, cwe)[1],
                        "dispara_gate": "sim" if sev == "ERROR" and conf in ("HIGH", "MEDIUM") else "nao"}
            registrar("semgrep", "semgrep", grupos, bruto, montar_semgrep)

        trivy = ler(dir_run, f"trivy-image-{alvo}")
        if trivy is not None:
            itens = [v for r in trivy.get("Results") or [] for v in r.get("Vulnerabilities") or []]
            grupos, bruto = agrupar(itens, lambda v: (v.get("VulnerabilityID"), v.get("PkgName"),
                                                      v.get("InstalledVersion")))

            def montar_image(v):
                score, fonte = qg.score_cvss(v, fallback)
                return {"id_achado": v.get("VulnerabilityID"), "titulo": (v.get("Title") or "")[:200],
                        "local": f"{v.get('PkgName')}@{v.get('InstalledVersion')}",
                        "severidade_nativa": v.get("Severity"), "cvss_v3": score, "fonte_score": fonte,
                        "cwe": primeiro_cwe(v.get("CweIDs")), "owasp": "A06", "owasp_origem": "definicao",
                        "dispara_gate": "sim" if score >= limiar else "nao"}
            registrar("trivy", "trivy-image", grupos, bruto, montar_image)

        segredos = ler(dir_run, f"trivy-fs-secret-{alvo}")
        if segredos is not None:
            itens = [dict(s, _alvo=r.get("Target")) for r in segredos.get("Results") or []
                     for s in r.get("Secrets") or []]
            grupos, bruto = agrupar(itens, lambda s: (s.get("RuleID"), s.get("_alvo"), s.get("StartLine")))
            registrar("trivy", "trivy-secret", grupos, bruto, lambda s: {
                "id_achado": s.get("RuleID"), "titulo": s.get("Title"),
                "local": f"{s.get('_alvo')}:{s.get('StartLine')}",
                "severidade_nativa": s.get("Severity"), "cwe": "CWE-798",
                "owasp": por_cwe(cwe_owasp, "CWE-798")[0],
                "owasp_origem": por_cwe(cwe_owasp, "CWE-798")[1], "dispara_gate": ""})

        config_iac = ler(dir_run, f"trivy-config-{alvo}")
        if config_iac is not None:
            itens = [dict(m, _alvo=r.get("Target")) for r in config_iac.get("Results") or []
                     for m in r.get("Misconfigurations") or []]
            grupos, bruto = agrupar(itens, lambda m: (m.get("ID"), m.get("_alvo"),
                                                      (m.get("CauseMetadata") or {}).get("StartLine")))
            registrar("trivy", "trivy-config", grupos, bruto, lambda m: {
                "id_achado": m.get("ID"), "titulo": m.get("Title"),
                "local": f"{m.get('_alvo')}:{(m.get('CauseMetadata') or {}).get('StartLine')}",
                "severidade_nativa": m.get("Severity"), "owasp": "A05", "owasp_origem": "definicao",
                "dispara_gate": ""})

        zap = ler(dir_run, f"zap-{alvo}")
        if zap is not None:
            dentro, fora = qg.sites_do_alvo(zap, f"http://localhost:{porta}")
            itens = [dict(i, _alerta=a) for s in dentro for a in s.get("alerts") or []
                     for i in (a.get("instances") or [{}])]
            grupos, bruto = agrupar(itens, lambda i: (i["_alerta"].get("pluginid"),
                                                      (i.get("uri") or "").split("?", 1)[0], i.get("param")))

            def montar_zap(i):
                a = i["_alerta"]
                risco, conf = int(a.get("riskcode", 0)), int(a.get("confidence", 0))
                cwe = f"CWE-{a.get('cweid')}" if str(a.get("cweid", "")).isdigit() and a.get("cweid") != "-1" else ""
                return {"id_achado": a.get("pluginid"), "titulo": a.get("name") or a.get("alert"),
                        "local": (i.get("uri") or "").split("?", 1)[0] + (f" [{i['param']}]" if i.get("param") else ""),
                        "severidade_nativa": risco, "confianca": conf, "cwe": cwe,
                        "owasp": por_cwe(cwe_owasp, cwe)[0], "owasp_origem": por_cwe(cwe_owasp, cwe)[1],
                        "dispara_gate": "sim" if risco == 3 and conf >= 2 else "nao"}
            registrar("zap", "zap", grupos, bruto, montar_zap,
                      fora=sum(len(s.get("alerts") or []) for s in fora))
    return linhas, contagens


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("lotes", nargs="+", type=Path)
    ap.add_argument("--saida", type=Path, default=RAIZ / "dados/processados/achados.csv")
    ap.add_argument("--contagem", type=Path, default=RAIZ / "dados/processados/achados-contagem.csv")
    args = ap.parse_args()
    regras = yaml.safe_load((RAIZ / "ci/regras/equivalencia.yaml").read_text(encoding="utf-8"))
    cwe_owasp = tabela_cwe()

    todas, contagens = [], []
    for lote in args.lotes:
        for dir_run in sorted(p for p in lote.iterdir() if p.is_dir()):
            linhas, cont = normalizar_run(dir_run, regras, cwe_owasp)
            todas += linhas
            contagens += cont

    for caminho, campos, dados in ((args.saida, CAMPOS, todas),
                                   (args.contagem, CAMPOS_CONTAGEM, contagens)):
        caminho.parent.mkdir(parents=True, exist_ok=True)
        with open(caminho, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=campos, lineterminator="\n", extrasaction="ignore")
            w.writeheader()
            w.writerows(dados)
        print(f"{caminho}: {len(dados)} linhas")


if __name__ == "__main__":
    main()
