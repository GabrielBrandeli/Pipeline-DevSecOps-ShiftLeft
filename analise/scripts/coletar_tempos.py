#!/usr/bin/env python3
"""Converte os jobs.json arquivados em tabelas de tempo (D5).

Uso:
    python analise/scripts/coletar_tempos.py dados/brutos/experimento \
        --saida dados/processados/tempos.csv \
        --resumo dados/processados/tempos-execucao.csv

Aceita um ou mais diretorios de lote (cada subdiretorio e um run_id arquivado
por baixar_run.sh). Gera:

tempos.csv            uma linha por job e por step (nivel = job | step)
tempos-execucao.csv   uma linha por (execucao, alvo), com as duas metricas do
                      Cap. 3: tempo de parede e minutos faturaveis

Definicoes:
- Tempo de parede de (execucao, alvo): do inicio do primeiro job daquele alvo
  ao fim do ultimo. Exclui a fila antes do primeiro job, que depende da
  plataforma e nao da esteira. Inclui a espera entre jobs encadeados por needs.
- Minutos faturaveis: soma das duracoes dos jobs do alvo. Reportada em segundos
  (soma exata) e em minutos arredondados por job para cima, que e como o
  GitHub contabiliza.

A rodada, o modo, o escopo e o spider AJAX vem do titulo da execucao
(run-name dos workflows). Execucoes antigas, sem run.json, tem esses campos
recuperados dos arquivos de decisao do gate e de integridade do DAST quando
existirem.
"""
import argparse
import csv
import json
import math
import re
from datetime import datetime
from pathlib import Path

CAMPOS = ["run_id", "run_attempt", "workflow", "rodada", "config", "escopo",
          "zap_ajax", "alvo", "nivel", "job", "step", "inicio_utc", "fim_utc",
          "duracao_s", "conclusao", "runner_name", "head_sha"]
CAMPOS_RESUMO = ["run_id", "run_attempt", "workflow", "rodada", "config",
                 "escopo", "zap_ajax", "alvo", "inicio_utc", "fim_utc",
                 "tempo_parede_s", "soma_jobs_s", "minutos_faturaveis",
                 "jobs", "jobs_com_falha", "jobs_pulados", "conclusao_execucao",
                 "head_sha"]

# Titulos definidos pelo run-name dos workflows:
#   00-baseline <rodada>
#   01-devsecops <rodada> [<modo>, <escopo>, ajax=<true|false>]
RE_TITULO = re.compile(
    r"^(?P<wf>\S+)\s+(?P<rodada>\S+)"
    r"(?:\s+\[(?P<modo>\w+),\s*(?P<escopo>\w+),\s*ajax=(?P<ajax>\w+)\])?\s*$")
RE_ALVO = re.compile(r"\((alvo\d)[^)]*\)")


def ts(valor):
    return datetime.fromisoformat(valor.replace("Z", "+00:00")) if valor else None


def duracao(inicio, fim):
    if inicio is None or fim is None:
        return None
    return max(0, int((fim - inicio).total_seconds()))


def metadados(dir_run, jobs):
    meta = {"workflow": "", "rodada": "", "modo": "", "escopo": "", "ajax": "",
            "run_attempt": "", "head_sha": "", "conclusao": ""}
    run_json = dir_run / "run.json"
    if run_json.exists():
        run = json.loads(run_json.read_text(encoding="utf-8"))
        # Com run-name, "name" traz o titulo da execucao; o workflow vem do path.
        meta.update(workflow=Path(run.get("path", "")).stem or run.get("name", ""),
                    run_attempt=run.get("run_attempt", ""),
                    head_sha=run.get("head_sha", ""), conclusao=run.get("conclusion", ""))
        m = RE_TITULO.match(run.get("display_title", ""))
        if m and m.group("wf") == meta["workflow"]:
            meta.update(rodada=m.group("rodada"), modo=m.group("modo") or "",
                        escopo=m.group("escopo") or "", ajax=m.group("ajax") or "")
    elif jobs:
        meta.update(workflow=jobs[0].get("workflow_name", ""),
                    run_attempt=jobs[0].get("run_attempt", ""),
                    head_sha=jobs[0].get("head_sha", ""))
    # Fallback para execucoes antigas (sem run-name) e conferencia cruzada.
    for gate in sorted(dir_run.glob("gate-decision-*.json")):
        d = json.loads(gate.read_text(encoding="utf-8"))
        meta["modo"] = meta["modo"] or d.get("modo", "")
        meta["escopo"] = meta["escopo"] or d.get("escopo", "")
        break
    for integ in sorted(dir_run.glob("dast-integridade-*.json")):
        d = json.loads(integ.read_text(encoding="utf-8"))
        # Execucoes anteriores ao parametro zap_ajax nao registram o campo.
        meta["ajax"] = meta["ajax"] or d.get("zap_ajax", "false")
        break
    return meta


def config(meta):
    wf = meta["workflow"]
    if wf.startswith("00-baseline"):
        return "baseline"
    if wf.startswith("01-devsecops"):
        return f"devsecops-{meta['modo']}" if meta["modo"] else "devsecops"
    if wf.startswith("02-gate-validation"):
        return "gate-validation"
    return wf


def processar(dir_run):
    jobs_json = dir_run / "jobs.json"
    if not jobs_json.exists():
        return [], []
    dados = json.loads(jobs_json.read_text(encoding="utf-8"))
    jobs = dados["jobs"] if isinstance(dados, dict) else dados
    meta = metadados(dir_run, jobs)
    base = {"run_id": dir_run.name, "run_attempt": meta["run_attempt"],
            "workflow": meta["workflow"], "rodada": meta["rodada"],
            "config": config(meta), "escopo": meta["escopo"],
            "zap_ajax": meta["ajax"], "head_sha": meta["head_sha"]}

    linhas, por_alvo = [], {}
    for job in jobs:
        m = RE_ALVO.search(job["name"])
        alvo = m.group(1) if m else ""
        ini, fim = ts(job.get("started_at")), ts(job.get("completed_at"))
        linha_job = dict(base, alvo=alvo, nivel="job", job=job["name"], step="",
                         inicio_utc=job.get("started_at") or "",
                         fim_utc=job.get("completed_at") or "",
                         duracao_s=duracao(ini, fim),
                         conclusao=job.get("conclusion") or "",
                         runner_name=job.get("runner_name") or "")
        linhas.append(linha_job)
        for step in job.get("steps") or []:
            s_ini, s_fim = ts(step.get("started_at")), ts(step.get("completed_at"))
            linhas.append(dict(linha_job, nivel="step", step=step["name"],
                               inicio_utc=step.get("started_at") or "",
                               fim_utc=step.get("completed_at") or "",
                               duracao_s=duracao(s_ini, s_fim),
                               conclusao=step.get("conclusion") or ""))
        por_alvo.setdefault(alvo, []).append((job, ini, fim))

    resumo = []
    for alvo, itens in sorted(por_alvo.items()):
        executados = [(j, i, f) for j, i, f in itens
                      if j.get("conclusion") != "skipped" and i and f]
        if not executados:
            continue
        inicio = min(i for _, i, _ in executados)
        fim = max(f for _, _, f in executados)
        duracoes = [duracao(i, f) for _, i, f in executados]
        resumo.append(dict(
            base, alvo=alvo,
            inicio_utc=inicio.strftime("%Y-%m-%dT%H:%M:%SZ"),
            fim_utc=fim.strftime("%Y-%m-%dT%H:%M:%SZ"),
            tempo_parede_s=duracao(inicio, fim),
            soma_jobs_s=sum(duracoes),
            minutos_faturaveis=sum(math.ceil(d / 60) if d else 0 for d in duracoes),
            jobs=len(itens),
            jobs_com_falha=sum(1 for j, _, _ in itens if j.get("conclusion") == "failure"),
            jobs_pulados=sum(1 for j, _, _ in itens if j.get("conclusion") == "skipped"),
            conclusao_execucao=meta["conclusao"]))
    return linhas, resumo


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("lotes", nargs="+", type=Path,
                    help="diretorios de lote em dados/brutos/")
    ap.add_argument("--saida", type=Path, default=Path("dados/processados/tempos.csv"))
    ap.add_argument("--resumo", type=Path,
                    default=Path("dados/processados/tempos-execucao.csv"))
    args = ap.parse_args()

    todas, resumos = [], []
    for lote in args.lotes:
        for dir_run in sorted(p for p in lote.iterdir() if p.is_dir()):
            linhas, resumo = processar(dir_run)
            todas += linhas
            resumos += resumo

    for caminho, campos, dados in ((args.saida, CAMPOS, todas),
                                   (args.resumo, CAMPOS_RESUMO, resumos)):
        caminho.parent.mkdir(parents=True, exist_ok=True)
        with open(caminho, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=campos, lineterminator="\n")
            w.writeheader()
            w.writerows(dados)
        print(f"{caminho}: {len(dados)} linhas")


if __name__ == "__main__":
    main()
