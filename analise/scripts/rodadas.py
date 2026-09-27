#!/usr/bin/env python3
"""Conduz as rodadas experimentais a partir de um plano (D5).

Uso:
    python analise/scripts/rodadas.py status   analise/rodadas/plano-experimento.yaml
    python analise/scripts/rodadas.py executar analise/rodadas/plano-experimento.yaml

`executar` dispara as execucoes na ordem do plano, sem ultrapassar
`concorrencia_max` execucoes em andamento, acompanha cada uma e arquiva as
concluidas com baixar_run.sh em dados/brutos/<lote>/<run_id>/. Pode ser
interrompido e retomado: o estado vem do proprio GitHub (a rodada e
identificada pelo titulo, definido pelo run-name dos workflows) e dos
diretorios ja arquivados. Uma rodada nunca e disparada duas vezes.

Ao final grava dados/brutos/<lote>/rodadas.csv, com rodada, run_id, commit,
horarios e conclusao. Execucoes com falha inesperada (baseline ou audit) sao
sinalizadas e nao sao repetidas automaticamente: repetir e decisao do
pesquisador, com novo identificador (ex.: AUD-03R) registrado no plano.
"""
import argparse
import csv
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parents[2]
BAIXAR = RAIZ / "analise" / "scripts" / "baixar_run.sh"
FALHA_ESPERADA = {"enforce"}   # o gate bloqueante termina em failure por desenho


def gh(*args, json_saida=False):
    proc = subprocess.run(["gh", *args], capture_output=True, text=True, cwd=RAIZ)
    if proc.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args)}: {proc.stderr.strip()}")
    return json.loads(proc.stdout) if json_saida else proc.stdout


def agora():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg):
    print(f"[{agora()}] {msg}", flush=True)


def execucoes_no_github(workflows):
    """rodada -> execucao mais recente com aquele titulo."""
    por_rodada = {}
    for wf in workflows:
        runs = gh("run", "list", "--workflow", wf, "--limit", "200", "--json",
                  "databaseId,displayTitle,status,conclusion,createdAt,headSha",
                  json_saida=True)
        for r in runs:
            partes = r["displayTitle"].split()
            if len(partes) < 2:
                continue   # execucoes antigas, sem run-name
            rodada = partes[1]
            atual = por_rodada.get(rodada)
            if atual is None or r["createdAt"] > atual["createdAt"]:
                por_rodada[rodada] = dict(r, workflow=wf)
    return por_rodada


def conferir_repositorio():
    """As execucoes rodam o main remoto: o local precisa estar igual a ele."""
    subprocess.run(["git", "fetch", "-q", "origin"], cwd=RAIZ, check=True)
    local = subprocess.run(["git", "rev-parse", "HEAD"], cwd=RAIZ, capture_output=True,
                           text=True).stdout.strip()
    remoto = subprocess.run(["git", "rev-parse", "origin/main"], cwd=RAIZ, capture_output=True,
                            text=True).stdout.strip()
    sujo = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=RAIZ,
                          capture_output=True, text=True).stdout.strip()
    if local != remoto or sujo:
        sys.exit(f"Repositorio local difere de origin/main (local {local[:7]}, remoto {remoto[:7]}, "
                 f"alteracoes: {'sim' if sujo else 'nao'}). Faca commit e push antes das rodadas.")
    return remoto


def disparar(item):
    args = ["workflow", "run", item["workflow"], "--ref", "main", "-f", f"rodada={item['rodada']}"]
    for campo in ("gate_mode", "gate_scope", "zap_ajax"):
        if campo in item:
            valor = item[campo]
            args += ["-f", f"{campo}={str(valor).lower() if isinstance(valor, bool) else valor}"]
    gh(*args)


def estado(plano):
    lote_dir = RAIZ / "dados" / "brutos" / plano["lote"]
    runs = execucoes_no_github({i["workflow"] for i in plano["execucoes"]})
    linhas = []
    for item in plano["execucoes"]:
        r = runs.get(item["rodada"])
        arquivado = bool(r) and (lote_dir / str(r["databaseId"]) / "run.json").exists()
        if r is None:
            situacao = "pendente"
        elif r["status"] != "completed":
            situacao = "em andamento"
        elif arquivado:
            situacao = "arquivada"
        else:
            situacao = "concluida"
        esperado_falha = item.get("gate_mode") in FALHA_ESPERADA
        alerta = bool(r) and r["status"] == "completed" and (
            (r["conclusion"] != "success" and not esperado_falha) or
            (r["conclusion"] == "success" and esperado_falha))
        linhas.append({"item": item, "run": r, "situacao": situacao, "alerta": alerta})
    return lote_dir, linhas


def imprimir(linhas):
    for l in linhas:
        r = l["run"] or {}
        print(f"  {l['item']['rodada']:<14} {l['situacao']:<13} "
              f"{str(r.get('databaseId', '')):<12} {r.get('conclusion') or '':<9} "
              f"{r.get('headSha', '')[:7]:<8} {'REVISAR' if l['alerta'] else ''}")


def gravar_registro(lote_dir, linhas):
    lote_dir.mkdir(parents=True, exist_ok=True)
    with open(lote_dir / "rodadas.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["rodada", "workflow", "gate_mode", "gate_scope", "zap_ajax", "run_id",
                    "head_sha", "criada_em", "situacao", "conclusao", "revisar"])
        for l in linhas:
            i, r = l["item"], l["run"] or {}
            w.writerow([i["rodada"], i["workflow"], i.get("gate_mode", ""), i.get("gate_scope", ""),
                        i.get("zap_ajax", ""), r.get("databaseId", ""), r.get("headSha", ""),
                        r.get("createdAt", ""), l["situacao"], r.get("conclusion", "") or "",
                        "sim" if l["alerta"] else ""])


def executar(plano, intervalo):
    commit = conferir_repositorio()
    log(f"Lote {plano['lote']}, {len(plano['execucoes'])} execucoes, commit {commit[:7]}, "
        f"concorrencia maxima {plano['concorrencia_max']}")
    falhas_seguidas = 0
    while True:
        try:
            if passo(plano):
                break
            falhas_seguidas = 0
        except (RuntimeError, subprocess.CalledProcessError) as erro:
            # Falha transitoria (rede, API do GitHub): as execucoes seguem no
            # GitHub; o acompanhamento tenta de novo no proximo ciclo.
            falhas_seguidas += 1
            log(f"Falha ao consultar o GitHub ({falhas_seguidas}a seguida): {str(erro).splitlines()[0]}")
            if falhas_seguidas >= 30:
                raise
        time.sleep(intervalo)
    lote_dir, linhas = estado(plano)
    shas = {l["run"]["headSha"] for l in linhas}
    log("Todas as execucoes arquivadas.")
    if len(shas) > 1:
        log(f"ATENCAO: execucoes em commits diferentes: {sorted(s[:7] for s in shas)}")
    imprimir(linhas)


def passo(plano):
    """Um ciclo: arquiva o que terminou, dispara o que couber. True se acabou."""
    lote_dir, linhas = estado(plano)
    for l in linhas:
        if l["situacao"] == "concluida":
            log(f"Arquivando {l['item']['rodada']} ({l['run']['databaseId']})")
            subprocess.run([str(BAIXAR), str(l["run"]["databaseId"]), plano["lote"]],
                           cwd=RAIZ, check=True)
            if l["alerta"]:
                log(f"ATENCAO: {l['item']['rodada']} terminou com {l['run']['conclusion']}")
    ativos = sum(1 for l in linhas if l["situacao"] == "em andamento")
    for l in linhas:
        if l["situacao"] != "pendente":
            continue
        if ativos >= plano["concorrencia_max"]:
            break
        disparar(l["item"])
        log(f"Disparada {l['item']['rodada']}")
        ativos += 1
        time.sleep(8)   # o GitHub leva alguns segundos para listar a execucao
    lote_dir, linhas = estado(plano)
    gravar_registro(lote_dir, linhas)
    return all(l["situacao"] == "arquivada" for l in linhas)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("acao", choices=["status", "executar"])
    ap.add_argument("plano", type=Path)
    ap.add_argument("--intervalo", type=int, default=120, help="segundos entre verificacoes")
    args = ap.parse_args()
    plano = yaml.safe_load(args.plano.read_text(encoding="utf-8"))
    rodadas = [i["rodada"] for i in plano["execucoes"]]
    if len(rodadas) != len(set(rodadas)):
        sys.exit("Identificadores de rodada repetidos no plano.")
    if args.acao == "status":
        lote_dir, linhas = estado(plano)
        imprimir(linhas)
        gravar_registro(lote_dir, linhas)
    else:
        executar(plano, args.intervalo)


if __name__ == "__main__":
    main()
