#!/usr/bin/env python3
"""E7: validacao funcional do Quality Gate.

Para cada cenario de cenarios.yaml, gera as entradas no formato de saida real
de Trivy, Semgrep e ZAP, executa ci/quality_gate.py como processo separado
(exatamente como a esteira faz) nos modos audit e enforce, e confere:

- decisao (aprovado/bloqueado) igual nos dois modos (D4);
- codigo de saida: 0 em audit; 1 em enforce somente se bloqueado;
- identificadores dos achados disparadores;
- fonte do score, contagem de fallback e totais deduplicados, quando declarados.

Sai com codigo 1 se qualquer verificacao falhar. Escreve resultado-e7.json e,
no CI, uma tabela no $GITHUB_STEP_SUMMARY.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parents[2]
GATE = RAIZ / "ci" / "quality_gate.py"
REGRAS = RAIZ / "ci" / "regras" / "equivalencia.yaml"


def trivy_json(itens):
    # Cada item em um Result proprio, como alvos distintos dentro da imagem.
    results = []
    for it in itens:
        vuln = {
            "VulnerabilityID": it["id"],
            "PkgName": it["pkg"],
            "InstalledVersion": it["versao"],
            "Severity": it["severity"],
        }
        if it.get("cvss"):
            vuln["CVSS"] = {fonte: {"V3Score": s} for fonte, s in it["cvss"].items()}
        results.append({"Target": f"fixture/{it['pkg']}", "Vulnerabilities": [vuln]})
    return {"SchemaVersion": 2, "Results": results}


def semgrep_json(itens):
    results = []
    for it in itens:
        metadata = {"confidence": it["confidence"]} if "confidence" in it else {}
        results.append({
            "check_id": it["check_id"],
            "path": it["path"],
            "start": {"line": it["line"]},
            "extra": {"severity": it["severity"], "metadata": metadata},
        })
    return {"results": results}


def zap_json(itens):
    alerts = [{
        "pluginid": it["pluginid"],
        "riskcode": str(it["riskcode"]),
        "confidence": str(it["confidence"]),
        "instances": it["instances"],
    } for it in itens]
    return {"site": [{"@name": "http://localhost", "alerts": alerts}]}


def executar(cenario, modo, pasta):
    args = [sys.executable, str(GATE), "--modo", modo, "--escopo", cenario["escopo"],
            "--regras", str(REGRAS), "--saida", str(pasta / f"decisao-{modo}.json")]
    entradas = {"trivy_image": ("--trivy-image", trivy_json),
                "semgrep": ("--semgrep", semgrep_json),
                "zap": ("--zap", zap_json)}
    for chave, (flag, gerar) in entradas.items():
        if chave in cenario:
            arq = pasta / f"{chave}.json"
            arq.write_text(json.dumps(gerar(cenario[chave])), encoding="utf-8")
            args += [flag, str(arq)]
    env = {k: v for k, v in os.environ.items() if k != "GITHUB_STEP_SUMMARY"}
    proc = subprocess.run(args, capture_output=True, text=True, env=env)
    decisao = json.loads((pasta / f"decisao-{modo}.json").read_text(encoding="utf-8"))
    return proc.returncode, decisao


def verificar(cenario):
    esperado = cenario["esperado"]
    falhas, obtido = [], {}
    with tempfile.TemporaryDirectory() as tmp:
        for modo in ("audit", "enforce"):
            rc, d = executar(cenario, modo, Path(tmp))
            obtido[modo] = {"rc": rc, "decisao": d}

    audit, enforce = obtido["audit"], obtido["enforce"]
    d = audit["decisao"]
    rc_enforce_esperado = 1 if esperado["decisao"] == "bloqueado" else 0

    if d["decisao"] != esperado["decisao"]:
        falhas.append(f"decisao {d['decisao']} != {esperado['decisao']}")
    if enforce["decisao"]["decisao"] != d["decisao"]:
        falhas.append("decisao difere entre audit e enforce")
    if audit["rc"] != 0:
        falhas.append(f"audit retornou {audit['rc']}")
    if enforce["rc"] != rc_enforce_esperado:
        falhas.append(f"enforce retornou {enforce['rc']}, esperado {rc_enforce_esperado}")

    ids = sorted(str(a["id"]) for a in d["disparadores"])
    if ids != sorted(str(i) for i in esperado["disparadores"]):
        falhas.append(f"disparadores {ids} != {sorted(esperado['disparadores'])}")

    if "fonte_score" in esperado:
        todos = {a["id"]: a for a in d["disparadores"]}
        # Achados que nao disparam nao aparecem em disparadores: reexecuta a
        # extracao pelo mesmo modulo do gate para inspecionar a fonte usada.
        sys.path.insert(0, str(GATE.parent))
        import quality_gate  # noqa: E402
        regras = yaml.safe_load(REGRAS.read_text(encoding="utf-8"))
        for a in quality_gate.achados_sca(trivy_json(cenario["trivy_image"]),
                                          float(regras["limiar_cvss"]),
                                          regras["sca"]["fallback_rotulo"]):
            todos.setdefault(a["id"], a)
        for vid, fonte in esperado["fonte_score"].items():
            if todos.get(vid, {}).get("fonte_score") != fonte:
                falhas.append(f"{vid}: fonte {todos.get(vid, {}).get('fonte_score')} != {fonte}")
    if "fallback" in esperado and d["sca_fallback_count"] != esperado["fallback"]:
        falhas.append(f"fallback {d['sca_fallback_count']} != {esperado['fallback']}")
    if "total_trivy" in esperado and d["por_ferramenta"]["trivy"]["total"] != esperado["total_trivy"]:
        falhas.append(f"total trivy {d['por_ferramenta']['trivy']['total']} != {esperado['total_trivy']}")
    if "total_zap" in esperado and d["por_ferramenta"]["zap"]["total"] != esperado["total_zap"]:
        falhas.append(f"total zap {d['por_ferramenta']['zap']['total']} != {esperado['total_zap']}")

    return {
        "id": cenario["id"],
        "nome": cenario["nome"],
        "escopo": cenario["escopo"],
        "decisao_esperada": esperado["decisao"],
        "decisao_obtida": d["decisao"],
        "disparadores": ids,
        "rc_audit": audit["rc"],
        "rc_enforce": enforce["rc"],
        "resultado": "ok" if not falhas else "falha",
        "falhas": falhas,
    }


def main():
    cenarios = yaml.safe_load((Path(__file__).parent / "cenarios.yaml").read_text(encoding="utf-8"))
    resultados = [verificar(c) for c in cenarios["cenarios"]]

    linhas = ["# E7: validacao do Quality Gate", "",
              "| Cenario | Nome | Escopo | Esperado | Obtido | rc audit | rc enforce | Resultado |",
              "|---|---|---|---|---|---|---|---|"]
    for r in resultados:
        linhas.append(f"| {r['id']} | {r['nome']} | {r['escopo']} | {r['decisao_esperada']} | "
                      f"{r['decisao_obtida']} | {r['rc_audit']} | {r['rc_enforce']} | {r['resultado']} |")
        for f in r["falhas"]:
            linhas.append(f"|  | falha: {f} | | | | | | |")
    tabela = "\n".join(linhas) + "\n"
    print(tabela)

    Path("resultado-e7.json").write_text(
        json.dumps({"versao_cenarios": cenarios["versao"], "resultados": resultados},
                   indent=2, ensure_ascii=False), encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(tabela)

    sys.exit(0 if all(r["resultado"] == "ok" for r in resultados) else 1)


if __name__ == "__main__":
    main()
