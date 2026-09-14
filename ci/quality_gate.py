#!/usr/bin/env python3
"""Quality Gate da esteira DevSecOps.

Le os achados de Trivy (SCA/IaC/secrets) e, no escopo ampliado, de Semgrep
(SAST) e OWASP ZAP (DAST), aplica o criterio de bloqueio de ci/regras/
equivalencia.yaml e emite a decisao em gate-decision.json e no
$GITHUB_STEP_SUMMARY.

Os dois modos (audit/enforce) usam exatamente a mesma logica de decisao
(D4); a unica diferenca e o codigo de saida no final deste script.
"""
import argparse
import json
import os
import sys
from pathlib import Path

import yaml

FONTES_SCORE = ["nvd", "ghsa", "redhat"]


def carregar_json(caminho):
    if not caminho or not Path(caminho).exists():
        return None
    with open(caminho, encoding="utf-8") as f:
        return json.load(f)


def score_cvss(vuln, fallback_rotulo):
    cvss = vuln.get("CVSS") or {}
    for fonte in FONTES_SCORE:
        v = (cvss.get(fonte) or {}).get("V3Score")
        if v is not None:
            return float(v), fonte
    return fallback_rotulo.get(vuln.get("Severity", "UNKNOWN"), 0.0), "fallback_rotulo"


def achados_sca(trivy_image, limiar, fallback_rotulo):
    """SCA (D9: trivy image e a unica fonte). Dedup por D6: (VulnerabilityID, PkgName, InstalledVersion)."""
    todos, vistos = [], set()
    if trivy_image is None:
        return todos
    for resultado in trivy_image.get("Results") or []:
        for vuln in resultado.get("Vulnerabilities") or []:
            chave = (vuln.get("VulnerabilityID"), vuln.get("PkgName"), vuln.get("InstalledVersion"))
            if chave in vistos:
                continue
            vistos.add(chave)
            score, fonte = score_cvss(vuln, fallback_rotulo)
            todos.append({
                "ferramenta": "trivy",
                "id": vuln.get("VulnerabilityID"),
                "local": f"{vuln.get('PkgName')}@{vuln.get('InstalledVersion')}",
                "severidade_nativa": vuln.get("Severity"),
                "score_cvss_v31": score,
                "fonte_score": fonte,
                "dispara_gate": score >= limiar,
            })
    return todos


def achados_sast(semgrep):
    """SAST (D3): severity == ERROR e confidence em {HIGH, MEDIUM}; ausente = MEDIUM.
    Dedup por D6: (check_id, path, start.line)."""
    todos, vistos = [], set()
    if semgrep is None:
        return todos
    for r in semgrep.get("results") or []:
        linha = (r.get("start") or {}).get("line")
        chave = (r.get("check_id"), r.get("path"), linha)
        if chave in vistos:
            continue
        vistos.add(chave)
        extra = r.get("extra") or {}
        severidade = extra.get("severity")
        confidence = (extra.get("metadata") or {}).get("confidence", "MEDIUM")
        todos.append({
            "ferramenta": "semgrep",
            "id": r.get("check_id"),
            "local": f"{r.get('path')}:{linha}",
            "severidade_nativa": severidade,
            "confidence": confidence,
            "dispara_gate": severidade == "ERROR" and confidence in ("HIGH", "MEDIUM"),
        })
    return todos


def achados_dast(zap):
    """DAST (D3): riskcode == 3 (High) e confidence >= 2 (Media ou superior).
    Dedup por D6: (pluginid, uri normalizada, param)."""
    todos, vistos = [], set()
    if zap is None:
        return todos
    for site in zap.get("site") or []:
        for alerta in site.get("alerts") or []:
            riskcode = int(alerta.get("riskcode", 0))
            confidence = int(alerta.get("confidence", 0))
            for instancia in alerta.get("instances") or [{}]:
                uri = (instancia.get("uri") or "").split("?", 1)[0]
                chave = (alerta.get("pluginid"), uri, instancia.get("param"))
                if chave in vistos:
                    continue
                vistos.add(chave)
                todos.append({
                    "ferramenta": "zap",
                    "id": alerta.get("pluginid"),
                    "local": uri,
                    "riskcode": riskcode,
                    "confidence": confidence,
                    "dispara_gate": riskcode == 3 and confidence >= 2,
                })
    return todos


def contar_por_severidade(achados, campo="severidade_nativa"):
    contagem = {}
    for a in achados:
        chave = a.get(campo)
        contagem[chave] = contagem.get(chave, 0) + 1
    return contagem


def escrever_resumo(caminho_summary, decisao):
    linhas = [
        f"# Quality Gate: {decisao['decisao'].upper()}",
        "",
        f"- Modo: `{decisao['modo']}`",
        f"- Escopo: `{decisao['escopo']}`",
        f"- Limiar CVSS: `{decisao['limiar_cvss']}`",
        f"- Achados que dispararam o gate: **{decisao['quantidade_disparadores']}**",
        f"- Achados de SCA sem score em nenhuma fonte (fallback por rotulo): {decisao['sca_fallback_count']}",
        "",
        "## Achados por ferramenta (deduplicado)",
        "",
        "| Ferramenta | Total | Disparadores |",
        "|---|---|---|",
    ]
    for ferramenta, stats in decisao["por_ferramenta"].items():
        linhas.append(f"| {ferramenta} | {stats['total']} | {stats['disparadores']} |")
    if decisao["avisos"]:
        linhas.append("")
        linhas.append("## Avisos")
        for aviso in decisao["avisos"]:
            linhas.append(f"- {aviso}")
    with open(caminho_summary, "a", encoding="utf-8") as f:
        f.write("\n".join(linhas) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--modo", choices=["audit", "enforce"], required=True)
    ap.add_argument("--escopo", choices=["sca_only", "all_tools"], required=True)
    ap.add_argument("--regras", default="ci/regras/equivalencia.yaml")
    ap.add_argument("--trivy-image")
    ap.add_argument("--trivy-config")
    ap.add_argument("--trivy-fs-secret")
    ap.add_argument("--semgrep")
    ap.add_argument("--zap")
    ap.add_argument("--saida", default="gate-decision.json")
    args = ap.parse_args()

    with open(args.regras, encoding="utf-8") as f:
        regras = yaml.safe_load(f)
    limiar = float(regras["limiar_cvss"])
    fallback_rotulo = regras["sca"]["fallback_rotulo"]

    trivy_image = carregar_json(args.trivy_image)
    trivy_config = carregar_json(args.trivy_config)
    trivy_secret = carregar_json(args.trivy_fs_secret)

    achados_por_ferramenta = {"trivy": achados_sca(trivy_image, limiar, fallback_rotulo)}
    avisos = []
    if trivy_image is None:
        avisos.append("sca: trivy-image.json nao encontrado")

    if args.escopo == "all_tools":
        semgrep = carregar_json(args.semgrep)
        zap = carregar_json(args.zap)
        achados_por_ferramenta["semgrep"] = achados_sast(semgrep)
        achados_por_ferramenta["zap"] = achados_dast(zap)
        if semgrep is None:
            avisos.append("sast: semgrep.json nao encontrado, estagio nao considerado nesta execucao")
        if zap is None:
            avisos.append("dast: zap.json nao encontrado, estagio ainda nao implementado nesta sprint (S4)")

    disparadores = [
        a for achados in achados_por_ferramenta.values() for a in achados if a["dispara_gate"]
    ]
    bloqueia = len(disparadores) > 0

    sca_todos = achados_por_ferramenta["trivy"]
    sca_fallback_count = sum(1 for a in sca_todos if a["fonte_score"] == "fallback_rotulo")

    decisao = {
        "modo": args.modo,
        "escopo": args.escopo,
        "limiar_cvss": limiar,
        "decisao": "bloqueado" if bloqueia else "aprovado",
        "quantidade_disparadores": len(disparadores),
        "disparadores": disparadores,
        "sca_fallback_count": sca_fallback_count,
        "sca_severidade_nativa": contar_por_severidade(sca_todos),
        "por_ferramenta": {
            ferramenta: {
                "total": len(achados),
                "disparadores": sum(1 for a in achados if a["dispara_gate"]),
            }
            for ferramenta, achados in achados_por_ferramenta.items()
        },
        "trivy_config_misconfiguracoes": sum(
            len(r.get("Misconfigurations") or []) for r in (trivy_config or {}).get("Results") or []
        ),
        "trivy_fs_secrets": sum(
            len(r.get("Secrets") or []) for r in (trivy_secret or {}).get("Results") or []
        ),
        "avisos": avisos,
    }

    Path(args.saida).write_text(json.dumps(decisao, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(decisao, indent=2, ensure_ascii=False))

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        escrever_resumo(summary_path, decisao)

    if args.modo == "enforce" and bloqueia:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
