#!/usr/bin/env python3
"""Gera o ground truth do alvo 1 (docs/GROUND-TRUTH.md).

Uso:
    python analise/scripts/ground_truth_juiceshop.py \
        --classificacao analise/ground_truth/classificacao-juiceshop.yaml \
        --saida dados/processados/ground_truth.csv

Parte mecanica do processo: le o catalogo do submodulo (e confere que esta na
tag v20.2.0), aplica as exclusoes, junta a classificacao de detectabilidade
(feita a mao, no YAML), confere que todo desafio incluido foi classificado e
imprime os denominadores da secao 6 do GROUND-TRUTH.md.

Exclusoes (secao 4 do GROUND-TRUTH.md):
- disabledEnv contendo Docker: o Juice Shop, com challenges.safetyMode=auto
  (padrao), desliga esses desafios quando roda em container;
- dependencia externa indisponivel: lista abaixo, extraida dos avisos da
  aplicacao na inicializacao (log do container).
"""
import argparse
import csv
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parents[2]
ALVO = RAIZ / "alvos" / "juice-shop"
TAG = "v20.2.0"

DEPENDENCIA_EXTERNA = {
    "nftMintChallenge": "ALCHEMY_API_KEY ausente (Web3)",
    "web3WalletChallenge": "ALCHEMY_API_KEY ausente (Web3)",
    "chatbotPromptInjectionChallenge": "API de LLM (localhost:11434) inacessivel",
    "chatbotGreedyInjectionChallenge": "API de LLM (localhost:11434) inacessivel",
    "aiDebuggingChallenge": "API de LLM (localhost:11434) inacessivel",
    "systemPromptExtractionChallenge": "API de LLM (localhost:11434) inacessivel",
}

# Categoria do catalogo -> OWASP Top 10:2021. Mapeamento por categoria,
# elaborado pelo autor; excecoes por desafio em POR_DESAFIO.
OWASP_2021 = {
    "Broken Access Control": "A01",
    "Unvalidated Redirects": "A01",
    "Cryptographic Issues": "A02",
    "Sensitive Data Exposure": "A02",
    "Injection": "A03",
    "XSS": "A03",
    "Improper Input Validation": "A04",
    "Broken Anti Automation": "A04",
    "Security through Obscurity": "A04",
    "Security Misconfiguration": "A05",
    "XXE": "A05",
    "Vulnerable Components": "A06",
    "Broken Authentication": "A07",
    "Insecure Deserialization": "A08",
    "Observability Failures": "A09",
    "Miscellaneous": "",
}
POR_DESAFIO = {"ssrfChallenge": "A10"}

VALORES = {"S": "Sim", "P": "Parcial", "N": "Nao"}
CAMPOS = ["id_desafio", "nome", "categoria_juiceshop", "categoria_owasp",
          "dificuldade", "descricao", "detectavel_sast", "detectavel_sca",
          "detectavel_dast", "local_esperado", "justificativa_detectabilidade",
          "excluido", "motivo_exclusao", "data_classificacao", "status"]


def conferir_tag():
    tag = subprocess.run(["git", "-C", str(ALVO), "describe", "--tags", "--exact-match"],
                         capture_output=True, text=True).stdout.strip()
    if tag != TAG:
        sys.exit(f"Submodulo do Juice Shop em '{tag or 'commit sem tag'}', esperado {TAG}.")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--classificacao", type=Path,
                    default=RAIZ / "analise/ground_truth/classificacao-juiceshop.yaml")
    ap.add_argument("--saida", type=Path, default=RAIZ / "dados/processados/ground_truth.csv")
    args = ap.parse_args()

    conferir_tag()
    catalogo = yaml.safe_load((ALVO / "data/static/challenges.yml").read_text(encoding="utf-8"))
    doc = yaml.safe_load(args.classificacao.read_text(encoding="utf-8"))
    classificacao, revisao = doc["desafios"], doc["revisao"]
    revisado = bool(revisao.get("revisado_em"))
    data = revisao["revisado_em"] if revisado else revisao["proposta_em"]
    status = "revisado" if revisado else "proposta"

    chaves = {c["key"] for c in catalogo}
    desconhecidas = set(classificacao) - chaves
    if desconhecidas:
        sys.exit(f"Chaves classificadas que nao existem no catalogo: {sorted(desconhecidas)}")

    linhas, faltando, sobrando = [], [], []
    for c in catalogo:
        chave = c["key"]
        motivo = ""
        if "Docker" in (c.get("disabledEnv") or []):
            motivo = "Desativado pelo proprio Juice Shop em container (safetyMode auto)"
        elif chave in DEPENDENCIA_EXTERNA:
            motivo = "Dependencia externa indisponivel: " + DEPENDENCIA_EXTERNA[chave]
        linha = {
            "id_desafio": chave, "nome": c["name"], "categoria_juiceshop": c["category"],
            "categoria_owasp": POR_DESAFIO.get(chave, OWASP_2021.get(c["category"], "")),
            "dificuldade": c["difficulty"],
            "descricao": re.sub(r"<[^>]+>", "", c["description"]).strip(),
            "excluido": "Sim" if motivo else "Nao", "motivo_exclusao": motivo,
            "data_classificacao": data, "status": status,
        }
        if motivo:
            if chave in classificacao:
                sobrando.append(chave)
            linha.update(detectavel_sast="", detectavel_sca="", detectavel_dast="",
                         local_esperado="", justificativa_detectabilidade="")
        elif chave not in classificacao:
            faltando.append(chave)
            continue
        else:
            sast, sca, dast, local, just = classificacao[chave]
            linha.update(detectavel_sast=VALORES[sast], detectavel_sca=VALORES[sca],
                         detectavel_dast=VALORES[dast], local_esperado=local,
                         justificativa_detectabilidade=just)
        linhas.append(linha)

    if faltando or sobrando:
        sys.exit(f"Sem classificacao: {faltando}\nExcluidos mas classificados: {sobrando}")

    args.saida.parent.mkdir(parents=True, exist_ok=True)
    with open(args.saida, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CAMPOS, lineterminator="\n")
        w.writeheader()
        w.writerows(linhas)

    incluidos = [l for l in linhas if l["excluido"] == "Nao"]
    print(f"{args.saida} ({status}, {data})")
    print(f"Catalogo: {len(catalogo)} | excluidos: {len(linhas) - len(incluidos)} "
          f"(container: {sum(1 for l in linhas if 'container' in l['motivo_exclusao'])}, "
          f"dependencia externa: {sum(1 for l in linhas if 'externa' in l['motivo_exclusao'])}) "
          f"| classificados: {len(incluidos)}")
    print(f"{'':8}{'Sim':>6}{'Parcial':>9}{'Nao':>6}")
    for eixo in ("sast", "sca", "dast"):
        n = Counter(l[f"detectavel_{eixo}"] for l in incluidos)
        print(f"{eixo.upper():8}{n['Sim']:>6}{n['Parcial']:>9}{n['Nao']:>6}")
    nenhuma = sum(1 for l in incluidos
                  if all(l[f"detectavel_{e}"] == "Nao" for e in ("sast", "sca", "dast")))
    alguma_sim = sum(1 for l in incluidos
                     if any(l[f"detectavel_{e}"] == "Sim" for e in ("sast", "sca", "dast")))
    print(f"Nao detectavel por nenhuma ferramenta: {nenhuma}")
    print(f"Detectavel (Sim) por ao menos uma: {alguma_sim}")


if __name__ == "__main__":
    main()
