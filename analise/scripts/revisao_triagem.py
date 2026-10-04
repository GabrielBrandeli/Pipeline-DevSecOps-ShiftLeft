#!/usr/bin/env python3
"""Revisao pelo autor da classificacao da IA (D17, etapa 3).

Uso:
    python3 analise/scripts/revisao_triagem.py gerar   # cria revisao-gbr.md
    python3 analise/scripts/revisao_triagem.py ler     # valida, exporta e consolida

`gerar` agrupa os 424 achados de triagem-ia.csv por alvo, fonte e regra (ou
pacote, ou alerta do ZAP) e escreve, para cada achado, a proposta da IA, a
justificativa, a evidencia, como verificar e os dados da ferramenta
(triagem-contexto.md). Nao sobrescreve um arquivo existente.

Campos que o autor preenche:
- `**Revisao do grupo:** ok` aceita a proposta da IA em todos os achados do
  grupo que ficarem com a revisao individual em branco;
- `**Revisao:**` por achado: `ok`, ou VP / FP / NE / IND para alterar;
- `**Motivo:**` obrigatorio quando a classificacao muda.

`ler` grava revisao-gbr.csv (uma linha por achado decidido, com a origem da
decisao: grupo ou individual) e, quando os 424 estao decididos, preenche em
triagem.csv as colunas classificacao, justificativa, evidencia, avaliador e
data com a classificacao final.
"""
import csv
import re
import sys
from datetime import date
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
PROC = RAIZ / "dados" / "processados"
TRIAGEM = PROC / "triagem.csv"
IA = PROC / "triagem-ia.csv"
CONTEXTO = PROC / "triagem-contexto.md"
SAIDA_MD = PROC / "revisao-gbr.md"
SAIDA_CSV = PROC / "revisao-gbr.csv"
CATEGORIAS = {"VP", "FP", "NE", "IND"}

INSTRUCOES = """# Revisao da classificacao da IA (D17)

Gerado por `analise/scripts/revisao_triagem.py gerar`. Regras usadas pela IA:
`docs/TRIAGEM-REGRAS.md`. Alvos locais para conferir: `analise/scripts/subir_alvos.sh`.

Como preencher (escreva depois dos dois-pontos; dentro ou fora do negrito funciona):

- **Revisao do grupo:** `ok` aceita a proposta da IA para todos os achados do
  grupo cuja revisao individual ficar em branco.
- **Revisao:** em um achado, `ok` aceita; `VP`, `FP`, `NE` ou `IND` altera.
- **Motivo:** obrigatorio quando alterar; uma frase.

Para ver o que falta: `python3 analise/scripts/revisao_triagem.py ler`.

"""


def ler_csv(caminho):
    with open(caminho, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def chave_grupo(t):
    fonte = t["fonte"]
    if fonte == "semgrep":
        regra = t["id_achado"].split(".")[-1]
    elif fonte == "trivy-image":
        regra = t["local"].rsplit("@", 1)[0]
    elif fonte == "zap":
        regra = t["titulo"][:60]
    else:
        regra = t["id_achado"]
    return f"{t['alvo']} · {fonte} · {regra}"


def blocos_contexto():
    texto = CONTEXTO.read_text(encoding="utf-8")
    partes = re.split(r"(?m)^(?=## T\d{4} )", texto)
    return {p[3:8]: p.split("\n", 1)[1].strip() for p in partes if p.startswith("## T")}


def campo(bloco, nome):
    m = re.search(rf"(?m)^\*\*{nome}:(.*)$", bloco)
    return m[1].strip().removeprefix("**").removesuffix("**").strip() if m else ""


def gerar():
    if SAIDA_MD.exists():
        sys.exit(f"{SAIDA_MD.name} ja existe; apague-o manualmente para gerar de novo.")
    triagem = {t["id_triagem"]: t for t in ler_csv(TRIAGEM)}
    ctx = blocos_contexto()
    grupos = {}
    for r in ler_csv(IA):
        grupos.setdefault(chave_grupo(triagem[r["id_triagem"]]), []).append(r)
    saida = [INSTRUCOES]
    for g, itens in grupos.items():
        cont = {c: sum(r["classificacao"] == c for r in itens) for c in ("VP", "FP", "NE", "IND")}
        resumo = ", ".join(f"{n} {c}" for c, n in cont.items() if n)
        saida.append(f"# Grupo: {g}\n\n{len(itens)} achado(s); proposta da IA: {resumo}\n\n"
                     f"**Revisao do grupo:** \n")
        for r in itens:
            dados = ctx[r["id_triagem"]]
            if r["fonte"] == "trivy-image":  # a evidencia da IA ja resume o registro do Trivy
                dados = dados.split("\n", 1)[0]
            saida.append(f"## {r['id_triagem']} · proposta IA: {r['classificacao']}\n\n"
                         f"**Justificativa IA:** {r['justificativa']}\n\n"
                         f"Evidencia: {r['evidencia']}\n\n"
                         f"Como verificar: `{r['como_verificar']}`\n\n"
                         f"<details><summary>Dados da ferramenta</summary>\n\n{dados}\n\n</details>\n\n"
                         f"**Revisao:** \n**Motivo:** \n")
        saida.append("---\n")
    SAIDA_MD.write_text("\n".join(saida), encoding="utf-8")
    print(f"{sum(len(i) for i in grupos.values())} achados em {len(grupos)} grupos -> {SAIDA_MD}")


def ler():
    ia = {r["id_triagem"]: r for r in ler_csv(IA)}
    texto = SAIDA_MD.read_text(encoding="utf-8")
    decisoes, pendentes = {}, []
    for grupo in re.split(r"(?m)^(?=# Grupo: )", texto)[1:]:
        rev_grupo = campo(grupo, "Revisao do grupo").lower()
        if rev_grupo not in ("", "ok"):
            pendentes.append(f"grupo '{grupo.splitlines()[0][9:]}': revisao do grupo '{rev_grupo}' invalida (use ok)")
        for bloco in re.split(r"(?m)^(?=## T\d{4} )", grupo)[1:]:
            i = bloco[3:8]
            rev, motivo = campo(bloco, "Revisao"), campo(bloco, "Motivo")
            proposta = ia[i]["classificacao"]
            if rev.lower() == "ok" or (not rev and rev_grupo == "ok"):
                final, origem = proposta, "individual" if rev else "grupo"
            elif rev.upper() in CATEGORIAS:
                final, origem = rev.upper(), "individual"
                if final != proposta and not motivo:
                    pendentes.append(f"{i}: alterado para {final} sem motivo")
                    continue
            else:
                pendentes.append(f"{i}: revisao {'em branco' if not rev else repr(rev) + ' invalida'}")
                continue
            decisoes[i] = {"id_triagem": i, "classificacao_ia": proposta, "classificacao_final": final,
                           "alterada": "sim" if final != proposta else "", "motivo": motivo if final != proposta else "",
                           "origem": origem}

    anteriores = {r["id_triagem"]: r for r in ler_csv(SAIDA_CSV)} if SAIDA_CSV.exists() else {}
    hoje = date.today().isoformat()
    for i, d in decisoes.items():
        a = anteriores.get(i)
        d["data"] = a["data"] if a and a["classificacao_final"] == d["classificacao_final"] and a["motivo"] == d["motivo"] else hoje
    campos = ["id_triagem", "classificacao_ia", "classificacao_final", "alterada", "motivo", "origem", "data"]
    with open(SAIDA_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=campos, lineterminator="\n")
        w.writeheader()
        w.writerows(sorted(decisoes.values(), key=lambda d: d["id_triagem"]))

    alteradas = sum(d["alterada"] == "sim" for d in decisoes.values())
    print(f"{len(decisoes)} de {len(ia)} decididos ({alteradas} alterados) -> {SAIDA_CSV.name}")
    for p in pendentes[:40]:
        print(f"  pendente {p}")
    if len(pendentes) > 40:
        print(f"  ... e mais {len(pendentes) - 40}")
    if len(decisoes) == len(ia) and not pendentes:
        consolidar(ia, decisoes)


def consolidar(ia, decisoes):
    with open(TRIAGEM, encoding="utf-8") as f:
        leitor = csv.DictReader(f)
        campos, linhas = leitor.fieldnames, list(leitor)
    for l in linhas:
        d, r = decisoes[l["id_triagem"]], ia[l["id_triagem"]]
        l["classificacao"] = d["classificacao_final"]
        l["justificativa"] = d["motivo"] if d["alterada"] else r["justificativa"]
        l["evidencia"] = r["evidencia"]
        l["avaliador"] = "GBR" if d["alterada"] else "IA+GBR"
        l["data"] = d["data"]
    with open(TRIAGEM, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=campos, lineterminator="\n")
        w.writeheader()
        w.writerows(linhas)
    print(f"Revisao completa: classificacao final gravada em {TRIAGEM.name}")


if __name__ == "__main__":
    {"gerar": gerar, "ler": ler}.get(sys.argv[1] if len(sys.argv) > 1 else "", lambda: sys.exit(__doc__))()
