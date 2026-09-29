#!/usr/bin/env python3
"""Cruza os achados do alvo 1 com o ground truth (docs/GROUND-TRUTH.md).

Uso:
    python analise/scripts/revocacao_juiceshop.py \
        --achados dados/processados/achados.csv \
        --ground-truth dados/processados/ground_truth.csv \
        --saida dados/processados/deteccao-juiceshop.csv

Um desafio conta como detectado por uma ferramenta, em uma rodada, quando
algum achado daquela ferramenta satisfaz o criterio de correspondencia abaixo.
Cada criterio operacionaliza o `local_esperado` e a classe de regra ja nomeada
na justificativa do ground truth (arquivo ou rota + tipo de regra/alerta).
Desafios que compartilham a mesma falha usam o mesmo criterio (coluna falha),
para que a revocacao possa ser reportada tambem por falha distinta.

Revocacao = detectados / desafios classificados "Sim" para a ferramenta.
Parciais sao reportados a parte, fora do denominador.
"""
import argparse
import re
from pathlib import Path

import pandas as pd

RAIZ = Path(__file__).resolve().parents[2]

# (ferramenta, falha, arquivo/URI regex, regra/alerta regex[, linha])
SQLI_LOGIN = [("semgrep", r"routes/login\.ts:", r"sql|sequelize"),
              ("zap", r"/rest/user/login", r"SQL Injection")]
SQLI_BUSCA = [("semgrep", r"routes/search\.ts:", r"sql|sequelize"),
              ("zap", r"/rest/products/search", r"SQL Injection")]
XSS_BUSCA = [("semgrep", r"search-result\.component\.ts:", r"bypasssecuritytrust"),
             ("zap", r"", r"Cross Site Scripting \(DOM Based\)")]
REDIRECT = [("semgrep", r"(?:routes/redirect|lib/insecurity)\.ts:", r"redirect"),
            ("zap", r"/redirect", r"External Redirect|Off-site Redirect")]
ARQ_FTP = [("semgrep", r"routes/fileServer\.ts:", r"sendfile|path|traversal"),
           ("zap", r"/ftp/", r"Backup File|Path Traversal|Source Code Disclosure|Bypassing 403")]
JWT_LIBS = [("trivy-image", r"^(?:jsonwebtoken@0\.4\.0|express-jwt@0\.1\.3)$", r"")]

CRITERIOS = {
    "loginAdminChallenge": ("SQLi login", SQLI_LOGIN),
    "loginBenderChallenge": ("SQLi login", SQLI_LOGIN),
    "loginJimChallenge": ("SQLi login", SQLI_LOGIN),
    "ephemeralAccountantChallenge": ("SQLi login", SQLI_LOGIN),
    "ghostLoginChallenge": ("SQLi login", SQLI_LOGIN),
    "unionSqlInjectionChallenge": ("SQLi busca", SQLI_BUSCA),
    "dbSchemaChallenge": ("SQLi busca", SQLI_BUSCA),
    "christmasSpecialChallenge": ("SQLi busca", SQLI_BUSCA),
    "localXssChallenge": ("XSS DOM busca", XSS_BUSCA),
    "xssBonusChallenge": ("XSS DOM busca", XSS_BUSCA),
    "redirectChallenge": ("Open redirect", REDIRECT),
    "directoryListingChallenge": ("Listagem /ftp", [
        ("semgrep", r"server\.ts:288$", r"directory-listing"),
        ("zap", r"/ftp/?$", r"Directory Browsing")]),
    "accessLogDisclosureChallenge": ("Listagem /support/logs", [
        ("semgrep", r"server\.ts:300$", r"directory-listing"),
        ("zap", r"/support/logs", r"Directory Browsing")]),
    "misplacedIacFiles": ("Listagem /infrastructure", [
        ("semgrep", r"server\.ts:268$", r"directory-listing"),
        ("zap", r"/infrastructure", r"Directory Browsing")]),
    "forgottenDevBackupChallenge": ("Arquivos /ftp", ARQ_FTP),
    "forgottenBackupChallenge": ("Arquivos /ftp", ARQ_FTP),
    "misplacedSignatureFileChallenge": ("Arquivos /ftp", ARQ_FTP),
    "easterEggLevelOneChallenge": ("Arquivos /ftp", ARQ_FTP),
    "nullByteChallenge": ("Arquivos /ftp", ARQ_FTP),
    "errorHandlingChallenge": ("Erro com pilha", [("zap", r"", r"Application Error Disclosure")]),
    "iacLeakedKeyChallenge": ("Chave privada IaC", [
        ("semgrep", r"infrastructure/terraform/networking\.tf:", r"private-key"),
        ("trivy-secret", r"infrastructure/terraform/networking\.tf", r"private-key")]),
    "jwtForgedChallenge": ("Bibliotecas JWT", JWT_LIBS + [
        ("semgrep", r"lib/insecurity\.ts:", r"private-key|jwt|secret")]),
    "jwtUnsignedChallenge": ("Bibliotecas JWT", JWT_LIBS),
    "knownVulnerableComponentChallenge": ("Dependencias vulneraveis", [
        ("trivy-image", r"^(?:sanitize-html@1\.4\.2|express-jwt@0\.1\.3|jsonwebtoken@0\.4\.0)$", r"")]),
    "passwordHashLeakChallenge": ("Hash em whoami", [("zap", r"/rest/user/whoami", r"Hash Disclosure")]),
    "noSqlReviewsChallenge": ("NoSQL reviews", [("zap", r"/rest/products/reviews", r"NoSQL")]),
    "ssrfChallenge": ("SSRF imagem", [
        ("semgrep", r"profileImageUrlUpload\.ts:", r"ssrf"),
        ("zap", r"/profile/image/url", r"Server Side Request Forgery")]),
    "csrfChallenge": ("CSRF perfil", [("zap", r"/profile$", r"Anti-CSRF")]),
    # Parciais de SCA sem achado possivel no escopo configurado (ver justificativa
    # no ground truth): criterio vazio, reportados como nao sinalizados.
    "csafChallenge": ("Advisory CSAF", []),
    "vulnerableDockerImageChallenge": ("Imagem em docker-compose", []),
}
EIXO = {"semgrep": "sast", "trivy-image": "sca", "trivy-secret": "sca", "zap": "dast"}


def casa(achados, fonte, local_re, regra_re):
    sub = achados[achados.fonte == fonte]
    if local_re:
        sub = sub[sub.local.fillna("").str.contains(local_re, regex=True, flags=re.I)]
    if regra_re:
        alvo = sub.id_achado.fillna("") + " " + sub.titulo.fillna("")
        sub = sub[alvo.str.contains(regra_re, regex=True, flags=re.I)]
    return len(sub) > 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--achados", type=Path, default=RAIZ / "dados/processados/achados.csv")
    ap.add_argument("--ground-truth", type=Path, default=RAIZ / "dados/processados/ground_truth.csv")
    ap.add_argument("--config", default="devsecops-audit")
    ap.add_argument("--excluir-rodadas", default="AUD-01")
    ap.add_argument("--saida", type=Path, default=RAIZ / "dados/processados/deteccao-juiceshop.csv")
    args = ap.parse_args()

    excluir = {r for r in args.excluir_rodadas.split(",") if r}
    gt = pd.read_csv(args.ground_truth)
    gt = gt[gt.excluido == "Nao"].set_index("id_desafio")
    a = pd.read_csv(args.achados, low_memory=False)
    a = a[(a.alvo == "alvo1") & (a.config == args.config) & ~a.rodada.isin(excluir)]
    rodadas = sorted(a.rodada.unique())

    faltando = [k for k in gt.index for eixo in ("sast", "sca", "dast")
                if gt.loc[k, f"detectavel_{eixo}"] in ("Sim", "Parcial") and k not in CRITERIOS]
    if faltando:
        raise SystemExit(f"Desafios Sim/Parcial sem criterio de correspondencia: {sorted(set(faltando))}")

    linhas = []
    for rodada in rodadas:
        ar = a[a.rodada == rodada]
        for chave, (falha, regras) in CRITERIOS.items():
            detec = {"sast": False, "sca": False, "dast": False}
            for fonte, local_re, regra_re in regras:
                detec[EIXO[fonte]] |= casa(ar, fonte, local_re, regra_re)
            for eixo, ok in detec.items():
                linhas.append({"rodada": rodada, "id_desafio": chave, "falha": falha, "eixo": eixo,
                               "classificacao": gt.loc[chave, f"detectavel_{eixo}"],
                               "detectado": ok})
    d = pd.DataFrame(linhas)
    args.saida.parent.mkdir(parents=True, exist_ok=True)
    d.to_csv(args.saida, index=False)

    print(f"Rodadas: {len(rodadas)} ({rodadas[0]} a {rodadas[-1]})")
    for eixo in ("sast", "sca", "dast"):
        sim = d[(d.eixo == eixo) & (d.classificacao == "Sim")]
        den = sim.id_desafio.nunique()
        por_rodada = sim.groupby("rodada").detectado.sum()
        uniao = sim.groupby("id_desafio").detectado.any()
        falhas = sim.groupby("falha").detectado.any()
        par = d[(d.eixo == eixo) & (d.classificacao == "Parcial")].groupby("id_desafio").detectado.any()
        print(f"{eixo.upper()}: denominador {den}; revocacao por rodada mediana "
              f"{por_rodada.median():.0f}/{den} (min {por_rodada.min()}, max {por_rodada.max()}); "
              f"uniao {uniao.sum()}/{den}; falhas distintas {falhas.sum()}/{len(falhas)}; "
              f"parciais sinalizados {par.sum()}/{len(par)}")
        nao = sorted(uniao[~uniao].index)
        if nao:
            print(f"   nao detectados: {nao}")
    todos = d[d.classificacao == "Sim"].groupby("id_desafio").detectado.any()
    print(f"Qualquer ferramenta: {todos.sum()} de {len(todos)} desafios detectaveis")


if __name__ == "__main__":
    main()
