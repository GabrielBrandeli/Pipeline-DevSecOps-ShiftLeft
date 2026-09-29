#!/usr/bin/env python3
"""Acrescenta contexto aos achados da triagem, sem sugerir classificacao.

Uso:
    python analise/scripts/contexto_triagem.py

Para cada linha de dados/processados/triagem.csv, busca o registro original do
achado nos relatorios brutos das rodadas validas (dados/brutos/experimento) e
reune o que a ferramenta ja informou, mais o trecho de codigo quando houver:

- Semgrep: mensagem da regra e o trecho do arquivo (3 linhas antes e depois);
- Trivy image: pacote, versao instalada, versao corrigida, status na
  distribuicao, caminho do pacote na imagem e link do advisory;
- Trivy secret e config: regra, mensagem e as linhas destacadas pelo Trivy;
- ZAP: metodo, URI, parametro, ataque, evidencia e informacao adicional.

Nada aqui e opiniao: so dados das ferramentas e do codigo. A classificacao
continua sendo do avaliador (PROTOCOLO-TRIAGEM, secao 3).

Saidas:
- coluna `link` em triagem.csv (advisory, arquivo ou URI), unica alteracao no
  CSV; as colunas preenchidas pelo avaliador sao preservadas;
- dados/processados/triagem-contexto.md, um bloco por achado, na ordem do
  CSV, para leitura durante a triagem.
"""
import csv
import gzip
import json
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
LOTE = RAIZ / "dados" / "brutos" / "experimento"
TRIAGEM = RAIZ / "dados" / "processados" / "triagem.csv"
SAIDA_MD = RAIZ / "dados" / "processados" / "triagem-contexto.md"
PORTAS = {"alvo1": 3000, "alvo2": 3001}
CAMINHO_ALVO = {"alvo1": RAIZ / "alvos" / "juice-shop", "alvo2": RAIZ / "alvos" / "uptime-kuma"}
PREFIXO = "ci.regras.semgrep."


def ler(caminho):
    with gzip.open(caminho, "rt", encoding="utf-8") as f:
        return json.load(f)


def chave(*partes):
    return "|".join(str(p) for p in partes)


def rodadas_validas():
    with open(LOTE / "rodadas.csv", encoding="utf-8") as f:
        return [LOTE / r["run_id"] for r in csv.DictReader(f)
                if r["rodada"].startswith("AUD-") and r["rodada"] != "AUD-01"]


def indexar():
    """(alvo, fonte, chave_dedup) -> registro bruto, na primeira rodada em que aparece."""
    idx = {}
    for d in rodadas_validas():
        for alvo, porta in PORTAS.items():
            sg = ler(d / f"semgrep-{alvo}.json.gz")
            for r in sg.get("results") or []:
                cid = r["check_id"][len(PREFIXO):] if r["check_id"].startswith(PREFIXO) else r["check_id"]
                idx.setdefault((alvo, "semgrep", chave(cid, r["path"], r["start"]["line"])), r)
            for res in ler(d / f"trivy-image-{alvo}.json.gz").get("Results") or []:
                for v in res.get("Vulnerabilities") or []:
                    idx.setdefault((alvo, "trivy-image", chave(v["VulnerabilityID"], v["PkgName"],
                                                               v["InstalledVersion"])), dict(v, _alvo=res["Target"]))
            for res in ler(d / f"trivy-fs-secret-{alvo}.json.gz").get("Results") or []:
                for s in res.get("Secrets") or []:
                    idx.setdefault((alvo, "trivy-secret", chave(s["RuleID"], res["Target"], s["StartLine"])),
                                   dict(s, _alvo=res["Target"]))
            for res in ler(d / f"trivy-config-{alvo}.json.gz").get("Results") or []:
                for m in res.get("Misconfigurations") or []:
                    linha = (m.get("CauseMetadata") or {}).get("StartLine")
                    idx.setdefault((alvo, "trivy-config", chave(m["ID"], res["Target"], linha)),
                                   dict(m, _alvo=res["Target"]))
            zap = ler(d / f"zap-{alvo}.json.gz")
            for site in zap.get("site") or []:
                if site.get("@name", "").rstrip("/") != f"http://localhost:{porta}":
                    continue
                for a in site.get("alerts") or []:
                    for i in a.get("instances") or [{}]:
                        k = chave(a["pluginid"], (i.get("uri") or "").split("?", 1)[0], i.get("param"))
                        idx.setdefault((alvo, "zap", k), dict(i, _alerta=a))
    return idx


def trecho(alvo, caminho, linha, raio=3):
    rel = caminho.split("/", 2)[2] if caminho.startswith("alvos/") else caminho
    arq = CAMINHO_ALVO[alvo] / rel
    try:
        linhas = arq.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "(arquivo nao encontrado no submodulo)"
    ini, fim = max(1, linha - raio), min(len(linhas), linha + raio)
    return "\n".join(f"{'>' if n == linha else ' '}{n:5d} | {linhas[n - 1][:160]}" for n in range(ini, fim + 1))


def contexto(linha, reg):
    alvo, fonte = linha["alvo"], linha["fonte"]
    if reg is None:
        return "", "(registro original nao encontrado)"
    if fonte == "semgrep":
        extra = reg.get("extra") or {}
        refs = (extra.get("metadata") or {}).get("references") or []
        link = refs[0] if refs else reg["path"]
        texto = (f"Regra: {linha['id_achado']}\nMensagem: {(extra.get('message') or '').strip()}\n\n"
                 f"```\n{trecho(alvo, reg['path'], reg['start']['line'])}\n```")
        return link, texto
    if fonte == "trivy-image":
        link = reg.get("PrimaryURL") or ""
        texto = "\n".join([
            f"Pacote: {reg.get('PkgName')} {reg.get('InstalledVersion')}",
            f"Versao corrigida: {reg.get('FixedVersion') or '(nenhuma publicada)'}",
            f"Status na fonte: {reg.get('Status') or '-'}",
            f"Onde esta na imagem: {reg.get('PkgPath') or reg.get('_alvo')}",
            f"Titulo: {reg.get('Title') or '-'}",
            f"Advisory: {link}"])
        return link, texto
    if fonte in ("trivy-secret", "trivy-config"):
        codigo = [l for l in ((reg.get("Code") or (reg.get("CauseMetadata") or {}).get("Code") or {})
                              .get("Lines") or []) if l.get("IsCause")]
        linhas = "\n".join(f"{l['Number']:5d} | {l['Content'][:160]}" for l in codigo[:8])
        cab = (f"Regra: {reg.get('RuleID') or reg.get('ID')} ({reg.get('Title')})\n"
               f"Arquivo: {reg.get('_alvo')}\n")
        if fonte == "trivy-config":
            cab += f"Mensagem: {reg.get('Message')}\nResolucao sugerida pela ferramenta: {reg.get('Resolution')}\n"
        return reg.get("PrimaryURL") or reg.get("_alvo", ""), cab + (f"\n```\n{linhas}\n```" if linhas else "")
    if fonte == "zap":
        a = reg["_alerta"]
        texto = "\n".join([
            f"Alerta: {a.get('name')} (plugin {a.get('pluginid')}, risco {a.get('riskcode')}, "
            f"confianca {a.get('confidence')}, CWE-{a.get('cweid')})",
            f"Requisicao: {reg.get('method', '')} {reg.get('uri', '')}",
            f"Parametro: {reg.get('param') or '-'}",
            f"Ataque: {reg.get('attack') or '-'}",
            f"Evidencia: {(reg.get('evidence') or '-')[:300]}",
            f"Informacao adicional: {(reg.get('otherinfo') or '-')[:500]}"])
        return reg.get("uri", ""), texto
    return "", ""


def main():
    idx = indexar()
    with open(TRIAGEM, encoding="utf-8") as f:
        leitor = csv.DictReader(f)
        campos = list(leitor.fieldnames)
        linhas = list(leitor)
    if "link" not in campos:
        campos.insert(campos.index("classificacao"), "link")

    blocos, sem = [], 0
    for l in linhas:
        reg = idx.get((l["alvo"], l["fonte"], l["chave_dedup"]))
        sem += reg is None
        link, texto = contexto(l, reg)
        l["link"] = link
        blocos.append(f"## {l['id_triagem']} · {l['alvo']} · {l['fonte']} · {l['severidade_nativa']}"
                      f"{' · RETRIAGEM' if l.get('retriagem') == 'sim' else ''}\n\n"
                      f"`{l['local']}` · aparece em {l['rodadas_em_que_aparece']} rodada(s)\n\n{texto}\n")

    with open(TRIAGEM, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=campos, lineterminator="\n")
        w.writeheader()
        w.writerows(linhas)
    SAIDA_MD.write_text("# Contexto para a triagem\n\nGerado por `analise/scripts/contexto_triagem.py`. "
                        "Somente dados das ferramentas e do codigo; a classificacao e do avaliador.\n\n"
                        + "\n".join(blocos), encoding="utf-8")
    print(f"{len(linhas)} achados; {len(linhas) - sem} com contexto; {sem} sem registro original")
    print(f"{SAIDA_MD}")


if __name__ == "__main__":
    main()
