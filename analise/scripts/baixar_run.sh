#!/usr/bin/env bash
# Arquiva uma execucao do GitHub Actions em dados/brutos/<lote>/<run_id>/ (D10).
#
# Uso:
#   analise/scripts/baixar_run.sh <run_id> [lote]      (lote padrao: experimento)
#   analise/scripts/baixar_run.sh -f <run_id> [lote]   (sobrescreve se ja existir)
#
# Grava:
#   run.json          metadados da execucao (titulo com rodada/modo/escopo/ajax,
#                     commit, horarios, tentativa, conclusao)
#   jobs.json         jobs e steps com horarios e runner_name (fonte dos tempos)
#   *.json / *.txt    conteudo dos artefatos, achatado em um unico diretorio
#
# Compressao (D10): relatorios brutos dos scanners e logs da aplicacao vao para
# gzip; gate-decision, dast-integridade, resultado-e7, run.json e jobs.json
# ficam em texto, como trilha de auditoria legivel no historico do git.
#
# Artefatos NAO baixados: imagem-* (tar da imagem Docker, centenas de MB) e
# zap-relatorios-* (HTML/MD redundante com o JSON do ZAP).
set -euo pipefail

forcar=0
if [ "${1:-}" = "-f" ]; then forcar=1; shift; fi
run_id="${1:?informe o run_id}"
lote="${2:-experimento}"

raiz="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
repo="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
destino="$raiz/dados/brutos/$lote/$run_id"

if [ -f "$destino/run.json" ] && [ "$forcar" -eq 0 ]; then
  echo "Ja arquivado: $destino (use -f para sobrescrever)"
  exit 0
fi

status="$(gh api "repos/$repo/actions/runs/$run_id" -q .status)"
if [ "$status" != "completed" ]; then
  echo "Execucao $run_id ainda nao terminou (status=$status). Nada foi baixado." >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

gh api "repos/$repo/actions/runs/$run_id" > "$tmp/run.json"
# per_page=100: um run desta esteira tem no maximo 10 jobs, cabe em uma pagina.
gh api "repos/$repo/actions/runs/$run_id/jobs?filter=latest&per_page=100" > "$tmp/jobs.json"

# Um -p por familia de artefato; o gh cria um subdiretorio por artefato.
gh run download "$run_id" -R "$repo" -D "$tmp/artefatos" \
  -p 'semgrep-*' -p 'trivy-*' -p 'gate-*' -p 'zap-alvo*' -p 'e7-*' \
  || echo "Aviso: nenhum artefato correspondente (execucao falhou cedo ou expirou)." >&2

mkdir -p "$tmp/final"
mv "$tmp/run.json" "$tmp/jobs.json" "$tmp/final/"
if [ -d "$tmp/artefatos" ]; then
  # Os nomes dos arquivos ja trazem o alvo (ex.: trivy-image-alvo1.json);
  # colisao indicaria mudanca no workflow e deve abortar.
  while IFS= read -r -d '' arq; do
    nome="$(basename "$arq")"
    if [ -e "$tmp/final/$nome" ]; then
      echo "Colisao de nome de arquivo entre artefatos: $nome" >&2
      exit 1
    fi
    mv "$arq" "$tmp/final/$nome"
  done < <(find "$tmp/artefatos" -type f -print0)
fi

# -n: sem nome/horario no cabecalho, para o mesmo conteudo gerar o mesmo .gz.
shopt -s nullglob
for arq in "$tmp"/final/semgrep-*.json "$tmp"/final/trivy-*.json \
           "$tmp"/final/zap-*.json "$tmp"/final/app-log-*.txt; do
  gzip -n -9 "$arq"
done
shopt -u nullglob

rm -rf "$destino"
mkdir -p "$(dirname "$destino")"
mv "$tmp/final" "$destino"

titulo="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['display_title'])" "$destino/run.json")"
echo "Arquivado: $destino"
echo "  $titulo"
du -sh "$destino" | cut -f1 | sed 's/^/  tamanho: /'
ls -1 "$destino" | sed 's/^/  /'
