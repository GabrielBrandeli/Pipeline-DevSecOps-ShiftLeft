#!/usr/bin/env bash
# Sobe localmente os dois alvos com as mesmas imagens das rodadas experimentais,
# para reproduzir achados do ZAP durante a triagem.
#
# Uso:
#   analise/scripts/subir_alvos.sh          # baixa (se preciso), carrega e sobe
#   analise/scripts/subir_alvos.sh parar    # remove os containers
#
# As imagens vem do artefato `imagem-<perfil>-AUD-02` da execucao AUD-02
# (todas as rodadas usam o mesmo commit e as mesmas bases, D13/D14). O start
# replica o job de DAST de 01-devsecops.yml: `docker create`, copia da fixture
# do alvo 2 (D11) e `docker start`. Artefatos expiram em 27/12/2026.
set -euo pipefail

RAIZ="$(cd "$(dirname "$0")/../.." && pwd)"
CACHE="$RAIZ/.cache/imagens"
RUN_ID="$(awk -F, '$1 == "AUD-02" {print $6}' "$RAIZ/dados/brutos/experimento/rodadas.csv")"

if [ "${1:-}" = "parar" ]; then
  docker rm -f triagem-alvo1 triagem-alvo2 2>/dev/null || true
  exit 0
fi

subir() {  # perfil, nome do container
  local perfil="$1" nome="$2"
  # shellcheck disable=SC1090
  source "$RAIZ/ci/perfis/$perfil.env"
  local tar="$CACHE/$perfil/imagem.tar"
  if [ ! -f "$tar" ]; then
    echo "Baixando imagem de $perfil (execucao $RUN_ID)..."
    gh run download "$RUN_ID" -n "imagem-$perfil-AUD-02" -D "$CACHE/$perfil"
  fi
  local img
  img="$(docker load -i "$tar" | sed -n 's/^Loaded image: //p' | head -1)"
  docker rm -f "$nome" >/dev/null 2>&1 || true
  docker create --name "$nome" -p "$ALVO_PORTA:$ALVO_PORTA" "$img" >/dev/null
  if [ -n "$ALVO_FIXTURE" ]; then
    docker cp "$RAIZ/$ALVO_FIXTURE/." "$nome:$ALVO_FIXTURE_DESTINO"
  fi
  docker start "$nome" >/dev/null
  for _ in $(seq 1 60); do
    if curl -sf "http://localhost:$ALVO_PORTA$ALVO_HEALTH" >/dev/null; then
      echo "$ALVO_NOME no ar: http://localhost:$ALVO_PORTA ($img)"
      return
    fi
    sleep 2
  done
  echo "$ALVO_NOME nao respondeu em 120 s; veja: docker logs $nome" >&2
  return 1
}

subir alvo1-juiceshop triagem-alvo1
subir alvo2-uptimekuma triagem-alvo2
