#!/usr/bin/env bash
# Gera a fixture de estado inicial do alvo 2 (D11): diretorio data/ do
# Uptime Kuma com banco SQLite e um usuario administrador pre-provisionado.
#
# O usuario e criado pelo mesmo evento de socket.io ("setup") que a interface
# usa na primeira execucao, e nao por INSERT direto no banco, para que o
# estado resultante seja identico ao de uma instalacao real.
#
# Uso: bash ci/fixtures/uptime-kuma/gerar_fixture.sh <imagem> [destino]
#   <imagem>: imagem do alvo 2 construida a partir do submodulo fixado
#             (ex.: tcc-uptimekuma:latest)
set -euo pipefail

IMAGEM="${1:?informe a imagem do alvo 2}"
DESTINO="${2:-$(cd "$(dirname "$0")" && pwd)/data}"
USUARIO="tcc-admin"
SENHA="TccDevSecOps#2026"
NOME="kuma-fixture-$$"

docker rm -f "$NOME" >/dev/null 2>&1 || true
docker run -d --name "$NOME" -e UPTIME_KUMA_DB_TYPE=sqlite "$IMAGEM" >/dev/null
trap 'docker rm -f "$NOME" >/dev/null 2>&1 || true' EXIT

# Espera o servidor principal (nao o servidor temporario de migracao, que
# tambem responde HTTP) anunciar que o banco esta vazio e aguardando setup.
for i in $(seq 1 60); do
  docker logs "$NOME" 2>&1 | grep -q "No user, need setup" && break
  sleep 2
done

docker exec -i "$NOME" node - "$USUARIO" "$SENHA" <<'EOF'
const { io } = require("/app/node_modules/socket.io-client");
const [usuario, senha] = process.argv.slice(2);
const s = io("http://localhost:3001");
s.on("connect", () => {
  s.emit("setup", usuario, senha, (res) => {
    console.log(JSON.stringify(res));
    s.close();
    process.exit(res.ok ? 0 : 1);
  });
});
setTimeout(() => { console.error("timeout no evento setup"); process.exit(1); }, 30000);
EOF

# Superficie publica padrao do produto (status page + monitor push)
docker exec -i "$NOME" node - "$USUARIO" "$SENHA" < "$(dirname "$0")/popular.js"

# Encerra o servidor antes de copiar, para o SQLite gravar o WAL no arquivo principal
docker stop "$NOME" >/dev/null
rm -rf "$DESTINO"
docker cp "$NOME:/app/data" "$DESTINO"
rm -rf "$DESTINO"/{screenshots,upload,docker-tls} "$DESTINO"/kuma.db-{wal,shm} 2>/dev/null || true
ls -la "$DESTINO"
