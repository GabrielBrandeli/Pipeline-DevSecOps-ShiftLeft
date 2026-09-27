# Dockerfiles ajustados dos alvos

## juice-shop.Dockerfile (D14 revisado, 27/09/2026)

Copia de `alvos/juice-shop/Dockerfile` (tag v20.2.0) com uma unica linha a
mais no estagio `installer`:

    ENV npm_config_before=2026-09-23T18:27:00Z

O Juice Shop declara `package-lock=false`: cada build resolve a versao
corrente das dependencias. Em 27/09/2026 o build passou a falhar
(`Missing metafile: dist/frontend/stats.json`) porque o `@angular/build`
22.2.0, publicado em 23/09/2026 21:37 UTC, entrou na resolucao. Com a data de
corte, o npm so considera versoes publicadas ate o inicio da execucao de
validacao 35902561486, a ultima que construiu o alvo com sucesso.

Verificado localmente em 27/09/2026: a imagem construida com a copia tem as
mesmas 81 vulnerabilidades de dependencia (`lang-pkgs`) que o `trivy image`
daquela execucao, identicas em identificador, pacote e versao.

Conferir que a copia so difere do original nessas linhas:

    diff alvos/juice-shop/Dockerfile ci/alvos/juice-shop.Dockerfile

O perfil `ci/perfis/alvo1-juiceshop.env` aponta `ALVO_DOCKERFILE` para esta
copia, igual na linha de base e na esteira. O contexto de build continua
sendo o submodulo, e o `trivy config` continua varrendo o Dockerfile original
do projeto, que e o artefato de configuracao avaliado.
