<!-- .claude/skills/achados-devsecops/SKILL.md -->
---
name: achados-devsecops
description: Normalizar, deduplicar e classificar achados de Semgrep, Trivy e OWASP ZAP no esquema unico do TCC. Use ao processar qualquer JSON de varredura, ao implementar ou alterar ci/quality_gate.py, ou ao gerar dados/processados/achados.csv.
---

# Normalizacao de achados

## Precedencia de pontuacao CVSS (D2)
1. CVSS.nvd.V3Score
2. CVSS.ghsa.V3Score
3. CVSS.redhat.V3Score
4. Fallback por rotulo: CRITICAL 9.0, HIGH 7.0, MEDIUM 4.0, LOW 0.1, UNKNOWN 0.0

Sempre registrar em `fonte_score` qual das quatro foi usada. A contagem de
fallbacks e resultado reportado no Capitulo 4.

## Chaves de deduplicacao (D6)
- Semgrep: (check_id, path, start.line)
- Trivy:   (VulnerabilityID, PkgName, InstalledVersion)
- ZAP:     (pluginid, uri normalizada, param)

Reportar sempre dois numeros: bruto e deduplicado.

## Regra de equivalencia (D3)
- Semgrep: severity == ERROR e confidence em {HIGH, MEDIUM}; ausente = MEDIUM
- Trivy:   score >= 7.0
- ZAP:     riskcode == 3 e confidence >= 2

## Esquema de saida
run_id, alvo, config, ferramenta, id_achado, local, severidade_nativa,
cvss_v3, fonte_score, owasp, cwe, chave_dedup, dispara_gate

## Armadilhas
- Trivy: usar apenas trivy image como fonte de SCA (D9). O trivy fs retorna
  zero no alvo 1 por ausencia de package-lock.json.
- Trivy: separar .Class os-pkgs de lang-pkgs. A assimetria entre os alvos e
  resultado, nao ruido.
- ZAP: a contagem varia entre execucoes por nao determinismo do spider. Nunca
  tratar divergencia entre rodadas como erro de parsing.