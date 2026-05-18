# MorinoLink GitHub Pages Loader

This directory contains GitHub Pages delivery copies for MorinoLink GPTs personality loading.

Purpose:
- Emergency replacement route for raw.githubusercontent.com Action loading failures.
- JSON delivery via GitHub Pages.
- Existing source personality JSON files must remain unchanged.

Status:
- LIMITED_E2E_COMPLETION
- NOT_FULL_AUTONOMOUS_COMPLETION
- FULL_AUTONOMOUS_COMPLETION=false
- Final decision owner: 島田善信オーナー

Rules:
- Do not modify source personality JSON files.
- Do not modify IntegratedReport.
- Do not modify FullsetCache.
- Do not modify OCR or PDF files.
- Do not run workflow_dispatch.
- Do not run manual Actions.
- Do not declare FULL_AUTONOMOUS_COMPLETION.

Expected GitHub Pages URLs after Pages is enabled:
- https://yoshi07bb1-prog.github.io/morinolink-governance/loader/loader_ping.json
- https://yoshi07bb1-prog.github.io/morinolink-governance/loader/loader_manifest.json
- https://yoshi07bb1-prog.github.io/morinolink-governance/loader/GPTs_load_contract.json
- https://yoshi07bb1-prog.github.io/morinolink-governance/loader/GPT5Master_personality2.json
- https://yoshi07bb1-prog.github.io/morinolink-governance/loader/GPT5Master_personality.json
- https://yoshi07bb1-prog.github.io/morinolink-governance/loader/strategy_personality.json
- https://yoshi07bb1-prog.github.io/morinolink-governance/loader/finance_personality.json
- https://yoshi07bb1-prog.github.io/morinolink-governance/loader/legal_personality.json
- https://yoshi07bb1-prog.github.io/morinolink-governance/loader/hr_personality.json
- https://yoshi07bb1-prog.github.io/morinolink-governance/loader/academy_personality.json

GitHub Pages設定：
CodexがGitHub UI設定を直接変更できない場合は、以下を報告してください。
- Settings → Pages
- Source: Deploy from a branch
- Branch: main
- Folder: /docs
- Save
