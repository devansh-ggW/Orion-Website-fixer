# Orion Repo Fixer

A static, browser-only deterministic pattern-intelligence and repository repair prototype. It runs on GitHub Pages without a backend, hosted AI, API keys, login, or external runtime libraries.

## What works

- Import multiple files, an entire folder, or a ZIP archive.
- Append more files to an open project, with path-based merge behavior.
- Background scanning in a Web Worker, with a fallback path when workers are unavailable.
- 41 built-in deterministic checks covering selected JavaScript/TypeScript, HTML, CSS, Python, shell, YAML, Go, Docker, secrets, transport security, SQL construction, accessibility, and project-integrity patterns.
- Cross-file checks for local HTML source and href references.
- Search and filter findings by query, severity, category, language, or selected file.
- Preview and apply the single explicitly registered safe repair: adding rel="noopener noreferrer" to eligible target="_blank" links.
- Batch application of eligible safe link repairs, rescan-based verification, undo, project ZIP export, JSON report export, and SARIF export.
- Import and export of custom literal-only pattern packs. Custom rules are data, never executable code; browser storage is used when available.
- Keyboard-friendly controls, a lightweight layout, and a light colour palette for readability.

## Deploy on GitHub Pages

1. Open Settings → Pages for this repository.
2. Select GitHub Actions as the build and deployment source if it is not already selected.
3. Push a commit to main. The included workflow checks both JavaScript modules and deploys the static project.

No build step or package installation is required. Asset paths are relative, so the site works under a GitHub Pages repository subpath.

## Custom pattern pack format

Import a JSON file with this shape:

    {
      "schemaVersion": 1,
      "name": "Local pack",
      "rules": [
        {
          "id": "CUSTOM-EXAMPLE-001",
          "title": "Example marker",
          "severity": "low",
          "category": "custom",
          "languages": ["javascript", "text"],
          "match": "REPLACE_WITH_A_LITERAL",
          "description": "Review the context around this literal."
        }
      ]
    }

Rules use case-insensitive literal matching, not user-supplied regex. Invalid IDs, duplicates, unsupported severity values, and empty or oversized literals are skipped. Packs are bounded to 5 MB and 10,000 rules per import.

## Scope and limitations

This is a prototype, not a complete security auditor or an intelligent model. Rules are heuristics and can report false positives or miss issues. Currently, only the link noopener repair has an automatic recipe. Other findings are advisory. Re-scan verification only checks whether the original rule still triggers; it does not prove the application works correctly.

ZIP import accepts ordinary non-encrypted ZIP files using stored or DEFLATE entries in a current browser. ZIP export writes uncompressed entries so it can be produced entirely with browser APIs. Import sizes are bounded to protect browser memory. Large and binary files are preserved for export but are not scanned as source text.

Project contents are processed in the browser. This site does not transmit source code to an application server. Browser downloads and local IndexedDB storage are handled by the user's browser.

## Frontend / logic separation

- index.html, assets/css/app.css, and assets/js/ui.js are the presentation layer.
- assets/js/engine.js is the deterministic logic layer.
- The UI-to-engine contract uses orf:action, orf:state, orf:progress, orf:toast, and orf:ui-ready events. See UI-CONTRACT.md.

The engine never executes uploaded source code and does not call AI APIs.
