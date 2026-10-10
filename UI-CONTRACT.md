# Orion Repo Fixer — UI contract

The design layer is a static GitHub Pages application. It contains no analysis engine, ZIP extraction, rule matching, patch logic, backend, API key, or external runtime dependency.

## Loading

Load `assets/js/ui.js` as a module after (or alongside) the engine. The UI is safe to initialize before the engine. Once the DOM is ready it dispatches:

```js
window.addEventListener('orf:ui-ready', event => {
  // event.detail.contractVersion === 1
  // dispatch the initial snapshot with window.dispatchEvent(new CustomEvent('orf:state', { detail: snapshot }))
});
```

## UI → engine

Every UI action is a `CustomEvent` on `window` named `orf:action`. Its `detail.type` is one of the following:

| Type | Detail payload |
| --- | --- |
| `PROJECT_IMPORT_FILES` | `{ files: File[], mode: "replace" | "append" }` |
| `PROJECT_IMPORT_FOLDER` | `{ files: File[], mode: "replace" | "append" }` |
| `PROJECT_IMPORT_ZIP` | `{ file: File, mode: "replace" | "append" }` |
| `SCAN_START` | `{}` |
| `SCAN_CANCEL` | `{}` |
| `FILTERS_CHANGE` | `{ query, severity, category, language }` |
| `FINDING_SELECT` | `{ findingId: string }` |
| `REPAIR_PREVIEW` | `{ findingId: string }` |
| `REPAIR_APPLY` | `{ findingId: string }` |
| `REPAIR_REJECT` | `{ findingId: string }` |
| `REPAIR_APPLY_SAFE` | `{}` |
| `REPAIR_UNDO` | `{}` |
| `EXPORT_ZIP` | `{}` |
| `EXPORT_REPORT` | `{ format: "json" | "sarif" }` |

Example listener:

```js
window.addEventListener('orf:action', ({ detail }) => {
  switch (detail.type) {
    case 'PROJECT_IMPORT_FILES':
      // retain detail.files and pass them into the deterministic engine
      break;
    case 'SCAN_START':
      break;
  }
});
```

The file and folder import controls provide native browser `File` objects. Folder files retain `webkitRelativePath` where the browser provides it. ZIP files are passed as the selected `File`; the UI never extracts archives. The Add More control always sends `mode: "append"`.

## Engine → UI

### State snapshots

Dispatch a complete or partial defensive snapshot as:

```js
window.dispatchEvent(new CustomEvent('orf:state', { detail: {
  status: 'empty', // empty | ready | scanning | complete | cancelled | error
  project: { name: '', files: [], fileCount: 0, totalBytes: 0 },
  scan: { scannedFiles: 0, totalFiles: 0, patternsChecked: 0, progress: 0 },
  summary: { findings: 0, critical: 0, high: 0, medium: 0, low: 0, repaired: 0, verified: 0, skipped: 0 },
  findings: [],
  selectedFindingId: null,
  repairPreview: null,
  filters: { query: '', severity: 'all', category: 'all', language: 'all' },
  capabilities: {
    canScan: false, canCancel: false, canApplySafe: false,
    canUndo: false, canExportZip: false, canExportReport: false
  }
} }));
```

The UI renders actual values only. It ships with no mock findings, fake metrics, fake progress, or pretend repair success. Missing optional fields are handled defensively.

Supported project file shape: `{ path, size, language, status }`.

Supported finding shape: `{ id, ruleId, title, severity, category, path, line, column, description, confidence, status, fixAvailable }`.

Supported repair preview shape: `{ findingId, path, before, after, explanation, safety, canApply }`.

### Progress

```js
window.dispatchEvent(new CustomEvent('orf:progress', { detail: {
  phase, message, completed, total, percent
} }));
```

Progress values are rendered in the scan strip. No timers are used to infer engine availability.

### Toasts

```js
window.dispatchEvent(new CustomEvent('orf:toast', { detail: {
  type: 'info' | 'success' | 'error',
  message: 'Human-readable notification'
} }));
```

The notification region is `#toast-region` and is exposed with `role="status"` and `aria-live="polite"`.

## Required DOM IDs

The implementation preserves every required integration ID: `project-input-files`, `project-input-folder`, `project-input-zip`, `scan-button`, `cancel-scan-button`, `fix-safe-button`, `undo-button`, `export-zip-button`, `export-report-button`, `finding-search`, `severity-filter`, `language-filter`, `project-status`, `scan-progress`, `findings-list`, `finding-detail`, `repair-preview`, and `toast-region`. Category filtering is `#category-filter`.

## Integration note

Use a normal `<script type="module" src="assets/js/ui.js"></script>` from the repository root. The relative path works on GitHub Pages repository subpaths. The engine should listen on `window`, preserve uploaded `File` references until its import operation is complete, and respond to `orf:ui-ready` with its initial state. The UI does not require the engine to be present in order to render its empty/disconnected state.
