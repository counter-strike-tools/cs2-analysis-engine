# cs2-analysis-engine

Read-only analysis tooling for Counter-Strike 2 module files and `cs2-dumper` output, with both a desktop GUI and CLI.

This is a static/offline reverse-engineering helper. It does not attach to the running game, edit process memory, bypass
anti-cheat, inject code, or automate gameplay.

## Features

- Desktop GUI built as a CS2 analysis workspace, not a generic debugger clone.
- Read-only CS2 context detection for running `cs2.exe` process entries, Steam install roots, and module candidates.
- Module fingerprinting with file size, image base, and SHA-256 for reproducible reports.
- Detected module inventory that fingerprints all auto-discovered CS2 module candidates.
- Auto-detection of existing `cs2-dumper` output folders without asking the user to browse.
- Startup auto-workspace that derives an in-memory runtime symbol dump from the detected CS2 module, then loads optional external dump symbols when present.
- Workspace health summary with coverage counts and warnings for missing module, dump, disassembly, strings, or signature data.
- Recursive workspace scan for `offsets.json` / `output/json/offsets.json` under nearby project folders.
- Built-in offline signature finders for common x64/RIP-relative/module-analysis patterns.
- Pattern and signature hits include section names and nearby extracted string anchors when available.
- Scan output can be narrowed by section and nearby string-anchor kind.
- Quick-load CS2 module candidates such as `client.dll`, `engine2.dll`, `schemasystem.dll`, `tier0.dll`, and `vstdlib.dll`.
- Module map for section browsing and focused disassembly.
- RIP-relative target resolution in disassembly, with dumper-symbol annotations when available.
- Cross-reference extraction from resolved disassembly targets, including target section and code/data/outside-image classification.
- Offline printable string extraction from non-executable module sections, with CS2-oriented classification for interfaces, schema names, classes, convars, source paths, format strings, and decorated symbols.
- Signature scanner for offline module files.
- Runtime-derived symbol browser for string anchors and signature hits, plus optional dumper-data browsing for offsets, buttons, and interfaces.
- Workspace report export for review and sharing.
- PE/module section listing.
- x86-64 disassembly over a virtual-address or RVA range.
- Hex pattern scanning with `??` wildcards.
- Symbol listing from `cs2-dumper` JSON output.
- Optional disassembly annotations from dumper symbols.
- Text and JSON output for scripting.

## Cheat Engine Comparison

Cheat Engine-style tools usually focus on live process attachment, memory scanning, memory editing, debugging,
trainers, pointer scanning, and cheat tables. This project intentionally does not clone the dangerous parts for CS2.
Instead, it maps those workflows to safe CS2-specific analysis:

| Cheat Engine area | CS2 Analysis Engine equivalent |
| --- | --- |
| Process selector | Read-only `cs2.exe` context detector plus Steam install discovery |
| Memory viewer | Offline module map and section browser |
| Disassembler | Offline x86-64 disassembly from module files |
| Array-of-byte scan | Offline section-aware signature scanner |
| Cheat tables | Auto-built in-memory module symbol workspace |
| Pointer/symbol notes | Runtime-derived string/signature symbols, optional dumper offsets, buttons, interfaces, and reports |
| Trainers/memory edits | Not implemented |
| Kernel/debug bypasses | Not implemented |

## Usage

Launch the GUI:

```text
cs2-analysis-engine
```

or:

```text
cs2-analysis-engine gui
```

Detect CS2 context from the CLI:

```text
cs2-analysis-engine detect
```

Build a full auto workspace report:

```text
cs2-analysis-engine workspace --string-min-len 5
```

Print a compact workspace summary:

```text
cs2-analysis-engine summary --string-min-len 8
cs2-analysis-engine summary --json --out reports/summary.json
```

Save a workspace report:

```text
cs2-analysis-engine workspace --out reports/workspace.txt
cs2-analysis-engine workspace --json --out reports/workspace.json
```

List sections:

```text
cs2-analysis-engine sections client.dll
```

Fingerprint a module:

```text
cs2-analysis-engine fingerprint client.dll
```

Fingerprint all detected CS2 modules:

```text
cs2-analysis-engine inventory
```

Disassemble 256 bytes at an RVA:

```text
cs2-analysis-engine disasm client.dll --start 0x123456 --rva --len 256
```

Annotate disassembly with dumper JSON output:

```text
cs2-analysis-engine disasm client.dll --start 0x123456 --rva --dump output --len 256
```

Scan for a byte pattern:

```text
cs2-analysis-engine scan client.dll "48 8B ?? ?? 89" --section .text --near-kind interface --limit 200
```

Extract module strings:

```text
cs2-analysis-engine strings client.dll --min-len 5 --limit 200
```

Run built-in signature finders:

```text
cs2-analysis-engine signatures client.dll
```

List known dumper symbols:

```text
cs2-analysis-engine symbols output --module client.dll
```

## Scope

The project is intentionally read-only. It is meant for module inspection, generated metadata review, SDK validation,
and offline reverse-engineering research around files you are allowed to analyze.

Non-goals:

- attaching to the live CS2 process
- writing process memory
- code injection
- anti-cheat bypass
- gameplay automation
- cheat table execution

## License

MIT
