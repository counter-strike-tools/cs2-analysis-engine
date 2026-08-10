# cs2-analysis-engine

Read-only analysis tooling for Counter-Strike 2 module files and `cs2-dumper` output, with both a desktop GUI and CLI.

This is a static/offline reverse-engineering helper. It does not attach to the running game, edit process memory, bypass
anti-cheat, inject code, or automate gameplay.

## Features

- Desktop GUI built as a CS2 analysis workspace, not a generic debugger clone.
- Read-only CS2 context detection for running `cs2.exe` process entries, Steam install roots, and module candidates.
- Auto-detection of existing `cs2-dumper` output folders without asking the user to browse.
- Startup auto-workspace that loads detected dump symbols, loads the best CS2 module candidate, and disassembles the first code section.
- Recursive workspace scan for `offsets.json` / `output/json/offsets.json` under nearby project folders.
- Built-in offline signature finders for common x64/RIP-relative/module-analysis patterns.
- Quick-load CS2 module candidates such as `client.dll`, `engine2.dll`, `schemasystem.dll`, `tier0.dll`, and `vstdlib.dll`.
- Module map for section browsing and focused disassembly.
- Signature scanner for offline module files.
- Dumper-data browser for offsets, buttons, and interfaces.
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
| Cheat tables | Auto-loaded `cs2-dumper` JSON symbol workspace |
| Pointer/symbol notes | Dumper offsets, buttons, interfaces, and reports |
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
cs2-analysis-engine workspace
```

List sections:

```text
cs2-analysis-engine sections client.dll
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
cs2-analysis-engine scan client.dll "48 8B ?? ?? 89"
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
