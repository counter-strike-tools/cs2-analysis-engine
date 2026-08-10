# cs2-analysis-engine

Read-only analysis tooling for Counter-Strike 2 module files and `cs2-dumper` output, with both a desktop GUI and CLI.

This is a static/offline reverse-engineering helper. It does not attach to the running game, edit process memory, bypass
anti-cheat, inject code, or automate gameplay.

## Features

- Desktop GUI for module loading, section browsing, disassembly, pattern scanning, symbol browsing, and report export.
- PE/module section listing.
- x86-64 disassembly over a virtual-address or RVA range.
- Hex pattern scanning with `??` wildcards.
- Symbol listing from `cs2-dumper` JSON output.
- Optional disassembly annotations from dumper symbols.
- Text and JSON output for scripting.

## Usage

Launch the GUI:

```text
cs2-analysis-engine
```

or:

```text
cs2-analysis-engine gui
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
