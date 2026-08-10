mod engine;
mod gui;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use engine::{
    CrossReferenceTargetKind, ModuleImage, Pattern, PatternMatch, StringKind,
    annotate_pattern_matches_with_strings, build_auto_workspace_report, detect_cs2_environment,
    disassemble, extract_ascii_strings, filter_pattern_matches, load_symbol_map, load_symbols,
    parse_string_kind_name, parse_u64, run_signature_presets, scan_pattern,
};

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Launch the desktop GUI.
    Gui,
    /// Detect read-only CS2 context, installs, and module candidates.
    Detect {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Auto-build a CS2 workspace report from detected modules and dump output.
    Workspace {
        /// Number of bytes to disassemble from the selected executable section.
        #[arg(long, default_value_t = 512)]
        disasm_len: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// List executable and data sections from a PE/module file.
    Sections {
        /// Path to a module file such as client.dll.
        module: PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print stable identity metadata for a module file.
    Fingerprint {
        /// Path to a module file such as client.dll.
        module: PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Disassemble a virtual-address range from a module file.
    Disasm {
        /// Path to a module file such as client.dll.
        module: PathBuf,
        /// Start virtual address or RVA. Accepts decimal or 0x-prefixed hex.
        #[arg(long)]
        start: String,
        /// Number of bytes to decode.
        #[arg(long, default_value_t = 256)]
        len: u64,
        /// Treat --start as an RVA instead of a virtual address.
        #[arg(long)]
        rva: bool,
        /// Optional cs2-dumper JSON folder for symbol annotations.
        #[arg(long)]
        dump: Option<PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Search module bytes for a hex pattern with wildcards.
    Scan {
        /// Path to a module file such as client.dll.
        module: PathBuf,
        /// Hex pattern, for example: "48 8B ?? ?? 89".
        pattern: String,
        /// Maximum text rows to print. JSON output always includes all matches.
        #[arg(long, default_value_t = 200)]
        limit: usize,
        /// Only keep matches from this section name, for example .text or .rdata.
        #[arg(long)]
        section: Option<String>,
        /// Only keep matches with a nearby string anchor of this kind.
        #[arg(long)]
        near_kind: Option<String>,
        /// Only keep matches that have any nearby string anchor.
        #[arg(long)]
        with_anchor: bool,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Extract printable ASCII strings from non-executable module sections.
    Strings {
        /// Path to a module file such as client.dll.
        module: PathBuf,
        /// Minimum string length.
        #[arg(long, default_value_t = 5)]
        min_len: usize,
        /// Maximum text rows to print. JSON output always includes all strings.
        #[arg(long, default_value_t = 200)]
        limit: usize,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run built-in offline signature finders against a module.
    Signatures {
        /// Path to a module file such as client.dll.
        module: PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show symbols loaded from cs2-dumper JSON output.
    Symbols {
        /// Path to cs2-dumper output directory.
        dump: PathBuf,
        /// Optional module filter, for example client.dll.
        #[arg(long)]
        module: Option<String>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command.unwrap_or(Command::Gui) {
        Command::Gui => gui::run_gui(),
        Command::Detect { json } => {
            let env = detect_cs2_environment();

            if json {
                println!("{}", serde_json::to_string_pretty(&env)?);
            } else {
                println!("cs2.exe processes: {}", env.processes.len());
                for process in env.processes {
                    println!(
                        "  {} pid={} {}",
                        process.name,
                        process.pid,
                        process
                            .exe
                            .as_ref()
                            .map(|path| path.display().to_string())
                            .unwrap_or_else(|| "<path unavailable>".to_string())
                    );
                }
                println!("install roots: {}", env.install_roots.len());
                for root in env.install_roots {
                    println!("  {}", root.display());
                }
                println!("module candidates: {}", env.module_candidates.len());
                for module in env.module_candidates {
                    println!("  {}", module.display());
                }
                println!("dump candidates: {}", env.dump_candidates.len());
                for dump in env.dump_candidates {
                    println!("  {}", dump.display());
                }
            }

            Ok(())
        }
        Command::Workspace { disasm_len, json } => {
            let report = build_auto_workspace_report(disasm_len)?;

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("cs2.exe processes: {}", report.environment.processes.len());
                println!("install roots: {}", report.environment.install_roots.len());
                println!(
                    "module candidates: {}",
                    report.environment.module_candidates.len()
                );
                println!(
                    "dump candidates: {}",
                    report.environment.dump_candidates.len()
                );
                println!(
                    "selected module: {}",
                    report
                        .selected_module
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "<none>".to_string())
                );
                println!(
                    "selected dump: {}",
                    report
                        .selected_dump
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "<none>".to_string())
                );
                println!("sections: {}", report.sections.len());
                if let Some(fingerprint) = &report.module_fingerprint {
                    println!(
                        "module fingerprint: {} size={} base={:#x}",
                        fingerprint.file_name, fingerprint.size, fingerprint.image_base
                    );
                    println!("module sha256: {}", fingerprint.sha256);
                }
                println!("symbols: {}", report.symbols.len());
                println!("disassembly rows: {}", report.disassembly.len());
                println!("cross references: {}", report.cross_references.len());
                println!(
                    "xref targets: {} code, {} data, {} outside-image",
                    report
                        .cross_references
                        .iter()
                        .filter(|xref| xref.target_kind == CrossReferenceTargetKind::Code)
                        .count(),
                    report
                        .cross_references
                        .iter()
                        .filter(|xref| xref.target_kind == CrossReferenceTargetKind::Data)
                        .count(),
                    report
                        .cross_references
                        .iter()
                        .filter(|xref| xref.target_kind == CrossReferenceTargetKind::OutsideImage)
                        .count()
                );
                println!("strings: {}", report.strings.len());
                println!(
                    "string anchors: {} interfaces, {} schema/classes, {} convars, {} source paths",
                    report
                        .strings
                        .iter()
                        .filter(|item| item.kind == StringKind::InterfaceName)
                        .count(),
                    report
                        .strings
                        .iter()
                        .filter(|item| matches!(
                            item.kind,
                            StringKind::SchemaName | StringKind::ClassName
                        ))
                        .count(),
                    report
                        .strings
                        .iter()
                        .filter(|item| item.kind == StringKind::ConVar)
                        .count(),
                    report
                        .strings
                        .iter()
                        .filter(|item| item.kind == StringKind::SourcePath)
                        .count()
                );
                let signature_hits = report
                    .signature_findings
                    .iter()
                    .map(|finding| finding.matches.len())
                    .sum::<usize>();
                println!(
                    "signature groups: {} hits: {}",
                    report.signature_findings.len(),
                    signature_hits
                );
            }

            Ok(())
        }
        Command::Sections { module, json } => {
            let image = ModuleImage::load(&module)?;
            let sections = image.sections()?;

            if json {
                println!("{}", serde_json::to_string_pretty(&sections)?);
            } else {
                for section in sections {
                    let kind = if section.executable { "code" } else { "data" };
                    println!(
                        "{:<18} va={:#014x} size={:#x} {}",
                        section.name, section.address, section.size, kind
                    );
                }
            }

            Ok(())
        }
        Command::Fingerprint { module, json } => {
            let image = ModuleImage::load(&module)?;
            let fingerprint = image.fingerprint();

            if json {
                println!("{}", serde_json::to_string_pretty(&fingerprint)?);
            } else {
                println!("module: {}", fingerprint.path.display());
                println!("file: {}", fingerprint.file_name);
                println!("size: {}", fingerprint.size);
                println!("image base: {:#x}", fingerprint.image_base);
                println!("sha256: {}", fingerprint.sha256);
            }

            Ok(())
        }
        Command::Disasm {
            module,
            start,
            len,
            rva,
            dump,
            format,
        } => {
            let image = ModuleImage::load(&module)?;
            let symbols = dump
                .as_deref()
                .map(load_symbol_map)
                .transpose()?
                .unwrap_or_default();
            let start = parse_u64(&start)?;
            let address = if rva { image.base + start } else { start };
            let instructions = disassemble(&image, address, len, &symbols)?;

            match format {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&instructions)?),
                OutputFormat::Text => {
                    for instruction in instructions {
                        if let Some(symbol) = &instruction.symbol {
                            println!("\n{}:", symbol);
                        }
                        println!(
                            "{:#014x}  {:<28} {:<42} {}",
                            instruction.address,
                            instruction.bytes,
                            instruction.text,
                            format_instruction_target(&instruction)
                        );
                    }
                }
            }

            Ok(())
        }
        Command::Scan {
            module,
            pattern,
            limit,
            section,
            near_kind,
            with_anchor,
            json,
        } => {
            let image = ModuleImage::load(&module)?;
            let pattern = Pattern::parse(&pattern)?;
            let strings = extract_ascii_strings(&image, 5);
            let matches = annotate_pattern_matches_with_strings(
                scan_pattern(&image, &pattern),
                &strings,
                512,
            );
            let near_kind = near_kind
                .as_deref()
                .map(parse_required_string_kind)
                .transpose()?;
            let matches =
                filter_pattern_matches(matches, section.as_deref(), near_kind, with_anchor);

            if json {
                println!("{}", serde_json::to_string_pretty(&matches)?);
            } else if matches.is_empty() {
                println!("no matches");
            } else {
                let total = matches.len();
                for item in matches.iter().take(limit) {
                    println!("{}", format_pattern_match(item));
                }
                if total > limit {
                    println!("... showing {limit} of {total} matches; use --limit to adjust");
                }
            }

            Ok(())
        }
        Command::Strings {
            module,
            min_len,
            limit,
            json,
        } => {
            let image = ModuleImage::load(&module)?;
            let strings = extract_ascii_strings(&image, min_len);

            if json {
                println!("{}", serde_json::to_string_pretty(&strings)?);
            } else if strings.is_empty() {
                println!("no strings");
            } else {
                let total = strings.len();
                for item in strings.iter().take(limit) {
                    println!(
                        "{:<10} {:<16} rva={:#010x} va={:#014x} {}",
                        item.section,
                        format_string_kind(item.kind),
                        item.rva,
                        item.virtual_address,
                        item.value
                    );
                }
                if total > limit {
                    println!("... showing {limit} of {total} strings; use --limit to adjust");
                }
            }

            Ok(())
        }
        Command::Signatures { module, json } => {
            let image = ModuleImage::load(&module)?;
            let findings = run_signature_presets(&image)?;

            if json {
                println!("{}", serde_json::to_string_pretty(&findings)?);
            } else {
                for finding in findings {
                    println!(
                        "{} [{}] {} matches",
                        finding.signature,
                        finding.module_hint,
                        finding.matches.len()
                    );
                    println!("  pattern: {}", finding.pattern);
                    println!("  {}", finding.description);
                    for item in finding.matches.iter().take(20) {
                        println!("    {}", format_pattern_match(item));
                    }
                }
            }

            Ok(())
        }
        Command::Symbols { dump, module, json } => {
            let symbols = load_symbols(&dump, module.as_deref())?;

            if json {
                println!("{}", serde_json::to_string_pretty(&symbols)?);
            } else {
                for symbol in symbols {
                    println!(
                        "{:<18} {:#010x} {}",
                        symbol.module, symbol.value, symbol.name
                    );
                }
            }

            Ok(())
        }
    }
}

fn format_instruction_target(instruction: &engine::DecodedInstruction) -> String {
    match (instruction.rip_target, instruction.target_symbol.as_deref()) {
        (Some(target), Some(symbol)) => format!("=> {target:#x} {symbol}"),
        (Some(target), None) => format!("=> {target:#x}"),
        (None, Some(symbol)) => format!("=> {symbol}"),
        (None, None) => String::new(),
    }
}

fn parse_required_string_kind(input: &str) -> Result<StringKind> {
    parse_string_kind_name(input).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown string kind '{input}'. Use interface, schema, class, convar, source-path, format, decorated-symbol, or other"
        )
    })
}

fn format_pattern_match(item: &PatternMatch) -> String {
    let mut out = format!(
        "{:<10} rva={:#010x} va={:#014x}",
        item.section, item.rva, item.virtual_address
    );

    if let Some(anchor) = &item.nearby_string {
        out.push_str(&format!(
            " near +{:#x} {} {}",
            anchor.distance,
            format_string_kind(anchor.kind),
            anchor.value
        ));
    }

    out
}

fn format_string_kind(kind: StringKind) -> &'static str {
    match kind {
        StringKind::InterfaceName => "interface",
        StringKind::SchemaName => "schema",
        StringKind::ClassName => "class",
        StringKind::ConVar => "convar",
        StringKind::SourcePath => "source-path",
        StringKind::FormatString => "format",
        StringKind::DecoratedSymbol => "decorated-symbol",
        StringKind::Other => "other",
    }
}
