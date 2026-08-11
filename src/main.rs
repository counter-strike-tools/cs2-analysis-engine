mod engine;
mod gui;

use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use engine::{
    CrossReferenceTargetKind, ModuleImage, Pattern, PatternMatch, StringKind,
    annotate_pattern_matches_with_strings, build_auto_workspace_report, derive_runtime_symbols,
    detect_cs2_environment, disassemble, extract_ascii_strings, filter_loaded_symbols,
    filter_pattern_matches, fingerprint_detected_modules, load_symbol_map, load_symbols,
    parse_string_kind_name, parse_u64, run_signature_presets, scan_pattern,
    summarize_runtime_symbols,
};
use serde::Serialize;

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
        /// Minimum printable string length for workspace string extraction.
        #[arg(long, default_value_t = 5)]
        string_min_len: usize,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Write the report to a file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Print a compact auto-workspace health and coverage summary.
    Summary {
        /// Number of bytes to disassemble from the selected executable section.
        #[arg(long, default_value_t = 512)]
        disasm_len: u64,
        /// Minimum printable string length for workspace string extraction.
        #[arg(long, default_value_t = 5)]
        string_min_len: usize,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Write the summary to a file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
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
    /// Fingerprint all auto-detected CS2 module candidates.
    Inventory {
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
    /// Auto-generate an in-memory runtime symbol dump from a CS2 module.
    RuntimeSymbols {
        /// Optional module file. If omitted, the best detected CS2 module is used.
        module: Option<PathBuf>,
        /// Minimum printable string length used for runtime string symbols.
        #[arg(long, default_value_t = 5)]
        min_len: usize,
        /// Maximum text rows to print. JSON output always includes all symbols.
        #[arg(long, default_value_t = 500)]
        limit: usize,
        /// Keep only symbols whose name or module contains this text.
        #[arg(long)]
        contains: Option<String>,
        /// Keep only a symbol kind: string, signature, interface, schema, class, convar, source-path, format, or decorated.
        #[arg(long)]
        kind: Option<String>,
        /// Keep only symbols whose address falls in this module section, for example .text or .rdata.
        #[arg(long)]
        section: Option<String>,
        /// List detected module sections and address ranges, then exit.
        #[arg(long)]
        list_sections: bool,
        /// Keep only symbols at or above this RVA. Accepts decimal or 0x-prefixed hex.
        #[arg(long)]
        rva_min: Option<String>,
        /// Keep only symbols at or below this RVA. Accepts decimal or 0x-prefixed hex.
        #[arg(long)]
        rva_max: Option<String>,
        /// Keep only symbols near this RVA. Accepts decimal or 0x-prefixed hex.
        #[arg(long)]
        rva_near: Option<String>,
        /// Radius for --rva-near. Accepts decimal or 0x-prefixed hex.
        #[arg(long, default_value = "0x100")]
        rva_radius: String,
        /// Sort generated symbols by address, name, or kind.
        #[arg(long, value_enum, default_value_t = RuntimeSymbolSort::Address)]
        sort: RuntimeSymbolSort,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// With --json, include module, filters, summaries, and symbols in one object.
        #[arg(long)]
        envelope: bool,
        /// Emit CSV with module, VA, RVA, kind, and name columns.
        #[arg(long)]
        csv: bool,
        /// With --csv, prepend comment metadata rows before the table header.
        #[arg(long)]
        csv_metadata: bool,
        /// Write the generated symbol dump to a file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
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

#[derive(Clone, Copy, Debug, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
enum RuntimeSymbolSort {
    Address,
    Name,
    Kind,
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
        Command::Workspace {
            disasm_len,
            string_min_len,
            json,
            out,
        } => {
            let report = build_auto_workspace_report(disasm_len, string_min_len)?;
            let output = if json {
                serde_json::to_string_pretty(&report)?
            } else {
                format_workspace_report_text(&report)
            };

            if let Some(path) = out {
                write_report_file(&path, &output)?;
                println!("wrote workspace report: {}", path.display());
            } else {
                println!("{output}");
            }

            Ok(())
        }
        Command::Summary {
            disasm_len,
            string_min_len,
            json,
            out,
        } => {
            let report = build_auto_workspace_report(disasm_len, string_min_len)?;
            let output = if json {
                serde_json::to_string_pretty(&build_workspace_summary(&report))?
            } else {
                format_workspace_summary_text(&report)
            };

            if let Some(path) = out {
                write_report_file(&path, &output)?;
                println!("wrote workspace summary: {}", path.display());
            } else {
                println!("{output}");
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
        Command::Inventory { json } => {
            let environment = detect_cs2_environment();
            let inventory = fingerprint_detected_modules(&environment);

            if json {
                println!("{}", serde_json::to_string_pretty(&inventory)?);
            } else if inventory.is_empty() {
                println!("no detected module candidates");
            } else {
                for item in inventory {
                    println!(
                        "{:<18} size={:<10} base={:#x} sha256={} {}",
                        item.file_name,
                        item.size,
                        item.image_base,
                        item.sha256,
                        item.path.display()
                    );
                }
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
        Command::RuntimeSymbols {
            module,
            min_len,
            limit,
            contains,
            kind,
            section,
            list_sections,
            rva_min,
            rva_max,
            rva_near,
            rva_radius,
            sort,
            json,
            envelope,
            csv,
            csv_metadata,
            out,
        } => {
            validate_runtime_symbol_output_options(json, envelope, csv, csv_metadata)?;
            let module = module
                .or_else(auto_selected_module)
                .context("no module provided and no CS2 module candidate was auto-detected")?;
            let image = ModuleImage::load(&module)?;
            let sections = image.sections()?;

            if list_sections {
                let output = if csv {
                    format_runtime_sections_csv(image.base, &sections)
                } else if json {
                    serde_json::to_string_pretty(&runtime_section_dumps(image.base, &sections))?
                } else {
                    format_runtime_sections_text(&module, image.base, &sections)
                };

                if let Some(path) = out {
                    write_report_file(&path, &output)?;
                    println!("wrote runtime section list: {}", path.display());
                } else {
                    println!("{output}");
                }

                return Ok(());
            }

            let strings = extract_ascii_strings(&image, min_len);
            let findings = run_signature_presets(&image)?;
            let symbols = derive_runtime_symbols(&image, &strings, &findings);
            let total_symbols = symbols.len();
            let total_summary = summarize_runtime_symbols(&symbols);
            let (rva_min, rva_max) = resolve_runtime_symbol_rva_window(
                rva_min.as_deref(),
                rva_max.as_deref(),
                rva_near.as_deref(),
                &rva_radius,
            )?;
            validate_runtime_symbol_rva_range(rva_min, rva_max)?;
            let mut symbols = filter_loaded_symbols(symbols, contains.as_deref(), kind.as_deref());
            symbols = filter_runtime_symbols_by_rva(symbols, image.base, rva_min, rva_max);
            symbols = filter_runtime_symbols_by_section(symbols, section.as_deref(), &sections)?;
            sort_runtime_symbols(&mut symbols, sort);
            let filtered_summary = summarize_runtime_symbols(&symbols);

            let output = if csv {
                format_runtime_symbols_csv(RuntimeSymbolsCsv {
                    module: &module,
                    module_base: image.base,
                    symbols: &symbols,
                    total_symbols,
                    filtered_summary: &filtered_summary,
                    total_summary: &total_summary,
                    sort,
                    contains: contains.as_deref(),
                    kind: kind.as_deref(),
                    section: section.as_deref(),
                    rva_min,
                    rva_max,
                    strings_scanned: strings.len(),
                    signature_hits: findings
                        .iter()
                        .map(|finding| finding.matches.len())
                        .sum::<usize>(),
                    include_metadata: csv_metadata,
                })
            } else if json {
                if envelope {
                    serde_json::to_string_pretty(&RuntimeSymbolDumpEnvelope {
                        module: module.display().to_string(),
                        module_base: image.base,
                        min_len,
                        contains: contains.clone(),
                        kind: kind.clone(),
                        section: section.clone(),
                        rva_min,
                        rva_max,
                        sort,
                        total_symbols,
                        filtered_symbols: symbols.len(),
                        total_summary: total_summary.clone(),
                        filtered_summary: filtered_summary.clone(),
                        strings_scanned: strings.len(),
                        signature_hits: findings
                            .iter()
                            .map(|finding| finding.matches.len())
                            .sum::<usize>(),
                        sections: runtime_section_dumps(image.base, &sections),
                        note: runtime_symbol_filter_note(&symbols, total_symbols)
                            .map(str::to_string),
                        symbols: symbols.clone(),
                    })?
                } else {
                    serde_json::to_string_pretty(&symbols)?
                }
            } else {
                format_runtime_symbols_text(RuntimeSymbolsText {
                    module: &module,
                    module_base: image.base,
                    symbols: &symbols,
                    total_symbols,
                    filtered_summary: &filtered_summary,
                    total_summary: &total_summary,
                    sort,
                    contains: contains.as_deref(),
                    kind: kind.as_deref(),
                    section: section.as_deref(),
                    rva_min,
                    rva_max,
                    strings_scanned: strings.len(),
                    signature_hits: findings
                        .iter()
                        .map(|finding| finding.matches.len())
                        .sum::<usize>(),
                    limit,
                })
            };

            if let Some(path) = out {
                write_report_file(&path, &output)?;
                println!("wrote runtime symbol dump: {}", path.display());
            } else {
                println!("{output}");
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

fn auto_selected_module() -> Option<PathBuf> {
    let env = detect_cs2_environment();
    ["client.dll", "engine2.dll"]
        .into_iter()
        .find_map(|name| {
            env.module_candidates.iter().find(|path| {
                path.file_name()
                    .is_some_and(|file| file.to_string_lossy().eq_ignore_ascii_case(name))
            })
        })
        .cloned()
        .or_else(|| env.module_candidates.first().cloned())
}

fn validate_runtime_symbol_output_options(
    json: bool,
    envelope: bool,
    csv: bool,
    csv_metadata: bool,
) -> Result<()> {
    if json && csv {
        anyhow::bail!("--json and --csv cannot be used together");
    }
    if envelope && !json {
        anyhow::bail!("--envelope requires --json");
    }
    if csv_metadata && !csv {
        anyhow::bail!("--csv-metadata requires --csv");
    }

    Ok(())
}

fn validate_runtime_symbol_rva_range(rva_min: Option<u64>, rva_max: Option<u64>) -> Result<()> {
    if let (Some(min), Some(max)) = (rva_min, rva_max) {
        if min > max {
            anyhow::bail!("--rva-min cannot be greater than --rva-max");
        }
    }

    Ok(())
}

fn resolve_runtime_symbol_rva_window(
    rva_min: Option<&str>,
    rva_max: Option<&str>,
    rva_near: Option<&str>,
    rva_radius: &str,
) -> Result<(Option<u64>, Option<u64>)> {
    if rva_near.is_some() && (rva_min.is_some() || rva_max.is_some()) {
        anyhow::bail!("--rva-near cannot be combined with --rva-min or --rva-max");
    }

    if let Some(center) = rva_near {
        let center = parse_u64(center).context("invalid --rva-near")?;
        let radius = parse_u64(rva_radius).context("invalid --rva-radius")?;
        return Ok((
            Some(center.saturating_sub(radius)),
            Some(center.saturating_add(radius)),
        ));
    }

    Ok((
        rva_min
            .map(parse_u64)
            .transpose()
            .context("invalid --rva-min")?,
        rva_max
            .map(parse_u64)
            .transpose()
            .context("invalid --rva-max")?,
    ))
}

fn filter_runtime_symbols_by_rva(
    symbols: Vec<engine::LoadedSymbol>,
    module_base: u64,
    rva_min: Option<u64>,
    rva_max: Option<u64>,
) -> Vec<engine::LoadedSymbol> {
    symbols
        .into_iter()
        .filter(|symbol| {
            let rva = symbol_rva(module_base, symbol.value);
            rva_min.is_none_or(|min| rva >= min) && rva_max.is_none_or(|max| rva <= max)
        })
        .collect()
}

fn filter_runtime_symbols_by_section(
    symbols: Vec<engine::LoadedSymbol>,
    section: Option<&str>,
    sections: &[engine::SectionInfo],
) -> Result<Vec<engine::LoadedSymbol>> {
    let Some(section_name) = section else {
        return Ok(symbols);
    };
    let Some(section) = sections
        .iter()
        .find(|item| item.name.eq_ignore_ascii_case(section_name))
    else {
        let available = sections
            .iter()
            .map(|item| item.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        anyhow::bail!(
            "section '{section_name}' was not found in the selected module; available sections: {available}"
        );
    };
    let start = section.address;
    let end = start.saturating_add(section.size);

    Ok(symbols
        .into_iter()
        .filter(|symbol| symbol.value >= start && symbol.value < end)
        .collect())
}

fn sort_runtime_symbols(symbols: &mut [engine::LoadedSymbol], sort: RuntimeSymbolSort) {
    match sort {
        RuntimeSymbolSort::Address => symbols.sort_by(|a, b| {
            a.value
                .cmp(&b.value)
                .then(a.module.cmp(&b.module))
                .then(a.name.cmp(&b.name))
        }),
        RuntimeSymbolSort::Name => symbols.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then(a.module.cmp(&b.module))
                .then(a.value.cmp(&b.value))
        }),
        RuntimeSymbolSort::Kind => symbols.sort_by(|a, b| {
            runtime_symbol_kind_key(&a.name)
                .cmp(runtime_symbol_kind_key(&b.name))
                .then(a.name.cmp(&b.name))
                .then(a.value.cmp(&b.value))
        }),
    }
}

fn runtime_symbol_kind_key(name: &str) -> &str {
    name.split(':').nth(1).unwrap_or(name)
}

fn symbol_rva(module_base: u64, value: u64) -> u64 {
    value.saturating_sub(module_base)
}

fn runtime_section_kind(section: &engine::SectionInfo) -> &'static str {
    if section.executable { "code" } else { "data" }
}

#[derive(Serialize)]
struct RuntimeSectionDump {
    name: String,
    va: u64,
    rva: u64,
    size: u64,
    kind: &'static str,
}

fn runtime_section_dumps(
    module_base: u64,
    sections: &[engine::SectionInfo],
) -> Vec<RuntimeSectionDump> {
    sections
        .iter()
        .map(|section| RuntimeSectionDump {
            name: section.name.clone(),
            va: section.address,
            rva: symbol_rva(module_base, section.address),
            size: section.size,
            kind: runtime_section_kind(section),
        })
        .collect()
}

fn format_runtime_sections_text(
    module: &PathBuf,
    module_base: u64,
    sections: &[engine::SectionInfo],
) -> String {
    let mut lines = Vec::new();
    lines.push(format!("module: {}", module.display()));
    lines.push(format!("module base: {module_base:#x}"));
    lines.push(format!("sections: {}", sections.len()));

    for section in sections {
        lines.push(format!(
            "{:<12} va={:#014x} rva={:#010x} size={:#x} kind={}",
            section.name,
            section.address,
            symbol_rva(module_base, section.address),
            section.size,
            runtime_section_kind(section)
        ));
    }

    lines.join("\n")
}

fn format_runtime_sections_csv(module_base: u64, sections: &[engine::SectionInfo]) -> String {
    let mut lines = vec!["name,va,rva,size,kind".to_string()];
    for section in sections {
        lines.push(format!(
            "{},{:#x},{:#x},{:#x},{}",
            csv_escape(&section.name),
            section.address,
            symbol_rva(module_base, section.address),
            section.size,
            runtime_section_kind(section)
        ));
    }
    lines.join("\n")
}

#[derive(Serialize)]
struct RuntimeSymbolDumpEnvelope {
    module: String,
    module_base: u64,
    min_len: usize,
    contains: Option<String>,
    kind: Option<String>,
    section: Option<String>,
    rva_min: Option<u64>,
    rva_max: Option<u64>,
    sort: RuntimeSymbolSort,
    total_symbols: usize,
    filtered_symbols: usize,
    total_summary: engine::RuntimeSymbolSummary,
    filtered_summary: engine::RuntimeSymbolSummary,
    strings_scanned: usize,
    signature_hits: usize,
    sections: Vec<RuntimeSectionDump>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    symbols: Vec<engine::LoadedSymbol>,
}

struct RuntimeSymbolsText<'a> {
    module: &'a PathBuf,
    module_base: u64,
    symbols: &'a [engine::LoadedSymbol],
    total_symbols: usize,
    filtered_summary: &'a engine::RuntimeSymbolSummary,
    total_summary: &'a engine::RuntimeSymbolSummary,
    sort: RuntimeSymbolSort,
    contains: Option<&'a str>,
    kind: Option<&'a str>,
    section: Option<&'a str>,
    rva_min: Option<u64>,
    rva_max: Option<u64>,
    strings_scanned: usize,
    signature_hits: usize,
    limit: usize,
}

fn format_runtime_symbols_text(input: RuntimeSymbolsText<'_>) -> String {
    let mut lines = Vec::new();
    lines.push(format!("module: {}", input.module.display()));
    lines.push(format!("module base: {:#x}", input.module_base));
    lines.push(format!(
        "runtime symbols: {} of {}",
        input.symbols.len(),
        input.total_symbols
    ));
    lines.push(format!("sort: {:?}", input.sort));
    lines.push(format!(
        "filters: contains={} kind={} section={} rva-min={} rva-max={}",
        input.contains.unwrap_or("<none>"),
        input.kind.unwrap_or("<none>"),
        input.section.unwrap_or("<none>"),
        input
            .rva_min
            .map(|value| format!("{value:#x}"))
            .unwrap_or_else(|| "<none>".to_string()),
        input
            .rva_max
            .map(|value| format!("{value:#x}"))
            .unwrap_or_else(|| "<none>".to_string())
    ));
    lines.push(format!(
        "runtime breakdown: strings={} signatures={} interfaces={} schemas={} classes={} convars={} source-paths={} formats={} decorated={} other={}",
        input.filtered_summary.strings,
        input.filtered_summary.signatures,
        input.filtered_summary.interfaces,
        input.filtered_summary.schemas,
        input.filtered_summary.classes,
        input.filtered_summary.convars,
        input.filtered_summary.source_paths,
        input.filtered_summary.formats,
        input.filtered_summary.decorated,
        input.filtered_summary.other
    ));
    if input.symbols.len() != input.total_symbols {
        lines.push(format!(
            "total breakdown: strings={} signatures={} interfaces={} schemas={} classes={} convars={} source-paths={} formats={} decorated={} other={}",
            input.total_summary.strings,
            input.total_summary.signatures,
            input.total_summary.interfaces,
            input.total_summary.schemas,
            input.total_summary.classes,
            input.total_summary.convars,
            input.total_summary.source_paths,
            input.total_summary.formats,
            input.total_summary.decorated,
            input.total_summary.other
        ));
    }
    lines.push(format!("strings scanned: {}", input.strings_scanned));
    lines.push(format!("signature hits: {}", input.signature_hits));
    if let Some(note) = runtime_symbol_filter_note(input.symbols, input.total_symbols) {
        lines.push(note.to_string());
    }

    for symbol in input.symbols.iter().take(input.limit) {
        lines.push(format!(
            "{:<18} va={:#014x} rva={:#010x} {}",
            symbol.module,
            symbol.value,
            symbol_rva(input.module_base, symbol.value),
            symbol.name
        ));
    }
    if input.symbols.len() > input.limit {
        lines.push(format!(
            "... {} more symbols",
            input.symbols.len() - input.limit
        ));
    }

    lines.join("\n")
}

struct RuntimeSymbolsCsv<'a> {
    module: &'a PathBuf,
    module_base: u64,
    symbols: &'a [engine::LoadedSymbol],
    total_symbols: usize,
    filtered_summary: &'a engine::RuntimeSymbolSummary,
    total_summary: &'a engine::RuntimeSymbolSummary,
    sort: RuntimeSymbolSort,
    contains: Option<&'a str>,
    kind: Option<&'a str>,
    section: Option<&'a str>,
    rva_min: Option<u64>,
    rva_max: Option<u64>,
    strings_scanned: usize,
    signature_hits: usize,
    include_metadata: bool,
}

fn format_runtime_symbols_csv(input: RuntimeSymbolsCsv<'_>) -> String {
    let mut lines = Vec::new();
    if input.include_metadata {
        lines.push(format!("# module={}", input.module.display()));
        lines.push(format!("# module_base={:#x}", input.module_base));
        lines.push(format!("# sort={:?}", input.sort));
        lines.push(format!(
            "# filters contains={} kind={} section={} rva_min={} rva_max={}",
            input.contains.unwrap_or("<none>"),
            input.kind.unwrap_or("<none>"),
            input.section.unwrap_or("<none>"),
            input
                .rva_min
                .map(|value| format!("{value:#x}"))
                .unwrap_or_else(|| "<none>".to_string()),
            input
                .rva_max
                .map(|value| format!("{value:#x}"))
                .unwrap_or_else(|| "<none>".to_string())
        ));
        lines.push(format!(
            "# symbols filtered={} total={}",
            input.symbols.len(),
            input.total_symbols
        ));
        lines.push(format!(
            "# filtered_breakdown strings={} signatures={} interfaces={} schemas={} classes={} convars={} source_paths={} formats={} decorated={} other={}",
            input.filtered_summary.strings,
            input.filtered_summary.signatures,
            input.filtered_summary.interfaces,
            input.filtered_summary.schemas,
            input.filtered_summary.classes,
            input.filtered_summary.convars,
            input.filtered_summary.source_paths,
            input.filtered_summary.formats,
            input.filtered_summary.decorated,
            input.filtered_summary.other
        ));
        lines.push(format!(
            "# total_breakdown strings={} signatures={} interfaces={} schemas={} classes={} convars={} source_paths={} formats={} decorated={} other={}",
            input.total_summary.strings,
            input.total_summary.signatures,
            input.total_summary.interfaces,
            input.total_summary.schemas,
            input.total_summary.classes,
            input.total_summary.convars,
            input.total_summary.source_paths,
            input.total_summary.formats,
            input.total_summary.decorated,
            input.total_summary.other
        ));
        lines.push(format!("# strings_scanned={}", input.strings_scanned));
        lines.push(format!("# signature_hits={}", input.signature_hits));
        if let Some(note) = runtime_symbol_filter_note(input.symbols, input.total_symbols) {
            lines.push(format!("# note={note}"));
        }
    }

    lines.push("module,va,rva,kind,name".to_string());
    for symbol in input.symbols {
        lines.push(format!(
            "{},{:#x},{:#x},{},{}",
            csv_escape(&symbol.module),
            symbol.value,
            symbol_rva(input.module_base, symbol.value),
            csv_escape(runtime_symbol_kind_key(&symbol.name)),
            csv_escape(&symbol.name)
        ));
    }
    lines.join("\n")
}

fn empty_runtime_symbol_filter_note() -> &'static str {
    "no runtime symbols matched the active filters; relax --contains, --kind, or RVA bounds"
}

fn runtime_symbol_filter_note(
    symbols: &[engine::LoadedSymbol],
    total_symbols: usize,
) -> Option<&'static str> {
    (symbols.is_empty() && total_symbols > 0).then_some(empty_runtime_symbol_filter_note())
}

fn csv_escape(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
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

fn format_workspace_report_text(report: &engine::WorkspaceReport) -> String {
    let mut lines = Vec::new();
    lines.push(format!("workspace health: {:?}", report.health.status));
    for warning in &report.health.warnings {
        lines.push(format!("  warning: {warning}"));
    }
    lines.push(format!(
        "health coverage: module={} dump={} disasm={} xrefs={} strings={} signatures={}/{}",
        report.health.module_loaded,
        report.health.dump_loaded,
        report.health.disassembly_rows,
        report.health.cross_references,
        report.health.strings,
        report.health.signature_groups,
        report.health.signature_hits
    ));
    lines.push(format!(
        "cs2.exe processes: {}",
        report.environment.processes.len()
    ));
    lines.push(format!(
        "install roots: {}",
        report.environment.install_roots.len()
    ));
    lines.push(format!(
        "module candidates: {}",
        report.environment.module_candidates.len()
    ));
    lines.push(format!(
        "dump candidates: {}",
        report.environment.dump_candidates.len()
    ));
    lines.push(format!(
        "selected module: {}",
        report
            .selected_module
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<none>".to_string())
    ));
    lines.push(format!(
        "selected dump: {}",
        report
            .selected_dump
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<none>".to_string())
    ));
    lines.push(format!("sections: {}", report.sections.len()));
    if let Some(fingerprint) = &report.module_fingerprint {
        lines.push(format!(
            "module fingerprint: {} size={} base={:#x}",
            fingerprint.file_name, fingerprint.size, fingerprint.image_base
        ));
        lines.push(format!("module sha256: {}", fingerprint.sha256));
    }
    lines.push(format!(
        "module inventory: {}",
        report.module_inventory.len()
    ));
    for item in &report.module_inventory {
        lines.push(format!(
            "  {:<18} size={:<10} base={:#x} sha256={}",
            item.file_name, item.size, item.image_base, item.sha256
        ));
    }
    lines.push(format!("symbols: {}", report.symbols.len()));
    lines.push(format!("runtime symbols: {}", report.runtime_symbols.len()));
    let runtime_summary = summarize_runtime_symbols(&report.runtime_symbols);
    lines.push(format!(
        "runtime symbol breakdown: strings={} signatures={} interfaces={} schemas={} classes={} convars={} source-paths={} formats={} decorated={} other={}",
        runtime_summary.strings,
        runtime_summary.signatures,
        runtime_summary.interfaces,
        runtime_summary.schemas,
        runtime_summary.classes,
        runtime_summary.convars,
        runtime_summary.source_paths,
        runtime_summary.formats,
        runtime_summary.decorated,
        runtime_summary.other
    ));
    lines.push(format!("disassembly rows: {}", report.disassembly.len()));
    lines.push(format!(
        "cross references: {}",
        report.cross_references.len()
    ));
    lines.push(format!(
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
    ));
    lines.push(format!("strings: {}", report.strings.len()));
    lines.push(format!(
        "string anchors: {} interfaces, {} schema/classes, {} convars, {} source paths",
        report
            .strings
            .iter()
            .filter(|item| item.kind == StringKind::InterfaceName)
            .count(),
        report
            .strings
            .iter()
            .filter(|item| matches!(item.kind, StringKind::SchemaName | StringKind::ClassName))
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
    ));
    let signature_hits = report
        .signature_findings
        .iter()
        .map(|finding| finding.matches.len())
        .sum::<usize>();
    lines.push(format!(
        "signature groups: {} hits: {}",
        report.signature_findings.len(),
        signature_hits
    ));
    lines.join("\n")
}

#[derive(Serialize)]
struct WorkspaceSummary {
    health: engine::WorkspaceHealth,
    selected_module: Option<String>,
    selected_dump: Option<String>,
    module_sha256: Option<String>,
    module_inventory_count: usize,
    sections: usize,
    symbols: usize,
    runtime_symbols: usize,
    runtime_string_symbols: usize,
    runtime_signature_symbols: usize,
    runtime_interface_symbols: usize,
    runtime_schema_symbols: usize,
    runtime_class_symbols: usize,
    runtime_convar_symbols: usize,
    disassembly_rows: usize,
    cross_references: usize,
    strings: usize,
    signature_groups: usize,
    signature_hits: usize,
}

fn build_workspace_summary(report: &engine::WorkspaceReport) -> WorkspaceSummary {
    let runtime_summary = summarize_runtime_symbols(&report.runtime_symbols);
    WorkspaceSummary {
        health: report.health.clone(),
        selected_module: report
            .selected_module
            .as_ref()
            .map(|path| path.display().to_string()),
        selected_dump: report
            .selected_dump
            .as_ref()
            .map(|path| path.display().to_string()),
        module_sha256: report
            .module_fingerprint
            .as_ref()
            .map(|fingerprint| fingerprint.sha256.clone()),
        module_inventory_count: report.module_inventory.len(),
        sections: report.sections.len(),
        symbols: report.symbols.len(),
        runtime_symbols: report.runtime_symbols.len(),
        runtime_string_symbols: runtime_summary.strings,
        runtime_signature_symbols: runtime_summary.signatures,
        runtime_interface_symbols: runtime_summary.interfaces,
        runtime_schema_symbols: runtime_summary.schemas,
        runtime_class_symbols: runtime_summary.classes,
        runtime_convar_symbols: runtime_summary.convars,
        disassembly_rows: report.disassembly.len(),
        cross_references: report.cross_references.len(),
        strings: report.strings.len(),
        signature_groups: report.signature_findings.len(),
        signature_hits: report
            .signature_findings
            .iter()
            .map(|finding| finding.matches.len())
            .sum(),
    }
}

fn format_workspace_summary_text(report: &engine::WorkspaceReport) -> String {
    let summary = build_workspace_summary(report);
    let mut lines = Vec::new();

    lines.push(format!("health: {:?}", summary.health.status));
    for warning in &summary.health.warnings {
        lines.push(format!("warning: {warning}"));
    }
    lines.push(format!(
        "selected module: {}",
        summary.selected_module.as_deref().unwrap_or("<none>")
    ));
    lines.push(format!(
        "selected dump: {}",
        summary.selected_dump.as_deref().unwrap_or("<none>")
    ));
    lines.push(format!(
        "module sha256: {}",
        summary.module_sha256.as_deref().unwrap_or("<none>")
    ));
    lines.push(format!(
        "coverage: modules={} sections={} symbols={} runtime-symbols={} disasm={} xrefs={} strings={} signatures={}/{}",
        summary.module_inventory_count,
        summary.sections,
        summary.symbols,
        summary.runtime_symbols,
        summary.disassembly_rows,
        summary.cross_references,
        summary.strings,
        summary.signature_groups,
        summary.signature_hits
    ));
    lines.push(format!(
        "runtime symbols: strings={} signatures={} interfaces={} schemas={} classes={} convars={}",
        summary.runtime_string_symbols,
        summary.runtime_signature_symbols,
        summary.runtime_interface_symbols,
        summary.runtime_schema_symbols,
        summary.runtime_class_symbols,
        summary.runtime_convar_symbols
    ));

    lines.join("\n")
}

fn write_report_file(path: &PathBuf, contents: &str) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create report directory {}", parent.display()))?;
    }

    fs::write(path, contents).with_context(|| format!("failed to write {}", path.display()))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sections() -> Vec<engine::SectionInfo> {
        vec![
            engine::SectionInfo {
                name: ".text".to_string(),
                address: 0x1800_1000,
                size: 0x100,
                file_range: None,
                executable: true,
            },
            engine::SectionInfo {
                name: ".rdata".to_string(),
                address: 0x1800_3000,
                size: 0x100,
                file_range: None,
                executable: false,
            },
        ]
    }

    #[test]
    fn runtime_symbol_csv_includes_va_rva_kind_and_escaped_name() {
        let symbols = vec![engine::LoadedSymbol {
            module: "client.dll".to_string(),
            name: "runtime-string:interface:Source2,Client\"002".to_string(),
            value: 0x1800_1234,
        }];

        let empty_summary = engine::RuntimeSymbolSummary::default();
        let csv = format_runtime_symbols_csv(RuntimeSymbolsCsv {
            module: &PathBuf::from("client.dll"),
            module_base: 0x1800_0000,
            symbols: &symbols,
            total_symbols: symbols.len(),
            filtered_summary: &empty_summary,
            total_summary: &empty_summary,
            sort: RuntimeSymbolSort::Address,
            contains: None,
            kind: None,
            section: None,
            rva_min: None,
            rva_max: None,
            strings_scanned: 0,
            signature_hits: 0,
            include_metadata: false,
        });
        let rows = csv.lines().collect::<Vec<_>>();

        assert_eq!(rows[0], "module,va,rva,kind,name");
        assert_eq!(
            rows[1],
            "client.dll,0x18001234,0x1234,interface,\"runtime-string:interface:Source2,Client\"\"002\""
        );
    }

    #[test]
    fn runtime_symbol_csv_can_include_comment_metadata() {
        let symbols = vec![engine::LoadedSymbol {
            module: "client.dll".to_string(),
            name: "runtime-signature:rip_relative_load:0000".to_string(),
            value: 0x1800_1000,
        }];
        let summary = engine::RuntimeSymbolSummary {
            total: 1,
            signatures: 1,
            ..engine::RuntimeSymbolSummary::default()
        };

        let csv = format_runtime_symbols_csv(RuntimeSymbolsCsv {
            module: &PathBuf::from("client.dll"),
            module_base: 0x1800_0000,
            symbols: &symbols,
            total_symbols: 3,
            filtered_summary: &summary,
            total_summary: &summary,
            sort: RuntimeSymbolSort::Kind,
            contains: Some("rip"),
            kind: Some("signature"),
            section: Some(".text"),
            rva_min: Some(0x1000),
            rva_max: Some(0x2000),
            strings_scanned: 12,
            signature_hits: 99,
            include_metadata: true,
        });
        let rows = csv.lines().collect::<Vec<_>>();

        assert_eq!(rows[0], "# module=client.dll");
        assert_eq!(rows[1], "# module_base=0x18000000");
        assert_eq!(rows[2], "# sort=Kind");
        assert_eq!(
            rows[3],
            "# filters contains=rip kind=signature section=.text rva_min=0x1000 rva_max=0x2000"
        );
        assert_eq!(rows[4], "# symbols filtered=1 total=3");
        assert_eq!(rows[8], "# signature_hits=99");
        assert_eq!(rows[9], "module,va,rva,kind,name");
    }

    #[test]
    fn runtime_symbol_csv_metadata_notes_empty_filtered_results() {
        let summary = engine::RuntimeSymbolSummary::default();
        let csv = format_runtime_symbols_csv(RuntimeSymbolsCsv {
            module: &PathBuf::from("client.dll"),
            module_base: 0x1800_0000,
            symbols: &[],
            total_symbols: 3,
            filtered_summary: &summary,
            total_summary: &summary,
            sort: RuntimeSymbolSort::Address,
            contains: Some("missing"),
            kind: None,
            section: None,
            rva_min: None,
            rva_max: None,
            strings_scanned: 12,
            signature_hits: 99,
            include_metadata: true,
        });

        assert!(csv.contains("# note=no runtime symbols matched the active filters"));
    }

    #[test]
    fn runtime_symbol_text_notes_empty_filtered_results() {
        let summary = engine::RuntimeSymbolSummary::default();
        let text = format_runtime_symbols_text(RuntimeSymbolsText {
            module: &PathBuf::from("client.dll"),
            module_base: 0x1800_0000,
            symbols: &[],
            total_symbols: 3,
            filtered_summary: &summary,
            total_summary: &summary,
            sort: RuntimeSymbolSort::Address,
            contains: Some("missing"),
            kind: None,
            section: None,
            rva_min: None,
            rva_max: None,
            strings_scanned: 12,
            signature_hits: 99,
            limit: 10,
        });

        assert!(text.contains("no runtime symbols matched the active filters"));
    }

    #[test]
    fn runtime_sections_text_includes_va_rva_size_and_kind() {
        let text = format_runtime_sections_text(
            &PathBuf::from("client.dll"),
            0x1800_0000,
            &test_sections(),
        );

        assert!(text.contains("module: client.dll"));
        assert!(text.contains("sections: 2"));
        assert!(text.contains(".text"));
        assert!(text.contains("va=0x000018001000"));
        assert!(text.contains("rva=0x00001000"));
        assert!(text.contains("size=0x100"));
        assert!(text.contains("kind=code"));
        assert!(text.contains("kind=data"));
    }

    #[test]
    fn runtime_sections_csv_includes_header_and_rows() {
        let csv = format_runtime_sections_csv(0x1800_0000, &test_sections());
        let rows = csv.lines().collect::<Vec<_>>();

        assert_eq!(rows[0], "name,va,rva,size,kind");
        assert_eq!(rows[1], ".text,0x18001000,0x1000,0x100,code");
        assert_eq!(rows[2], ".rdata,0x18003000,0x3000,0x100,data");
    }

    #[test]
    fn runtime_section_dumps_include_normalized_rva_and_kind() {
        let sections = runtime_section_dumps(0x1800_0000, &test_sections());

        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].name, ".text");
        assert_eq!(sections[0].va, 0x1800_1000);
        assert_eq!(sections[0].rva, 0x1000);
        assert_eq!(sections[0].size, 0x100);
        assert_eq!(sections[0].kind, "code");
        assert_eq!(sections[1].kind, "data");
    }

    #[test]
    fn runtime_section_json_includes_rva_and_kind_fields() {
        let sections = runtime_section_dumps(0x1800_0000, &test_sections());
        let json = serde_json::to_string(&sections).unwrap();

        assert!(json.contains("\"name\":\".text\""));
        assert!(json.contains("\"va\":402657280"));
        assert!(json.contains("\"rva\":4096"));
        assert!(json.contains("\"kind\":\"code\""));
    }

    #[test]
    fn runtime_symbol_filter_note_only_reports_empty_filtered_sets() {
        let symbols = vec![engine::LoadedSymbol {
            module: "client.dll".to_string(),
            name: "runtime-signature:rip_relative_load:0000".to_string(),
            value: 0x1800_1000,
        }];

        assert!(runtime_symbol_filter_note(&[], 3).is_some());
        assert!(runtime_symbol_filter_note(&[], 0).is_none());
        assert!(runtime_symbol_filter_note(&symbols, 3).is_none());
    }

    #[test]
    fn runtime_symbols_can_be_filtered_by_rva_window() {
        let symbols = vec![
            engine::LoadedSymbol {
                module: "client.dll".to_string(),
                name: "runtime-signature:early:0000".to_string(),
                value: 0x1800_1000,
            },
            engine::LoadedSymbol {
                module: "client.dll".to_string(),
                name: "runtime-signature:inside:0000".to_string(),
                value: 0x1800_2000,
            },
            engine::LoadedSymbol {
                module: "client.dll".to_string(),
                name: "runtime-signature:late:0000".to_string(),
                value: 0x1800_3000,
            },
        ];

        let filtered =
            filter_runtime_symbols_by_rva(symbols, 0x1800_0000, Some(0x1800), Some(0x2800));

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "runtime-signature:inside:0000");
    }

    #[test]
    fn runtime_symbols_can_be_filtered_by_section() {
        let symbols = vec![
            engine::LoadedSymbol {
                module: "client.dll".to_string(),
                name: "runtime-signature:text:0000".to_string(),
                value: 0x1800_1010,
            },
            engine::LoadedSymbol {
                module: "client.dll".to_string(),
                name: "runtime-string:rdata:0000".to_string(),
                value: 0x1800_3010,
            },
        ];

        let filtered =
            filter_runtime_symbols_by_section(symbols, Some(".TEXT"), &test_sections()).unwrap();

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "runtime-signature:text:0000");
    }

    #[test]
    fn runtime_symbol_section_filter_reports_unknown_section() {
        let err = filter_runtime_symbols_by_section(Vec::new(), Some(".missing"), &test_sections())
            .unwrap_err();

        assert!(err.to_string().contains("section '.missing' was not found"));
        assert!(
            err.to_string()
                .contains("available sections: .text, .rdata")
        );
    }

    #[test]
    fn runtime_symbol_rva_range_rejects_inverted_bounds() {
        let err = validate_runtime_symbol_rva_range(Some(0x3000), Some(0x2000)).unwrap_err();
        assert!(err.to_string().contains("--rva-min cannot be greater"));

        validate_runtime_symbol_rva_range(Some(0x1000), Some(0x2000)).unwrap();
        validate_runtime_symbol_rva_range(None, Some(0x2000)).unwrap();
        validate_runtime_symbol_rva_range(Some(0x1000), None).unwrap();
    }

    #[test]
    fn runtime_symbol_rva_near_resolves_to_window() {
        assert_eq!(
            resolve_runtime_symbol_rva_window(None, None, Some("0x2000"), "0x100").unwrap(),
            (Some(0x1f00), Some(0x2100))
        );
        assert_eq!(
            resolve_runtime_symbol_rva_window(None, None, Some("0x20"), "0x100").unwrap(),
            (Some(0), Some(0x120))
        );
    }

    #[test]
    fn runtime_symbol_rva_near_rejects_explicit_bounds() {
        let err = resolve_runtime_symbol_rva_window(Some("0x1000"), None, Some("0x2000"), "0x100")
            .unwrap_err();
        assert!(err.to_string().contains("--rva-near cannot be combined"));
    }

    #[test]
    fn runtime_symbol_rva_saturates_below_module_base() {
        assert_eq!(symbol_rva(0x1800_0000, 0x1800_1000), 0x1000);
        assert_eq!(symbol_rva(0x1800_0000, 0x1700_0000), 0);
    }

    #[test]
    fn csv_escape_quotes_special_values_only() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("needs,quote"), "\"needs,quote\"");
        assert_eq!(csv_escape("has \"quote\""), "\"has \"\"quote\"\"\"");
    }

    #[test]
    fn runtime_symbol_output_options_reject_conflicting_modes() {
        let err = validate_runtime_symbol_output_options(true, false, true, false).unwrap_err();
        assert!(err.to_string().contains("--json and --csv"));

        let err = validate_runtime_symbol_output_options(false, true, false, false).unwrap_err();
        assert!(err.to_string().contains("--envelope requires --json"));

        let err = validate_runtime_symbol_output_options(false, false, false, true).unwrap_err();
        assert!(err.to_string().contains("--csv-metadata requires --csv"));
    }

    #[test]
    fn runtime_symbol_output_options_allow_each_valid_mode() {
        validate_runtime_symbol_output_options(false, false, false, false).unwrap();
        validate_runtime_symbol_output_options(true, false, false, false).unwrap();
        validate_runtime_symbol_output_options(true, true, false, false).unwrap();
        validate_runtime_symbol_output_options(false, false, true, false).unwrap();
        validate_runtime_symbol_output_options(false, false, true, true).unwrap();
    }
}
