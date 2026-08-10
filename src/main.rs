mod engine;
mod gui;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use engine::{
    ModuleImage, Pattern, detect_cs2_environment, disassemble, load_symbol_map, load_symbols,
    parse_u64, scan_pattern,
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
    /// List executable and data sections from a PE/module file.
    Sections {
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
                        if let Some(symbol) = instruction.symbol {
                            println!("\n{}:", symbol);
                        }
                        println!(
                            "{:#014x}  {:<28} {}",
                            instruction.address, instruction.bytes, instruction.text
                        );
                    }
                }
            }

            Ok(())
        }
        Command::Scan {
            module,
            pattern,
            json,
        } => {
            let image = ModuleImage::load(&module)?;
            let pattern = Pattern::parse(&pattern)?;
            let matches = scan_pattern(&image, &pattern);

            if json {
                println!("{}", serde_json::to_string_pretty(&matches)?);
            } else if matches.is_empty() {
                println!("no matches");
            } else {
                for item in matches {
                    println!("rva={:#x} va={:#x}", item.rva, item.virtual_address);
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
