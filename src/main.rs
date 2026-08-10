use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};
use object::{Object, ObjectSection};
use serde::Serialize;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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

#[derive(Debug, Serialize)]
struct SectionInfo {
    name: String,
    address: u64,
    size: u64,
    file_range: Option<(u64, u64)>,
    executable: bool,
}

#[derive(Debug, Serialize)]
struct DecodedInstruction {
    address: u64,
    bytes: String,
    text: String,
    symbol: Option<String>,
}

#[derive(Debug, Serialize)]
struct PatternMatch {
    rva: u64,
    virtual_address: u64,
}

#[derive(Debug, Default, Serialize)]
struct SymbolMap {
    symbols: BTreeMap<u64, Vec<String>>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
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
        }
    }

    Ok(())
}

struct ModuleImage {
    base: u64,
    bytes: Vec<u8>,
    file: object::File<'static>,
}

impl ModuleImage {
    fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        let leaked: &'static [u8] = Box::leak(bytes.clone().into_boxed_slice());
        let file = object::File::parse(leaked)
            .with_context(|| format!("failed to parse object file {}", path.display()))?;
        let base = file.relative_address_base();

        Ok(Self { base, bytes, file })
    }

    fn sections(&self) -> Result<Vec<SectionInfo>> {
        self.file
            .sections()
            .map(|section| {
                let name = section.name().unwrap_or("<unnamed>").to_string();
                let file_range = section.file_range();
                let executable = match section.flags() {
                    object::SectionFlags::Coff { characteristics } => {
                        characteristics & object::pe::IMAGE_SCN_MEM_EXECUTE != 0
                    }
                    _ => false,
                };

                Ok(SectionInfo {
                    name,
                    address: self.base + section.address(),
                    size: section.size(),
                    file_range,
                    executable,
                })
            })
            .collect()
    }

    fn bytes_at_va(&self, va: u64, len: u64) -> Result<&[u8]> {
        let rva = va
            .checked_sub(self.base)
            .with_context(|| format!("address {va:#x} is below image base {:#x}", self.base))?;

        for section in self.file.sections() {
            let start = section.address();
            let end = start.saturating_add(section.size());
            if rva >= start && rva < end {
                let offset_in_section = rva - start;
                let (file_offset, file_size) = section
                    .file_range()
                    .with_context(|| format!("section has no file range for address {va:#x}"))?;
                let available = file_size.saturating_sub(offset_in_section);
                let read_len = len.min(available);
                let start = (file_offset + offset_in_section) as usize;
                let end = start
                    .saturating_add(read_len as usize)
                    .min(self.bytes.len());
                return Ok(&self.bytes[start..end]);
            }
        }

        bail!("address {va:#x} does not map to a section")
    }
}

fn disassemble(
    image: &ModuleImage,
    start_va: u64,
    len: u64,
    symbols: &SymbolMap,
) -> Result<Vec<DecodedInstruction>> {
    let bytes = image.bytes_at_va(start_va, len)?;
    let mut decoder = Decoder::with_ip(64, bytes, start_va, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    formatter.options_mut().set_digit_separator("`");

    let mut output = String::new();
    let mut instructions = Vec::new();

    while decoder.can_decode() {
        let mut instruction = Instruction::default();
        decoder.decode_out(&mut instruction);

        output.clear();
        formatter.format(&instruction, &mut output);

        let start = instruction.ip() as usize - start_va as usize;
        let end = start.saturating_add(instruction.len()).min(bytes.len());
        let encoded = hex::encode_upper(&bytes[start..end]);
        let spaced = encoded
            .as_bytes()
            .chunks(2)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join(" ");
        let symbol = symbols
            .symbols
            .get(&instruction.ip())
            .map(|items| items.join(", "));

        instructions.push(DecodedInstruction {
            address: instruction.ip(),
            bytes: spaced,
            text: output.clone(),
            symbol,
        });
    }

    Ok(instructions)
}

#[derive(Debug)]
struct Pattern(Vec<Option<u8>>);

impl Pattern {
    fn parse(input: &str) -> Result<Self> {
        let mut bytes = Vec::new();
        for token in input.split_whitespace() {
            if token == "?" || token == "??" {
                bytes.push(None);
                continue;
            }

            let value = u8::from_str_radix(token, 16)
                .with_context(|| format!("invalid pattern byte: {token}"))?;
            bytes.push(Some(value));
        }

        if bytes.is_empty() {
            bail!("pattern cannot be empty");
        }

        Ok(Self(bytes))
    }
}

fn scan_pattern(image: &ModuleImage, pattern: &Pattern) -> Vec<PatternMatch> {
    let len = pattern.0.len();
    let mut matches = Vec::new();

    for section in image.file.sections() {
        let Some((file_offset, file_size)) = section.file_range() else {
            continue;
        };

        let start = file_offset as usize;
        let end = start
            .saturating_add(file_size as usize)
            .min(image.bytes.len());
        let bytes = &image.bytes[start..end];

        if len > bytes.len() {
            continue;
        }

        for (offset, window) in bytes.windows(len).enumerate() {
            let is_match = pattern
                .0
                .iter()
                .zip(window)
                .all(|(expected, actual)| expected.is_none_or(|value| value == *actual));

            if is_match {
                let rva = section.address() + offset as u64;
                matches.push(PatternMatch {
                    rva,
                    virtual_address: image.base + rva,
                });
            }
        }
    }

    matches
}

#[derive(Debug, Serialize)]
struct LoadedSymbol {
    module: String,
    name: String,
    value: u64,
}

fn load_symbol_map(dump: &Path) -> Result<SymbolMap> {
    let mut map = SymbolMap::default();
    for symbol in load_symbols(dump, None)? {
        map.symbols
            .entry(symbol.value)
            .or_default()
            .push(format!("{}!{}", symbol.module, symbol.name));
    }
    Ok(map)
}

fn load_symbols(dump: &Path, module_filter: Option<&str>) -> Result<Vec<LoadedSymbol>> {
    let offsets = read_json_map(&json_path(dump, "offsets.json"))?;
    let buttons = read_json_map(&json_path(dump, "buttons.json")).unwrap_or_default();
    let interfaces = read_json_map(&json_path(dump, "interfaces.json")).unwrap_or_default();

    let mut symbols = Vec::new();
    collect_symbol_file(&mut symbols, "offset", &offsets, module_filter);
    collect_symbol_file(&mut symbols, "button", &buttons, module_filter);
    collect_symbol_file(&mut symbols, "interface", &interfaces, module_filter);

    symbols.sort_by(|a, b| {
        a.module
            .cmp(&b.module)
            .then(a.value.cmp(&b.value))
            .then(a.name.cmp(&b.name))
    });

    Ok(symbols)
}

fn collect_symbol_file(
    out: &mut Vec<LoadedSymbol>,
    kind: &str,
    data: &BTreeMap<String, BTreeMap<String, u64>>,
    module_filter: Option<&str>,
) {
    for (module, values) in data {
        if module_filter.is_some_and(|filter| !module.eq_ignore_ascii_case(filter)) {
            continue;
        }

        for (name, value) in values {
            out.push(LoadedSymbol {
                module: module.clone(),
                name: format!("{kind}:{name}"),
                value: *value,
            });
        }
    }
}

fn json_path(dump: &Path, name: &str) -> PathBuf {
    let grouped = dump.join("json").join(name);
    if grouped.exists() {
        grouped
    } else {
        dump.join(name)
    }
}

fn read_json_map(path: &Path) -> Result<BTreeMap<String, BTreeMap<String, u64>>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("failed to parse {}", path.display()))
}

fn parse_u64(input: &str) -> Result<u64> {
    if let Some(hex) = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).with_context(|| format!("invalid hex integer: {input}"))
    } else {
        input
            .parse::<u64>()
            .with_context(|| format!("invalid integer: {input}"))
    }
}
