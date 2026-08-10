use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};
use object::{Object, ObjectSection};
use serde::Serialize;
use sysinfo::System;

#[derive(Debug, Clone, Serialize)]
pub struct SectionInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub file_range: Option<(u64, u64)>,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecodedInstruction {
    pub address: u64,
    pub bytes: String,
    pub text: String,
    pub symbol: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PatternMatch {
    pub rva: u64,
    pub virtual_address: u64,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct SymbolMap {
    pub symbols: BTreeMap<u64, Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Cs2Environment {
    pub processes: Vec<Cs2Process>,
    pub install_roots: Vec<PathBuf>,
    pub module_candidates: Vec<PathBuf>,
    pub dump_candidates: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Cs2Process {
    pub pid: String,
    pub name: String,
    pub exe: Option<PathBuf>,
}

pub struct ModuleImage {
    pub path: PathBuf,
    pub base: u64,
    bytes: Vec<u8>,
    file: object::File<'static>,
}

pub fn detect_cs2_environment() -> Cs2Environment {
    let mut system = System::new_all();
    system.refresh_all();

    let mut processes = Vec::new();
    for (pid, process) in system.processes() {
        let name = process.name().to_string_lossy().to_string();
        let lower = name.to_ascii_lowercase();
        if lower == "cs2.exe" {
            processes.push(Cs2Process {
                pid: pid.to_string(),
                name,
                exe: process.exe().map(Path::to_path_buf),
            });
        }
    }

    processes.sort_by(|a, b| a.pid.cmp(&b.pid));

    let install_roots = find_steam_cs2_roots();
    let module_candidates = find_cs2_module_candidates(&install_roots);
    let dump_candidates = find_dumper_output_candidates();

    Cs2Environment {
        processes,
        install_roots,
        module_candidates,
        dump_candidates,
    }
}

fn find_steam_cs2_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let mut steam_roots = Vec::new();

    for key in ["ProgramFiles(x86)", "ProgramFiles"] {
        if let Ok(value) = env::var(key) {
            steam_roots.push(PathBuf::from(value).join("Steam"));
        }
    }

    if let Ok(value) = env::var("STEAM_DIR") {
        steam_roots.push(PathBuf::from(value));
    }

    let mut library_roots = steam_roots.clone();
    for steam_root in &steam_roots {
        library_roots.extend(parse_steam_library_folders(steam_root));
    }

    for library_root in library_roots {
        let candidate = library_root
            .join("steamapps")
            .join("common")
            .join("Counter-Strike Global Offensive");
        if candidate.exists() && !roots.contains(&candidate) {
            roots.push(candidate);
        }
    }

    roots
}

fn parse_steam_library_folders(steam_root: &Path) -> Vec<PathBuf> {
    let path = steam_root.join("steamapps").join("libraryfolders.vdf");
    let Ok(contents) = fs::read_to_string(path) else {
        return Vec::new();
    };

    contents
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if !trimmed.starts_with("\"path\"") {
                return None;
            }

            let parts = trimmed.split('"').collect::<Vec<_>>();
            parts
                .get(3)
                .map(|value| PathBuf::from(value.replace("\\\\", "\\")))
        })
        .collect()
}

fn find_cs2_module_candidates(install_roots: &[PathBuf]) -> Vec<PathBuf> {
    let relative_modules = [
        ["game", "csgo", "bin", "win64", "client.dll"].as_slice(),
        ["game", "bin", "win64", "engine2.dll"].as_slice(),
        ["game", "bin", "win64", "schemasystem.dll"].as_slice(),
        ["game", "bin", "win64", "tier0.dll"].as_slice(),
        ["game", "bin", "win64", "vstdlib.dll"].as_slice(),
    ];

    let mut modules = Vec::new();
    for root in install_roots {
        for parts in relative_modules {
            let mut path = root.clone();
            for part in parts {
                path.push(part);
            }

            if path.exists() && !modules.contains(&path) {
                modules.push(path);
            }
        }
    }

    modules
}

fn find_dumper_output_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let Ok(current_dir) = env::current_dir() else {
        return candidates;
    };

    let mut roots = vec![current_dir.clone()];
    if let Some(parent) = current_dir.parent() {
        roots.push(parent.to_path_buf());
    }

    for root in roots {
        let paths = [
            root.join("output"),
            root.join("cs2-dumper").join("output"),
            root.join("..").join("cs2-dumper").join("output"),
        ];

        for path in paths {
            let normalized = fs::canonicalize(&path).unwrap_or(path);
            if is_dumper_output(&normalized) && !candidates.contains(&normalized) {
                candidates.push(normalized);
            }
        }
    }

    candidates
}

fn is_dumper_output(path: &Path) -> bool {
    path.join("json").join("offsets.json").exists() || path.join("offsets.json").exists()
}

impl ModuleImage {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        let leaked: &'static [u8] = Box::leak(bytes.clone().into_boxed_slice());
        let file = object::File::parse(leaked)
            .with_context(|| format!("failed to parse object file {}", path.display()))?;
        let base = file.relative_address_base();

        Ok(Self {
            path: path.to_path_buf(),
            base,
            bytes,
            file,
        })
    }

    pub fn sections(&self) -> Result<Vec<SectionInfo>> {
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

pub fn disassemble(
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

#[derive(Debug, Clone)]
pub struct Pattern(Vec<Option<u8>>);

impl Pattern {
    pub fn parse(input: &str) -> Result<Self> {
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

pub fn scan_pattern(image: &ModuleImage, pattern: &Pattern) -> Vec<PatternMatch> {
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

#[derive(Debug, Clone, Serialize)]
pub struct LoadedSymbol {
    pub module: String,
    pub name: String,
    pub value: u64,
}

pub fn load_symbol_map(dump: &Path) -> Result<SymbolMap> {
    let mut map = SymbolMap::default();
    for symbol in load_symbols(dump, None)? {
        map.symbols
            .entry(symbol.value)
            .or_default()
            .push(format!("{}!{}", symbol.module, symbol.name));
    }
    Ok(map)
}

pub fn load_symbols(dump: &Path, module_filter: Option<&str>) -> Result<Vec<LoadedSymbol>> {
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

pub fn parse_u64(input: &str) -> Result<u64> {
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
