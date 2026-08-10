use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter, Register};
use object::{Object, ObjectSection};
use serde::Serialize;
use sha2::{Digest, Sha256};
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
    pub rip_target: Option<u64>,
    pub target_symbol: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PatternMatch {
    pub rva: u64,
    pub virtual_address: u64,
    pub section: String,
    pub nearby_string: Option<NearbyStringAnchor>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NearbyStringAnchor {
    pub rva: u64,
    pub virtual_address: u64,
    pub section: String,
    pub kind: StringKind,
    pub value: String,
    pub distance: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignaturePreset {
    pub name: &'static str,
    pub module_hint: &'static str,
    pub pattern: &'static str,
    pub description: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignatureFinding {
    pub signature: String,
    pub module_hint: String,
    pub pattern: String,
    pub description: String,
    pub matches: Vec<PatternMatch>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrossReference {
    pub source: u64,
    pub target: u64,
    pub instruction: String,
    pub target_symbol: Option<String>,
    pub target_section: Option<String>,
    pub target_kind: CrossReferenceTargetKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CrossReferenceTargetKind {
    Code,
    Data,
    OutsideImage,
}

#[derive(Debug, Clone, Serialize)]
pub struct StringReference {
    pub rva: u64,
    pub virtual_address: u64,
    pub section: String,
    pub kind: StringKind,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum StringKind {
    InterfaceName,
    SchemaName,
    ClassName,
    ConVar,
    SourcePath,
    FormatString,
    DecoratedSymbol,
    Other,
}

#[derive(Debug, Serialize)]
pub struct WorkspaceReport {
    pub environment: Cs2Environment,
    pub selected_module: Option<PathBuf>,
    pub selected_dump: Option<PathBuf>,
    pub module_fingerprint: Option<ModuleFingerprint>,
    pub module_inventory: Vec<ModuleFingerprint>,
    pub health: WorkspaceHealth,
    pub sections: Vec<SectionInfo>,
    pub symbols: Vec<LoadedSymbol>,
    pub disassembly: Vec<DecodedInstruction>,
    pub cross_references: Vec<CrossReference>,
    pub strings: Vec<StringReference>,
    pub signature_findings: Vec<SignatureFinding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceHealth {
    pub status: WorkspaceHealthStatus,
    pub warnings: Vec<String>,
    pub module_loaded: bool,
    pub dump_loaded: bool,
    pub disassembly_rows: usize,
    pub cross_references: usize,
    pub strings: usize,
    pub signature_groups: usize,
    pub signature_hits: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum WorkspaceHealthStatus {
    Ready,
    Partial,
    Empty,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleFingerprint {
    pub path: PathBuf,
    pub file_name: String,
    pub size: u64,
    pub image_base: u64,
    pub sha256: String,
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

fn normalize_object_va(image_base: u64, object_address: u64) -> u64 {
    if object_address >= image_base {
        object_address
    } else {
        image_base + object_address
    }
}

fn normalize_object_rva(image_base: u64, object_address: u64) -> u64 {
    if object_address >= image_base {
        object_address - image_base
    } else {
        object_address
    }
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

pub fn fingerprint_detected_modules(environment: &Cs2Environment) -> Vec<ModuleFingerprint> {
    environment
        .module_candidates
        .iter()
        .filter_map(|path| {
            ModuleImage::load(path)
                .ok()
                .map(|image| image.fingerprint())
        })
        .collect()
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

    for root in roots.clone() {
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

    for root in roots {
        find_dumper_outputs_recursive(&root, 4, &mut candidates);
    }

    candidates
}

fn is_dumper_output(path: &Path) -> bool {
    path.join("json").join("offsets.json").exists() || path.join("offsets.json").exists()
}

fn find_dumper_outputs_recursive(root: &Path, depth: usize, candidates: &mut Vec<PathBuf>) {
    if depth == 0 || !root.exists() {
        return;
    }

    if is_dumper_output(root) {
        let normalized = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
        if !candidates.contains(&normalized) {
            candidates.push(normalized);
        }
        return;
    }

    let Ok(entries) = fs::read_dir(root) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let Some(name) = path
            .file_name()
            .map(|value| value.to_string_lossy().to_ascii_lowercase())
        else {
            continue;
        };

        if matches!(
            name.as_str(),
            ".git" | "target" | "build" | "dist" | "node_modules" | "fixtures"
        ) {
            continue;
        }

        if name == "json" && path.join("offsets.json").exists() {
            if let Some(parent) = path.parent() {
                let normalized = fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
                if !candidates.contains(&normalized) {
                    candidates.push(normalized);
                }
            }
            continue;
        }

        find_dumper_outputs_recursive(&path, depth - 1, candidates);
    }
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
                    address: normalize_object_va(self.base, section.address()),
                    size: section.size(),
                    file_range,
                    executable,
                })
            })
            .collect()
    }

    pub fn fingerprint(&self) -> ModuleFingerprint {
        ModuleFingerprint {
            path: self.path.clone(),
            file_name: self
                .path
                .file_name()
                .map(|value| value.to_string_lossy().to_string())
                .unwrap_or_else(|| self.path.display().to_string()),
            size: self.bytes.len() as u64,
            image_base: self.base,
            sha256: sha256_hex(&self.bytes),
        }
    }

    fn bytes_at_va(&self, va: u64, len: u64) -> Result<&[u8]> {
        let rva = va
            .checked_sub(self.base)
            .with_context(|| format!("address {va:#x} is below image base {:#x}", self.base))?;

        for section in self.file.sections() {
            let start = normalize_object_rva(self.base, section.address());
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

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
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
        let rip_target = rip_relative_target(&instruction);
        let target_symbol = rip_target
            .and_then(|target| symbols.symbols.get(&target).map(|items| items.join(", ")));

        instructions.push(DecodedInstruction {
            address: instruction.ip(),
            bytes: spaced,
            text: output.clone(),
            symbol,
            rip_target,
            target_symbol,
        });
    }

    Ok(instructions)
}

fn rip_relative_target(instruction: &Instruction) -> Option<u64> {
    (0..instruction.op_count())
        .find(|operand| {
            instruction.op_register(*operand) == Register::RIP
                || instruction.memory_base() == Register::RIP
        })
        .map(|_| instruction.ip_rel_memory_address())
        .filter(|target| *target != 0)
}

pub fn extract_cross_references(
    instructions: &[DecodedInstruction],
    sections: &[SectionInfo],
) -> Vec<CrossReference> {
    instructions
        .iter()
        .filter_map(|instruction| {
            let target = instruction.rip_target?;
            let (target_section, target_kind) = classify_cross_reference_target(sections, target);
            Some(CrossReference {
                source: instruction.address,
                target,
                instruction: instruction.text.clone(),
                target_symbol: instruction.target_symbol.clone(),
                target_section,
                target_kind,
            })
        })
        .collect()
}

pub fn classify_cross_reference_target(
    sections: &[SectionInfo],
    target: u64,
) -> (Option<String>, CrossReferenceTargetKind) {
    let Some(section) = sections.iter().find(|section| {
        let start = section.address;
        let end = start.saturating_add(section.size);
        target >= start && target < end
    }) else {
        return (None, CrossReferenceTargetKind::OutsideImage);
    };

    let kind = if section.executable {
        CrossReferenceTargetKind::Code
    } else {
        CrossReferenceTargetKind::Data
    };

    (Some(section.name.clone()), kind)
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
                let rva = normalize_object_rva(image.base, section.address()) + offset as u64;
                matches.push(PatternMatch {
                    rva,
                    virtual_address: image.base + rva,
                    section: section.name().unwrap_or("<unnamed>").to_string(),
                    nearby_string: None,
                });
            }
        }
    }

    matches
}

pub fn signature_presets() -> Vec<SignaturePreset> {
    vec![
        SignaturePreset {
            name: "x64 function prologue",
            module_hint: "any",
            pattern: "48 89 5C 24 ?? 57 48 83 EC ??",
            description: "Common MSVC x64 function entry sequence.",
        },
        SignaturePreset {
            name: "rip relative load",
            module_hint: "client.dll",
            pattern: "48 8B 05 ?? ?? ?? ??",
            description: "RIP-relative pointer load often used around globals and interfaces.",
        },
        SignaturePreset {
            name: "rip relative lea",
            module_hint: "client.dll",
            pattern: "48 8D 0D ?? ?? ?? ??",
            description: "RIP-relative address calculation candidate.",
        },
        SignaturePreset {
            name: "virtual call site",
            module_hint: "any",
            pattern: "48 8B 01 FF 50 ??",
            description: "Simple virtual dispatch pattern.",
        },
        SignaturePreset {
            name: "schema string reference setup",
            module_hint: "schemasystem.dll",
            pattern: "48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ??",
            description: "Adjacent RIP-relative address setup useful near schema-related string references.",
        },
    ]
}

pub fn run_signature_preset(
    image: &ModuleImage,
    preset: &SignaturePreset,
    strings: &[StringReference],
) -> Result<SignatureFinding> {
    let pattern = Pattern::parse(preset.pattern)?;
    Ok(SignatureFinding {
        signature: preset.name.to_string(),
        module_hint: preset.module_hint.to_string(),
        pattern: preset.pattern.to_string(),
        description: preset.description.to_string(),
        matches: annotate_pattern_matches_with_strings(scan_pattern(image, &pattern), strings, 512),
    })
}

pub fn run_signature_presets(image: &ModuleImage) -> Result<Vec<SignatureFinding>> {
    let strings = extract_ascii_strings(image, 5);
    signature_presets()
        .into_iter()
        .filter(|preset| {
            preset.module_hint == "any" || module_name_matches(&image.path, preset.module_hint)
        })
        .map(|preset| run_signature_preset(image, &preset, &strings))
        .collect()
}

pub fn annotate_pattern_matches_with_strings(
    mut matches: Vec<PatternMatch>,
    strings: &[StringReference],
    max_distance: u64,
) -> Vec<PatternMatch> {
    for item in &mut matches {
        item.nearby_string = nearest_string_anchor(strings, item.virtual_address, max_distance);
    }
    matches
}

pub fn filter_pattern_matches(
    matches: Vec<PatternMatch>,
    section: Option<&str>,
    anchor_kind: Option<StringKind>,
    require_anchor: bool,
) -> Vec<PatternMatch> {
    matches
        .into_iter()
        .filter(|item| {
            section.is_none_or(|section| item.section.eq_ignore_ascii_case(section))
                && anchor_kind.is_none_or(|kind| {
                    item.nearby_string
                        .as_ref()
                        .is_some_and(|anchor| anchor.kind == kind)
                })
                && (!require_anchor || item.nearby_string.is_some())
        })
        .collect()
}

pub fn parse_string_kind_name(input: &str) -> Option<StringKind> {
    match input.trim().to_ascii_lowercase().as_str() {
        "interface" | "interface-name" => Some(StringKind::InterfaceName),
        "schema" | "schema-name" => Some(StringKind::SchemaName),
        "class" | "class-name" => Some(StringKind::ClassName),
        "convar" | "con-command" | "concommand" => Some(StringKind::ConVar),
        "source" | "source-path" | "path" => Some(StringKind::SourcePath),
        "format" | "format-string" => Some(StringKind::FormatString),
        "decorated" | "decorated-symbol" => Some(StringKind::DecoratedSymbol),
        "other" => Some(StringKind::Other),
        _ => None,
    }
}

pub fn nearest_string_anchor(
    strings: &[StringReference],
    virtual_address: u64,
    max_distance: u64,
) -> Option<NearbyStringAnchor> {
    strings
        .iter()
        .filter_map(|item| {
            let distance = item.virtual_address.abs_diff(virtual_address);
            (distance <= max_distance).then_some((item, distance))
        })
        .min_by(|(left, left_distance), (right, right_distance)| {
            left_distance
                .cmp(right_distance)
                .then(left.virtual_address.cmp(&right.virtual_address))
        })
        .map(|(item, distance)| NearbyStringAnchor {
            rva: item.rva,
            virtual_address: item.virtual_address,
            section: item.section.clone(),
            kind: item.kind,
            value: item.value.clone(),
            distance,
        })
}

pub fn extract_ascii_strings(image: &ModuleImage, min_len: usize) -> Vec<StringReference> {
    let min_len = min_len.max(1);
    let mut strings = Vec::new();

    for section in image.file.sections() {
        let executable = match section.flags() {
            object::SectionFlags::Coff { characteristics } => {
                characteristics & object::pe::IMAGE_SCN_MEM_EXECUTE != 0
            }
            _ => false,
        };

        if executable {
            continue;
        }

        let Some((file_offset, file_size)) = section.file_range() else {
            continue;
        };

        let start = file_offset as usize;
        let end = start
            .saturating_add(file_size as usize)
            .min(image.bytes.len());
        let section_name = section.name().unwrap_or("<unnamed>");
        collect_ascii_strings_from_bytes(
            &mut strings,
            section_name,
            image.base,
            normalize_object_va(image.base, section.address()),
            &image.bytes[start..end],
            min_len,
        );
    }

    strings
}

fn collect_ascii_strings_from_bytes(
    out: &mut Vec<StringReference>,
    section: &str,
    image_base: u64,
    section_va: u64,
    bytes: &[u8],
    min_len: usize,
) {
    let mut start = None;

    for (index, byte) in bytes.iter().enumerate() {
        if is_ascii_string_byte(*byte) {
            start.get_or_insert(index);
            continue;
        }

        if let Some(start_index) = start.take() {
            push_ascii_string(
                out,
                section,
                image_base,
                section_va,
                bytes,
                start_index,
                index,
                min_len,
            );
        }
    }

    if let Some(start_index) = start {
        push_ascii_string(
            out,
            section,
            image_base,
            section_va,
            bytes,
            start_index,
            bytes.len(),
            min_len,
        );
    }
}

fn push_ascii_string(
    out: &mut Vec<StringReference>,
    section: &str,
    image_base: u64,
    section_va: u64,
    bytes: &[u8],
    start: usize,
    end: usize,
    min_len: usize,
) {
    if end.saturating_sub(start) < min_len {
        return;
    }

    let value = String::from_utf8_lossy(&bytes[start..end]).to_string();
    let virtual_address = section_va + start as u64;
    let kind = classify_string_value(&value);

    out.push(StringReference {
        rva: virtual_address.saturating_sub(image_base),
        virtual_address,
        section: section.to_string(),
        kind,
        value,
    });
}

fn is_ascii_string_byte(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7e)
}

pub fn classify_string_value(value: &str) -> StringKind {
    let lower = value.to_ascii_lowercase();

    if value.starts_with("Source2")
        || value.starts_with('V') && value.chars().last().is_some_and(|ch| ch.is_ascii_digit())
    {
        return StringKind::InterfaceName;
    }

    if lower.contains("schema") || value.starts_with("C_") || value.starts_with("CCS") {
        return StringKind::SchemaName;
    }

    if value.starts_with(".?AV") || value.starts_with(".?AU") || value.starts_with("??_7") {
        return StringKind::DecoratedSymbol;
    }

    if value.starts_with('C')
        && value.len() > 2
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | ':' | '<' | '>' | '$'))
        && value.chars().skip(1).any(|ch| ch.is_ascii_uppercase())
    {
        return StringKind::ClassName;
    }

    if lower.contains("convar") || lower.contains("concommand") || lower.starts_with("sv_") {
        return StringKind::ConVar;
    }

    if value.contains(":\\")
        || value.contains(":/")
        || value.contains(".cpp")
        || value.contains(".h")
    {
        return StringKind::SourcePath;
    }

    if value.contains("%s") || value.contains("%d") || value.contains("{}") {
        return StringKind::FormatString;
    }

    StringKind::Other
}

pub fn build_auto_workspace_report(
    disasm_len: u64,
    string_min_len: usize,
) -> Result<WorkspaceReport> {
    let environment = detect_cs2_environment();
    let selected_module = select_best_module(&environment.module_candidates).cloned();
    let selected_dump = environment.dump_candidates.first().cloned();
    let module_inventory = fingerprint_detected_modules(&environment);

    let mut sections = Vec::new();
    let mut disassembly = Vec::new();
    let mut cross_references = Vec::new();
    let mut signature_findings = Vec::new();
    let mut strings = Vec::new();
    let mut module_fingerprint = None;
    let mut symbols = Vec::new();
    let mut symbol_map = SymbolMap::default();

    if let Some(dump) = &selected_dump {
        symbols = load_symbols(dump, None).unwrap_or_default();
        symbol_map = load_symbol_map(dump).unwrap_or_default();
    }

    if let Some(module_path) = &selected_module {
        let image = ModuleImage::load(module_path)?;
        module_fingerprint = Some(image.fingerprint());
        sections = image.sections()?;
        if let Some(section) = sections
            .iter()
            .find(|section| section.executable)
            .or_else(|| sections.first())
        {
            disassembly = disassemble(&image, section.address, disasm_len, &symbol_map)?;
            cross_references = extract_cross_references(&disassembly, &sections);
        }
        strings = extract_ascii_strings(&image, string_min_len);
        signature_findings = run_signature_presets(&image)?;
    }

    let health = build_workspace_health(
        selected_module.is_some(),
        selected_dump.is_some(),
        &sections,
        &disassembly,
        &cross_references,
        &strings,
        &signature_findings,
    );

    Ok(WorkspaceReport {
        environment,
        selected_module,
        selected_dump,
        module_fingerprint,
        module_inventory,
        health,
        sections,
        symbols,
        disassembly,
        cross_references,
        strings,
        signature_findings,
    })
}

pub fn build_workspace_health(
    module_loaded: bool,
    dump_loaded: bool,
    sections: &[SectionInfo],
    disassembly: &[DecodedInstruction],
    cross_references: &[CrossReference],
    strings: &[StringReference],
    signature_findings: &[SignatureFinding],
) -> WorkspaceHealth {
    let signature_hits = signature_findings
        .iter()
        .map(|finding| finding.matches.len())
        .sum::<usize>();
    let mut warnings = Vec::new();

    if !module_loaded {
        warnings.push("no CS2 module was auto-loaded".to_string());
    }
    if !dump_loaded {
        warnings.push("no cs2-dumper output was auto-detected".to_string());
    }
    if sections.is_empty() {
        warnings.push("no module sections were parsed".to_string());
    }
    if disassembly.is_empty() {
        warnings.push("no disassembly rows were decoded".to_string());
    }
    if strings.is_empty() {
        warnings.push("no printable strings were extracted".to_string());
    }
    if signature_hits == 0 {
        warnings.push("built-in signatures produced no hits".to_string());
    }

    let status = if !module_loaded && !dump_loaded {
        WorkspaceHealthStatus::Empty
    } else if warnings.is_empty() {
        WorkspaceHealthStatus::Ready
    } else {
        WorkspaceHealthStatus::Partial
    };

    WorkspaceHealth {
        status,
        warnings,
        module_loaded,
        dump_loaded,
        disassembly_rows: disassembly.len(),
        cross_references: cross_references.len(),
        strings: strings.len(),
        signature_groups: signature_findings.len(),
        signature_hits,
    }
}

fn select_best_module(candidates: &[PathBuf]) -> Option<&PathBuf> {
    ["client.dll", "engine2.dll"]
        .into_iter()
        .find_map(|name| {
            candidates.iter().find(|path| {
                path.file_name()
                    .is_some_and(|file| file.to_string_lossy().eq_ignore_ascii_case(name))
            })
        })
        .or_else(|| candidates.first())
}

fn module_name_matches(path: &Path, hint: &str) -> bool {
    path.file_name()
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case(hint))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sections() -> Vec<SectionInfo> {
        vec![
            SectionInfo {
                name: ".text".to_string(),
                address: 0x1800_1000,
                size: 0x100,
                file_range: Some((0, 0x100)),
                executable: true,
            },
            SectionInfo {
                name: ".rdata".to_string(),
                address: 0x1800_3000,
                size: 0x80,
                file_range: Some((0x200, 0x80)),
                executable: false,
            },
        ]
    }

    #[test]
    fn normalizes_object_addresses_from_rva_or_already_based_va() {
        let image_base = 0x1800_0000;

        assert_eq!(normalize_object_va(image_base, 0x3000), 0x1800_3000);
        assert_eq!(normalize_object_rva(image_base, 0x3000), 0x3000);
        assert_eq!(normalize_object_va(image_base, 0x1800_3000), 0x1800_3000);
        assert_eq!(normalize_object_rva(image_base, 0x1800_3000), 0x3000);
    }

    #[test]
    fn classifies_cross_reference_targets_by_section_kind() {
        let sections = test_sections();

        assert_eq!(
            classify_cross_reference_target(&sections, 0x1800_1010),
            (Some(".text".to_string()), CrossReferenceTargetKind::Code)
        );
        assert_eq!(
            classify_cross_reference_target(&sections, 0x1800_307f),
            (Some(".rdata".to_string()), CrossReferenceTargetKind::Data)
        );
        assert_eq!(
            classify_cross_reference_target(&sections, 0x1800_3080),
            (None, CrossReferenceTargetKind::OutsideImage)
        );
    }

    #[test]
    fn extracts_only_targeted_cross_references_with_target_metadata() {
        let instructions = vec![
            DecodedInstruction {
                address: 0x1800_1000,
                bytes: "48 8B 05 00 20 00 00".to_string(),
                text: "mov rax,[rel 18003007h]".to_string(),
                symbol: None,
                rip_target: Some(0x1800_3007),
                target_symbol: Some("client.dll!offset:dwEntityList".to_string()),
            },
            DecodedInstruction {
                address: 0x1800_1007,
                bytes: "90".to_string(),
                text: "nop".to_string(),
                symbol: None,
                rip_target: None,
                target_symbol: None,
            },
        ];

        let xrefs = extract_cross_references(&instructions, &test_sections());

        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].source, 0x1800_1000);
        assert_eq!(xrefs[0].target, 0x1800_3007);
        assert_eq!(xrefs[0].target_section.as_deref(), Some(".rdata"));
        assert_eq!(xrefs[0].target_kind, CrossReferenceTargetKind::Data);
        assert_eq!(
            xrefs[0].target_symbol.as_deref(),
            Some("client.dll!offset:dwEntityList")
        );
    }

    #[test]
    fn collects_ascii_strings_with_addresses_and_minimum_length() {
        let mut strings = Vec::new();
        collect_ascii_strings_from_bytes(
            &mut strings,
            ".rdata",
            0x1800_0000,
            0x1800_3000,
            b"\0Source2Client002\0abc\0C_CSPlayerPawn\0",
            5,
        );

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].section, ".rdata");
        assert_eq!(strings[0].rva, 0x3001);
        assert_eq!(strings[0].virtual_address, 0x1800_3001);
        assert_eq!(strings[0].kind, StringKind::InterfaceName);
        assert_eq!(strings[0].value, "Source2Client002");
        assert_eq!(strings[1].rva, 0x3016);
        assert_eq!(strings[1].kind, StringKind::SchemaName);
        assert_eq!(strings[1].value, "C_CSPlayerPawn");
    }

    #[test]
    fn classifies_cs2_relevant_string_values() {
        assert_eq!(
            classify_string_value("Source2Client002"),
            StringKind::InterfaceName
        );
        assert_eq!(
            classify_string_value("C_CSPlayerPawn"),
            StringKind::SchemaName
        );
        assert_eq!(
            classify_string_value(".?AVCGameEventSystem@@"),
            StringKind::DecoratedSymbol
        );
        assert_eq!(classify_string_value("sv_cheats"), StringKind::ConVar);
        assert_eq!(
            classify_string_value("U:\\source2\\game\\client.cpp"),
            StringKind::SourcePath
        );
        assert_eq!(
            classify_string_value("failed: %s"),
            StringKind::FormatString
        );
        assert_eq!(
            classify_string_value("CHECK failed: this == other"),
            StringKind::Other
        );
        assert_eq!(classify_string_value("plain text"), StringKind::Other);
    }

    #[test]
    fn annotates_pattern_matches_with_nearest_string_anchor() {
        let strings = vec![
            StringReference {
                rva: 0x1000,
                virtual_address: 0x1800_1000,
                section: ".rdata".to_string(),
                kind: StringKind::Other,
                value: "far".to_string(),
            },
            StringReference {
                rva: 0x12f0,
                virtual_address: 0x1800_12f0,
                section: ".rdata".to_string(),
                kind: StringKind::InterfaceName,
                value: "Source2Client002".to_string(),
            },
        ];
        let matches = vec![PatternMatch {
            rva: 0x1300,
            virtual_address: 0x1800_1300,
            section: ".text".to_string(),
            nearby_string: None,
        }];

        let annotated = annotate_pattern_matches_with_strings(matches, &strings, 0x40);
        let anchor = annotated[0].nearby_string.as_ref().unwrap();

        assert_eq!(anchor.value, "Source2Client002");
        assert_eq!(anchor.distance, 0x10);
        assert_eq!(anchor.kind, StringKind::InterfaceName);
    }

    #[test]
    fn omits_string_anchor_outside_max_distance() {
        let strings = vec![StringReference {
            rva: 0x1000,
            virtual_address: 0x1800_1000,
            section: ".rdata".to_string(),
            kind: StringKind::Other,
            value: "too far".to_string(),
        }];

        assert!(nearest_string_anchor(&strings, 0x1800_1300, 0x40).is_none());
    }

    #[test]
    fn filters_pattern_matches_by_section_and_anchor_kind() {
        let matches = vec![
            PatternMatch {
                rva: 0x1000,
                virtual_address: 0x1800_1000,
                section: ".text".to_string(),
                nearby_string: Some(NearbyStringAnchor {
                    rva: 0x1100,
                    virtual_address: 0x1800_1100,
                    section: ".rdata".to_string(),
                    kind: StringKind::InterfaceName,
                    value: "Source2Client002".to_string(),
                    distance: 0x100,
                }),
            },
            PatternMatch {
                rva: 0x2000,
                virtual_address: 0x1800_2000,
                section: ".rdata".to_string(),
                nearby_string: Some(NearbyStringAnchor {
                    rva: 0x2010,
                    virtual_address: 0x1800_2010,
                    section: ".rdata".to_string(),
                    kind: StringKind::ConVar,
                    value: "sv_cheats".to_string(),
                    distance: 0x10,
                }),
            },
            PatternMatch {
                rva: 0x3000,
                virtual_address: 0x1800_3000,
                section: ".text".to_string(),
                nearby_string: None,
            },
        ];

        assert_eq!(
            filter_pattern_matches(matches.clone(), Some(".TEXT"), None, false).len(),
            2
        );
        assert_eq!(
            filter_pattern_matches(
                matches.clone(),
                None,
                Some(StringKind::InterfaceName),
                false
            )
            .len(),
            1
        );
        assert_eq!(filter_pattern_matches(matches, None, None, true).len(), 2);
    }

    #[test]
    fn parses_string_kind_filter_names() {
        assert_eq!(
            parse_string_kind_name("source-path"),
            Some(StringKind::SourcePath)
        );
        assert_eq!(
            parse_string_kind_name("decorated"),
            Some(StringKind::DecoratedSymbol)
        );
        assert_eq!(parse_string_kind_name("not-a-kind"), None);
    }

    #[test]
    fn formats_sha256_as_lowercase_hex() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"cs2"),
            "27321e07197e4d90d196e8ddec937344e6c7803f1d203d2e564eb3185e8b1ce1"
        );
    }

    #[test]
    fn fingerprints_no_modules_for_empty_environment() {
        let environment = Cs2Environment {
            processes: Vec::new(),
            install_roots: Vec::new(),
            module_candidates: Vec::new(),
            dump_candidates: Vec::new(),
        };

        assert!(fingerprint_detected_modules(&environment).is_empty());
    }

    #[test]
    fn workspace_health_reports_empty_without_module_or_dump() {
        let health = build_workspace_health(false, false, &[], &[], &[], &[], &[]);

        assert_eq!(health.status, WorkspaceHealthStatus::Empty);
        assert!(!health.warnings.is_empty());
        assert!(!health.module_loaded);
        assert!(!health.dump_loaded);
    }

    #[test]
    fn workspace_health_reports_ready_when_analysis_has_coverage() {
        let sections = test_sections();
        let disassembly = vec![DecodedInstruction {
            address: 0x1800_1000,
            bytes: "90".to_string(),
            text: "nop".to_string(),
            symbol: None,
            rip_target: None,
            target_symbol: None,
        }];
        let strings = vec![StringReference {
            rva: 0x3000,
            virtual_address: 0x1800_3000,
            section: ".rdata".to_string(),
            kind: StringKind::Other,
            value: "ready".to_string(),
        }];
        let signatures = vec![SignatureFinding {
            signature: "test".to_string(),
            module_hint: "any".to_string(),
            pattern: "90".to_string(),
            description: "test signature".to_string(),
            matches: vec![PatternMatch {
                rva: 0x1000,
                virtual_address: 0x1800_1000,
                section: ".text".to_string(),
                nearby_string: None,
            }],
        }];

        let health = build_workspace_health(
            true,
            true,
            &sections,
            &disassembly,
            &[],
            &strings,
            &signatures,
        );

        assert_eq!(health.status, WorkspaceHealthStatus::Ready);
        assert!(health.warnings.is_empty());
        assert_eq!(health.signature_hits, 1);
    }
}
