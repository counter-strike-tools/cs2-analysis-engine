use std::{fmt::Write, path::PathBuf};

use anyhow::Result;
use eframe::egui::{self, Color32, RichText, TextEdit};

use crate::engine::{
    CrossReference, CrossReferenceTargetKind, Cs2Environment, DecodedInstruction, LoadedSymbol,
    ModuleImage, Pattern, PatternMatch, SectionInfo, SignatureFinding, StringKind, StringReference,
    SymbolMap, annotate_pattern_matches_with_strings, detect_cs2_environment, disassemble,
    extract_ascii_strings, extract_cross_references, filter_pattern_matches, load_symbol_map,
    load_symbols, parse_string_kind_name, parse_u64, run_signature_presets, scan_pattern,
};

pub fn run_gui() -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("CS2 Analysis Engine")
            .with_inner_size([1320.0, 860.0])
            .with_min_inner_size([980.0, 640.0]),
        ..Default::default()
    };

    eframe::run_native(
        "CS2 Analysis Engine",
        options,
        Box::new(|cc| {
            configure_style(&cc.egui_ctx);
            Ok(Box::<AnalysisApp>::default())
        }),
    )
    .map_err(|err| anyhow::anyhow!(err.to_string()))
}

fn configure_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals.dark_mode = true;
    style.visuals.window_fill = Color32::from_rgb(9, 12, 15);
    style.visuals.panel_fill = Color32::from_rgb(9, 12, 15);
    style.visuals.extreme_bg_color = Color32::from_rgb(5, 7, 9);
    style.visuals.faint_bg_color = Color32::from_rgb(17, 23, 28);
    style.visuals.selection.bg_fill = Color32::from_rgb(51, 190, 113);
    style.spacing.item_spacing = egui::vec2(10.0, 8.0);
    ctx.set_style(style);
}

struct AnalysisApp {
    env: Cs2Environment,
    module_path: String,
    dump_path: String,
    module: Option<ModuleImage>,
    sections: Vec<SectionInfo>,
    symbols: Vec<LoadedSymbol>,
    symbol_map: SymbolMap,
    selected_section: Option<usize>,
    disasm_start: String,
    disasm_len: String,
    disasm_is_rva: bool,
    scan_pattern_text: String,
    scan_section_filter: String,
    scan_anchor_kind_filter: String,
    scan_require_anchor: bool,
    instructions: Vec<DecodedInstruction>,
    cross_references: Vec<CrossReference>,
    strings: Vec<StringReference>,
    scan_matches: Vec<PatternMatch>,
    signature_findings: Vec<SignatureFinding>,
    status: String,
    output: String,
    active_tab: Tab,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Tab {
    #[default]
    Overview,
    ModuleMap,
    Strings,
    Signatures,
    DumperData,
    Report,
}

impl Default for AnalysisApp {
    fn default() -> Self {
        let mut app = Self {
            env: detect_cs2_environment(),
            module_path: String::new(),
            dump_path: String::new(),
            module: None,
            sections: Vec::new(),
            symbols: Vec::new(),
            symbol_map: SymbolMap::default(),
            selected_section: None,
            disasm_start: String::new(),
            disasm_len: "256".to_string(),
            disasm_is_rva: false,
            scan_pattern_text: String::new(),
            scan_section_filter: String::new(),
            scan_anchor_kind_filter: String::new(),
            scan_require_anchor: false,
            instructions: Vec::new(),
            cross_references: Vec::new(),
            strings: Vec::new(),
            scan_matches: Vec::new(),
            signature_findings: Vec::new(),
            status: String::new(),
            output: String::new(),
            active_tab: Tab::Overview,
        };
        app.auto_load_workspace();
        app
    }
}

impl eframe::App for AnalysisApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| self.top_bar(ui));
        egui::SidePanel::left("left")
            .resizable(true)
            .default_width(320.0)
            .width_range(270.0..=460.0)
            .show(ctx, |ui| self.sidebar(ui));
        egui::CentralPanel::default().show(ctx, |ui| self.main_panel(ui));
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new("READ-ONLY")
                        .color(Color32::from_rgb(124, 255, 178))
                        .strong(),
                );
                ui.separator();
                ui.label(if self.status.is_empty() {
                    "Static CS2 workspace. Prioritizes cs2.exe context, analyzes files, and never attaches to the live game."
                } else {
                    &self.status
                });
            });
        });
    }
}

impl AnalysisApp {
    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            ui.heading("CS2 Analysis Engine");
            ui.separator();
            ui.label("CS2-first workspace, module intelligence, signatures, dumper data");
        });
        ui.add_space(4.0);
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        ui.heading("CS2 workspace");
        if ui.button("Refresh CS2 context").clicked() {
            self.refresh_environment();
        }

        ui.add_space(10.0);
        self.cs2_context_card(ui);

        ui.add_space(16.0);
        ui.label("Module file");
        ui.horizontal(|ui| {
            ui.add(TextEdit::singleline(&mut self.module_path).hint_text("client.dll"));
            if ui.button("Browse").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("PE files", &["dll", "exe"])
                    .pick_file()
                {
                    self.module_path = path.display().to_string();
                }
            }
        });

        if ui.button("Load module").clicked() {
            self.load_module();
        }

        ui.add_space(14.0);
        ui.label("cs2-dumper output");
        ui.horizontal(|ui| {
            ui.add(TextEdit::singleline(&mut self.dump_path).hint_text("output"));
            if ui.button("Browse").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    self.dump_path = path.display().to_string();
                }
            }
        });

        if ui.button("Load symbols").clicked() {
            self.load_symbols();
        }

        ui.add_space(18.0);
        self.module_summary(ui);

        ui.add_space(18.0);
        ui.heading("Module sections");
        egui::ScrollArea::vertical()
            .id_salt("sections")
            .max_height(320.0)
            .show(ui, |ui| {
                if self.sections.is_empty() {
                    ui.label("No module loaded.");
                }

                for index in 0..self.sections.len() {
                    let section = &self.sections[index];
                    let label = format!(
                        "{}  {:#x}  {}",
                        section.name,
                        section.address,
                        if section.executable { "code" } else { "data" }
                    );
                    if ui
                        .selectable_label(self.selected_section == Some(index), label)
                        .clicked()
                    {
                        self.selected_section = Some(index);
                        self.disasm_start = format!("0x{:x}", section.address);
                        self.disasm_is_rva = false;
                    }
                }
            });
    }

    fn cs2_context_card(&mut self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.label(RichText::new("Detected context").strong());
            ui.horizontal(|ui| {
                ui.label("Processes:");
                ui.label(self.env.processes.len().to_string());
                ui.separator();
                ui.label("Installs:");
                ui.label(self.env.install_roots.len().to_string());
                ui.separator();
                ui.label("Modules:");
                ui.label(self.env.module_candidates.len().to_string());
                ui.separator();
                ui.label("Dumps:");
                ui.label(self.env.dump_candidates.len().to_string());
            });

            if self.env.processes.is_empty() {
                ui.label(
                    RichText::new("cs2.exe is not currently visible in the process list.")
                        .color(Color32::GRAY),
                );
            } else {
                for process in &self.env.processes {
                    ui.monospace(format!(
                        "{} pid={} {}",
                        process.name,
                        process.pid,
                        process
                            .exe
                            .as_ref()
                            .map(|path| path.display().to_string())
                            .unwrap_or_else(|| "<path unavailable>".to_string())
                    ));
                }
            }

            if !self.env.module_candidates.is_empty() {
                ui.separator();
                ui.label("Quick-load module");
                let module_candidates = self.env.module_candidates.clone();
                for module in module_candidates.iter().take(5) {
                    let file_name = module
                        .file_name()
                        .map(|value| value.to_string_lossy().to_string())
                        .unwrap_or_else(|| module.display().to_string());
                    if ui.button(file_name).clicked() {
                        self.module_path = module.display().to_string();
                        self.load_module();
                    }
                }
            }

            if !self.env.dump_candidates.is_empty() {
                ui.separator();
                ui.label("Auto-detected dump data");
                let dump_candidates = self.env.dump_candidates.clone();
                for dump in dump_candidates.iter().take(3) {
                    let label = dump.display().to_string();
                    if ui.button(label).clicked() {
                        self.dump_path = dump.display().to_string();
                        self.load_symbols();
                    }
                }
            }
        });
    }

    fn module_summary(&self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.label(RichText::new("Analysis scope").strong());
            ui.label("Static files only. No process attach. No memory writes. No injection.");

            if let Some(module) = &self.module {
                ui.separator();
                ui.monospace(format!("base: {:#x}", module.base));
                ui.monospace(format!("file: {}", module.path.display()));
                ui.monospace(format!("sections: {}", self.sections.len()));
                ui.monospace(format!("symbols: {}", self.symbols.len()));
            }
        });
    }

    fn main_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            self.tab_button(ui, Tab::Overview, "Overview");
            self.tab_button(ui, Tab::ModuleMap, "Module map");
            self.tab_button(ui, Tab::Strings, "Strings");
            self.tab_button(ui, Tab::Signatures, "Signatures");
            self.tab_button(ui, Tab::DumperData, "Dumper data");
            self.tab_button(ui, Tab::Report, "Report");
        });
        ui.separator();

        match self.active_tab {
            Tab::Overview => self.overview_tab(ui),
            Tab::ModuleMap => self.module_map_tab(ui),
            Tab::Strings => self.strings_tab(ui),
            Tab::Signatures => self.signatures_tab(ui),
            Tab::DumperData => self.dumper_data_tab(ui),
            Tab::Report => self.report_tab(ui),
        }
    }

    fn tab_button(&mut self, ui: &mut egui::Ui, tab: Tab, label: &str) {
        if ui.selectable_label(self.active_tab == tab, label).clicked() {
            self.active_tab = tab;
        }
    }

    fn overview_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("CS2 analysis dashboard");
        ui.label("Start from a detected install/module, load dumper output, then scan or inspect only the files you choose.");
        ui.add_space(14.0);

        egui::Grid::new("overview_cards")
            .num_columns(2)
            .spacing([16.0, 16.0])
            .show(ui, |ui| {
                self.summary_card(
                    ui,
                    "Runtime context",
                    &format!(
                        "{} process entries, {} install roots",
                        self.env.processes.len(),
                        self.env.install_roots.len()
                    ),
                );
                self.summary_card(
                    ui,
                    "Loaded module",
                    self.module
                        .as_ref()
                        .map(|module| module.path.display().to_string())
                        .unwrap_or_else(|| "No module loaded".to_string())
                        .as_str(),
                );
                ui.end_row();
                self.summary_card(ui, "Sections", &self.sections.len().to_string());
                self.summary_card(ui, "Dumper symbols", &self.symbols.len().to_string());
                ui.end_row();
                self.summary_card(
                    ui,
                    "Auto candidates",
                    &format!(
                        "{} modules, {} dumps",
                        self.env.module_candidates.len(),
                        self.env.dump_candidates.len()
                    ),
                );
                self.summary_card(ui, "Disassembly rows", &self.instructions.len().to_string());
                ui.end_row();
                self.summary_card(
                    ui,
                    "Cross references",
                    &self.cross_references.len().to_string(),
                );
                self.summary_card(
                    ui,
                    "Symbol xrefs",
                    &self
                        .cross_references
                        .iter()
                        .filter(|xref| xref.target_symbol.is_some())
                        .count()
                        .to_string(),
                );
                ui.end_row();
                self.summary_card(ui, "Module strings", &self.strings.len().to_string());
                self.summary_card(
                    ui,
                    "Interface strings",
                    &self
                        .string_kind_count(StringKind::InterfaceName)
                        .to_string(),
                );
                ui.end_row();
                self.summary_card(
                    ui,
                    "Schema/class strings",
                    &format!(
                        "{} schema, {} class",
                        self.string_kind_count(StringKind::SchemaName),
                        self.string_kind_count(StringKind::ClassName)
                    ),
                );
                self.summary_card(
                    ui,
                    "Convars/source paths",
                    &format!(
                        "{} convars, {} paths",
                        self.string_kind_count(StringKind::ConVar),
                        self.string_kind_count(StringKind::SourcePath)
                    ),
                );
                ui.end_row();
                self.summary_card(
                    ui,
                    "Code/data xrefs",
                    &format!(
                        "{} code, {} data",
                        self.cross_reference_kind_count(CrossReferenceTargetKind::Code),
                        self.cross_reference_kind_count(CrossReferenceTargetKind::Data)
                    ),
                );
                self.summary_card(
                    ui,
                    "Outside-image xrefs",
                    &self
                        .cross_reference_kind_count(CrossReferenceTargetKind::OutsideImage)
                        .to_string(),
                );
                ui.end_row();
                self.summary_card(
                    ui,
                    "Signature groups",
                    &self.signature_findings.len().to_string(),
                );
                self.summary_card(
                    ui,
                    "Signature hits",
                    &self
                        .signature_findings
                        .iter()
                        .map(|finding| finding.matches.len())
                        .sum::<usize>()
                        .to_string(),
                );
                ui.end_row();
            });

        ui.add_space(18.0);
        ui.heading("Recommended next actions");
        ui.horizontal_wrapped(|ui| {
            if ui.button("Auto-load CS2 workspace").clicked() {
                self.auto_load_workspace();
            }
            if ui.button("Load detected client.dll").clicked() {
                self.load_first_named_module("client.dll");
            }
            if ui.button("Load detected engine2.dll").clicked() {
                self.load_first_named_module("engine2.dll");
            }
            if ui.button("Disassemble entry section").clicked() {
                self.run_disassembly();
            }
            if ui.button("Find built-in signatures").clicked() {
                self.run_signature_findings();
            }
            if ui.button("Extract strings").clicked() {
                self.run_string_extraction();
            }
            if ui.button("Build report").clicked() {
                self.build_report();
                self.active_tab = Tab::Report;
            }
        });
    }

    fn summary_card(&self, ui: &mut egui::Ui, title: &str, value: &str) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_min_size(egui::vec2(280.0, 92.0));
            ui.label(
                RichText::new(title)
                    .color(Color32::from_rgb(124, 255, 178))
                    .strong(),
            );
            ui.label(value);
        });
    }

    fn module_map_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label("Start");
            ui.add_sized([150.0, 24.0], TextEdit::singleline(&mut self.disasm_start));
            ui.label("Bytes");
            ui.add_sized([84.0, 24.0], TextEdit::singleline(&mut self.disasm_len));
            ui.checkbox(&mut self.disasm_is_rva, "RVA");
            if ui.button("Disassemble").clicked() {
                self.run_disassembly();
            }
            if ui.button("Copy report").clicked() {
                ui.ctx().copy_text(self.output.clone());
            }
        });

        ui.add_space(8.0);
        ui.heading("Disassembly");
        egui::ScrollArea::both().id_salt("disasm").show(ui, |ui| {
            if self.instructions.is_empty() {
                ui.label("Choose a section or address, then disassemble. This reads module bytes from disk only.");
                return;
            }

            egui::Grid::new("instruction_grid")
                .striped(true)
                .num_columns(5)
                .show(ui, |ui| {
                    ui.strong("Address");
                    ui.strong("Bytes");
                    ui.strong("Instruction");
                    ui.strong("Target");
                    ui.strong("Symbol");
                    ui.end_row();

                    for instruction in &self.instructions {
                        ui.monospace(format!("{:#014x}", instruction.address));
                        ui.monospace(&instruction.bytes);
                        ui.monospace(&instruction.text);
                        ui.monospace(format_instruction_target(instruction));
                        ui.label(instruction.symbol.as_deref().unwrap_or(""));
                        ui.end_row();
                    }
                });
        });
    }

    fn strings_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label(format!("Extracted strings: {}", self.strings.len()));
            if ui.button("Extract strings").clicked() {
                self.run_string_extraction();
            }
            if ui.button("Copy strings").clicked() {
                ui.ctx().copy_text(self.output.clone());
            }
        });

        ui.add_space(8.0);
        ui.label("Reads printable strings from non-executable module sections on disk.");

        egui::ScrollArea::both().id_salt("strings").show(ui, |ui| {
            if self.strings.is_empty() {
                ui.label("String references will appear here after a module is loaded.");
                return;
            }

            egui::Grid::new("strings_grid")
                .striped(true)
                .num_columns(5)
                .show(ui, |ui| {
                    ui.strong("Section");
                    ui.strong("Kind");
                    ui.strong("RVA");
                    ui.strong("VA");
                    ui.strong("Value");
                    ui.end_row();

                    for item in self.strings.iter().take(500) {
                        ui.monospace(&item.section);
                        ui.label(format_string_kind(item.kind));
                        ui.monospace(format!("{:#010x}", item.rva));
                        ui.monospace(format!("{:#014x}", item.virtual_address));
                        ui.label(&item.value);
                        ui.end_row();
                    }
                });
        });
    }

    fn signatures_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label("Pattern");
            ui.add_sized(
                [420.0, 24.0],
                TextEdit::singleline(&mut self.scan_pattern_text).hint_text("48 8B ?? ?? 89"),
            );
            if ui.button("Scan sections").clicked() {
                self.run_scan();
            }
            if ui.button("Run built-in finders").clicked() {
                self.run_signature_findings();
            }
            if ui.button("Copy matches").clicked() {
                ui.ctx().copy_text(self.output.clone());
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("Section");
            ui.add_sized(
                [96.0, 24.0],
                TextEdit::singleline(&mut self.scan_section_filter).hint_text(".text"),
            );
            ui.label("Nearby kind");
            ui.add_sized(
                [132.0, 24.0],
                TextEdit::singleline(&mut self.scan_anchor_kind_filter).hint_text("interface"),
            );
            ui.checkbox(&mut self.scan_require_anchor, "Has nearby string");
        });

        ui.add_space(8.0);
        ui.label(
            "Scans the loaded module file by section and reports RVAs/VAs. Wildcards use ? or ??.",
        );
        if !self.signature_findings.is_empty() {
            ui.add_space(8.0);
            ui.heading("Built-in signature findings");
            egui::Grid::new("signature_finding_grid")
                .striped(true)
                .num_columns(4)
                .show(ui, |ui| {
                    ui.strong("Signature");
                    ui.strong("Hint");
                    ui.strong("Matches");
                    ui.strong("Pattern");
                    ui.end_row();

                    for finding in &self.signature_findings {
                        ui.label(&finding.signature);
                        ui.label(&finding.module_hint);
                        ui.label(finding.matches.len().to_string());
                        ui.monospace(&finding.pattern);
                        ui.end_row();
                    }
                });
            ui.separator();
        }
        egui::ScrollArea::both().id_salt("scan").show(ui, |ui| {
            if self.scan_matches.is_empty() {
                ui.label("Pattern matches will appear here.");
                return;
            }

            egui::Grid::new("scan_grid")
                .striped(true)
                .num_columns(4)
                .show(ui, |ui| {
                    ui.strong("Section");
                    ui.strong("RVA");
                    ui.strong("Virtual address");
                    ui.strong("Nearby string");
                    ui.end_row();

                    for item in &self.scan_matches {
                        ui.monospace(&item.section);
                        ui.monospace(format!("{:#010x}", item.rva));
                        ui.monospace(format!("{:#014x}", item.virtual_address));
                        ui.label(format_nearby_string(item));
                        ui.end_row();
                    }
                });
        });
    }

    fn dumper_data_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label(format!("Loaded symbols: {}", self.symbols.len()));
            if ui.button("Copy symbols").clicked() {
                ui.ctx().copy_text(self.output.clone());
            }
        });
        ui.add_space(8.0);

        egui::ScrollArea::both().id_salt("symbols").show(ui, |ui| {
            if self.symbols.is_empty() {
                ui.label(
                    "Load a cs2-dumper output folder to view offsets, buttons, and interfaces.",
                );
                return;
            }

            egui::Grid::new("symbol_grid")
                .striped(true)
                .num_columns(3)
                .show(ui, |ui| {
                    ui.strong("Module");
                    ui.strong("Value");
                    ui.strong("Name");
                    ui.end_row();

                    for symbol in &self.symbols {
                        ui.monospace(&symbol.module);
                        ui.monospace(format!("{:#010x}", symbol.value));
                        ui.label(&symbol.name);
                        ui.end_row();
                    }
                });
        });
    }

    fn report_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("Build workspace report").clicked() {
                self.build_report();
            }
            if ui.button("Copy").clicked() {
                ui.ctx().copy_text(self.output.clone());
            }
        });
        ui.add_space(8.0);
        ui.add(
            TextEdit::multiline(&mut self.output)
                .font(egui::TextStyle::Monospace)
                .desired_rows(32)
                .desired_width(f32::INFINITY),
        );
    }

    fn load_module(&mut self) {
        match ModuleImage::load(PathBuf::from(self.module_path.trim()).as_path()) {
            Ok(module) => match module.sections() {
                Ok(sections) => {
                    self.disasm_len = if self.disasm_len.is_empty() {
                        "256".to_string()
                    } else {
                        self.disasm_len.clone()
                    };
                    self.disasm_start = sections
                        .iter()
                        .find(|section| section.executable)
                        .or_else(|| sections.first())
                        .map(|section| format!("0x{:x}", section.address))
                        .unwrap_or_default();
                    self.selected_section = sections
                        .iter()
                        .position(|section| section.executable)
                        .or(Some(0));
                    self.module = Some(module);
                    self.sections = sections;
                    self.instructions.clear();
                    self.cross_references.clear();
                    self.strings.clear();
                    self.scan_matches.clear();
                    self.signature_findings.clear();
                    self.status = format!("Loaded module with {} sections.", self.sections.len());
                    self.auto_disassemble_loaded_module();
                }
                Err(err) => self.set_error(err),
            },
            Err(err) => self.set_error(err),
        }
    }

    fn load_symbols(&mut self) {
        let dump = PathBuf::from(self.dump_path.trim());
        match (load_symbols(&dump, None), load_symbol_map(&dump)) {
            (Ok(symbols), Ok(symbol_map)) => {
                self.status = format!("Loaded {} symbols.", symbols.len());
                self.symbols = symbols;
                self.symbol_map = symbol_map;
                self.active_tab = Tab::DumperData;
                self.build_symbol_output();
            }
            (Err(err), _) | (_, Err(err)) => self.set_error(err),
        }
    }

    fn run_disassembly(&mut self) {
        let Some(module) = &self.module else {
            self.status = "Load a module before disassembling.".to_string();
            return;
        };

        let parsed = parse_u64(self.disasm_start.trim()).and_then(|start| {
            self.disasm_len
                .trim()
                .parse::<u64>()
                .map(|len| (start, len))
                .map_err(anyhow::Error::from)
        });

        match parsed {
            Ok((start, len)) => {
                let address = if self.disasm_is_rva {
                    module.base + start
                } else {
                    start
                };
                match disassemble(module, address, len, &self.symbol_map) {
                    Ok(instructions) => {
                        self.status = format!("Decoded {} instructions.", instructions.len());
                        self.instructions = instructions;
                        self.cross_references =
                            extract_cross_references(&self.instructions, &self.sections);
                        self.active_tab = Tab::ModuleMap;
                        self.build_disasm_output();
                    }
                    Err(err) => self.set_error(err),
                }
            }
            Err(err) => self.set_error(err),
        }
    }

    fn run_scan(&mut self) {
        let Some(module) = &self.module else {
            self.status = "Load a module before scanning.".to_string();
            return;
        };

        match Pattern::parse(self.scan_pattern_text.trim()) {
            Ok(pattern) => {
                let strings = if self.strings.is_empty() {
                    extract_ascii_strings(module, 5)
                } else {
                    self.strings.clone()
                };
                let matches = annotate_pattern_matches_with_strings(
                    scan_pattern(module, &pattern),
                    &strings,
                    512,
                );
                let section = non_empty_trimmed(&self.scan_section_filter);
                let anchor_kind = match non_empty_trimmed(&self.scan_anchor_kind_filter) {
                    Some(value) => match parse_string_kind_name(value) {
                        Some(kind) => Some(kind),
                        None => {
                            self.status = format!(
                                "Unknown nearby kind '{value}'. Use interface, schema, class, convar, source-path, format, decorated-symbol, or other."
                            );
                            return;
                        }
                    },
                    None => None,
                };
                let matches =
                    filter_pattern_matches(matches, section, anchor_kind, self.scan_require_anchor);
                self.strings = strings;
                self.scan_matches = matches;
                self.status = format!("Found {} matches.", self.scan_matches.len());
                self.active_tab = Tab::Signatures;
                self.build_scan_output();
            }
            Err(err) => self.set_error(err),
        }
    }

    fn run_string_extraction(&mut self) {
        let Some(module) = &self.module else {
            self.status = "Load a module before extracting strings.".to_string();
            return;
        };

        self.strings = extract_ascii_strings(module, 5);
        self.status = format!("Extracted {} strings.", self.strings.len());
        self.active_tab = Tab::Strings;
        self.build_string_output();
    }

    fn run_signature_findings(&mut self) {
        let Some(module) = &self.module else {
            self.status = "Load a module before running signature finders.".to_string();
            return;
        };

        match run_signature_presets(module) {
            Ok(findings) => {
                let hits = findings
                    .iter()
                    .map(|finding| finding.matches.len())
                    .sum::<usize>();
                self.status = format!(
                    "Ran {} signature groups and found {} total hits.",
                    findings.len(),
                    hits
                );
                self.signature_findings = findings;
                self.active_tab = Tab::Signatures;
                self.build_signature_output();
            }
            Err(err) => self.set_error(err),
        }
    }

    fn build_report(&mut self) {
        let mut report = String::new();
        writeln!(&mut report, "CS2 Analysis Engine report").ok();
        writeln!(&mut report, "scope: read-only offline analysis").ok();
        writeln!(
            &mut report,
            "detected processes: {}",
            self.env.processes.len()
        )
        .ok();
        for process in &self.env.processes {
            writeln!(
                &mut report,
                "  {} pid={} {}",
                process.name,
                process.pid,
                process
                    .exe
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "<path unavailable>".to_string())
            )
            .ok();
        }
        writeln!(
            &mut report,
            "detected install roots: {}",
            self.env.install_roots.len()
        )
        .ok();
        for root in &self.env.install_roots {
            writeln!(&mut report, "  {}", root.display()).ok();
        }

        if let Some(module) = &self.module {
            writeln!(&mut report, "module: {}", module.path.display()).ok();
            writeln!(&mut report, "base: {:#x}", module.base).ok();
        }

        writeln!(&mut report, "sections: {}", self.sections.len()).ok();
        for section in &self.sections {
            writeln!(
                &mut report,
                "  {:<12} va={:#014x} size={:#x} {}",
                section.name,
                section.address,
                section.size,
                if section.executable { "code" } else { "data" }
            )
            .ok();
        }

        writeln!(&mut report, "symbols: {}", self.symbols.len()).ok();
        writeln!(
            &mut report,
            "last disassembly rows: {}",
            self.instructions.len()
        )
        .ok();
        writeln!(
            &mut report,
            "cross references: {}",
            self.cross_references.len()
        )
        .ok();
        for xref in self.cross_references.iter().take(50) {
            writeln!(
                &mut report,
                "  {:#014x} -> {:#014x} {:<13} {:<12} {} {}",
                xref.source,
                xref.target,
                format_cross_reference_kind(xref.target_kind),
                xref.target_section.as_deref().unwrap_or("<no section>"),
                xref.instruction,
                xref.target_symbol.as_deref().unwrap_or("")
            )
            .ok();
        }
        writeln!(&mut report, "strings: {}", self.strings.len()).ok();
        for item in self.strings.iter().take(80) {
            writeln!(
                &mut report,
                "  {:<10} {:<16} rva={:#010x} va={:#014x} {}",
                item.section,
                format_string_kind(item.kind),
                item.rva,
                item.virtual_address,
                item.value
            )
            .ok();
        }
        writeln!(
            &mut report,
            "last pattern matches: {}",
            self.scan_matches.len()
        )
        .ok();
        for item in self.scan_matches.iter().take(80) {
            writeln!(&mut report, "  {}", format_pattern_match(item)).ok();
        }
        writeln!(
            &mut report,
            "signature groups: {}",
            self.signature_findings.len()
        )
        .ok();
        writeln!(
            &mut report,
            "signature hits: {}",
            self.signature_findings
                .iter()
                .map(|finding| finding.matches.len())
                .sum::<usize>()
        )
        .ok();
        self.output = report;
    }

    fn build_disasm_output(&mut self) {
        let mut out = String::new();
        for instruction in &self.instructions {
            if let Some(symbol) = &instruction.symbol {
                writeln!(&mut out, "\n{}:", symbol).ok();
            }
            writeln!(
                &mut out,
                "{:#014x}  {:<28} {:<42} {}",
                instruction.address,
                instruction.bytes,
                instruction.text,
                format_instruction_target(instruction)
            )
            .ok();
        }
        self.output = out;
    }

    fn build_scan_output(&mut self) {
        let mut out = String::new();
        for item in &self.scan_matches {
            writeln!(&mut out, "{}", format_pattern_match(item)).ok();
        }
        self.output = out;
    }

    fn build_string_output(&mut self) {
        let mut out = String::new();
        for item in &self.strings {
            writeln!(
                &mut out,
                "{:<10} {:<16} rva={:#010x} va={:#014x} {}",
                item.section,
                format_string_kind(item.kind),
                item.rva,
                item.virtual_address,
                item.value
            )
            .ok();
        }
        self.output = out;
    }

    fn build_symbol_output(&mut self) {
        let mut out = String::new();
        for symbol in &self.symbols {
            writeln!(
                &mut out,
                "{:<18} {:#010x} {}",
                symbol.module, symbol.value, symbol.name
            )
            .ok();
        }
        self.output = out;
    }

    fn build_signature_output(&mut self) {
        let mut out = String::new();
        for finding in &self.signature_findings {
            writeln!(
                &mut out,
                "{} [{}] {} matches",
                finding.signature,
                finding.module_hint,
                finding.matches.len()
            )
            .ok();
            writeln!(&mut out, "  pattern: {}", finding.pattern).ok();
            writeln!(&mut out, "  {}", finding.description).ok();
            for item in finding.matches.iter().take(50) {
                writeln!(&mut out, "    {}", format_pattern_match(item)).ok();
            }
        }
        self.output = out;
    }

    fn set_error(&mut self, err: anyhow::Error) {
        self.status = format!("Error: {err:#}");
    }

    fn refresh_environment(&mut self) {
        self.env = detect_cs2_environment();
        self.status = format!(
            "Refreshed CS2 context: {} cs2.exe processes, {} install roots, {} module candidates.",
            self.env.processes.len(),
            self.env.install_roots.len(),
            self.env.module_candidates.len()
        );
    }

    fn auto_load_workspace(&mut self) {
        self.env = detect_cs2_environment();

        if self.dump_path.trim().is_empty() {
            if let Some(dump) = self.env.dump_candidates.first() {
                self.dump_path = dump.display().to_string();
                self.load_symbols();
            }
        }

        if self.module_path.trim().is_empty() {
            if self.try_load_first_named_module("client.dll")
                || self.try_load_first_named_module("engine2.dll")
                || self.try_load_first_module_candidate()
            {
                return;
            }
        }

        self.status = format!(
            "Auto workspace ready: {} cs2.exe processes, {} modules, {} dumps. No module was auto-loaded.",
            self.env.processes.len(),
            self.env.module_candidates.len(),
            self.env.dump_candidates.len()
        );
        self.build_report();
    }

    fn load_first_named_module(&mut self, name: &str) {
        if self.try_load_first_named_module(name) {
            return;
        }

        self.status = format!("No detected {name}. Use Browse to select it manually.");
    }

    fn try_load_first_named_module(&mut self, name: &str) -> bool {
        let Some(path) = self.env.module_candidates.iter().find(|path| {
            path.file_name()
                .is_some_and(|file| file.to_string_lossy().eq_ignore_ascii_case(name))
        }) else {
            return false;
        };

        self.module_path = path.display().to_string();
        self.load_module();
        true
    }

    fn try_load_first_module_candidate(&mut self) -> bool {
        let Some(path) = self.env.module_candidates.first() else {
            return false;
        };

        self.module_path = path.display().to_string();
        self.load_module();
        true
    }

    fn auto_disassemble_loaded_module(&mut self) {
        let Some(index) = self
            .selected_section
            .or_else(|| self.sections.iter().position(|section| section.executable))
        else {
            self.build_report();
            self.active_tab = Tab::ModuleMap;
            return;
        };

        if let Some(section) = self.sections.get(index) {
            self.selected_section = Some(index);
            self.disasm_start = format!("0x{:x}", section.address);
            self.disasm_is_rva = false;
            if self.disasm_len.trim().is_empty() {
                self.disasm_len = "512".to_string();
            }
            self.run_disassembly();
            self.run_string_extraction();
            self.run_signature_findings();
        }
    }

    fn cross_reference_kind_count(&self, kind: CrossReferenceTargetKind) -> usize {
        self.cross_references
            .iter()
            .filter(|xref| xref.target_kind == kind)
            .count()
    }

    fn string_kind_count(&self, kind: StringKind) -> usize {
        self.strings.iter().filter(|item| item.kind == kind).count()
    }
}

fn format_instruction_target(instruction: &DecodedInstruction) -> String {
    match (instruction.rip_target, instruction.target_symbol.as_deref()) {
        (Some(target), Some(symbol)) => format!("=> {target:#x} {symbol}"),
        (Some(target), None) => format!("=> {target:#x}"),
        (None, Some(symbol)) => format!("=> {symbol}"),
        (None, None) => String::new(),
    }
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

fn format_nearby_string(item: &PatternMatch) -> String {
    item.nearby_string
        .as_ref()
        .map(|anchor| {
            format!(
                "+{:#x} {} {}",
                anchor.distance,
                format_string_kind(anchor.kind),
                anchor.value
            )
        })
        .unwrap_or_default()
}

fn non_empty_trimmed(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

fn format_cross_reference_kind(kind: CrossReferenceTargetKind) -> &'static str {
    match kind {
        CrossReferenceTargetKind::Code => "code",
        CrossReferenceTargetKind::Data => "data",
        CrossReferenceTargetKind::OutsideImage => "outside-image",
    }
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
