use std::{fmt::Write, path::PathBuf};

use anyhow::Result;
use eframe::egui::{self, Color32, RichText, TextEdit};

use crate::engine::{
    DecodedInstruction, LoadedSymbol, ModuleImage, Pattern, PatternMatch, SectionInfo, SymbolMap,
    disassemble, load_symbol_map, load_symbols, parse_u64, scan_pattern,
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

#[derive(Default)]
struct AnalysisApp {
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
    instructions: Vec<DecodedInstruction>,
    scan_matches: Vec<PatternMatch>,
    status: String,
    output: String,
    active_tab: Tab,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Tab {
    #[default]
    Disassembly,
    Scanner,
    Symbols,
    Report,
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
                    "Load a CS2 module file or any PE file to begin."
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
            ui.label("offline disassembler, scanner, and cs2-dumper metadata explorer");
        });
        ui.add_space(4.0);
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        ui.heading("Workspace");
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
        ui.heading("Sections");
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
            self.tab_button(ui, Tab::Disassembly, "Disassembly");
            self.tab_button(ui, Tab::Scanner, "Pattern scanner");
            self.tab_button(ui, Tab::Symbols, "Symbols");
            self.tab_button(ui, Tab::Report, "Report");
        });
        ui.separator();

        match self.active_tab {
            Tab::Disassembly => self.disassembly_tab(ui),
            Tab::Scanner => self.scanner_tab(ui),
            Tab::Symbols => self.symbols_tab(ui),
            Tab::Report => self.report_tab(ui),
        }
    }

    fn tab_button(&mut self, ui: &mut egui::Ui, tab: Tab, label: &str) {
        if ui.selectable_label(self.active_tab == tab, label).clicked() {
            self.active_tab = tab;
        }
    }

    fn disassembly_tab(&mut self, ui: &mut egui::Ui) {
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
        egui::ScrollArea::both().id_salt("disasm").show(ui, |ui| {
            if self.instructions.is_empty() {
                ui.label("Disassembly results will appear here.");
                return;
            }

            egui::Grid::new("instruction_grid")
                .striped(true)
                .num_columns(4)
                .show(ui, |ui| {
                    ui.strong("Address");
                    ui.strong("Bytes");
                    ui.strong("Instruction");
                    ui.strong("Symbol");
                    ui.end_row();

                    for instruction in &self.instructions {
                        ui.monospace(format!("{:#014x}", instruction.address));
                        ui.monospace(&instruction.bytes);
                        ui.monospace(&instruction.text);
                        ui.label(instruction.symbol.as_deref().unwrap_or(""));
                        ui.end_row();
                    }
                });
        });
    }

    fn scanner_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label("Pattern");
            ui.add_sized(
                [420.0, 24.0],
                TextEdit::singleline(&mut self.scan_pattern_text).hint_text("48 8B ?? ?? 89"),
            );
            if ui.button("Scan sections").clicked() {
                self.run_scan();
            }
            if ui.button("Copy matches").clicked() {
                ui.ctx().copy_text(self.output.clone());
            }
        });

        ui.add_space(8.0);
        egui::ScrollArea::both().id_salt("scan").show(ui, |ui| {
            if self.scan_matches.is_empty() {
                ui.label("Pattern matches will appear here.");
                return;
            }

            egui::Grid::new("scan_grid")
                .striped(true)
                .num_columns(2)
                .show(ui, |ui| {
                    ui.strong("RVA");
                    ui.strong("Virtual address");
                    ui.end_row();

                    for item in &self.scan_matches {
                        ui.monospace(format!("{:#010x}", item.rva));
                        ui.monospace(format!("{:#014x}", item.virtual_address));
                        ui.end_row();
                    }
                });
        });
    }

    fn symbols_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label(format!("Loaded symbols: {}", self.symbols.len()));
            if ui.button("Copy symbols").clicked() {
                ui.ctx().copy_text(self.output.clone());
            }
        });
        ui.add_space(8.0);

        egui::ScrollArea::both().id_salt("symbols").show(ui, |ui| {
            if self.symbols.is_empty() {
                ui.label("Load a cs2-dumper output folder to view symbols.");
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
                    self.status = format!("Loaded module with {} sections.", sections.len());
                    self.module = Some(module);
                    self.sections = sections;
                    self.instructions.clear();
                    self.scan_matches.clear();
                    self.build_report();
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
                self.active_tab = Tab::Symbols;
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
                        self.active_tab = Tab::Disassembly;
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
                self.scan_matches = scan_pattern(module, &pattern);
                self.status = format!("Found {} matches.", self.scan_matches.len());
                self.active_tab = Tab::Scanner;
                self.build_scan_output();
            }
            Err(err) => self.set_error(err),
        }
    }

    fn build_report(&mut self) {
        let mut report = String::new();
        writeln!(&mut report, "CS2 Analysis Engine report").ok();
        writeln!(&mut report, "scope: read-only offline analysis").ok();

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
            "last pattern matches: {}",
            self.scan_matches.len()
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
                "{:#014x}  {:<28} {}",
                instruction.address, instruction.bytes, instruction.text
            )
            .ok();
        }
        self.output = out;
    }

    fn build_scan_output(&mut self) {
        let mut out = String::new();
        for item in &self.scan_matches {
            writeln!(
                &mut out,
                "rva={:#x} va={:#x}",
                item.rva, item.virtual_address
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

    fn set_error(&mut self, err: anyhow::Error) {
        self.status = format!("Error: {err:#}");
    }
}
