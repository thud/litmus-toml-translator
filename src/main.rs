use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::io::{BufReader, Read};

use regex::Regex;
use toml::Value;

use isla_axiomatic::litmus::exp::{Exp, Loc};
use isla_axiomatic::litmus::{self, exp_lexer, exp_parser};
use isla_axiomatic::page_table;
use isla_lib::bitvector::{b64::B64, BV};
use isla_lib::config::ISAConfig;
use isla_lib::ir::serialize::DeserializedArchitecture;
use isla_lib::ir::*;
use isla_lib::zencode;

const INCLUDES: &str = "#include \"lib.h\"";

#[derive(Debug)]
pub struct Litmus {
    pub arch: String,
    pub name: String,
    pub hash: Option<String>,
    pub page_table_setup_source: String,
    pub page_table_setup: Vec<page_table::setup::Constraint>,
    pub threads: Vec<Thread>,
    pub final_assertion: String, //exp::Exp<String>,
    pub var_names: Vec<String>,
    pub additional_vars: Vec<String>,
    pub regs: Vec<(u8, Reg)>,
    pub mmu_on: bool,
    pub init_state: Vec<InitState>,
}

#[derive(Debug)]
pub struct Thread {
    pub name: String,
    pub code: String,
    pub el: u8,
    pub regs_clobber: Vec<Reg>,
    pub reset: HashMap<Reg, MovSrc>,
}

fn load_aarch64_config_irx() -> Result<DeserializedArchitecture<B64>, String> {
    let ir = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/isla-snapshots/armv8p5.irx"));
    let mut buf = BufReader::new(&ir[..]);

    let mut isla_magic = [0u8; 8];
    buf.read_exact(&mut isla_magic).unwrap(); //.map_err(IOError)?;
    if &isla_magic != b"ISLAARCH" {
        panic!("Isla arch snapshot magic invalid {:?}", String::from_utf8(isla_magic.to_vec()));
    }

    let mut len = [0u8; 8];

    buf.read_exact(&mut len).unwrap(); //(IOError)?;
    let mut version = vec![0; usize::from_le_bytes(len)];
    buf.read_exact(&mut version).unwrap(); //(IOError)?;

    if version != env!("ISLA_VERSION").as_bytes() {
        let v = String::from_utf8_lossy(&version).into_owned();
        panic!("Isla version mismatch (got {v})");
    }

    buf.read_exact(&mut len).unwrap(); //(IOError)?;
    let mut raw_ir = vec![0; usize::from_le_bytes(len)];
    buf.read_exact(&mut raw_ir).unwrap(); //(IOError)?;

    buf.read_exact(&mut len).unwrap(); //(IOError)?;
    let mut raw_symtab = vec![0; usize::from_le_bytes(len)];
    buf.read_exact(&mut raw_symtab).unwrap(); //(IOError)?;

    let ir: Vec<Def<Name, B64>> = serialize::deserialize(&raw_ir).unwrap(); //.ok_or(SerializationError::ArchitectureError)?;
    let (strings, files): (Vec<String>, Vec<String>) = isla_lib::bincode::deserialize(&raw_symtab).unwrap(); //.map_err(|_| SerializationError::ArchitectureError)?;

    let arch = DeserializedArchitecture { files, strings, ir: ir.clone() };
    Ok(arch)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MovSrc {
    Nat(B64),
    Bin(B64),
    Hex(B64),
    Reg(String),
    Pte(String),
    Desc(String),
}

impl MovSrc {
    pub fn map<F>(&self, f: F) -> Self
    where
        F: FnOnce(B64) -> B64,
    {
        match self {
            Self::Nat(bv) => Self::Nat(f(*bv)),
            Self::Bin(bv) => Self::Bin(f(*bv)),
            Self::Hex(bv) => Self::Hex(f(*bv)),
            Self::Reg(_) | Self::Pte(_) | Self::Desc(_) => panic!(),
        }
    }

    pub fn bits(&self) -> &B64 {
        match self {
            Self::Nat(bv) | Self::Bin(bv) | Self::Hex(bv) => bv,
            Self::Reg(_) | Self::Pte(_) | Self::Desc(_) => panic!(),
        }
    }

    pub fn as_asm(&self) -> String {
        match self {
            Self::Nat(n) => format!("#{}", n.lower_u64()),
            Self::Bin(n) => format!("#0b{:b}", n.lower_u64()),
            Self::Hex(n) => format!("#0x{:x}", n.lower_u64()),
            Self::Reg(reg) => format!("%[{reg}]"),
            Self::Pte(sym) => format!("%[{sym}pte]"),
            Self::Desc(sym) => format!("%[{sym}desc]"),
        }
    }
}

impl From<&Exp<String>> for MovSrc {
    fn from(exp: &Exp<String>) -> Self {
        eprintln!("exp {exp:?}");
        match exp {
            Exp::Nat(n) => Self::Nat(B64::new(*n, 64)),
            Exp::Bin(s) => Self::Bin(B64::new(u64::from_str_radix(s, 16).unwrap(), 64)),
            Exp::Hex(s) => Self::Hex(B64::new(u64::from_str_radix(s, 2).unwrap(), 64)),
            Exp::Bits64(bits, _len) => Self::Bin(B64::new(*bits, 64)),
            Exp::Loc(var) => Self::Reg(var.clone()),
            _ => panic!(),
        }
    }
}

impl fmt::Display for MovSrc {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Nat(n) => write!(f, "{}", n.lower_u64()),
            Self::Bin(n) => write!(f, "0b{:b}", n.lower_u64()),
            Self::Hex(n) => write!(f, "0x{:x}", n.lower_u64()),
            Self::Reg(reg) => write!(f, "{reg}"),
            Self::Pte(reg) => write!(f, "pte({reg})"),
            Self::Desc(reg) => write!(f, "desc({reg})"),
        }
    }
}

fn parse_reset_val(unparsed_val: &Value, symtab: &Symtab) -> MovSrc {
    let parsed = litmus::parse_reset_value(unparsed_val, symtab).unwrap();
    // eprintln!("{parsed:#?}");

    fn bv_from_exp(exp: &Exp<String>) -> Option<B64> {
        match exp {
            Exp::Nat(n) => Some(B64::new(*n, 64)),
            Exp::Bin(s) | Exp::Hex(s) => B64::from_str(s),
            Exp::Bits64(bits, _len) => Some(B64::new(*bits, 64)),
            _ => None,
        }
    }

    fn finalise_val(exp: &Exp<String>) -> MovSrc {
        match exp {
            Exp::Loc(..) | Exp::Bin(..) | Exp::Hex(..) | Exp::Nat(..) => exp.into(),
            Exp::App(f, args, _kwargs) => match f.as_ref() {
                "extz" => finalise_val(args.get(0).unwrap()),
                "exts" => {
                    let mov_src: MovSrc = exp.into();
                    let extend_by = bv_from_exp(args.get(1).unwrap()).unwrap().lower_u64() as u32;
                    mov_src.map(|bv| bv.sign_extend(extend_by))
                }
                "bvand" => {
                    let mov_src_bv1: MovSrc = args.get(0).unwrap().into();
                    let bv2 = bv_from_exp(&args[1]).unwrap();
                    mov_src_bv1.map(|bv1| bv1 & bv2)
                }
                "bvor" => {
                    let mov_src_bv1: MovSrc = args.get(0).unwrap().into();
                    let bv2 = bv_from_exp(&args[1]).unwrap();
                    mov_src_bv1.map(|bv1| bv1 | bv2)
                }
                "bvxor" => {
                    let mov_src_bv1: MovSrc = args.get(0).unwrap().into();
                    let bv2 = bv_from_exp(&args[1]).unwrap();
                    mov_src_bv1.map(|bv1| bv1 ^ bv2)
                }
                "bvlshr" => {
                    let mov_src: MovSrc = args.get(0).unwrap().into();
                    let shift_by = bv_from_exp(&args[1]).unwrap();
                    mov_src.map(|bv1| bv1 >> shift_by)
                }
                "bvshl" => {
                    let mov_src: MovSrc = args.get(0).unwrap().into();
                    let shift_by = bv_from_exp(&args[1]).unwrap();
                    mov_src.map(|bv1| bv1 << shift_by)
                }
                "pte3" => {
                    if let Exp::Loc(var) = args.get(0).unwrap().clone() {
                        MovSrc::Pte(var)
                    } else {
                        panic!()
                    }
                }
                "desc" => {
                    if let Exp::Loc(var) = args.get(0).unwrap().clone() {
                        MovSrc::Desc(var)
                    } else {
                        panic!()
                    }
                }
                f => unimplemented!("Function {f:?} not implemented"),
            },
            _ => panic!(),
        }
    }

    finalise_val(&parsed)
}

fn parse_resets(unparsed_resets: Option<&Value>, symtab: &Symtab) -> HashMap<Reg, MovSrc> {
    if let Some(unparsed_resets) = unparsed_resets {
        let resets = unparsed_resets
            .as_table()
            .ok_or_else(|| "Thread init/reset must be a list of register name/value pairs".to_string())
            .unwrap();
        resets.into_iter().map(|(reg, val)| (parse_reg_from_str(reg), parse_reset_val(val, symtab))).collect()
    } else {
        HashMap::new()
    }
}

fn merge_inits_resets(
    inits: HashMap<Reg, MovSrc>,
    resets: HashMap<Reg, MovSrc>,
) -> (HashMap<Reg, MovSrc>, HashMap<Reg, MovSrc>) {
    let mut gp = HashMap::with_capacity(inits.len() + resets.len());
    let mut special = HashMap::new();
    for (reg, val) in inits.into_iter().chain(resets) {
        match reg {
            // TODO: not all special registers are PSTATEs
            Reg::PState(_) => special.insert(reg, val),
            _ => gp.insert(reg, val),
        };
    }
    (gp, special)
}

fn parse_thread(thread_name: &str, thread: &Value, symtab: &Symtab) -> Thread {
    let (code, regs_clobber) = match thread.get("code") {
        Some(code) => code
            .as_str()
            .map(|code| {
                let regs_clobber = parse_regs_from_asm(code);
                (code, regs_clobber)
            })
            .ok_or_else(|| "thread code must be a string".to_string()),
        None => match thread.get("call") {
            Some(_call) => {
                unimplemented!()
                // let call = call.as_str().ok_or_else(|| "Thread call must be a string".to_string())?;
                // let call = symtab
                //     .get(&zencode::encode(call))
                //     .ok_or_else(|| format!("Could not find function {}", call))?;
                // Ok((thread_name.to_string(), ThreadBody::Call(call)))
            }
            None => Err(format!("No code or call found for thread {}", thread_name)),
        },
    }
    .unwrap();

    let inits = parse_resets(thread.get("init"), symtab);
    let resets = parse_resets(thread.get("reset"), symtab);
    let (merged_resets, special_resets) = merge_inits_resets(inits, resets);

    let el = {
        let el_src = special_resets.get(&Reg::PState("PSTATE.EL".to_owned()));

        if let Some(MovSrc::Reg(r)) = el_src {
            panic!("Invalid EL level ({r})");
        }

        let el_u8 = el_src.map(|mov_src| mov_src.bits().lower_u8()).unwrap_or(B64::zeros(64).lower_u8()); // By default EL = 0

        if el_u8 > 1 {
            eprintln!("WARNING: EL > 1 not allowed");
        }
        el_u8
    };

    Thread {
        name: thread_name.to_owned(),
        code: code.to_owned(),
        el,
        reset: merged_resets.into_iter().map(|(reg, val)| (reg, val.to_owned())).collect(),
        regs_clobber: regs_clobber.into_iter().collect(),
    }
}

fn regs_from_final_assertion(symtab: &Symtab, final_assertion: Exp<String>) -> Vec<(u8, Reg)> {
    fn extract_regs_from_exp(symtab: &Symtab, set: &mut BTreeSet<(u8, Reg)>, exp: Exp<String>) {
        match exp {
            Exp::EqLoc(Loc::Register { reg, thread_id }, _exp) => {
                set.insert((thread_id.try_into().unwrap(), parse_reg_from_str(&zencode::decode(symtab.to_str(reg)))));
            }
            Exp::Not(exp) => extract_regs_from_exp(symtab, set, *exp),
            Exp::And(exps) | Exp::Or(exps) => {
                for exp in exps {
                    extract_regs_from_exp(symtab, set, exp);
                }
            }
            Exp::Implies(exp1, exp2) => {
                extract_regs_from_exp(symtab, set, *exp1);
                extract_regs_from_exp(symtab, set, *exp2);
            }
            // TODO: Currently ignoring function application
            _ => unreachable!("Can't yet use final assertions with more complex terms"),
            // Exp::Loc(A),
            // Exp::Label(String),
            // Exp::True,
            // Exp::False,
            // Exp::Bin(String),
            // Exp::Hex(String),
            // Exp::Bits64(u64, u32),
            // Exp::Nat(u64),
            // Exp::App(String, Vec<Exp<A>>, HashMap<String, Exp<A>>),
        }
    }
    let mut set = BTreeSet::new();
    extract_regs_from_exp(symtab, &mut set, final_assertion);
    set.into_iter().collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitState {
    Unmapped(String),
    Var(String, String), // TODO: This should use MovSrc's?
    Alias(String, String),
}

fn gen_init_state(page_table_setup: &[page_table::setup::Constraint]) -> Vec<InitState> {
    use page_table::setup::{Constraint, Exp, TableConstraint};
    page_table_setup
        .iter()
        .filter_map(|constraint| match constraint {
            Constraint::Initial(Exp::Id(id), val) => {
                let val = match val {
                    Exp::I128(n) => Some(n.to_string()),
                    Exp::Hex(s) | Exp::Bin(s) => Some(s.clone()),
                    _ => None,
                    //Exp:://Some(InitState::Var(id.clone(), val)),
                };
                val.map(|v| InitState::Var(id.clone(), v))
            }
            Constraint::Table(TableConstraint::MapsTo(Exp::Id(from), Exp::Id(to), _, _lvl, _)) => {
                Some(InitState::Alias(from.clone(), to.clone()))
            }
            _ => None,
        })
        .collect()
}

fn get_additional_vars_from_pts(
    page_table_setup: &Vec<page_table::setup::Constraint>,
    existing_vars: Vec<String>,
) -> Vec<String> {
    use page_table::setup::{Constraint, Exp, TableConstraint};
    let existing_vars: BTreeSet<String> = existing_vars.into_iter().collect();
    let mut all_vars = BTreeSet::new();
    for constraint in page_table_setup {
        match constraint {
            Constraint::Initial(Exp::Id(id), _) => {
                all_vars.insert(id.clone());
            }
            Constraint::Table(TableConstraint::MapsTo(Exp::Id(from), Exp::Id(to), ..)) => {
                all_vars.insert(from.clone());
                all_vars.insert(to.clone());
            }
            e => eprintln!("Not parsing additional vars from {e:?}"),
        };
    }

    all_vars.difference(&existing_vars).cloned().collect()
}

pub fn parse(contents: &str) -> Result<Litmus, String> {
    let arch = load_aarch64_config_irx().unwrap();
    let symtab = Symtab::from_raw_table(&arch.strings, &arch.files);
    let type_info = IRTypeInfo::new(&arch.ir);

    let litmus_toml = match contents.parse::<Value>() {
        Ok(toml) => toml,
        Err(e) => return Err(format!("Error when parsing litmus: {}", e)),
    };

    let mmu_on = litmus_toml.get("page_table_setup").is_some();

    let isa: ISAConfig<B64> = if mmu_on {
        ISAConfig::parse(
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/isla/configs/armv8p5_mmu_on.toml")),
            None,
            &symtab,
            &type_info,
        )
        .unwrap()
    } else {
        assert!(
            litmus_toml.get("symbolic").is_none(),
            "\"symbolic\" key should not be present if no page table setup specified"
        );
        ISAConfig::parse(
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/isla/configs/armv8p5.toml")),
            None,
            &symtab,
            &type_info,
        )
        .unwrap()
    };

    let arch =
        litmus_toml.get("arch").and_then(|n| n.as_str().map(str::to_string)).unwrap_or_else(|| "unknown".to_string());

    let name = litmus_toml
        .get("name")
        .and_then(|n| n.as_str().map(str::to_string))
        .ok_or_else(|| "No name found in litmus file".to_string())?;

    let hash = litmus_toml.get("hash").map(|h| h.to_string());

    let symbolic = litmus_toml
        .get("symbolic")
        .or(litmus_toml.get("addresses"))
        .and_then(Value::as_array)
        .ok_or("No symbolic addresses found in litmus file")?;

    let var_names: Vec<String> = symbolic.iter().map(Value::as_str).map(|v| v.unwrap().to_string()).collect();

    let (page_table_setup, page_table_setup_source) = if let Some(setup) = litmus_toml.get("page_table_setup") {
        if litmus_toml.get("locations").is_some() {
            return Err("Cannot have a page_table_setup and locations in the same test".to_string());
        }
        if let Some(litmus_setup) = setup.as_str() {
            let setup = format!("{}{}", isa.default_page_table_setup, litmus_setup);
            let lexer = page_table::setup_lexer::SetupLexer::new(&setup);
            (
                page_table::setup_parser::SetupParser::new().parse(&isa, lexer).map_err(|error| {
                    litmus::format_error_page_table_setup(
                        litmus_setup,
                        error.map_location(|pos| pos - isa.default_page_table_setup.len()),
                    )
                })?,
                litmus_setup.to_string(),
            )
        } else {
            return Err("page_table_setup must be a string".to_string());
        }
    } else {
        (Vec::new(), "".to_string())
    };

    eprintln!("{page_table_setup:#?}");

    let init_state = if mmu_on {
        gen_init_state(&page_table_setup)
    } else {
        var_names.clone().into_iter().map(|var| InitState::Var(var, "0".to_owned())).collect()
    };

    let additional_vars = get_additional_vars_from_pts(&page_table_setup, var_names.clone());

    let threads = {
        let toml = litmus_toml.get("thread").and_then(|t| t.as_table()).ok_or("No threads found in litmus file")?;
        toml.into_iter().map(|(name, thread)| parse_thread(name.as_ref(), thread, &symtab)).collect()
    };

    let fin = litmus_toml.get("final").ok_or("No final section found in litmus file")?;
    let final_assertion = (match fin.get("assertion").and_then(Value::as_str) {
        Some(assertion) => {
            let lexer = exp_lexer::ExpLexer::new(assertion);
            let sizeof = isla_axiomatic::litmus::parse_sizeof_types(&litmus_toml).unwrap();
            if let Ok(exp) = exp_parser::ExpParser::new()
                .parse(&sizeof, isa.default_sizeof, &symtab, &isa.register_renames, lexer)
                .map_err(|error| error.to_string())
            {
                Ok(exp)
            } else {
                Err("".to_owned())
            }
        }
        None => Err("No final.assertion found in litmus file".to_string()),
    })?;
    let regs = regs_from_final_assertion(&symtab, final_assertion.clone());
    eprintln!("Final assertion: {final_assertion:?}");

    Ok(Litmus {
        arch,
        name,
        hash,
        page_table_setup_source,
        page_table_setup,
        threads,
        final_assertion: "test assertion TODO".to_owned(), //final_assertion,
        var_names,
        additional_vars,
        regs,
        mmu_on,
        init_state,
    })
}

#[derive(Debug, Clone, Hash, PartialOrd, Ord, PartialEq, Eq)]
pub enum Reg {
    X(u8), // X0..X30 General purpose reg (all 64 bits)
    W(u8), // W0..W30 General purpose reg (bottom 32 bits)

    B(u8), // B0..B30 General purpose floating point reg (bottom 8 bits)
    H(u8), // H0..H30 General purpose floating point reg (bottom 16 bits)
    S(u8), // S0..S30 General purpose floating point reg (bottom 32 bits)
    D(u8), // D0..D30 General purpose floating point reg (bottom 64 bits)
    Q(u8), // Q0..Q30 General purpose floating point reg (all 128 bits)
    // V(u8, u8)   // V[0..30].[0..?] General purpose floating point reg (vec)
    PState(String), // PSTATE regs
}

impl Reg {
    pub fn as_asm(&self) -> String {
        use Reg::*;
        match &self {
            X(n) => "x".to_owned() + &n.to_string(),
            W(n) => "w".to_owned() + &n.to_string(),
            B(n) => "b".to_owned() + &n.to_string(),
            H(n) => "h".to_owned() + &n.to_string(),
            S(n) => "s".to_owned() + &n.to_string(),
            D(n) => "d".to_owned() + &n.to_string(),
            Q(n) => "q".to_owned() + &n.to_string(),

            PState(_) => unimplemented!("Converting PSTATE regs to asm is not implemented properly yet."),
        }
    }

    pub fn as_asm_quoted(&self) -> String {
        format!("\"{}\"", self.as_asm())
    }

    pub fn as_output_str(&self, thread_no: u8) -> String {
        match &self {
            Self::X(n) => format!("outp{thread_no}r{n}"),
            _ => unimplemented!("output reg name generation not implemented for non \"X\" registers."),
        }
    }
}

pub fn parse_regs_from_asm(asm: &str) -> BTreeSet<Reg> {
    let lines = asm.trim().split('\n');
    let mut hs = BTreeSet::new();
    for line in lines {
        let line = match line.split_once(';') {
            Some((instr, _comment)) => instr,
            _ => line,
        }
        .trim();

        let re = Regex::new(r"\b([xXwWbBhHsSdDqQ]([0-9]|[12][0-9]|30))\b").unwrap();
        for tok in re.find_iter(line) {
            let reg = parse_reg_from_str(tok.into());
            hs.insert(reg);
        }
    }
    hs
}

fn parse_reg_from_str(asm: &str) -> Reg {
    use Reg::*;

    if asm.starts_with("PSTATE") {
        return Reg::PState(asm.to_owned());
    }

    let (t, idx) = asm.split_at(1);
    let idx: u8 = idx.parse().unwrap();
    match t {
        "x" | "X" => X(idx),
        "w" | "W" => W(idx),
        "b" | "B" => B(idx),
        "h" | "H" => H(idx),
        "s" | "S" => S(idx),
        "d" | "D" => D(idx),
        "q" | "Q" => Q(idx),

        "r" | "R" => X(idx), // TODO: this should use register renames
        _ => unimplemented![],
    }
}

pub fn write_output(litmus: Litmus) -> Result<(), String> {
    // println!("{litmus:#?}");
    let name = litmus.name;
    let name_cleaned = name.clone();
    let vars = litmus.var_names.join(", ");
    let additional_vars = if litmus.additional_vars.is_empty() {
        "".to_owned()
    } else {
        format!(", {}", litmus.additional_vars.join(", "))
    };
    let regs =
        litmus.regs.iter().map(|(thread, reg)| format!("p{thread}{}", reg.as_asm())).collect::<Vec<_>>().join(", ");

    let thread_count = litmus.threads.len();
    let start_els = if thread_count == 1 {
        litmus.threads[0].el.to_string() + ","
    } else {
        litmus.threads.iter().map(|thread| thread.el.to_string()).collect::<Vec<_>>().join(",")
    };
    let c_threads: String = litmus
        .threads
        .into_iter()
        .map(|thread| {
            let thread_name = format!("P{}", thread.name);

            let reg_setup = if thread.reset.is_empty() {
                "".to_owned()
            } else {
                let reg_movs = thread
                    .reset
                    .iter()
                    .map(|(reg, val)| format!("\"mov {}, {}\\n\\t\"", reg.as_asm(), val.as_asm()))
                    .collect::<Vec<_>>()
                    .join("\n    ");
                format!(
                    "\n    /* initial registers */\
                         \n    {reg_movs}\n"
                )
            };

            let output_var = {
                let reg_strs = litmus
                    .regs
                    .iter()
                    .filter(|(thread_name, _)| thread_name.to_string() == thread.name)
                    .map(|(thread, reg)| format!("\"str {}, [%[{}]]\\n\\t\"", reg.as_asm(), reg.as_output_str(*thread)))
                    .collect::<Vec<_>>();
                if reg_strs.is_empty() {
                    "".to_string()
                } else {
                    format!(
                        "\n\n    /* output */\
                             \n    {}",
                        reg_strs.join("\n    ")
                    )
                }
            };

            let body = thread
                .code
                .split('\n')
                .map(|ln| {
                    let trimmed = ln.trim();
                    if !trimmed.is_empty() {
                        format!("    \"{trimmed}\\n\\t\"\n")
                    } else {
                        "".to_string()
                    }
                })
                .collect::<Vec<String>>()
                .join("");
            let body = body.trim();
            let regs_clobber = thread.regs_clobber.iter().map(Reg::as_asm_quoted).collect::<Vec<_>>().join(", ");

            format!(
                "static void {thread_name}(litmus_test_run* data) {{\
                \n  asm volatile (\
                      {reg_setup}\
                \n    /* test */\
                \n    {body}\
                      {output_var}\
                \n  :\
                \n  : ASM_VARS(data, VARS),\
                \n    ASM_REGS(data, REGS)\
                \n  : \"cc\", \"memory\", {regs_clobber}\
                \n  );\
                \n}}\
                "
            )
        })
        .collect::<Vec<String>>()
        .join("\n\n");

    let final_assertion = litmus.final_assertion;

    let init_state = if litmus.init_state.is_empty() {
        "".to_owned()
    } else {
        let len = litmus.init_state.len();
        let state_str = litmus
            .init_state
            .into_iter()
            .map(|state| match state {
                InitState::Unmapped(var) => format!("INIT_UNMAPPED({var})"),
                InitState::Var(var, val) => format!("INIT_VAR({var}, {val})"),
                InitState::Alias(from, to) => format!("INIT_ALIAS({from}, {to})"),
            })
            .collect::<Vec<_>>()
            .join(",\n    ");
        format!("\n    {len},\n    {state_str},\n  ")
    };

    let interesting_results: Vec<String> = vec![];
    let no_interesting_results = interesting_results.len();
    let interesting_results = interesting_results.join(",\n");

    let requires_pgtable = if litmus.mmu_on { "1" } else { "0" };

    let out = format!(
        "\
// {name} [litmus-toml-translator]

{INCLUDES}

#define VARS {vars}
#define REGS {regs}

// Thread bodies
{c_threads}

// Final assertion
// {final_assertion}

// Final test struct
litmus_test_t test /* {name_cleaned} */ = {{
  \"{name}\",
  MAKE_THREADS({thread_count}),
  MAKE_VARS(VARS{additional_vars}),
  MAKE_REGS(REGS),
  INIT_STATE({init_state}),
  .no_interesting_results = {no_interesting_results},
  .interesting_results = (uint64_t*[]){{{interesting_results}}},
  // .no_sc_results = TODO,
  .requires_pgtable = {requires_pgtable},
  .start_els = (int[]){{{start_els}}},
}};
",
    );

    println!("{out}");

    Ok(())
}

fn main() {
    let litmus_toml = std::fs::read_to_string("test.toml").unwrap();
    let litmus = parse(&litmus_toml);
    // println!("{litmus:?}");
    write_output(litmus.unwrap()).unwrap();
}
