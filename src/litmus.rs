use std::collections::{BTreeSet, HashMap};
use std::fmt;

use once_cell::sync::Lazy;
use regex::Regex;

use isla_axiomatic::litmus::exp::Exp;
use isla_axiomatic::page_table;
use isla_lib::bitvector::{b64::B64, BV};

use crate::error::{Error, Result};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MovSrc {
    Nat(B64),
    Bin(B64),
    Hex(B64),
    Reg(String),
    Pte(String),
    Desc(String),
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
    VBar(String),   // VBAR regs
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitState {
    Unmapped(String),
    Var(String, String), // TODO: This should use MovSrc's?
    Alias(String, String),
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

impl TryFrom<&Exp<String>> for MovSrc {
    type Error = Error;

    fn try_from(exp: &Exp<String>) -> Result<Self> {
        // eprintln!("exp {exp:?}");

        fn bv_from_exp(exp: &Exp<String>) -> Result<B64> {
            match exp {
                Exp::Nat(n) => Ok(B64::new(*n, 64)),
                Exp::Bin(s) | Exp::Hex(s) => {
                    B64::from_str(s).ok_or_else(|| Error::ParseExp(format!("couldn't create B64 from {s}")))
                }
                Exp::Bits64(bits, _len) => Ok(B64::new(*bits, 64)),
                exp => Err(Error::ParseExp(format!("couldn't create B64 from {exp:?}"))),
            }
        }

        fn get_arg<'a>(fun: &str, args: &'a [Exp<String>], idx: usize) -> Result<&'a Exp<String>> {
            args.get(idx).ok_or_else(|| Error::GetFunctionArg(format!("{fun}:arg{idx}")))
        }

        log::info!("parsing {exp:?}");
        match exp {
            Exp::Nat(n) => Ok(Self::Nat(B64::new(*n, 64))),
            Exp::Bin(s) => {
                let b64 = u64::from_str_radix(s, 2).map_err(Error::ParseBitsFromString)?;
                Ok(Self::Bin(B64::new(b64, 64)))
            }
            Exp::Hex(s) => {
                let b64 = u64::from_str_radix(s, 16).map_err(Error::ParseBitsFromString)?;
                Ok(Self::Hex(B64::new(b64, 64)))
            }
            Exp::Bits64(bits, _len) => Ok(Self::Bin(B64::new(*bits, 64))),
            Exp::Loc(var) => Ok(Self::Reg(var.clone())),

            Exp::App(f, args, _kwargs) => match f.as_ref() {
                "extz" => get_arg(f, args, 0)?.try_into(),
                "exts" => {
                    let mov_src: MovSrc = get_arg(f, args, 0)?.try_into()?;
                    let extend_by = bv_from_exp(get_arg(f, args, 1)?)?.lower_u64() as u32;
                    Ok(mov_src.map(|bv| bv.sign_extend(extend_by)))
                }
                "bvand" => {
                    let mov_src_bv1: MovSrc = get_arg(f, args, 0)?.try_into()?;
                    let bv2 = bv_from_exp(&get_arg(f, args, 1)?.clone())?;
                    Ok(mov_src_bv1.map(|bv1| bv1 & bv2))
                }
                "bvor" => {
                    let mov_src_bv1: MovSrc = get_arg(f, args, 0)?.try_into()?;
                    let bv2 = bv_from_exp(&get_arg(f, args, 1)?.clone())?;
                    Ok(mov_src_bv1.map(|bv1| bv1 | bv2))
                }
                "bvxor" => {
                    let mov_src_bv1: MovSrc = get_arg(f, args, 0)?.try_into()?;
                    let bv2 = bv_from_exp(&get_arg(f, args, 1)?.clone())?;
                    Ok(mov_src_bv1.map(|bv1| bv1 ^ bv2))
                }
                "bvlshr" => {
                    let mov_src: MovSrc = get_arg(f, args, 0)?.try_into()?;
                    let shift_by = bv_from_exp(&get_arg(f, args, 1)?.clone())?;
                    Ok(mov_src.map(|bv1| bv1 >> shift_by))
                }
                "bvshl" => {
                    let mov_src: MovSrc = get_arg(f, args, 0)?.try_into()?;
                    let shift_by = bv_from_exp(&get_arg(f, args, 1)?.clone())?;
                    Ok(mov_src.map(|bv1| bv1 << shift_by))
                }
                "pte3" => {
                    if let Exp::Loc(var) = get_arg(f, args, 0)? {
                        Ok(MovSrc::Pte(var.clone()))
                    } else {
                        Err(Error::GetFunctionArg("pte3:arg0 was not parsed correctly".to_owned()))
                    }
                }
                "desc3" => {
                    if let Exp::Loc(var) = get_arg(f, args, 0)? {
                        Ok(MovSrc::Desc(var.to_owned()))
                    } else {
                        Err(Error::GetFunctionArg("desc:arg0 was not parsed correctly".to_owned()))
                    }
                }
                "vector_subrange" => {
                    let mov_src: MovSrc = get_arg(f, args, 0)?.try_into()?;
                    let from = bv_from_exp(get_arg(f, args, 1)?)?.lower_u64() as u32;
                    let len = bv_from_exp(get_arg(f, args, 2)?)?.lower_u64() as u32;
                    Ok(mov_src.map(|bv| bv.slice(from, len).unwrap()))
                }
                "page" | "offset" => Err(Error::Unsupported(format!("function {f} not supported"))),
                // "page" => {
                //     let mov_src: MovSrc = get_arg(f, args, 0)?.try_into()?;
                //     Ok(mov_src.map(|bv| bv.slice(12, 36).unwrap()))
                // }
                // TODO: offset()
                f => Err(Error::UnimplementedFunction(f.to_owned())),
            },
            other => Err(Error::ParseResetValue(format!("handling of {other:?} is not implemented"))),
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
            VBar(_) => unimplemented!("Converting PSTATE regs to asm is not implemented properly yet."),
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

pub fn parse_regs_from_asm(asm: &str) -> Result<BTreeSet<Reg>> {
    let lines = asm.trim().split('\n');
    let mut hs = BTreeSet::new();
    for line in lines {
        let line = match line.split_once(';') {
            Some((instr, _comment)) => instr,
            _ => line,
        }
        .trim();

        static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b([xXwWbBhHsSdDqQ]([0-9]|[12][0-9]|30))\b").unwrap());
        for tok in RE.find_iter(line) {
            let reg = parse_reg_from_str(tok.into())?;
            hs.insert(reg);
        }
    }
    Ok(hs)
}

pub fn parse_reg_from_str(asm: &str) -> Result<Reg> {
    use Reg::*;

    if asm.starts_with("PSTATE") {
        return Ok(Reg::PState(asm.to_owned()));
    }

    if asm.starts_with("VBAR") {
        return Ok(Reg::VBar(asm.to_owned()));
    }

    let (t, idx) = asm.split_at(1);
    let idx: u8 = idx.parse().map_err(|e: std::num::ParseIntError| Error::ParseReg(e.to_string()))?;
    match t {
        "x" | "X" => Ok(X(idx)),
        "w" | "W" => Ok(W(idx)),
        "b" | "B" => Ok(B(idx)),
        "h" | "H" => Ok(H(idx)),
        "s" | "S" => Ok(S(idx)),
        "d" | "D" => Ok(D(idx)),
        "q" | "Q" => Ok(Q(idx)),

        "r" | "R" => Ok(X(idx)), // TODO: this should use register renames
        t => Err(Error::ParseReg(t.to_string())),
    }
}

pub fn gen_init_state(page_table_setup: &[page_table::setup::Constraint]) -> Vec<InitState> {
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
