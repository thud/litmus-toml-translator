use std::collections::{BTreeSet, HashMap};

use once_cell::sync::Lazy;

use isla_axiomatic::litmus::exp::{Exp, Loc};
use isla_axiomatic::litmus::{self as axiomatic_litmus, exp_lexer, exp_parser};
use isla_axiomatic::page_table;
use isla_lib::bitvector::{b64::B64, BV};
use isla_lib::ir::serialize::DeserializedArchitecture;
use isla_lib::ir::Symtab;
use isla_lib::zencode;
use toml::Value;

use crate::arch;
use crate::error::{Error, Result};
use crate::litmus::{self, InitState, Litmus, MovSrc, Reg, Thread};

fn parse_reset_val(unparsed_val: &Value, symtab: &Symtab) -> Result<MovSrc> {
    let parsed =
        axiomatic_litmus::parse_reset_value(unparsed_val, symtab).map_err(|e| Error::ParseResetValue(e.to_string()))?;

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

    fn finalise_val(exp: &Exp<String>) -> Result<MovSrc> {
        // TODO: remove these unwraps
        match exp {
            Exp::Loc(..) | Exp::Bin(..) | Exp::Hex(..) | Exp::Nat(..) => Ok(exp.try_into()?),
            Exp::App(f, args, _kwargs) => match f.as_ref() {
                "extz" => finalise_val(get_arg(f, args, 0)?),
                "exts" => {
                    let mov_src: MovSrc = exp.try_into()?;
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
                "desc" => {
                    if let Exp::Loc(var) = get_arg(f, args, 0)? {
                        Ok(MovSrc::Desc(var.to_owned()))
                    } else {
                        Err(Error::GetFunctionArg("desc:arg0 was not parsed correctly".to_owned()))
                    }
                }
                f => Err(Error::UnimplementedFunction(f.to_owned())),
            },
            other => Err(Error::ParseResetValue(format!("handling of {other:?} is not implemented"))),
        }
    }

    finalise_val(&parsed)
}

fn parse_resets(unparsed_resets: Option<&Value>, symtab: &Symtab) -> Result<HashMap<Reg, MovSrc>> {
    if let Some(unparsed_resets) = unparsed_resets {
        unparsed_resets
            .as_table()
            .ok_or_else(|| "Thread init/reset must be a list of register name/value pairs".to_string())
            .map_err(Error::ParseResetValue)?
            .into_iter()
            .map(|(reg, val)| Ok((litmus::parse_reg_from_str(reg)?, parse_reset_val(val, symtab)?)))
            .collect()
    } else {
        Ok(HashMap::new())
    }
}

fn merge_inits_resets(
    inits: HashMap<Reg, MovSrc>,
    resets: HashMap<Reg, MovSrc>,
) -> Result<(HashMap<Reg, MovSrc>, HashMap<Reg, MovSrc>)> {
    let mut gp = HashMap::with_capacity(inits.len() + resets.len());
    let mut special = HashMap::new();
    for (reg, val) in inits.into_iter().chain(resets) {
        match reg {
            // TODO: not all special registers are PSTATEs
            Reg::PState(_) => special.insert(reg, val),
            _ => gp.insert(reg, val),
        };
    }
    Ok((gp, special))
}

fn parse_thread(thread_name: &str, thread: &Value, symtab: &Symtab) -> Result<Thread> {
    let (code, regs_clobber) = match thread.get("code") {
        Some(code) => code
            .as_str()
            .map(|code| {
                let regs_clobber = litmus::parse_regs_from_asm(code)?;
                Ok((code, regs_clobber))
            })
            .ok_or_else(|| Error::ParseThread("thread code must be a string".to_string()))?,
        None => match thread.get("call") {
            Some(_call) => {
                unimplemented!()
                // TODO: implement call parsing
                // let call = call.as_str().ok_or_else(|| "Thread call must be a string".to_string())?;
                // let call = symtab
                //     .get(&zencode::encode(call))
                //     .ok_or_else(|| format!("Could not find function {}", call))?;
                // Ok((thread_name.to_string(), ThreadBody::Call(call)))
            }
            None => Err(Error::ParseThread(format!("No code or call found for thread {}", thread_name)))?,
        },
    }?;

    let inits = parse_resets(thread.get("init"), symtab)?;
    let resets = parse_resets(thread.get("reset"), symtab)?;
    let (merged_resets, special_resets) = merge_inits_resets(inits, resets)?;

    let el = {
        let el_src = special_resets.get(&Reg::PState("PSTATE.EL".to_owned()));

        if let Some(MovSrc::Reg(r)) = el_src {
            return Err(Error::ParseThread(format!("Invalid EL level ({r})")));
        }

        let el_u8 = el_src.map(|mov_src| mov_src.bits().lower_u8()).unwrap_or(B64::zeros(64).lower_u8()); // By default EL = 0

        if el_u8 > 1 {
            eprintln!("WARNING: EL > 1 not allowed");
        }
        el_u8
    };

    Ok(Thread {
        name: thread_name.to_owned(),
        code: code.to_owned(),
        el,
        reset: merged_resets.into_iter().map(|(reg, val)| (reg, val.to_owned())).collect(),
        regs_clobber: regs_clobber.into_iter().collect(),
    })
}

fn regs_from_final_assertion(symtab: &Symtab, final_assertion: Exp<String>) -> Result<Vec<(u8, Reg)>> {
    fn extract_regs_from_exp(symtab: &Symtab, set: &mut BTreeSet<(u8, Reg)>, exp: Exp<String>) -> Result<()> {
        match exp {
            Exp::EqLoc(Loc::Register { reg, thread_id }, _exp) => {
                let thread_id = thread_id.try_into().map_err(|e| Error::ParseThread(format!("{e}")))?;
                set.insert((thread_id, litmus::parse_reg_from_str(&zencode::decode(symtab.to_str(reg)))?));
                Ok(())
            }
            Exp::Not(exp) => extract_regs_from_exp(symtab, set, *exp),
            Exp::And(exps) | Exp::Or(exps) => {
                for exp in exps {
                    extract_regs_from_exp(symtab, set, exp)?;
                }
                Ok(())
            }
            Exp::Implies(exp1, exp2) => {
                extract_regs_from_exp(symtab, set, *exp1)?;
                extract_regs_from_exp(symtab, set, *exp2)?;
                Ok(())
            }
            // TODO: Currently ignoring function application
            exp => {
                Err(Error::ParseFinalAssertion(format!("Can't yet use final assertions with complex terms {exp:?}")))
            }
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
    extract_regs_from_exp(symtab, &mut set, final_assertion)?;
    Ok(set.into_iter().collect())
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

pub fn parse(contents: &str) -> Result<Litmus> {
    let litmus_toml = contents.parse::<Value>().map_err(Error::ParseToml)?;

    let mmu_on = litmus_toml.get("page_table_setup").is_some();
    static ARCH: Lazy<DeserializedArchitecture<B64>> = Lazy::new(|| arch::load_aarch64_config_irx().unwrap());
    let (isa, symtab) = arch::load_aarch64_isa(&ARCH, mmu_on)?;

    let arch =
        litmus_toml.get("arch").and_then(|n| n.as_str().map(str::to_string)).unwrap_or_else(|| "unknown".to_string());

    let name = litmus_toml
        .get("name")
        .and_then(|n| n.as_str().map(str::to_string))
        .ok_or_else(|| Error::GetTomlValue("No name found in litmus file".to_owned()))?;

    let hash = litmus_toml.get("hash").map(|h| h.to_string());

    let symbolic = litmus_toml
        .get("symbolic")
        .or(litmus_toml.get("addresses"))
        .and_then(Value::as_array)
        .ok_or_else(|| Error::GetTomlValue("No symbolic addresses found in litmus file".to_owned()))?;

    let var_names: Vec<String> = symbolic.iter().map(Value::as_str).map(|v| v.unwrap().to_owned()).collect();

    let (page_table_setup, page_table_setup_source) = if let Some(setup) = litmus_toml.get("page_table_setup") {
        if litmus_toml.get("locations").is_some() {
            return Err(Error::GetTomlValue(
                "Cannot have a page_table_setup and locations in the same test".to_owned(),
            ));
        }
        if let Some(litmus_setup) = setup.as_str() {
            let setup = format!("{}{}", isa.default_page_table_setup, litmus_setup);
            let lexer = page_table::setup_lexer::SetupLexer::new(&setup);
            (
                page_table::setup_parser::SetupParser::new()
                    .parse(&isa, lexer)
                    .map_err(|error| {
                        axiomatic_litmus::format_error_page_table_setup(
                            litmus_setup,
                            error.map_location(|pos| pos - isa.default_page_table_setup.len()),
                        )
                    })
                    .map_err(Error::PageTableSetup)?,
                litmus_setup.to_string(),
            )
        } else {
            return Err(Error::PageTableSetup("page_table_setup must be a string".to_string()));
        }
    } else {
        (Vec::new(), "".to_string())
    };

    // eprintln!("{page_table_setup:#?}");

    let init_state = if mmu_on {
        litmus::gen_init_state(&page_table_setup)
    } else {
        var_names.clone().into_iter().map(|var| InitState::Var(var, "0".to_owned())).collect()
    };

    let additional_vars = get_additional_vars_from_pts(&page_table_setup, var_names.clone());

    let threads = litmus_toml
        .get("thread")
        .and_then(|t| t.as_table())
        .ok_or_else(|| Error::GetTomlValue("No threads found in litmus file (must be a toml table)".to_owned()))
        .and_then(|t| t.into_iter().map(|(name, thread)| parse_thread(name.as_ref(), thread, &symtab)).collect())?;

    let fin = litmus_toml
        .get("final")
        .ok_or_else(|| Error::GetTomlValue("No final section found in litmus file".to_owned()))?;
    let final_assertion = (match fin.get("assertion").and_then(Value::as_str) {
        Some(assertion) => {
            let lexer = exp_lexer::ExpLexer::new(assertion);
            let sizeof = axiomatic_litmus::parse_sizeof_types(&litmus_toml).unwrap();
            exp_parser::ExpParser::new()
                .parse(&sizeof, isa.default_sizeof, &symtab, &isa.register_renames, lexer)
                .map_err(|error| Error::ParseFinalAssertion(error.to_string()))
        }
        None => Err(Error::GetTomlValue("No final assertion found in litmus file".to_owned())),
    })?;
    let regs = regs_from_final_assertion(&symtab, final_assertion.clone())?;
    // eprintln!("Final assertion: {final_assertion:?}");

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
