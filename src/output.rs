use std::collections::{HashMap, BTreeSet};

use crate::error::Result;
use crate::litmus::{InitState, Litmus, Reg, MovSrc};

const INCLUDES: &str = "#include \"lib.h\"";

fn sanitised_test_name(name: &str) -> String {
    name.chars()
        .filter_map(|c| match c {
            '+' => Some('_'),
            '.' => Some('_'), // temporary TODO: remove me
            '-' | '.' => None,
            'a'..='z' | 'A'..='Z' | '0'..='9' => Some(c),
            _ => {
                log::warn!("found unexpected char {c:?} in test name");
                Some('_')
            }
        })
        .collect()
}

fn asm_subs_from_thread_reset(reset: HashMap<Reg, MovSrc>) -> Result<String> {
    let mut vas = BTreeSet::new();
    let mut ptes = BTreeSet::new();
    let mut pages = BTreeSet::new();
    let mut descs = BTreeSet::new();
    let mut pmds = BTreeSet::new();
    let mut puds = BTreeSet::new();
    let mut pmddescs = BTreeSet::new();
    let mut puddescs = BTreeSet::new();
    for (reg, val) in reset {
        if matches!(reg, Reg::Isla(_)) {
            continue;
        }
        match val {
            MovSrc::Nat(_) | MovSrc::Bin(_) | MovSrc::Hex(_)  => {},
            MovSrc::Reg(var) => {vas.insert(var);},
            MovSrc::Page(var) => {pages.insert(var);},
            MovSrc::Pte(var, 1) => {puds.insert(var);},
            MovSrc::Pte(var, 2) => {pmds.insert(var);},
            MovSrc::Pte(var, _) => {ptes.insert(var);},
            MovSrc::Desc(var, 1) => {puddescs.insert(var);},
            MovSrc::Desc(var, 2) => {pmddescs.insert(var);},
            MovSrc::Desc(var, _) => {descs.insert(var);},
        }
    }

    fn to_comma_list(a: BTreeSet<String>) -> String {
        a.iter().cloned().collect::<Vec<_>>().join(", ")
    }

    let mut res = vec![];
    if !vas.is_empty() {
        res.push(format!("ASM_VAR_VAs(data, {})", to_comma_list(vas)));
    }
    if !ptes.is_empty() {
        res.push(format!("ASM_VAR_PTEs(data, {})", to_comma_list(ptes)));
    }
    if !pages.is_empty() {
        res.push(format!("ASM_VAR_PAGEs(data, {})", to_comma_list(pages)));
    }
    if !descs.is_empty() {
        res.push(format!("ASM_VAR_DESCs(data, {})", to_comma_list(descs)));
    }
    if !pmds.is_empty() {
        res.push(format!("ASM_VAR_PMDs(data, {})", to_comma_list(pmds)));
    }
    if !puds.is_empty() {
        res.push(format!("ASM_VAR_PUDs(data, {})", to_comma_list(puds)));
    }
    if !pmddescs.is_empty() {
        res.push(format!("ASM_VAR_PMDDESCs(data, {})", to_comma_list(pmddescs)));
    }
    if !puddescs.is_empty() {
        res.push(format!("ASM_VAR_PUDDESCs(data, {})", to_comma_list(puddescs)));
    }
    res.push("ASM_REGS(data, REGS)".to_owned());

    Ok(res.join(",\n    "))
}


pub fn write_output(litmus: Litmus) -> Result<String> {
    // println!("{litmus:#?}");
    let name = litmus.name;
    let sanitised_name = sanitised_test_name(&name) + "__toml";
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
    let mut handler_erets = HashMap::new();
    for t in &litmus.thread_sync_handlers {
        if let Some(eret_reg) = &t.eret_reg {
            for (thread, _el) in &t.threads_els {
                if !handler_erets.contains_key(thread) {
                    handler_erets.insert(thread.clone(), vec![]);
                }
                let thread_erets = handler_erets.get_mut(thread).unwrap();
                thread_erets.push(eret_reg.clone());
            }
        }
    }
    let thread_sync_handler_refs = {
        let mut handler_refs = vec![vec![None, None]; thread_count];
        for handler in &litmus.thread_sync_handlers {
            for (thread, el) in &handler.threads_els {
                handler_refs[*thread][*el as usize] = Some(&handler.name);
            }
        }
        let lines = handler_refs
            .into_iter()
            .map(|els| {
                els.into_iter()
                    .map(|name| name.map(|name| format!("(u32*){name}")).unwrap_or("NULL".to_owned()))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .map(|inner| format!("(u32*[]){{{inner}}},"))
            .collect::<Vec<_>>()
            .join("\n    ");
        format!(
            ".thread_sync_handlers = (u32**[]){{\
            \n    {lines}\
            \n  }},\
            "
        )
    };
    let c_thread_sync_handlers: String = litmus
        .thread_sync_handlers
        .into_iter()
        .map(|handler| {
            let handler_name = handler.name;
            let thread_names = handler
                .threads_els
                .iter()
                .map(|(thread, el)| format!("{thread} (EL{el})"))
                .collect::<Vec<_>>()
                .join(", ");

            let body = handler
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

            format!(
                "// Thread sync handler for thread {thread_names}\
                \nstatic void {handler_name}(void) {{\
                \n  asm volatile (\
                \n    {body}\
                \n  );\
                \n}}\
                "
            )
        })
        .collect::<Vec<String>>()
        .join("\n\n");
    let c_threads: String = litmus
        .threads
        .into_iter()
        .map(|thread| {
            let thread_no: usize = thread.name.parse().unwrap(); // TODO: this should be error checked
            let thread_name = format!("P{thread_no}");

            let reg_setup = if thread.reset.is_empty() {
                "".to_owned()
            } else {
                let reg_movs = thread
                    .reset
                    .iter()
                    .filter(|(reg, _val)| !matches!(reg, Reg::Isla(_)))
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
            let mut regs_clobber = thread.regs_clobber.iter().map(Reg::as_asm_quoted).collect::<Vec<_>>().join(", ");
            if let Some(eret_regs) = handler_erets.get(&thread_no) {
                let eret_regs = eret_regs.iter().map(|r| r.as_asm_quoted()).collect::<Vec<_>>().join(", ");
                regs_clobber = [regs_clobber, eret_regs].join(", ");
            }

            let asm_subs = asm_subs_from_thread_reset(thread.reset).unwrap();
            format!(
                "static void {thread_name}(litmus_test_run* data) {{\
                \n  asm volatile (\
                      {reg_setup}\
                \n    /* test */\
                \n    {body}\
                      {output_var}\
                \n  :\
                \n  : {asm_subs}\
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
        let mut unmapped = vec![];
        let mut vars = vec![];
        let mut aliases = vec![];
        for state in &litmus.init_state {
            match state {
                InitState::Unmapped(var) => unmapped.push(format!("INIT_UNMAPPED({var})")),
                InitState::Var(var, val) => vars.push(format!("INIT_VAR({var}, {val})")),
                InitState::Alias(from, to) => aliases.push(format!("INIT_ALIAS({from}, {to})")),
            }
        }
        unmapped.sort();
        vars.sort();
        aliases.sort();
        let state_str = [unmapped, vars, aliases].into_iter().flatten().collect::<Vec<_>>().join(",\n    ");
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

{c_thread_sync_handlers}

// Final assertion
// {final_assertion}

// Final test struct
litmus_test_t {sanitised_name} = {{
  \"{name}\",
  MAKE_THREADS({thread_count}),
  MAKE_VARS(VARS{additional_vars}),
  MAKE_REGS(REGS),
  INIT_STATE({init_state}),
  .no_interesting_results = {no_interesting_results},
  .interesting_results = (uint64_t*[]){{{interesting_results}}},
  // .no_sc_results = TODO,
  {thread_sync_handler_refs}
  .requires_pgtable = {requires_pgtable},
  .start_els = (int[]){{{start_els}}},
}};
",
    );

    Ok(out)
}
