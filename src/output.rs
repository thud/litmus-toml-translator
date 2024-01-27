use std::collections::HashMap;

use crate::error::Result;
use crate::litmus::{InitState, Litmus, Reg};

const INCLUDES: &str = "#include \"lib.h\"";

fn sanitised_test_name(name: &str) -> String {
    name.chars()
        .filter_map(|c| match c {
            '+' => Some('_'),
            '-' | '.' => None,
            'a'..='z' | 'A'..='Z' | '0'..='9' => Some(c),
            _ => {
                log::warn!("found unexpected char {c:?} in test name");
                Some('_')
            }
        })
        .collect()
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
    let mut used_handler_erets = HashMap::new();
    for t in &litmus.threads {
        let tn: usize = t.name.parse().unwrap();
        handler_erets.insert(tn, t.eret_reg.clone());
    }
    let thread_sync_handler_refs = {
        let mut handler_refs = vec![vec![None, None]; thread_count];
        for handler in &litmus.thread_sync_handlers {
            handler_refs[handler.thread][handler.el as usize] = Some(&handler.name);
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
            let thread_name = handler.thread;
            let el = handler.el;

            let eret_reg = handler_erets.get(&handler.thread).unwrap();
            used_handler_erets.insert(handler.thread, eret_reg);
            let eret = format!("ERET_TO_NEXT({})", eret_reg.as_asm());

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
                "// Thread sync handler for thread {thread_name} (EL{el})\
                \nstatic void {handler_name}(void) {{\
                \n  asm volatile (\
                \n    {body}\
                \n\
                \n    {eret}\
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
            if let Some(eret_reg) = used_handler_erets.get(&thread_no) {
                regs_clobber = [regs_clobber, eret_reg.as_asm_quoted()].join(", ");
            }

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
        let mut state_lines = litmus
            .init_state
            .into_iter()
            .map(|state| match state {
                InitState::Unmapped(var) => format!("INIT_UNMAPPED({var})"),
                InitState::Var(var, val) => format!("INIT_VAR({var}, {val})"),
                InitState::Alias(from, to) => format!("INIT_ALIAS({from}, {to})"),
            })
            .collect::<Vec<_>>();
        state_lines.sort();
        let state_str = state_lines.join(",\n    ");
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
