use crate::error::Result;
use crate::litmus::{InitState, Litmus, Reg};

const INCLUDES: &str = "#include \"lib.h\"";

pub fn write_output(litmus: Litmus) -> Result<String> {
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

    Ok(out)
}
