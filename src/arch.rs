use std::io::{BufReader, Read};

use isla_lib::bitvector::b64::B64;
use isla_lib::ir::serialize::DeserializedArchitecture;
use isla_lib::ir::*;

pub fn load_aarch64_config_irx() -> Result<DeserializedArchitecture<B64>, String> {
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

    let v_exp = env!("ISLA_VERSION").as_bytes();
    if version != v_exp {
        let v_got = String::from_utf8_lossy(&version).into_owned();
        let v_exp = String::from_utf8_lossy(v_exp).into_owned();
        panic!("Isla version mismatch (got {v_got}, expected {v_exp})");
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
