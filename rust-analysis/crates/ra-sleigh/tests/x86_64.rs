use ra_sleigh::{default_processors_dir, Access, FlowKind, Language};

fn lang() -> Language {
    Language::load(&default_processors_dir(), "x86:LE:64:default").expect("x86-64 spec compiles")
}

#[test]
fn x86_64_flow_and_refs() {
    let l = lang();
    let mut d = l.decoder();
    let dec = |d: &mut ra_sleigh::Decoder, bytes: &[u8]| {
        let mut buf = bytes.to_vec();
        buf.resize(16, 0x90);
        d.decode(0x1000, &buf).expect("decodes")
    };

    let call = dec(&mut d, &[0xe8, 0x10, 0, 0, 0]);
    println!("{call:?}");
    assert_eq!(
        (call.mnemonic.as_str(), call.len, call.flow),
        ("CALL", 5, FlowKind::Call)
    );
    assert_eq!(call.targets, vec![0x1015]);
    assert!(call.has_fallthrough);

    let ret = dec(&mut d, &[0xc3]);
    assert_eq!(
        (ret.mnemonic.as_str(), ret.flow, ret.has_fallthrough),
        ("RET", FlowKind::Return, false)
    );

    let jz = dec(&mut d, &[0x74, 0x05]);
    assert_eq!(
        (jz.mnemonic.as_str(), jz.flow, jz.has_fallthrough),
        ("JZ", FlowKind::CondJump, true)
    );
    assert_eq!(jz.targets, vec![0x1007]);

    let jmp = dec(&mut d, &[0xeb, 0xfe]);
    assert_eq!((jmp.flow, jmp.has_fallthrough), (FlowKind::Jump, false));
    assert_eq!(jmp.targets, vec![0x1000]);

    let jmp_mem = dec(&mut d, &[0xff, 0x25, 0x10, 0, 0, 0]);
    println!("{jmp_mem:?}");
    assert_eq!(
        (jmp_mem.flow, jmp_mem.has_fallthrough, jmp_mem.indirect),
        (FlowKind::Jump, false, true)
    );
    assert_eq!(jmp_mem.indirect_via, Some(0x1016));
    assert!(jmp_mem.data_refs.contains(&(0x1016, Access::Read)));

    let lea = dec(&mut d, &[0x48, 0x8d, 0x05, 0x10, 0, 0, 0]);
    println!("{lea:?}");
    assert_eq!(lea.mnemonic, "LEA");
    assert!(
        lea.data_refs.contains(&(0x1017, Access::Address)),
        "{:?}",
        lea.data_refs
    );

    let rep = dec(&mut d, &[0xf3, 0xa4]);
    println!("{rep:?}");
    assert!(rep.has_fallthrough);
    assert!(rep.targets.is_empty());

    let hlt = dec(&mut d, &[0xf4]);
    println!("{hlt:?}");
}

#[test]
fn i386_and_aarch64_basic_flows() {
    let p = default_processors_dir();
    let x86 = Language::load(&p, "x86:LE:32:default").unwrap();
    let mut d = x86.decoder();
    let call = d.decode(0x1000, &[0xe8, 0x10, 0, 0, 0, 0x90]).unwrap();
    assert_eq!(
        (call.flow, call.targets.clone()),
        (FlowKind::Call, vec![0x1015])
    );
    // jmp dword ptr [0x2000]
    let jmp = d.decode(0x1000, &[0xff, 0x25, 0x00, 0x20, 0, 0]).unwrap();
    assert_eq!(jmp.indirect_via, Some(0x2000));

    let a64 = Language::load(&p, "AARCH64:LE:64:v8A").unwrap();
    let mut d = a64.decoder();
    // bl #0x40
    let bl = d.decode(0x1000, &0x9400_0010u32.to_le_bytes()).unwrap();
    assert_eq!(
        (bl.mnemonic.as_str(), bl.flow, bl.targets.clone()),
        ("BL", FlowKind::Call, vec![0x1040])
    );
    // ret
    let ret = d.decode(0x1000, &0xd65f_03c0u32.to_le_bytes()).unwrap();
    assert_eq!((ret.flow, ret.has_fallthrough), (FlowKind::Return, false));
    // b.eq #0x8
    let beq = d.decode(0x1000, &0x5400_0040u32.to_le_bytes()).unwrap();
    assert_eq!(
        (beq.flow, beq.targets.clone()),
        (FlowKind::CondJump, vec![0x1008])
    );
    // adrp x0, #0x2000 carries no reference itself (as in Ghidra); the
    // following `ldr x1, [x0, #8]` reads 0x2008 once the register value is
    // propagated.
    let mut st = ra_sleigh::RegState::default();
    let adrp = d
        .decode_in(0x1000, &0xb000_0000u32.to_le_bytes(), Some(&mut st))
        .unwrap();
    assert!(adrp.data_refs.is_empty(), "{:?}", adrp);
    let ldr = d
        .decode_in(0x1004, &0xf940_0401u32.to_le_bytes(), Some(&mut st))
        .unwrap();
    assert!(ldr.data_refs.contains(&(0x2008, Access::Read)), "{:?}", ldr);
    // bl writes the return address to x30: not a data reference.
    assert!(bl.data_refs.is_empty(), "{:?}", bl);
}
