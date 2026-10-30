use omnisec_loader_pe::peparse::parse_pe;

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn sample() -> Vec<u8> {
    let mut b = vec![0u8; 2048];
    b[0..2].copy_from_slice(b"MZ");
    put32(&mut b, 0x3c, 0x80);
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    put16(&mut b, 0x84, 0x8664);
    put16(&mut b, 0x86, 1);
    put16(&mut b, 0x94, 240);
    put16(&mut b, 0x98, 0x20b);
    put32(&mut b, 0x98 + 108, 16);
    let s = 0x98 + 240;
    b[s..s + 5].copy_from_slice(b".text");
    put32(&mut b, s + 8, 0x400);
    put32(&mut b, s + 12, 0x1000);
    put32(&mut b, s + 16, 0x400);
    put32(&mut b, s + 20, 0x200);
    b
}

#[test]
fn review_rva_overflow() {
    let mut b = sample();
    put32(&mut b, 0x98 + 240 + 20, 0xfffffff0);
    put32(&mut b, 0x98 + 112 + 8, 0x1020);
    put32(&mut b, 0x98 + 112 + 12, 40);
    let parsed = std::panic::catch_unwind(|| parse_pe(&b));
    assert!(parsed.is_ok(), "RVA mapping panicked on u32 overflow");
    assert!(parsed.unwrap().is_err(), "invalid raw offset accepted");
}

#[test]
fn review_ordinal_only_export() {
    let mut b = sample();
    put32(&mut b, 0x98 + 112, 0x1000);
    put32(&mut b, 0x98 + 116, 0x80);
    put32(&mut b, 0x200 + 16, 5); // Export ordinal base.
    put32(&mut b, 0x200 + 20, 1); // NumberOfFunctions.
    put32(&mut b, 0x200 + 24, 0); // NumberOfNames: NONAME export.
    put32(&mut b, 0x200 + 28, 0x1050);
    put32(&mut b, 0x250, 0x1100);
    let pe = parse_pe(&b).unwrap();
    assert_eq!(pe.exports.len(), 1, "ordinal-only export lost");
    assert_eq!(pe.exports[0].ordinal, Some(5));
}

#[test]
fn review_zero_optional_header() {
    let mut b = sample();
    put16(&mut b, 0x94, 0);
    assert!(
        parse_pe(&b).is_err(),
        "SizeOfOptionalHeader=0 accepted as PE64"
    );
}

#[test]
fn review_truncated_section_table() {
    let mut b = sample();
    b.truncate(0x98 + 240);
    assert!(parse_pe(&b).is_err(), "missing declared section accepted");
}
