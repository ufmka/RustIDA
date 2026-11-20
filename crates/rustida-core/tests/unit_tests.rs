use rustida_core::{Address, Endianness, Permissions, RustidaError};

#[test]
fn test_address_creation() {
    let addr = Address::new(0x1000);
    assert_eq!(addr.as_u64(), 0x1000);
}

#[test]
fn test_address_equality() {
    let addr1 = Address::new(0x1000);
    let addr2 = Address::new(0x1000);
    let addr3 = Address::new(0x2000);
    assert_eq!(addr1, addr2);
    assert_ne!(addr1, addr3);
}

#[test]
fn test_endianness() {
    let le = Endianness::LittleEndian;
    let be = Endianness::BigEndian;
    assert!(format!("{:?}", le) == "LittleEndian");
    assert!(format!("{:?}", be) == "BigEndian");
    assert_ne!(le, be);
}

#[test]
fn test_permissions() {
    let exec = Permissions::Execute;
    let read = Permissions::Read;
    let write = Permissions::Write;
    let re = Permissions::ReadExecute;
    let rw = Permissions::ReadWrite;
    let rwe = Permissions::ReadWriteExecute;
    assert!(format!("{:?}", exec) == "Execute");
    assert!(format!("{:?}", read) == "Read");
    assert!(format!("{:?}", write) == "Write");
    assert!(format!("{:?}", re) == "ReadExecute");
    assert!(format!("{:?}", rw) == "ReadWrite");
    assert!(format!("{:?}", rwe) == "ReadWriteExecute");
}

#[test]
fn test_error_display() {
    let err = RustidaError::InvalidFormat("bad format".to_string());
    assert_eq!(format!("{}", err), "invalid binary format: bad format");
}

#[test]
fn test_error_from_io() {
    let err = RustidaError::Io(std::io::Error::other("io error"));
    assert!(format!("{}", err).contains("io error"));
}
