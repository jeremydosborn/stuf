pub trait Bundle {
    fn payload(&self) -> &[u8];
    fn evidence(&self) -> &[u8];
}
