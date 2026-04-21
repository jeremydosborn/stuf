//! stuf toaster demo — TUF firmware updater on ARM Cortex-M3

#![no_std]
#![no_main]

extern crate alloc;

use cortex_m_rt::entry;
use cortex_m_semihosting::hprintln;
use panic_semihosting as _;

use stuf_tuf::verify::chain::TrustAnchor;
use stuf_tuf::verify::state::FixedClock;
use stuf_tuf::encoding::Encoding;
use stuf_tuf::env::transport::Transport;
use stuf_tuf::error::Error;
use stuf_env::crypto::Ed25519Verifier;

static ROOT_BYTES: &[u8] = include_bytes!("../factory/root.json");

const CURRENT_VERSION: &str = "1.0.0";
const NEW_VERSION: &str = "1.1.0";
const TARGET_FIRMWARE: &str = "toaster-firmware-1.1.0.bin";
const META_BUF: usize = 4096;
const FIRMWARE_BUF: usize = 2048;
const PATH_BUF: usize = 64;

mod semi {
    use cortex_m_semihosting::nr;

    pub fn open(path: &[u8]) -> Option<usize> {
        let args = [path.as_ptr() as usize, 0usize, path.len() - 1];
        let fd = unsafe { cortex_m_semihosting::syscall(nr::OPEN, &args) };
        if fd == usize::MAX { None } else { Some(fd) }
    }

    pub fn flen(fd: usize) -> Option<usize> {
        let len = unsafe { cortex_m_semihosting::syscall(nr::FLEN, &fd) };
        if len == usize::MAX { None } else { Some(len) }
    }

    pub fn read(fd: usize, buf: &mut [u8]) -> bool {
        let args = [fd, buf.as_mut_ptr() as usize, buf.len()];
        unsafe { cortex_m_semihosting::syscall(nr::READ, &args) == 0 }
    }

    pub fn close(fd: usize) {
        unsafe { cortex_m_semihosting::syscall(nr::CLOSE, &fd) };
    }
}

fn build_path(filename: &str, buf: &mut [u8; PATH_BUF]) -> usize {
    let prefix = b"stuf-examples/publisher-repo/";
    let fname = filename.as_bytes();
    let total = prefix.len() + fname.len() + 1;
    debug_assert!(total <= PATH_BUF, "path too long");
    buf[..prefix.len()].copy_from_slice(prefix);
    buf[prefix.len()..prefix.len() + fname.len()].copy_from_slice(fname);
    buf[prefix.len() + fname.len()] = 0;
    total
}

#[derive(Clone)]
struct SemihostingTransport;

#[derive(Debug)]
struct SemiError;

impl Transport for SemihostingTransport {
    type Buffer = alloc::vec::Vec<u8>;
    type Error = SemiError;

    fn fetch(&self, id: &str) -> Result<alloc::vec::Vec<u8>, SemiError> {
        let mut path = [0u8; PATH_BUF];
        build_path(id, &mut path);
        let fd = semi::open(&path).ok_or(SemiError)?;
        let len = semi::flen(fd).ok_or_else(|| { semi::close(fd); SemiError })?;
        let mut buf = alloc::vec![0u8; len];
        let ok = semi::read(fd, &mut buf);
        semi::close(fd);
        if ok { Ok(buf) } else { Err(SemiError) }
    }
}

fn fetch_to_buf<'a>(filename: &str, buf: &'a mut [u8]) -> Option<&'a [u8]> {
    let mut path = [0u8; PATH_BUF];
    build_path(filename, &mut path);
    let fd = semi::open(&path)?;
    let len = semi::flen(fd)?;
    if len > buf.len() { semi::close(fd); return None; }
    let ok = semi::read(fd, &mut buf[..len]);
    semi::close(fd);
    if ok { Some(&buf[..len]) } else { None }
}

#[derive(Clone)]
struct BareMetalJson;

impl Encoding for BareMetalJson {
    fn decode<T>(&self, bytes: &[u8]) -> Result<T, Error>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        let (val, _) = serde_json_core::from_slice::<T>(bytes)
            .map_err(|_| Error::Deserialize)?;
        Ok(val)
    }

    fn canonical<T>(&self, value: &T) -> Result<alloc::vec::Vec<u8>, Error>
    where
        T: serde::Serialize,
    {
        let mut buf = alloc::vec![0u8; META_BUF];
        let len = serde_json_core::to_slice(value, &mut buf)
            .map_err(|_| Error::Encoding)?;
        buf.truncate(len);
        Ok(buf)
    }
}

fn flash_write(firmware: &[u8]) {
    let checksum = firmware.iter().fold(0u32, |acc, &b| acc.wrapping_add(b as u32));
    hprintln!("  writing {} bytes to flash (checksum: 0x{:08x})", firmware.len(), checksum);
}

#[entry]
fn main() -> ! {
    hprintln!("");
    hprintln!("╔══════════════════════════════════════════════╗");
    hprintln!("║  stuf v0.1.0 — TUF firmware updater         ║");
    hprintln!("║  target: ARM Cortex-M3 (lm3s6965evb)        ║");
    hprintln!("║  flash:  256KB  ram: 64KB  no heap          ║");
    hprintln!("╚══════════════════════════════════════════════╝");
    hprintln!("");
    hprintln!("installed: firmware v{}", CURRENT_VERSION);
    hprintln!("root:      {} bytes (manufacture burn)", ROOT_BYTES.len());

    hprintln!("");
    hprintln!("━━━ UPDATE SEQUENCE ━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let mut ts_buf = [0u8; META_BUF];
    let mut snap_buf = [0u8; META_BUF];
    let mut targets_buf = [0u8; META_BUF];
    let mut firmware_buf = [0u8; FIRMWARE_BUF];

    hprintln!("[1/5] fetching timestamp...");
    let ts = fetch_to_buf("timestamp.json", &mut ts_buf)
        .unwrap_or_else(|| { hprintln!("      FAILED"); loop {} });
    hprintln!("      ok ({} bytes)", ts.len());

    hprintln!("[2/5] fetching snapshot...");
    let snap = fetch_to_buf("snapshot.json", &mut snap_buf)
        .unwrap_or_else(|| { hprintln!("      FAILED"); loop {} });
    hprintln!("      ok ({} bytes)", snap.len());

    hprintln!("[3/5] fetching targets...");
    let targets = fetch_to_buf("targets.json", &mut targets_buf)
        .unwrap_or_else(|| { hprintln!("      FAILED"); loop {} });
    hprintln!("      ok ({} bytes)", targets.len());

    hprintln!("[4/5] verifying TUF metadata chain...");
    let clock = FixedClock(1_700_000_000);

    let anchor = TrustAnchor::new(
        ROOT_BYTES, Ed25519Verifier, SemihostingTransport, clock, BareMetalJson,
    ).unwrap_or_else(|e| { hprintln!("  root FAILED: {:?}", e); loop {} });
    hprintln!("      root verified");

    let ts_ok = anchor.verify_timestamp_bytes(ts)
        .unwrap_or_else(|e| { hprintln!("  timestamp FAILED: {:?}", e); loop {} });
    hprintln!("      timestamp verified");

    let snap_ok = ts_ok.verify_snapshot_bytes(snap)
        .unwrap_or_else(|e| { hprintln!("  snapshot FAILED: {:?}", e); loop {} });
    hprintln!("      snapshot verified");

    let tgt_ok = snap_ok.verify_targets_bytes(targets)
        .unwrap_or_else(|e| { hprintln!("  targets FAILED: {:?}", e); loop {} });
    hprintln!("      targets verified");

    hprintln!("[5/5] fetching firmware v{}...", NEW_VERSION);
    let firmware = fetch_to_buf(TARGET_FIRMWARE, &mut firmware_buf)
        .unwrap_or_else(|| { hprintln!("      FAILED"); loop {} });

    let _verified = tgt_ok.verify_target_bytes(TARGET_FIRMWARE, firmware)
        .unwrap_or_else(|e| { hprintln!("  firmware REJECTED: {:?}", e); loop {} });
    hprintln!("      firmware verified ({} bytes)", firmware.len());

    hprintln!("");
    hprintln!("update: v{} -> v{}", CURRENT_VERSION, NEW_VERSION);
    hprintln!("installing...");
    flash_write(firmware);
    hprintln!("ok firmware v{} installed (verified)", NEW_VERSION);
    hprintln!("");
    hprintln!("   toast setting: golden brown");
    hprintln!("   stuf kept your toaster safe.");
    hprintln!("demo complete.");

    cortex_m_semihosting::debug::exit(cortex_m_semihosting::debug::EXIT_SUCCESS);
    loop {}
}
