// Interactive manual test rig for InfusedFilesystem. Mounts a small demo
// (or a real TOML device description, if given) so you can poke at it with
// plain shell commands.
//
// Usage:
//   cargo run -p fuse-fs --example mount_demo -- <mountpoint> [device-description.toml]
//
// Then, in another terminal:
//   ls <mountpoint>/holding-registers
//   cat <mountpoint>/holding-registers/Tank_Temperature
//   echo 0xbad > <mountpoint>/transactions/Stop_Process
//   cat <mountpoint>/transactions/Stop_Process
//   ls <mountpoint>/transactions
//   rm <mountpoint>/transactions/Stop_Process
//
// Ctrl+C to stop; the kernel unmounts automatically once the process exits.

use fuse_fs::filesystem::InfusedFilesystem;
use fuse_fs::{RegisterStore, RegisterValue};
use protocol::device_description::{AccessRight, DataType, DeviceDescription, RegisterDescription};
use std::sync::{Arc, Mutex};

fn demo_registers() -> Vec<RegisterDescription> {
    vec![
        RegisterDescription {
            name: "Tank_Temperature".to_string(),
            address: 40001,
            data_type: DataType::U16,
            access: AccessRight::ReadOnly,
        },
        RegisterDescription {
            name: "Flow_Rate".to_string(),
            address: 40002,
            data_type: DataType::F32,
            access: AccessRight::ReadOnly,
        },
        RegisterDescription {
            name: "Stop_Process".to_string(),
            address: 40003,
            data_type: DataType::U16,
            access: AccessRight::ReadWrite,
        },
    ]
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(mountpoint) = args.next() else {
        eprintln!("Usage: mount_demo <mountpoint> [device-description.toml]");
        std::process::exit(1);
    };

    let registers = match args.next() {
        Some(path) => {
            let toml_source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("failed to read {path}: {error}"));
            DeviceDescription::parse(&toml_source)
                .unwrap_or_else(|error| panic!("failed to parse {path}: {error}"))
                .registers
        }
        None => demo_registers(),
    };

    let store = Arc::new(Mutex::new(RegisterStore::new()));
    {
        let mut store = store.lock().unwrap();
        store.set("Tank_Temperature", RegisterValue::U16(72));
        store.set("Flow_Rate", RegisterValue::F32(3.5));
    }

    std::fs::create_dir_all(&mountpoint).ok();

    println!("Mounting infused_modbus demo filesystem at {mountpoint}");
    println!();
    println!("Try, from another terminal:");
    println!("  ls {mountpoint}/holding-registers");
    println!("  cat {mountpoint}/holding-registers/Tank_Temperature");
    println!("  echo 0xbad > {mountpoint}/transactions/Stop_Process");
    println!("  cat {mountpoint}/transactions/Stop_Process");
    println!("  ls {mountpoint}/transactions");
    println!("  rm {mountpoint}/transactions/Stop_Process");
    println!();
    println!("Ctrl+C to stop (the kernel unmounts automatically on exit).");

    let filesystem = InfusedFilesystem::new(registers, store);
    fuser::mount(filesystem, &mountpoint, &fuser::Config::default())
        .unwrap_or_else(|error| panic!("mount failed: {error}"));
}
