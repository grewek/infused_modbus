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
//   touch <mountpoint>/transactions/TRANSACTION_END
//   cat <mountpoint>/report/Stop_Process
//
// There's no real Modbus device here, so "confirming" a transaction is
// faked by a background thread that applies it to the store and reports it
// as OK, immediately instead of waiting on a real write response — see the
// println! it prints when it does so.
//
// Ctrl+C to stop; the kernel unmounts automatically once the process exits.

use fuse_fs::filesystem::{InfusedFilesystem, WriteMode};
use fuse_fs::{
    CoilStore, CoilValue, DiscreteInputStore, InputRegisterStore, RegisterStore, RegisterValue,
    StagedValue, WriteReport, WriteStatus,
};
use protocol::device_description::{
    AccessRight, CoilDescription, DataType, DeviceDescription, RegisterDescription,
};
use std::sync::{Arc, Mutex, mpsc};

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

fn demo_coils() -> Vec<CoilDescription> {
    vec![CoilDescription {
        name: "Motor_Running".to_string(),
        address: 1,
    }]
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(mountpoint) = args.next() else {
        eprintln!("Usage: mount_demo <mountpoint> [device-description.toml]");
        std::process::exit(1);
    };

    let (registers, coils, discrete_inputs, input_registers) = match args.next() {
        Some(path) => {
            let toml_source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("failed to read {path}: {error}"));
            let description = DeviceDescription::parse(&toml_source)
                .unwrap_or_else(|error| panic!("failed to parse {path}: {error}"));
            (
                description.registers,
                description.coils,
                description.discrete_inputs,
                description.input_registers,
            )
        }
        None => (demo_registers(), demo_coils(), Vec::new(), Vec::new()),
    };

    let store = Arc::new(Mutex::new(RegisterStore::new()));
    {
        let mut store = store.lock().unwrap();
        store.set("Tank_Temperature", RegisterValue::U16(72));
        store.set("Flow_Rate", RegisterValue::F32(3.5));
    }

    let coil_store = Arc::new(Mutex::new(CoilStore::new()));
    {
        let mut coil_store = coil_store.lock().unwrap();
        coil_store.set("Motor_Running", CoilValue(true));
    }

    std::fs::create_dir_all(&mountpoint).ok();

    let report = Arc::new(Mutex::new(WriteReport::new()));

    let (transaction_sender, transaction_receiver) =
        mpsc::channel::<std::collections::HashMap<String, StagedValue>>();
    {
        let store = Arc::clone(&store);
        let report = Arc::clone(&report);
        std::thread::spawn(move || {
            for transaction in transaction_receiver {
                let mut store = store.lock().unwrap();
                let mut report = report.lock().unwrap();
                for (name, value) in transaction {
                    match value {
                        StagedValue::Register(value) => {
                            println!("(demo) confirming write: {name} = {value}");
                            report.set(name.clone(), WriteStatus::Ok);
                            store.set(name, value);
                        }
                        StagedValue::Coil(_) => {
                            println!("(demo) coil writes aren't wired up yet: {name}");
                            report.set(
                                name,
                                WriteStatus::Failed(
                                    "coils not supported yet in this demo".to_string(),
                                ),
                            );
                        }
                        StagedValue::DiscreteInput(_) | StagedValue::InputRegister(_) => {
                            // This demo only mounts in WriteMode::Staged, so
                            // these are never actually produced — see
                            // fuse_fs::filesystem's "server direct-write
                            // model" doc comment.
                            println!("(demo) unreachable in WriteMode::Staged: {name}");
                        }
                    }
                }
            }
        });
    }

    println!("Mounting infused_modbus demo filesystem at {mountpoint}");
    println!();
    println!("Try, from another terminal:");
    println!("  ls {mountpoint}/holding-registers");
    println!("  cat {mountpoint}/holding-registers/Tank_Temperature");
    println!("  ls {mountpoint}/coils");
    println!("  cat {mountpoint}/coils/Motor_Running");
    println!("  echo 0xbad > {mountpoint}/transactions/Stop_Process");
    println!("  cat {mountpoint}/transactions/Stop_Process");
    println!("  ls {mountpoint}/transactions");
    println!("  rm {mountpoint}/transactions/Stop_Process");
    println!("  touch {mountpoint}/transactions/TRANSACTION_END");
    println!("  cat {mountpoint}/report/Stop_Process");
    println!();
    println!("Ctrl+C to stop (the kernel unmounts automatically on exit).");

    let discrete_input_store = Arc::new(Mutex::new(DiscreteInputStore::new()));
    let input_register_store = Arc::new(Mutex::new(InputRegisterStore::new()));

    let filesystem = InfusedFilesystem::new(
        registers,
        coils,
        discrete_inputs,
        input_registers,
        store,
        coil_store,
        discrete_input_store,
        input_register_store,
        transaction_sender,
        report,
        None,
        fuse_fs::permissions::FusePermissions::default(),
        WriteMode::Staged,
    );
    let mut config = fuser::Config::default();
    config.mount_options = vec![fuser::MountOption::DefaultPermissions];
    fuser::mount(filesystem, &mountpoint, &config)
        .unwrap_or_else(|error| panic!("mount failed: {error}"));
}
