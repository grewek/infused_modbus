// Interactive manual test rig for InfusedFilesystem. Mounts a small demo
// (or a real TOML device description, if given) so you can poke at it with
// plain shell commands.
//
// Usage:
//   cargo run -p datafs --example mount_demo -- <mountpoint> [device-description.toml]
//
// If given a TOML file, only its *first* configured machine is mounted —
// this rig predates the multi-machine device description and is a manual
// smoke-test tool, not a full multi-machine demo (see `client`/`server`'s
// own `main.rs` for that). The mounted machine is always named "Demo", so
// every path below is under <mountpoint>/Demo/ (every machine gets its own
// top-level directory — see datafs::filesystem::InfusedFilesystem).
//
// Then, in another terminal:
//   ls <mountpoint>/Demo/holding-registers
//   cat <mountpoint>/Demo/holding-registers/Tank_Temperature
//   echo 0xbad > <mountpoint>/Demo/transactions/Stop_Process
//   cat <mountpoint>/Demo/transactions/Stop_Process
//   ls <mountpoint>/Demo/transactions
//   rm <mountpoint>/Demo/transactions/Stop_Process
//   touch <mountpoint>/Demo/transactions/TRANSACTION_END
//   cat <mountpoint>/Demo/report/Stop_Process
//
// There's no real Modbus device here, so "confirming" a transaction is
// faked by a background thread that applies it to the store and reports it
// as OK, immediately instead of waiting on a real write response — see the
// println! it prints when it does so.
//
// Ctrl+C to stop; the kernel unmounts automatically once the process exits.

use datafs::filesystem::{InfusedFilesystem, MachineConfig, WriteMode};
use datafs::{
    CoilStore, CoilValue, DiscreteInputStore, FileRecordStore, InputRegisterStore, RegisterStore,
    RegisterValue, StagedValue, WriteReport, WriteStatus,
};
use protocol::device_description::{
    AccessRight, CoilDescription, DataType, DeviceDescription, RegisterDescription,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, mpsc};

const DEMO_MACHINE_NAME: &str = "Demo";

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
            let machine = description
                .machines
                .into_iter()
                .next()
                .unwrap_or_else(|| panic!("{path} has no [[machines]] entries"));
            (
                machine.registers,
                machine.coils,
                machine.discrete_inputs,
                machine.input_registers,
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
        mpsc::channel::<(String, HashMap<String, StagedValue>)>();
    {
        let store = Arc::clone(&store);
        let report = Arc::clone(&report);
        std::thread::spawn(move || {
            for (_machine_name, transaction) in transaction_receiver {
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
                        StagedValue::DiscreteInput(_)
                        | StagedValue::InputRegister(_)
                        | StagedValue::FileRecord { .. } => {
                            // This demo only mounts in WriteMode::Staged, so
                            // these are never actually produced — see
                            // datafs::filesystem's "server direct-write
                            // model" doc comment.
                            println!("(demo) unreachable in WriteMode::Staged: {name}");
                        }
                        StagedValue::MaskedRegister { .. } => {
                            println!("(demo) mask writes aren't wired up yet: {name}");
                            report.set(
                                name,
                                WriteStatus::Failed(
                                    "mask writes not supported yet in this demo".to_string(),
                                ),
                            );
                        }
                    }
                }
            }
        });
    }

    println!("Mounting infused_modbus demo filesystem at {mountpoint}");
    println!();
    println!("Try, from another terminal:");
    println!("  ls {mountpoint}/{DEMO_MACHINE_NAME}/holding-registers");
    println!("  cat {mountpoint}/{DEMO_MACHINE_NAME}/holding-registers/Tank_Temperature");
    println!("  ls {mountpoint}/{DEMO_MACHINE_NAME}/coils");
    println!("  cat {mountpoint}/{DEMO_MACHINE_NAME}/coils/Motor_Running");
    println!("  echo 0xbad > {mountpoint}/{DEMO_MACHINE_NAME}/transactions/Stop_Process");
    println!("  cat {mountpoint}/{DEMO_MACHINE_NAME}/transactions/Stop_Process");
    println!("  ls {mountpoint}/{DEMO_MACHINE_NAME}/transactions");
    println!("  rm {mountpoint}/{DEMO_MACHINE_NAME}/transactions/Stop_Process");
    println!("  touch {mountpoint}/{DEMO_MACHINE_NAME}/transactions/TRANSACTION_END");
    println!("  cat {mountpoint}/{DEMO_MACHINE_NAME}/report/Stop_Process");
    println!();
    println!("Ctrl+C to stop (the kernel unmounts automatically on exit).");

    let discrete_input_store = Arc::new(Mutex::new(DiscreteInputStore::new()));
    let input_register_store = Arc::new(Mutex::new(InputRegisterStore::new()));
    let file_record_store = Arc::new(Mutex::new(FileRecordStore::new()));

    let machine = MachineConfig {
        name: DEMO_MACHINE_NAME.to_string(),
        registers,
        coils,
        discrete_inputs,
        input_registers,
        file_records: Vec::new(),
        store,
        coil_store,
        discrete_input_store,
        input_register_store,
        file_record_store,
        report,
        permissions: datafs::permissions::FusePermissions::default(),
        server_id: None,
    };
    let filesystem =
        InfusedFilesystem::new(vec![machine], transaction_sender, WriteMode::Staged, None);
    let mut config = fuser::Config::default();
    config.mount_options = vec![fuser::MountOption::DefaultPermissions];
    fuser::mount(filesystem, &mountpoint, &config)
        .unwrap_or_else(|error| panic!("mount failed: {error}"));
}
