//! A custom Modbus server for a single roller shutter / industrial roll-up
//! door ("Rolltor"), built on `server::server_handle::ServerHandle` -- the
//! programmatic, type-safe Rust API documented in CLAUDE.md's "Programmatic
//! Rust API for ServerHandle" section.
//!
//! Two things run side by side, sharing the exact same `MachineStores`:
//!   - a real Modbus TCP listener (`server::connection::serve_tcp_connection`),
//!     so any real Modbus master -- this project's own `client`, `mbpoll`,
//!     a SCADA system -- can read the door's state and send Open/Close
//!     commands, exactly like talking to a real door controller.
//!   - this example's own simulation loop, which *is* the door controller's
//!     firmware: it drives the motor, enforces the light-barrier safety
//!     interlock, and reports position/status -- all through `ServerHandle`
//!     directly, with no socket/FFI/filesystem in between.
//!
//! Run with `cargo run -p rolling_door_server` from the repository root,
//! then see this directory's README.md for how to interact with it.

use datafs::{CoilValue, MachineStores, RegisterValue, build_machine_stores};
use protocol::device_description::DeviceDescription;
use server::connection::serve_tcp_connection;
use server::handler::ServerMachineState;
use server::server_handle::ServerHandle;
use server::server_options::ServerOptions;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;

const DEVICE_DESCRIPTION_TOML: &str = include_str!("../device-description.toml");
const SERVER_OPTIONS_TOML: &str = include_str!("../server-options.toml");
const MACHINE_NAME: &str = "RollingDoor";
const BIND_ADDRESS: &str = "127.0.0.1:15502";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const SIMULATION_TICK: Duration = Duration::from_millis(200);
const MOTOR_STEP_PERCENT: u8 = 5;

#[derive(Clone, Copy, PartialEq, Eq)]
enum DoorState {
    Idle,
    Opening,
    Closing,
}

#[tokio::main]
async fn main() {
    let description = DeviceDescription::parse(DEVICE_DESCRIPTION_TOML)
        .unwrap_or_else(|error| panic!("failed to parse device-description.toml: {error}"));
    let server_options = ServerOptions::parse(SERVER_OPTIONS_TOML)
        .unwrap_or_else(|error| panic!("failed to parse server-options.toml: {error}"));

    // One set of stores per machine (here, just "RollingDoor") -- shared,
    // via Arc, between the wire-facing handler below and `ServerHandle`,
    // so a real Modbus master and this process's own simulation loop are
    // always looking at the same data, never two drifting copies.
    let machine_stores: HashMap<String, MachineStores> =
        build_machine_stores(&description.machines);

    let machines: Arc<HashMap<u8, ServerMachineState>> = Arc::new(
        description
            .machines
            .iter()
            .map(|machine| {
                let stores = &machine_stores[&machine.name];
                (
                    machine.unit_id,
                    ServerMachineState {
                        registers: Arc::new(machine.registers.clone()),
                        store: Arc::clone(&stores.registers),
                        coils: Arc::new(machine.coils.clone()),
                        coil_store: Arc::clone(&stores.coils),
                        discrete_inputs: Arc::new(machine.discrete_inputs.clone()),
                        discrete_input_store: Arc::clone(&stores.discrete_inputs),
                        input_registers: Arc::new(machine.input_registers.clone()),
                        input_register_store: Arc::clone(&stores.input_registers),
                        file_records: Arc::new(machine.file_records.clone()),
                        file_record_store: Arc::clone(&stores.file_records),
                        mem_layout: machine.mem_layout,
                        input_register_mem_layout: machine.input_register_mem_layout,
                        server_id: machine.server_id.clone(),
                    },
                )
            })
            .collect(),
    );
    let toml_source = Arc::new(DEVICE_DESCRIPTION_TOML.to_string());

    let handle = Arc::new(ServerHandle::new(&description.machines, &machine_stores));

    let listener = TcpListener::bind(BIND_ADDRESS)
        .await
        .unwrap_or_else(|error| panic!("failed to bind {BIND_ADDRESS}: {error}"));
    println!("Rolling door Modbus server listening on tcp://{BIND_ADDRESS}");
    tokio::spawn(async move {
        loop {
            let (stream, _peer_address) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(_) => continue,
            };
            let machines = Arc::clone(&machines);
            let toml_source = Arc::clone(&toml_source);
            tokio::spawn(async move {
                serve_tcp_connection(
                    stream,
                    server_options,
                    machines,
                    toml_source,
                    REQUEST_TIMEOUT,
                )
                .await;
            });
        }
    });

    tokio::spawn(run_simulation(Arc::clone(&handle)));
    tokio::spawn(run_console(handle));

    // The console (not awaited directly above) is a convenience, not this
    // process's lifetime -- stdin hitting EOF (e.g. no TTY attached, as
    // happens running this under a process supervisor) must not take the
    // Modbus listener and simulation down with it. Ctrl+C/SIGTERM is the
    // real shutdown signal, matching `client`/`server`'s own binaries.
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl_c");
    println!("Shutting down.");
}

/// The door's own control logic -- everything here goes through
/// `ServerHandle`, reading the remote commands a Modbus master sent
/// (coils) and driving the local safety/status I/O (discrete inputs) and
/// position (an input register) a real door controller's firmware would
/// own itself.
async fn run_simulation(handle: Arc<ServerHandle>) {
    let mut position: u8 = 0;
    let mut state = DoorState::Idle;
    let mut interval = tokio::time::interval(SIMULATION_TICK);

    loop {
        interval.tick().await;

        let emergency_stop = get_discrete_input(&handle, "Emergency_Stop");
        let light_barrier = get_discrete_input(&handle, "Light_Barrier");

        if emergency_stop {
            if state != DoorState::Idle {
                println!("[door] emergency stop -- motor halted");
            }
            state = DoorState::Idle;
        } else {
            match state {
                DoorState::Idle => {
                    let open_requested = take_coil(&handle, "Open_Command");
                    let close_requested = take_coil(&handle, "Close_Command");
                    if open_requested && position < 100 {
                        state = DoorState::Opening;
                        println!("[door] opening");
                    } else if close_requested && position > 0 && !light_barrier {
                        state = DoorState::Closing;
                        println!("[door] closing");
                    }
                }
                DoorState::Opening => {
                    position = position.saturating_add(MOTOR_STEP_PERCENT).min(100);
                    if position == 100 {
                        state = DoorState::Idle;
                        println!("[door] fully open");
                    }
                }
                DoorState::Closing => {
                    if light_barrier {
                        state = DoorState::Opening;
                        println!("[door] light barrier blocked -- reversing");
                    } else {
                        position = position.saturating_sub(MOTOR_STEP_PERCENT);
                        if position == 0 {
                            state = DoorState::Idle;
                            println!("[door] fully closed");
                        }
                    }
                }
            }
        }

        let motor_running = state != DoorState::Idle;
        set_discrete_input(&handle, "Motor_Running", motor_running);
        set_discrete_input(&handle, "Fully_Open", position == 100);
        set_discrete_input(&handle, "Fully_Closed", position == 0);
        handle
            .set_input_register(MACHINE_NAME, "Door_Position", RegisterValue::U8(position))
            .expect("Door_Position is declared in device-description.toml");
    }
}

fn get_discrete_input(handle: &ServerHandle, name: &str) -> bool {
    handle
        .get_discrete_input(MACHINE_NAME, name)
        .unwrap_or_else(|error| panic!("{name} is declared in device-description.toml: {error}"))
        .0
}

fn set_discrete_input(handle: &ServerHandle, name: &str, value: bool) {
    handle
        .set_discrete_input(MACHINE_NAME, name, CoilValue(value))
        .unwrap_or_else(|error| panic!("{name} is declared in device-description.toml: {error}"));
}

/// Reads a coil and, if it was set, immediately clears it back to `false`
/// -- the simulation's equivalent of a momentary pushbutton contact: a
/// Modbus master sets `Open_Command`/`Close_Command` to request movement,
/// and the door consumes that request rather than latching it.
fn take_coil(handle: &ServerHandle, name: &str) -> bool {
    let value = handle
        .get_coil(MACHINE_NAME, name)
        .unwrap_or_else(|error| panic!("{name} is declared in device-description.toml: {error}"))
        .0;
    if value {
        handle
            .set_coil(MACHINE_NAME, name, CoilValue(false))
            .unwrap_or_else(|error| {
                panic!("{name} is declared in device-description.toml: {error}")
            });
    }
    value
}

/// Stands in for the door's local control panel -- a real installation
/// wires an emergency-stop button and a light barrier directly to the
/// controller's own inputs; this console lets a person at the keyboard do
/// the same thing for this demo, via the identical `ServerHandle` calls
/// `run_simulation` itself uses to report status.
async fn run_console(handle: Arc<ServerHandle>) {
    println!(
        "Commands: estop | estop-clear | block | block-clear | status | help | quit (Ctrl+D also works)"
    );
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    // Stdin closed or erroring (e.g. no TTY attached) ends this loop -- the
    // console stops processing commands, but the Modbus listener and
    // simulation keep running regardless, see the ctrl_c() comment in
    // `main`.
    while let Ok(Some(line)) = lines.next_line().await {
        match line.trim() {
            "estop" => {
                set_discrete_input(&handle, "Emergency_Stop", true);
                println!("[panel] emergency stop engaged");
            }
            "estop-clear" => {
                set_discrete_input(&handle, "Emergency_Stop", false);
                println!("[panel] emergency stop released");
            }
            "block" => {
                set_discrete_input(&handle, "Light_Barrier", true);
                println!("[panel] light barrier blocked");
            }
            "block-clear" => {
                set_discrete_input(&handle, "Light_Barrier", false);
                println!("[panel] light barrier clear");
            }
            "status" => print_status(&handle),
            "help" => {
                println!(
                    "estop/estop-clear, block/block-clear, status, quit -- \
                     open/close the door itself via a real Modbus write \
                     to Open_Command/Close_Command, e.g. with this \
                     project's own `client`."
                );
            }
            "quit" => std::process::exit(0),
            "" => {}
            other => println!("unknown command {other:?} (type 'help')"),
        }
    }
}

fn print_status(handle: &ServerHandle) {
    let position = handle
        .get_input_register(MACHINE_NAME, "Door_Position")
        .expect("Door_Position is declared in device-description.toml");
    println!(
        "position={position} motor_running={} emergency_stop={} light_barrier={}",
        get_discrete_input(handle, "Motor_Running"),
        get_discrete_input(handle, "Emergency_Stop"),
        get_discrete_input(handle, "Light_Barrier"),
    );
}
