#![feature(pointer_byte_offsets)]

use std::mem::transmute;
use std::time::Duration;

use detour::static_detour;
use faithe::internal::*;
use faithe::process::Process;
use windows::{
    Win32::{
        Foundation::{HINSTANCE},
        System::Console::AllocConsole,
        System::Console::FreeConsole,
    },
};

static mut FOV: f32 = 120_f32;

#[no_mangle]
unsafe extern "system" fn DllMain(
    hinst_dll: HINSTANCE,
    fdw_reason: u32,
    _reserved: usize,
) -> isize {
    match fdw_reason {
        1 => {
            std::thread::spawn(move ||
                main_thread(hinst_dll)
            );
            1
        }
        _ => 0,
    }
}

#[repr(C)]
struct FovInfo {
    padding: [u8; 0x40],
    packed_fov: f32,
}

type UpdateFovFn = unsafe extern "system" fn(*mut FovInfo) -> usize;

static_detour! {
    static update_fov_hk: unsafe extern "system" fn(*mut FovInfo) -> usize;
}

static mut BASE_ADDRESS: *const usize = std::ptr::null();

#[no_mangle]
unsafe extern "system" fn main_thread(_lp_thread_parameter: HINSTANCE) {
    AllocConsole();

    std::panic::set_hook(Box::new(|panic_info| {
        if let Some(_str) = panic_info.payload().downcast_ref::<&str>() {
            println!("panic occurred: {_str:?}");
        } else {
            println!("panic occurred");
        }
    }));

    println!("Created by: Exceptis#0001");
    println!("Begin looking for camera::update_fov function.");

    let current_process = Process::from_handle(get_current_process());
    let mut modules = current_process
        .modules()
        .expect("failed to get current modules");

    if let Some(module) = modules.find(|bin| bin.sz_module == "SoTGame.exe") {
        BASE_ADDRESS = module.mod_base_addr as *const usize;
    }

    let fov_function_ptr: usize = transmute(find_pattern("SoTGame.exe", faithe::pattern::Pattern::from_ida_style("48 89 74 24 ? ? 48 83 ec 30 0f 29 74 24 ? ? 8b f9 0f")).expect("didn't find pattern").unwrap());
    println!("Found camera::update_fov {:x}", fov_function_ptr);

    let target: UpdateFovFn = transmute(fov_function_ptr);
    update_fov_hk
        .initialize(target, |x| update_fov(x))
        .expect("invalid hook")
        .enable()
        .expect("unable to enable hook");

    println!("Completed hooking!");
    std::thread::sleep(Duration::new(3, 0));
    FreeConsole();
    loop {
        std::thread::sleep(Duration::new(5, 0));

        if let Ok(file_data) = std::fs::read_to_string("C:\\marryjane\\fov.ini"){
            if let Ok(float) = file_data.parse(){
                FOV = float;
            }
        }
    }
}

#[no_mangle]
unsafe extern "system" fn update_fov(fov: *mut FovInfo) -> usize {
    let result = update_fov_hk.call(fov);
    (*fov).packed_fov = FOV / 78_f32;
    result
}