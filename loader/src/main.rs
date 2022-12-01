/*
 * Copyright © 2020-2022 Mrack
 * Email: Mrack@qq.com
 */

use std::ffi::CString;
use winapi as win;

#[cfg(target_os = "windows")]
fn main() {
    println!("input inject dll path:");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");
    let dll_path = input.trim().to_string();

    println!("input inject process id:");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");
    let pid = input.trim().to_string().parse::<u32>().unwrap();

    let dll_len = dll_path.len();
    let dll_path = std::ffi::CString::new(dll_path).unwrap();
    let dll_path = dll_path.as_ptr();
    let h_process = unsafe {
        win::um::processthreadsapi::OpenProcess(win::um::winnt::PROCESS_ALL_ACCESS, 0, pid)
    };
    if h_process.is_null() {
        println!("OpenProcess failed");
        return;
    }

    let alloc_addr = unsafe {
        win::um::memoryapi::VirtualAllocEx(
            h_process,
            std::ptr::null_mut(),
            dll_len,
            win::um::winnt::MEM_COMMIT,
            win::um::winnt::PAGE_READWRITE,
        )
    };

    if alloc_addr.is_null() {
        println!("VirtualAllocEx failed");
        return;
    }

    let mut bytes_write = 0;

    let fn_lla_addr = unsafe {
        std::mem::transmute(match get_fn_addr("Kernel32.dll", "LoadLibraryA") {
            Ok(addr) => addr,
            Err(_e) => 0,
        })
    };

    unsafe {
        win::um::memoryapi::WriteProcessMemory(
            h_process,
            alloc_addr,
            dll_path as *const win::ctypes::c_void,
            dll_len,
            &mut bytes_write,
        )
    };
    let h_thread = unsafe {
        win::um::processthreadsapi::CreateRemoteThread(
            h_process,
            std::ptr::null_mut(),
            0,
            Some(fn_lla_addr),
            alloc_addr,
            0,
            std::ptr::null_mut(),
        )
    };
    unsafe { win::um::handleapi::CloseHandle(h_thread) };
    unsafe { win::um::handleapi::CloseHandle(h_process) };
}

fn get_fn_addr<'a>(mod_name: &str, fn_name: &str) -> Result<u64, &'a str> {
    let mod_str = CString::new(mod_name).unwrap();
    let fn_str = CString::new(fn_name).unwrap();

    let mod_handle = unsafe { winapi::um::libloaderapi::GetModuleHandleA(mod_str.as_ptr()) };

    if mod_handle == core::ptr::null_mut() {
        return Err("GetModuleHandleA");
    }

    let fn_addr = unsafe { winapi::um::libloaderapi::GetProcAddress(mod_handle, fn_str.as_ptr()) };

    if fn_addr == core::ptr::null_mut() {
        return Err("GetProcAddress");
    }
    Ok(fn_addr as u64)
}
