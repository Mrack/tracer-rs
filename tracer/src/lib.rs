/*
 * Copyright © 2020-2022 Mrack
 * Email: Mrack@qq.com
 */

use frida_gum as gum;
use frida_gum::stalker::{Stalker, Transformer};
use gum::interceptor::{Interceptor, InvocationListener};
use gum::stalker::NoneEventSink;
use lazy_static::lazy_static;
use winapi::shared::windef::HWND;
use std::collections::HashMap;
use std::os::raw::c_void;
use std::sync::Mutex;
use winapi::um::winnt::{DLL_PROCESS_ATTACH, LPCSTR};
use winapi::shared::minwindef::*;
use std::io::Write;
use std::ffi::CString;

#[cfg(target_os = "windows")]
#[no_mangle]
extern "stdcall" fn DllMain(_: HINSTANCE, fdw_reason: DWORD, _: LPVOID){
    if fdw_reason == DLL_PROCESS_ATTACH {
        let msg = CString::new("injected").unwrap();
        let title = CString::new("mrack").unwrap();
        unsafe {
            winapi::um::winuser::MessageBoxA(0 as HWND, msg.as_ptr() as LPCSTR, title.as_ptr() as LPCSTR, 0);
        }
        start_stalker()
    }
}

fn write_to_file(path: &str, content: &str) {
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .unwrap();
    file.write_all((content.to_string() + "\n").as_bytes()).unwrap();
}

lazy_static! {
    static ref GUM: gum::Gum = unsafe { gum::Gum::obtain() };

    static ref RANGE: TraceRange = 
        TraceRange {
            begin: 0x0007FF6C15E13F0 as u64,
            size: 800,
        };
    
    static ref MAP: Mutex<HashMap<String, u64>> = Mutex::new(HashMap::new());
    
    static ref INS_INFO: Mutex<HashMap<u64, String>> = Mutex::new(HashMap::new());
}

static mut STALKER: *mut c_void = 0 as *mut c_void;

struct TraceRange {
    begin: u64,
    size: u64,
}
struct AttachListener;

macro_rules! save_context {
    ($map:ident,$ct:expr ,$($name:ident),*) => {
        $(
            $map.insert(stringify!($name).to_string(), $ct.$name());
        )*
    };

    
    ($map:ident,$ct:expr) => {
        save_context!($map,$ct, sp, fp, lr);
        for i in 0..29{
            $map.insert(format!("x{}", i), $ct.reg(i));
        }
    };
}


impl InvocationListener for AttachListener {
    fn on_enter(&mut self, _: gum::interceptor::InvocationContext) {

        let transformer = Transformer::from_callback(&GUM, |basic_block, _output| {
        
            for instr in basic_block {
                
                if instr.instr().address() >= RANGE.begin
                    && instr.instr().address() <= RANGE.begin + RANGE.size
                {
                    
                    let ins = format!(
                        "{:x} {} {}",
                        instr.instr().address(),
                        instr.instr().mnemonic().unwrap(),
                        instr.instr().op_str().unwrap()
                    );

                    INS_INFO.lock().unwrap().insert(instr.instr().address(), ins);
                    instr.put_callout(|_cpu_context| {
                        let mut ct = MAP.lock().unwrap();
                        if !ct.is_empty() {
                            let mut cur = HashMap::new();

                            #[cfg(target_arch = "x86_64")]
                            save_context!(cur,&_cpu_context,r15,r14,r13,r12,r11,r10,r9,r8,rdi,rsi,rbp,rsp,rbx,rdx,rcx,rax);

                            #[cfg(target_arch = "aarch64")]
                            save_context!(cur,&_cpu_context);

                            for (k,v) in cur.iter(){
                                if ct[k]!= *v {
                                    write_to_file("log.txt", &format!("\t{}: {:x} -> {:x}",k,ct[k],v));
                                }
                            }
                        }
                        #[cfg(target_arch = "x86_64")]
                        save_context!(ct,&_cpu_context,r15,r14,r13,r12,r11,r10,r9,r8,rdi,rsi,rbp,rsp,rbx,rdx,rcx,rax);
                        #[cfg(target_arch = "aarch64")]
                        save_context!(ct,&_cpu_context);
                        
                        #[cfg(target_arch = "x86_64")]
                        write_to_file("log.txt", INS_INFO.lock().unwrap()[&_cpu_context.rip()].as_str());
                        #[cfg(target_arch = "aarch64")]
                        write_to_file("log.txt", INS_INFO.lock().unwrap()[&_cpu_context.pc()].as_str());
                    });
                }
                
                instr.keep();
            }
            
        });
        unsafe {
            let mut s = Stalker::new(&GUM);
            s.follow_me::<NoneEventSink>(&transformer, None);
            STALKER = Box::leak(Box::new(s)) as *mut _ as *mut c_void;
        }
    }

    fn on_leave(&mut self, _: gum::interceptor::InvocationContext) {
        unsafe {
            let s = STALKER as *mut Stalker;
            (*s).unfollow_me();
        }
    }
}


#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64"
))]
extern "C" fn start_stalker() {
    let mut interceptor = Interceptor::obtain(&GUM);
 
    let mut listener = AttachListener {};

    interceptor.attach(
        gum::NativePointer(RANGE.begin as *mut c_void),
        &mut listener,
    );
}
