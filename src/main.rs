/*
 * Copyright © 2020-2022 Mrack
 * Email: Mrack@qq.com
 */

use frida_gum as gum;
use frida_gum::stalker::{Stalker, Transformer};
use gum::interceptor::{Interceptor, InvocationListener};
use gum::stalker::NoneEventSink;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::os::raw::c_void;
use std::sync::Mutex;

lazy_static! {
    static ref GUM: gum::Gum = unsafe { gum::Gum::obtain() };
    static ref RANGE: TraceRange = 
        TraceRange {
            begin: verify as u64,
            size: 800,
        };
    
    static ref MAP: Mutex<HashMap<String, u64>> = Mutex::new(HashMap::new());
    
    static ref INS_INFO: Mutex<HashMap<u64, String>> = Mutex::new(HashMap::new());
}

struct TraceRange {
    begin: u64,
    size: u64,
}
struct AttachListener<'d> {
    stalker: Stalker<'d>,
}

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

impl<'d> InvocationListener for AttachListener<'d> {
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
                                    println!("\t{} {:x} => {:x}",k, ct[k],v);
                                }
                            }
                        }
                        #[cfg(target_arch = "x86_64")]
                        save_context!(ct,&_cpu_context,r15,r14,r13,r12,r11,r10,r9,r8,rdi,rsi,rbp,rsp,rbx,rdx,rcx,rax);
                        #[cfg(target_arch = "aarch64")]
                        save_context!(ct,&_cpu_context);
                        
                        #[cfg(target_arch = "x86_64")]
                        println!("{}",INS_INFO.lock().unwrap()[&_cpu_context.rip()]);
                        #[cfg(target_arch = "aarch64")]
                        println!("{}",INS_INFO.lock().unwrap()[&_cpu_context.pc()]);
                    });
                }
                
                instr.keep();
            }
            
        });

        println!("on_enter");
        self.stalker.follow_me::<NoneEventSink>(&transformer, None);
    }

    fn on_leave(&mut self, _: gum::interceptor::InvocationContext) {
        self.stalker.unfollow_me();
        println!("on_leave");
    }
}

#[no_mangle]
fn verify(input: &String) -> bool {
    let key = vec!['m', 'r', 'a', 'c', 'k'];
    let input_arr = input.as_bytes();
    if key.len() != input_arr.len() {
        return false;
    }
    for (i, c) in input_arr.iter().enumerate() {
        if key[i] as u8 != *c {
            return false;
        }
    }
    true
}
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64"
))]
fn main() {
    let mut cmd_line = std::env::args();
    cmd_line.next();
    let input = cmd_line.next().unwrap_or(String::from(""));
    let mut interceptor = Interceptor::obtain(&GUM);
 
    let mut listener = AttachListener {
        stalker: Stalker::new(&GUM),
    };

    interceptor.attach(
        gum::NativePointer(RANGE.begin as *mut c_void),
        &mut listener,
    );

    if verify(&input.to_ascii_lowercase()) {
        println!("Thank you for your purchase! key is {}", input)
    } else {
        println!("This unauthorized key.")
    }
}
