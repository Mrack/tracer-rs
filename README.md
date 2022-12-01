# tracer-rs

Rust写的一个x86_64,aarch64 trace工具
使用 frida stalker 实现的 trace
记录执行指令以及统计寄存器变化
###  x86_64
![Image text](https://raw.githubusercontent.com/Mrack/tracer-rs/master/pic/1.png)

### aarch64
![Image text](https://raw.githubusercontent.com/Mrack/tracer-rs/master/pic/2.png)


## tracer
fun_addr fun_size 为 trace 函数地址 以及大小
···
    static ref RANGE: TraceRange = 
        TraceRange {
            begin: {fun_addr} as u64,
            size: {fun_size},
        };
···

## loader(windows)
注入dll工具

## loader(Android)
todo.

## 用法
修改 fun_addr fun_size 指定函数地址编译
使用loader注入生成的tracer.dll (libtracer.so)

## 样例
![Image text](https://raw.githubusercontent.com/Mrack/tracer-rs/master/pic/3.png)