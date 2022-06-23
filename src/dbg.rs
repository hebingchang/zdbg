use nix::{
    libc::user_regs_struct,
    sys::{
        personality::{self, Persona},
        ptrace,
        wait::{waitpid, WaitStatus},
    },
    unistd::{execvp, fork, ForkResult, Pid},
};
use std::{
    collections::HashMap,
    error::Error,
    ffi::{c_void, CString},
    mem::size_of,
};

/// 调试器中的信息
pub struct DbgInfo {
    pid: Pid,
    brk_addr: Option<*mut c_void>, // 断点地址
    brk_val: i64,                  // 设置断点的内存的原始值
    filename: String,              // 可执行文件
}

/// 调试器
/// ZDbg<Running> -> 正在运行子进程
/// ZDbg<NotRunning> -> 没有运行子进程
pub struct ZDbg<T> {
    info: Box<DbgInfo>,
    _state: T,
}

/// 调试器的实现
pub struct Running; // 运行中
pub struct NotRunning; // 未运行

/// 调试器实现的枚举类型表示。Exit 时退出
pub enum State {
    Running(ZDbg<Running>),
    NotRunning(ZDbg<NotRunning>),
    Exit,
}

/// RunningとNotRunningで共通の実装
impl<T> ZDbg<T> {
    /// 设置断点地址的函数。 它不会反映在子进程的内存中。
    /// 地址设置成功返回 true
    fn set_break_addr(&mut self, cmd: &[&str]) -> bool {
        if self.info.brk_addr.is_some() {
            eprintln!("<<已设置断点: Addr = {:p}>>", self.info.brk_addr.unwrap());
            false
        } else if let Some(addr) = get_break_addr(cmd) {
            self.info.brk_addr = Some(addr); // 保存断点地址
            true
        } else {
            false
        }
    }

    /// 执行通用命令
    fn do_cmd_common(&self, cmd: &[&str]) {
        match cmd[0] {
            "help" | "h" => do_help(),
            _ => (),
        }
    }
}

/// NotRunning 期间可以调用的方法
impl ZDbg<NotRunning> {
    pub fn new(filename: String) -> Self {
        ZDbg {
            info: Box::new(DbgInfo {
                pid: Pid::from_raw(0),
                brk_addr: None,
                brk_val: 0,
                filename,
            }),
            _state: NotRunning,
        }
    }

    /// 设置断点
    fn do_break(&mut self, cmd: &[&str]) -> bool {
        self.set_break_addr(cmd)
    }

    /// 如果成功，创建一个子进程并转换到运行状态
    fn do_run(mut self, cmd: &[&str]) -> Result<State, Box<dyn Error>> {
        // 传递给子进程的命令行参数
        let args: Vec<CString> = cmd.iter().map(|s| CString::new(*s).unwrap()).collect();

        match unsafe { fork()? } {
            ForkResult::Child => {
                // ASLRを無効に
                let p = personality::get().unwrap();
                personality::set(p | Persona::ADDR_NO_RANDOMIZE).unwrap();
                ptrace::traceme().unwrap();

                // exec
                execvp(&CString::new(self.info.filename.as_str()).unwrap(), &args).unwrap();
                unreachable!();
            }
            ForkResult::Parent { child, .. } => match waitpid(child, None)? {
                WaitStatus::Stopped(..) => {
                    println!("<<child process started with PID = {child}>>");
                    self.info.pid = child;
                    let mut dbg = ZDbg::<Running> {
                        info: self.info,
                        _state: Running,
                    };
                    dbg.set_break()?; // 设置断点
                    dbg.do_continue()
                }
                WaitStatus::Exited(..) | WaitStatus::Signaled(..) => Err("child process failed to start".into()),
                _ => Err("child process is in illegal status".into()),
            },
        }
    }

    pub fn do_cmd(mut self, cmd: &[&str]) -> Result<State, Box<dyn Error>> {
        if cmd.is_empty() {
            return Ok(State::NotRunning(self));
        }

        match cmd[0] {
            "run" | "r" => return self.do_run(cmd),
            "break" | "b" => {
                self.do_break(cmd);
            }
            "exit" => return Ok(State::Exit),
            "continue" | "c" | "stepi" | "s" | "registers" | "regs" => {
                eprintln!("<<target is not running, please run first>>")
            }
            _ => self.do_cmd_common(cmd),
        }

        Ok(State::NotRunning(self))
    }
}

/// Running 时可调用的方法
impl ZDbg<Running> {
    pub fn do_cmd(mut self, cmd: &[&str]) -> Result<State, Box<dyn Error>> {
        if cmd.is_empty() {
            return Ok(State::Running(self));
        }

        match cmd[0] {
            "break" | "b" => self.do_break(cmd)?,
            "continue" | "c" => return self.do_continue(),
            "registers" | "regs" => {
                let regs = ptrace::getregs(self.info.pid)?;
                print_regs(&regs);
            }
            "stepi" | "s" => return self.do_stepi(),
            "run" | "r" => eprintln!("<<target is already running>>"),
            "exit" => {
                self.do_exit()?;
                return Ok(State::Exit);
            }
            _ => self.do_cmd_common(cmd),
        }

        Ok(State::Running(self))
    }

    /// exitを実行。実行中のプロセスはkill
    fn do_exit(self) -> Result<(), Box<dyn Error>> {
        loop {
            ptrace::kill(self.info.pid)?;
            match waitpid(self.info.pid, None)? {
                WaitStatus::Exited(..) | WaitStatus::Signaled(..) => return Ok(()),
                _ => (),
            }
        }
    }

    /// 实际设置断点
    /// 也就是说，将对应地址的内存设置为 "int 3" = 0xcc
    fn set_break(&mut self) -> Result<(), Box<dyn Error>> {
        let addr = if let Some(addr) = self.info.brk_addr {
            addr
        } else {
            return Ok(());
        };

        // TODO:
        //
        // addrの位置にブレークポイントを設定せよ
        // Read 8 bytes from the process memory

        println!("<<the following memory has been updated>>");
        println!("<<before: {:?}: {:02x?}>>", addr, ptrace::read(self.info.pid, addr as ptrace::AddressType)?.to_le_bytes());
        self.info.brk_val = write_byte(self.info.pid, addr, 0xcc).unwrap() as i64;
        println!("<<after : {:?}: {:02x?}>>", addr, ptrace::read(self.info.pid, addr as ptrace::AddressType)?.to_le_bytes());    

        // println!("read start");
        // let value = ptrace::read(self.info.pid, addr as *mut c_void).unwrap() as u64;
        // println!("{:?}", value);

        // // Insert breakpoint by write new values
        // let bp = (value & (u64::MAX ^ 0xFF)) | 0xCC;

        // unsafe {
        //     ptrace::write(self.info.pid, addr as *mut c_void, bp as *mut c_void).unwrap();
        // }

        // Err("TODO".into())
        Ok(())
    }

    /// breakを実行
    fn do_break(&mut self, cmd: &[&str]) -> Result<(), Box<dyn Error>> {
        if self.set_break_addr(cmd) {
            self.set_break()?;
        }
        Ok(())
    }

    fn get_rip(self) -> Result<usize, Box<dyn Error>> {
        let mut regs = ptrace::getregs(self.info.pid)?;
        Ok(regs.rip as usize)
    }

    /// stepiを実行。機械語レベルで1行実行
    fn do_stepi(self) -> Result<State, Box<dyn Error>> {
        // TODO: ここを実装せよ
        //
        // 次の実行アドレスがブレークポイントの場合、
        // 先に、0xccに書き換えたメモリを元に戻す必要がある
        // また、0xccを元に戻してステップ実行して、再度ブレークポイントを設定する必要がある (step_and_breakを呼び出すとよい)
        //
        // 次の実行アドレスがブレークポイントではない場合は、ptrace::stepとwait_childを呼び出すのみでよい

        let mut regs = ptrace::getregs(self.info.pid)?;
        let rip = regs.rip as usize;

        let addr = if let Some(addr) = self.info.brk_addr {
            addr
        } else {
            return Ok(State::Running(self));
        };


        if addr as usize == rip {
            write_byte(self.info.pid, addr, self.info.brk_val as u8).ok();
            return self.step_and_break();
        } else {
            ptrace::step(self.info.pid, None).ok();
            return self.wait_child()
        }
    }

    /// ブレークポイントで停止していた場合は
    /// 1ステップ実行しブレークポイントを再設定
    fn step_and_break(mut self) -> Result<State, Box<dyn Error>> {
        // TODO: ここを実装せよ
        //
        // 停止した位置がブレークポイントの場合、
        // 1ステップ機械語レベルで実行しwaitpidで待機
        // その後、再度ブレークポイントを設定
        //
        // ブレークポイントでない場合は何もしない

        let mut regs = ptrace::getregs(self.info.pid)?;
        let rip = regs.rip as usize;

        let addr = if let Some(addr) = self.info.brk_addr {
            addr
        } else {
            return Ok(State::Running(self));
        };


        if addr as usize == rip {
            ptrace::step(self.info.pid, None).ok();
            return match waitpid(self.info.pid, None)? {
                WaitStatus::Exited(..) | WaitStatus::Signaled(..) => {
                    let not_run = ZDbg::<NotRunning> {
                        info: self.info,
                        _state: NotRunning,
                    };
                    return Ok(State::NotRunning(not_run))
                }
                WaitStatus::Stopped(..) => {
                    let mut regs = ptrace::getregs(self.info.pid)?;
                    let rip = regs.rip as usize;
            
                    println!("<<the following memory has been updated>>");
                    println!("<<before: {:?}: {:02x?}>>", addr, ptrace::read(self.info.pid, addr as ptrace::AddressType)?.to_le_bytes());
                    write_byte(self.info.pid, addr, 0xcc as u8).ok();
                    println!("<<after : {:?}: {:02x?}>>", addr, ptrace::read(self.info.pid, addr as ptrace::AddressType)?.to_le_bytes());                
                    println!("<<child process stopped with PC = {:#x}>>", regs.rip);
                    return Ok(State::Running(self))
                }
                _ => Err("illegal return vale from waitpid".into()),
            }
        }

        Ok(State::Running(self))
    }

    /// continueを実行
    fn do_continue(self) -> Result<State, Box<dyn Error>> {
        // ブレークポイントで停止していた場合は1ステップ実行後再設定
        match self.step_and_break()? {
            State::Running(r) => {
                // 実行再開
                ptrace::cont(r.info.pid, None)?;
                r.wait_child()
            }
            n => Ok(n),
        }
    }

    /// 子プロセスをwait。子プロセスが終了した場合はNotRunning状態に遷移
    fn wait_child(self) -> Result<State, Box<dyn Error>> {
        match waitpid(self.info.pid, None)? {
            WaitStatus::Exited(..) | WaitStatus::Signaled(..) => {
                println!("<<child process finished>>");
                let not_run = ZDbg::<NotRunning> {
                    info: self.info,
                    _state: NotRunning,
                };
                Ok(State::NotRunning(not_run))
            }
            WaitStatus::Stopped(..) => {
                // TODO: ここを実装せよ
                //
                // 停止したアドレスがブレークポイントのアドレスかを調べ
                // ブレークポイントの場合は以下を行う
                // - プログラムカウンタを1減らす
                // - 0xccに書き換えたメモリを元の値に戻す

                let mut regs = ptrace::getregs(self.info.pid)?;
                let rip = regs.rip as usize;

                let addr = if let Some(addr) = self.info.brk_addr {
                    addr
                } else {
                    return Ok(State::Running(self));
                };

                if addr as usize == rip - 1 {
                    write_byte(self.info.pid, addr, self.info.brk_val as u8).ok();
                    regs.rip = (rip - 1) as u64;
                    ptrace::setregs(self.info.pid, regs).ok();
                }
        
                println!("<<child process stopped with PC = {:#x}>>", regs.rip);
                Ok(State::Running(self))
            }
            _ => Err("illegal return value from waitpid".into()),
        }
    }
}

/// ヘルプを表示
fn do_help() {
    println!(
        r#"コマンド一覧 (括弧内は省略記法)
break 0x8000 : ブレークポイントを0x8000番地に設定 (b 0x8000)
run          : プログラムを実行 (r)
continue     : プログラムを再開 (c)
stepi        : 機械語レベルで1ステップ実行 (s)
registers    : レジスタを表示 (regs)
exit         : 終了
help         : このヘルプを表示 (h)"#
    );
}

/// レジスタを表示
fn print_regs(regs: &user_regs_struct) {
    println!(
        r#"RIP: {:#016x}, RSP: {:#016x}, RBP: {:#016x}
RAX: {:#016x}, RBX: {:#016x}, RCX: {:#016x}
RDX: {:#016x}, RSI: {:#016x}, RDI: {:#016x}
 R8: {:#016x},  R9: {:#016x}, R10: {:#016x}
R11: {:#016x}, R12: {:#016x}, R13: {:#016x}
R14: {:#016x}, R15: {:#016x}"#,
        regs.rip,
        regs.rsp,
        regs.rbp,
        regs.rax,
        regs.rbx,
        regs.rcx,
        regs.rdx,
        regs.rsi,
        regs.rdi,
        regs.r8,
        regs.r9,
        regs.r10,
        regs.r11,
        regs.r12,
        regs.r13,
        regs.r14,
        regs.r15,
    );
}

/// コマンドからブレークポイントを計算
fn get_break_addr(cmd: &[&str]) -> Option<*mut c_void> {
    if cmd.len() < 2 {
        eprintln!("<<invalid argument>>");
        return None;
    }

    let addr_str = cmd[1];
    if &addr_str[0..2] != "0x" {
        eprintln!("<<please specify address with hex number>>");
        return None;
    }

    let addr = match usize::from_str_radix(&addr_str[2..], 16) {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("<<address conversion error: {}>>", e);
            return None;
        }
    } as *mut c_void;

    Some(addr)
}

fn align_addr_to_word(addr: u64) -> u64 {
    addr & (-(size_of::<u64>() as i64) as u64)
}

fn write_byte(pid: Pid, addr: *mut c_void, val: u8) -> Result<u8, nix::Error> {
    let aligned_addr = align_addr_to_word(addr as u64);
    let byte_offset = addr as u64 - aligned_addr;
    let word = ptrace::read(pid, aligned_addr as ptrace::AddressType)? as u64;
    let orig_byte = (word >> 8 * byte_offset) & 0xff;
    let masked_word = word & !(0xff << 8 * byte_offset);
    let updated_word = masked_word | ((val as u64) << 8 * byte_offset);

    unsafe {
        ptrace::write(
            pid,
            aligned_addr as ptrace::AddressType,
            updated_word as *mut std::ffi::c_void,
        )?;
    }

    Ok(orig_byte as u8)
}
