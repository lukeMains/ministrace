use clap::Parser;
//use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::wait::waitpid;
use nix::unistd::{fork, ForkResult, Pid};
use std::process::ExitCode;

//const ORIG_RAX: usize = 8 * 15; // TODO: create user struct for better names instead of constants, sizeof(long) * ORIG_EAX

/// TODO: Add ministrace-rs description.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Executable program to trace syscalls for.
    #[arg(required = true)]
    program: String,

    /// Arguments to pass to the program under test.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    program_args: Vec<String>,
}

fn main() -> ExitCode {
    let args = Args::parse();

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => run_tracer(child),
        Ok(ForkResult::Child) => run_tracee(args.program, args.program_args),
        Err(e) => {
            eprintln!("fork() failed with errno = {}", e);
            ExitCode::FAILURE
        }
    }
}

/// TODO: description
fn run_tracee(program: String, args: Vec<String>) -> ExitCode {
    // Note: Unsafe to use `println!` (or `unwrap`) here. See Safety in fork() docs.

    if ptrace::traceme().is_err() {
        return ExitCode::FAILURE;
    } else {}
    
    if nix::sys::signal::kill(nix::unistd::getpid(), nix::sys::signal::SIGSTOP).is_err() {
        return ExitCode::FAILURE;
    } else {}
    
    let new_prog = std::ffi::CString::new(program.as_str()).unwrap();
    let new_args: Vec<std::ffi::CString> = args.into_iter().map(|a| {std::ffi::CString::new(a.as_str()).unwrap()}).collect();
    
    match nix::unistd::execvp(&new_prog, &new_args) {
        Ok(_) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

/// TODO: description
fn run_tracer(pid: Pid) -> ExitCode {
    let _status = match waitpid(pid, None) {
        Ok(status) => status,
        Err(_) => return ExitCode::FAILURE,
    };

    // TODO: Check value of status

    // First, set TRACESYSGOOD option on first ptrace call.
    if let Ok(()) = ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD) {
        loop {
            if 0 != wait_for_syscall(pid) { break }
            
            //let data: *const usize = &ORIG_RAX;
            if let Ok(regs) = ptrace::getregs(pid) {
                print!("syscall({})", regs.orig_rax);
            } else {
                eprintln!("Error: first wait_for_syscall()");
            }
            
            if 0 != wait_for_syscall(pid) { break }

            if let Ok(regs) = ptrace::getregs(pid) {
                println!(" = {}", regs.rax);
            } else {
                eprintln!("Error: second wait_for_syscall()")
            }
        }
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// TODO: description
pub fn wait_for_syscall(pid: Pid) -> i32 {
    loop {
        if ptrace::syscall(pid, None).is_err() {
            break 1;
        }; // Error

        match waitpid(pid, None) {
            Ok(status) => match status {
                nix::sys::wait::WaitStatus::PtraceSyscall(_pid) => break 0, // FIXME: Shouldn't this be `pid` instead of `_pid`?!?!
                nix::sys::wait::WaitStatus::Exited(_pid, 1) => break 1,
                _ => break 2,
            },
            Err(_) => break 1,
        }
    }
}
