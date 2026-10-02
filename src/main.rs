//! quicwire 命令行入口。隧道数据面尚未实现。

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() > 1 {
        eprintln!("当前仅支持 --help 和 --version。");
        return ExitCode::from(2);
    }
    match args.first().and_then(|arg| arg.to_str()) {
        None if args.is_empty() => print_help(),
        Some("--help" | "-h") => print_help(),
        Some("--version" | "-V") => println!("quicwire {}", env!("CARGO_PKG_VERSION")),
        _ => {
            eprintln!("未知参数，请使用 --help 查看用法。");
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}

fn print_help() {
    println!(
        "quicwire — 多路径 QUIC 冗余 IP 隧道

         用法：quicwire [--help | --version]

         当前版本为工程骨架，尚未实现隧道连接、密钥管理或流量转发。
         需求与实施顺序见 docs/requirements.md 和 docs/roadmap.md。"
    );
}
