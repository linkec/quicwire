use anyhow::Result;
use clap::{Parser, Subcommand};
use quicwire::{config::Config, identity::Identity};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "quicwire",
    version,
    about = "使用双向公钥认证的 QUIC + TUN 基础隧道"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 生成私钥文件，仅输出公钥；不会覆盖已有文件
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// 从私钥文件导出公钥
    Pubkey {
        #[arg(long)]
        private_key: PathBuf,
    },
    /// 校验配置和私钥，不创建网络接口
    Check {
        #[arg(long)]
        config: PathBuf,
    },
    /// 查看本机运行状态
    Status {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        json: bool,
        /// 展开路径探测、评分、生命周期与完整异常计数
        #[arg(long)]
        verbose: bool,
    },
    /// 启动 Linux 隧道，需要 root 或 CAP_NET_ADMIN
    Run {
        #[arg(long)]
        config: PathBuf,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen { out } => println!("{}", Identity::generate_file(&out)?.encode()),
        Command::Pubkey { private_key } => {
            println!("{}", Identity::load(&private_key)?.public.encode())
        }
        Command::Check { config } => {
            let config = Config::load(&config)?;
            let identity = Identity::load(&config.private_key_file)?;
            anyhow::ensure!(
                identity.public.encode() != config.peer_public_key.trim(),
                "本地与对端公钥不能相同"
            );
            println!(
                "配置有效 mode={:?} tun={} local={} peer={} mtu={}",
                config.mode, config.tun_name, config.tun_address, config.peer_address, config.mtu
            );
        }
        Command::Status {
            config,
            json,
            verbose,
        } => {
            let config = Config::load(&config)?;
            #[cfg(unix)]
            quicwire::status::read(&config.status_path(), json, verbose).await?;
            #[cfg(not(unix))]
            anyhow::bail!("状态命令仅支持 Unix 平台");
        }
        Command::Run { config } => {
            let config = Config::load(&config)?;
            let identity = Identity::load(&config.private_key_file)?;
            anyhow::ensure!(
                identity.public.encode() != config.peer_public_key.trim(),
                "本地与对端公钥不能相同"
            );
            #[cfg(target_os = "linux")]
            quicwire::tunnel::run(config, identity).await?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("当前 TUN 数据面仅支持 Linux；本平台可生成密钥及校验配置");
        }
    }
    Ok(())
}
