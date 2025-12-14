use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    // 1. 获取 Cargo 元数据 (就像运行 `cargo metadata`)
    // 目的是为了找到 workspace 里都有哪些包
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;

    // 2. 找到名为 "masdeepflow-ebpf" 的那个包
    // 我们的 eBPF 内核代码就在这个包里
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "masdeepflow-ebpf")
        .ok_or_else(|| anyhow!("masdeepflow-ebpf package not found"))?;

    // 3. 提取这个包的路径信息
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;

    // 4. 构建 aya_build 所需的 Package 对象
    // 告诉 aya：eBPF 代码在这个目录下，请帮我处理
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };

    // 5. 【核心步骤】执行 eBPF 编译
    // 这行代码会调用 Rust Nightly + bpf-linker 去编译内核代码
    // 并把生成的 .o (ELF) 文件自动放到 OUT_DIR 目录下供 main.rs 加载
    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}
