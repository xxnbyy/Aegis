**文档编号 / Document ID:** Doc-11

## 文档名称：构建、签名与发布流水线设计 (Build & Supply Chain Security)

版本: v1.1

状态: Draft（部分落地）

适用角色: DevOps、安全工程师、开源用户

核心目标: 确保用户能自己编译出可信的二进制文件，并掌握密钥控制权（User Sovereignty）。

#### 1. 用户主权密钥注入 (User Key Injection)

**1.1 标准构建流程 (Embedded Key Mode)** _(此处保持 v1.0 内容)_

- **机制:** 编译时读取 `AEGIS_ORG_PUBKEY_PATH`，将公钥嵌入二进制。
    
- **优点:** 部署简单，防篡改能力强（公钥与二进制一体）。
    

**1.2 无签名发布模式 (Unsigned Release Mode) [新增 Fix 4]**

- **场景:** 用户希望利用 GitHub Actions 或 GitLab CI 进行自动化构建，但出于安全考虑，**绝不**将机构私钥/公钥上传到 CI 服务器。
    
- **流程:**
    
    1. **Build Command:** 设置环境变量 `AEGIS_UNSIGNED_RELEASE=true` 执行构建。
        
    2. **Build Script (`build.rs`):** 检测到该变量后，跳过公钥注入步骤，并在二进制中标记 `is_unsigned_build = true`。
        
    3. **Artifact:** 生成的二进制文件不包含公钥，**无法独立启动**。
        
- **运行时约束:** 启动此类二进制时，**必须**通过 CLI 参数 `--org-key-path` 或配置文件显式传入公钥路径；否则 Probe 启动时会检测到 `is_unsigned_build` 标记且无外部 Key，并返回错误后退出。
        

#### 2. 可复现构建 (Reproducible Builds)

确保用户编译出的二进制文件 Hash 与官方发布的完全一致，防止“编译器后门”。

- **Docker Builder:**
    
    - `Dockerfile.build`：规划项（当前仓库未提供）。
        
    - 固定 Rust 工具链版本 (e.g., `1.75.0-bullseye`)。
        
    - 固定系统依赖库 (`musl-tools`, `libssl-dev`) 的 apt 版本。
        
- **Path Remapping:**
    
    - 编译参数中加入 `RUSTFLAGS="--remap-path-prefix /workspace/aegis=."`。
        
    - **作用:** 去除二进制 debug info 中的绝对路径信息（如 `/home/user/project/...`），确保不同机器构建出的 Hash 一致。
        

#### 3. 代码签名与交叉编译 (Signing & Cross-Compile)

- **Windows 交叉编译:**
    
    - 由于 Windows 目标依赖 Windows SDK/CRT 等平台库，推荐使用 **Docker + cargo-xwin** 方案。
        
    - 镜像内预装 Windows SDK CRT 和 Libs，解决在 Linux 上编译 `.exe` 的链接问题。
        
- **Native Plugin Signing:**
    
    - 定义插件签名流程: `sign_plugin --key org_private.pem --input my_plugin.dll` -> 生成 `my_plugin.dll.sig` (Ed25519 Signature)（规划项）。
        
    - Probe 加载 Native 插件时，必须校验 `.sig` 文件（规划项）。

#### 4. musl 静态构建与 YARA 依赖 (musl Static Build & YARA)

- **背景:** `common` 使用 `yara`/`yara-sys` 的 `vendored` 构建，会在 Linux 默认选择 OpenSSL 作为 crypto backend；在 `x86_64-unknown-linux-musl` 静态交叉编译环境中，如果未提供 musl 兼容的 OpenSSL（`libcrypto`/`libssl`），会导致 CI 构建失败。
- **当前策略（CI）:** musl 构建步骤设置 `YARA_CRYPTO_LIB_x86_64_unknown_linux_musl=disable`，避免引入 OpenSSL 依赖，从而保证 `probe` 的 musl 静态构建稳定。
- **功能影响范围:** 仅影响 YARA 中依赖 crypto 的能力（例如 `hash` 模块与 PE Authenticode 相关解析）；不影响常规字符串匹配与不依赖 crypto 的规则逻辑。
- **保留完整能力（可选）:** 如生产规则依赖 `import "hash"`、`hash.*` 或 `pe` 的 Authenticode 能力，则需要在 musl 构建环境提供 OpenSSL（musl 兼容，通常为静态库）并配置 `YARA_CRYPTO_LIB_x86_64_unknown_linux_musl=openssl` 与 `YARA_OPENSSL_DIR_x86_64_unknown_linux_musl`（或分别设置 include/lib 路径）。
        
