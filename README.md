# LockHere Vault 🔒

LockHere is a 100% offline, zero-knowledge desktop vault designed to store and stream-encrypt sensitive files using AES-256-GCM and Argon2id.

Unlike basic file-hiding utilities, LockHere combines 4MB-chunked stream encryption with a multi-pass physical zero-fill disk wiper, preventing data recovery even with physical disk forensics.

## Key Features
- **True Air-Gap:** Zero network calls, zero analytics, zero cloud dependencies.
- **TB-Scale Architecture:** Memory-bounded 4MB stream buffers allow encrypting files of arbitrary size (1GB to 1TB+) on low-spec hardware (2GB RAM).
- **Physical Disk Shredder:** Original files are overwritten with binary zeroes (`0x00`) before file system unlinking.
- **Volatile In-App Viewing:** Stream-decrypt files to an ephemeral sandbox for immediate viewing, shredded automatically upon vault lock.
- **Hardware-Accelerated:** Leverages native CPU AES-NI instructions for maximum disk-speed encryption.

## Direct Download
Pre-compiled Windows installers are available on the [Releases](https://github.com/sportshere001-netizen/lockhere/releases) tab (`lockhere_0.1.0_x64-setup.exe`).

## Build from Source
```bash
git clone [https://github.com/sportshere001-netizen/lockhere.git](https://github.com/sportshere001-netizen/lockhere.git)
cd lockhere
npm install
npm run tauri build
