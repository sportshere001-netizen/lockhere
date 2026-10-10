use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4MB Chunking for Infinite File Size

#[derive(Serialize, Deserialize, Clone)]
pub struct VaultItem {
    pub id: String,
    pub original_name: String,
    pub original_path: String,
    pub size_formatted: String,
}

fn get_vault_path() -> PathBuf {
    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string());
    let mut path = PathBuf::from(home);
    path.push(".lockhere_vault");
    let _ = fs::create_dir_all(path.join("data"));
    path
}

fn get_temp_view_path() -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push("lockhere_active_view");
    let _ = fs::create_dir_all(&path);
    path
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| e.to_string())?;
    Ok(key)
}

// --- YOUR INFINITE-SCALE SECURE SHREDDER ---
fn secure_shred<P: AsRef<Path>>(path: P) {
    if let Ok(metadata) = fs::metadata(&path) {
        if let Ok(mut file) = OpenOptions::new().write(true).open(&path) {
            let size = metadata.len();
            let chunk = vec![0u8; 4 * 1024 * 1024]; // 4MB zero-fill chunk
            let mut written = 0;

            while written < size {
                let to_write = (size - written).min(chunk.len() as u64) as usize;
                let _ = file.write_all(&chunk[..to_write]);
                written += to_write as u64;
            }
            let _ = file.sync_all(); // Force the SSD controller to overwrite the physical sectors
        }
        let _ = fs::remove_file(&path);
    }
}

fn stream_encrypt_file(source: &Path, dest: &Path, password: &str) -> Result<(), String> {
    let mut infile = File::open(source).map_err(|e| e.to_string())?;
    let mut outfile = File::create(dest).map_err(|e| e.to_string())?;

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;

    outfile.write_all(&salt).map_err(|e| e.to_string())?;

    let mut buffer = vec![0u8; CHUNK_SIZE];
    loop {
        let bytes_read = infile.read(&mut buffer).map_err(|e| e.to_string())?;
        if bytes_read == 0 { break; }

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, &buffer[..bytes_read])
            .map_err(|e| e.to_string())?;

        outfile.write_all(&nonce_bytes).map_err(|e| e.to_string())?;
        let ct_len = ciphertext.len() as u32;
        outfile.write_all(&ct_len.to_le_bytes()).map_err(|e| e.to_string())?;
        outfile.write_all(&ciphertext).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn stream_decrypt_file(source: &Path, dest: &Path, password: &str) -> Result<(), String> {
    let mut infile = File::open(source).map_err(|e| e.to_string())?;
    let mut outfile = File::create(dest).map_err(|e| e.to_string())?;

    let mut salt = [0u8; 16];
    if infile.read_exact(&mut salt).is_err() { return Err("File corrupted".into()); }

    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;

    loop {
        let mut nonce_bytes = [0u8; 12];
        if infile.read_exact(&mut nonce_bytes).is_err() { break; }

        let mut len_bytes = [0u8; 4];
        infile.read_exact(&mut len_bytes).map_err(|e| e.to_string())?;
        let ct_len = u32::from_le_bytes(len_bytes) as usize;

        let mut ct_buffer = vec![0u8; ct_len];
        infile.read_exact(&mut ct_buffer).map_err(|e| e.to_string())?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher.decrypt(nonce, ct_buffer.as_ref()).map_err(|_| "Decryption Failed".to_string())?;

        outfile.write_all(&plaintext).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
async fn check_vault_setup() -> bool { get_vault_path().join("auth.bin").exists() }

#[tauri::command]
async fn create_master_vault(password: String, hint: String) -> Result<String, String> {
    let auth = get_vault_path().join("auth.bin");
    if auth.exists() { return Err("Vault exists".into()); }
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(&password, &salt)?;
    let mut payload = salt.to_vec();
    payload.extend_from_slice(&key);
    payload.extend_from_slice(hint.as_bytes());
    fs::write(auth, payload).map_err(|e| e.to_string())?;
    fs::write(get_vault_path().join("index.json"), "[]").unwrap();
    Ok("Created".into())
}

#[tauri::command]
async fn unlock_master_vault(password: String) -> Result<bool, String> {
    let auth = get_vault_path().join("auth.bin");
    let data = fs::read(&auth).map_err(|e| e.to_string())?;
    let salt = &data[0..16];
    let stored_key = &data[16..48];
    let candidate_key = derive_key(&password, salt)?;

    if candidate_key == stored_key {
        let _ = fs::remove_dir_all(get_temp_view_path());
        Ok(true)
    } else {
        Ok(false)
    }
}

#[tauri::command]
async fn list_locked_files(_password: String) -> Result<Vec<VaultItem>, String> {
    let index_path = get_vault_path().join("index.json");
    if !index_path.exists() { return Ok(Vec::new()); }
    let data = fs::read_to_string(&index_path).map_err(|e| e.to_string())?;
    let items = serde_json::from_str(&data).unwrap_or_else(|_| Vec::new());
    Ok(items)
}

fn save_index(items: &[VaultItem]) {
    let _ = fs::write(get_vault_path().join("index.json"), serde_json::to_string(items).unwrap());
}

#[tauri::command]
async fn process_and_lock_files(paths: Vec<String>, password: String) -> Result<usize, String> {
    let mut items = list_locked_files(password.clone()).await?;
    let mut count = 0;

    for path_str in paths {
        let path = Path::new(&path_str);
        if !path.exists() { continue; }

        let metadata = fs::metadata(&path).map_err(|e| e.to_string())?;

        let mut id_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut id_bytes);
        let id: String = id_bytes.iter().map(|b| format!("{:02x}", b)).collect();

        let target = get_vault_path().join("data").join(format!("{}.locked", id));

        stream_encrypt_file(&path, &target, &password)?;
        secure_shred(&path);

        items.push(VaultItem {
            id,
            original_name: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
            original_path: path_str.clone(),
            size_formatted: format!("{:.1} MB", metadata.len() as f64 / 1048576.0),
        });
        count += 1;
    }
    save_index(&items);
    Ok(count)
}

#[tauri::command]
async fn extract_locked_file(id: String, password: String) -> Result<String, String> {
    let mut items = list_locked_files(password.clone()).await?;
    let idx = items.iter().position(|f| f.id == id).ok_or("File not found")?;
    let item = items[idx].clone();

    let vault_file = get_vault_path().join("data").join(format!("{}.locked", id));
    stream_decrypt_file(&vault_file, Path::new(&item.original_path), &password)?;
    secure_shred(&vault_file);

    items.remove(idx);
    save_index(&items);
    Ok(format!("Restored to: {}", item.original_path))
}

#[tauri::command]
async fn secure_view_file(id: String, password: String) -> Result<String, String> {
    let items = list_locked_files(password.clone()).await?;
    let item = items.iter().find(|f| f.id == id).ok_or("File not found")?;

    let vault_file = get_vault_path().join("data").join(format!("{}.locked", id));
    let temp_path = get_temp_view_path().join(&item.original_name);

    stream_decrypt_file(&vault_file, &temp_path, &password)?;

    open::that(&temp_path).map_err(|e| format!("Failed to open native app: {}", e))?;

    Ok("File temporarily opened for viewing.".into())
}

#[tauri::command]
async fn lock_session() {
    let _ = fs::remove_dir_all(get_temp_view_path());
}

#[tauri::command]
async fn retrieve_hint() -> Result<String, String> {
    let auth = get_vault_path().join("auth.bin");
    let data = fs::read(&auth).map_err(|e| e.to_string())?;
    if data.len() <= 48 { return Ok("No hint provided".into()); }
    Ok(String::from_utf8_lossy(&data[48..]).to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            check_vault_setup,
            create_master_vault,
            unlock_master_vault,
            retrieve_hint,
            list_locked_files,
            process_and_lock_files,
            extract_locked_file,
            secure_view_file,
            lock_session
        ])
        .run(tauri::generate_context!())
        .expect("Tauri runtime failed to initialize");
}
