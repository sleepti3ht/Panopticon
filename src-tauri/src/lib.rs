use tauri::command;
use std::process::Command;
use std::io::Write;
use std::process::Stdio;
use std::env;
use std::path::PathBuf;

// Helper: resolve paths to Python script and interpreter.
// Keeps the per-command boilerplate minimal and consistent.
fn python_paths(script_name: &str) -> Result<(PathBuf, PathBuf), String> {
    let src_tauri_dir = env::current_dir().map_err(|e| format!("Failed to get current dir: {}", e))?;
    let project_root = src_tauri_dir.parent().ok_or("Failed to get parent dir")?;
    let script_path = project_root.join("panopticon-python").join(script_name);
    let python_path = project_root.join("panopticon-python").join("venv").join("Scripts").join("python.exe");
    Ok((script_path, python_path))
}

// Helper: execute a Python script and return stdout as String.
// Converts non-zero exit codes into Rust errors with stderr content.
fn run_python(script_name: &str, args: &[&str]) -> Result<String, String> {
    let (script_path, python_path) = python_paths(script_name)?;
    let output = Command::new(&python_path)
        .arg(&script_path)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to execute python at {:?}: {}", python_path, e))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(format!("Python error: {}", String::from_utf8_lossy(&output.stderr)))
    }
}

// ==========================================
// Graph & Search
// ==========================================

#[command]
async fn get_graph_data(vendor: Option<String>, min_year: Option<i32>) -> Result<String, String> {
    let mut args: Vec<String> = Vec::new();
    if let Some(v) = vendor { args.push(v); }
    if let Some(y) = min_year { args.push(y.to_string()); }
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run_python("graph_builder.py", &refs)
}

#[command]
async fn get_vendors(query: Option<String>) -> Result<String, String> {
    let args_vec: Vec<String> = query.into_iter().collect();
    let refs: Vec<&str> = args_vec.iter().map(|s| s.as_str()).collect();
    run_python("get_vendors.py", &refs)
}

#[command]
async fn global_search(query: String) -> Result<String, String> {
    run_python("global_search.py", &[&query])
}

// ==========================================
// AI Agent
// ==========================================

#[command]
async fn generate_mitigation(cve_id: String, model: String) -> Result<String, String> {
    run_python("ai_agent.py", &["--mitigate", &cve_id, &model])
}

#[command]
async fn chat_with_agent(cve_id: String, messages: String, model: String) -> Result<String, String> {
    let (script_path, python_path) = python_paths("ai_agent.py")?;

    // Pass conversation history via stdin: Windows CLI args are limited to ~32KB,
    // and long chats with mitigation payloads exceed that silently.
    let mut child = Command::new(&python_path)
        .arg(&script_path)
        .arg("--chat")
        .arg(&cve_id)
        .arg(&model)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn python at {:?}: {}", python_path, e))?;

    // Write payload, then drop stdin so the child sees EOF
    {
        let stdin = child.stdin.as_mut().ok_or("Failed to open python stdin")?;
        stdin
            .write_all(messages.as_bytes())
            .map_err(|e| format!("Failed to write to python stdin: {}", e))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for python: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(format!("Python error: {}", String::from_utf8_lossy(&output.stderr)))
    }
}

#[command]
async fn get_available_models() -> Result<String, String> {
    let src_tauri_dir = env::current_dir().map_err(|e| format!("Failed to get current dir: {}", e))?;
    let env_path = src_tauri_dir.parent().unwrap().join("panopticon-python").join(".env");

    if !env_path.exists() {
        return Ok("nvidia/nemotron-3.5-lightning:free,nvidia/nemotron-3-ultra-550b-a55b:free,nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free".to_string());
    }

    let content = std::fs::read_to_string(&env_path).map_err(|e| format!("Failed to read .env: {}", e))?;

    for line in content.lines() {
        if line.starts_with("AVAILABLE_MODELS=") {
            let models = line.trim_start_matches("AVAILABLE_MODELS=").trim_matches('"');
            return Ok(models.to_string());
        }
    }
    Ok("nvidia/nemotron-3.5-lightning:free".to_string())
}
#[command]
async fn export_markdown(filename: String, content: String, dir: String) -> Result<String, String> {
    // Sanitize filename: strip everything except safe chars to prevent path traversal
    let safe_name: String = filename
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect();
    if safe_name.is_empty() || !safe_name.ends_with(".md") {
        return Err("Invalid filename".to_string());
    }

    // Resolve target directory: user-configured path or default Documents/Panopticon
    let target_dir = if dir.trim().is_empty() {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .map_err(|e| format!("Cannot resolve home directory: {}", e))?;
        std::path::PathBuf::from(home).join("Documents").join("Panopticon")
    } else {
        std::path::PathBuf::from(dir.trim())
    };

    std::fs::create_dir_all(&target_dir)
        .map_err(|e| format!("Failed to create export dir {:?}: {}", target_dir, e))?;

    let path = target_dir.join(&safe_name);
    std::fs::write(&path, content).map_err(|e| format!("Failed to write file: {}", e))?;
    Ok(path.to_string_lossy().into_owned())
}
// ==========================================
// Chat Reports (CRUD + pinning + tagging)
// ==========================================

#[command]
async fn save_chat_report(
    cve_id: String,
    title: String,
    messages: String,
    model: String,
    vendor: String,
) -> Result<String, String> {
    // Pass vendor as the 6th positional argument
    run_python("save_report.py", &["save", &cve_id, &title, &messages, &model, &vendor])
}

#[command]
async fn get_chat_reports(cve_id: String) -> Result<String, String> {
    run_python("save_report.py", &["list", &cve_id])
}

#[command]
async fn load_chat_report(report_id: i64) -> Result<String, String> {
    let id_str = report_id.to_string();
    run_python("save_report.py", &["load", &id_str])
}

#[command]
async fn delete_chat_report(report_id: i64) -> Result<String, String> {
    let id_str = report_id.to_string();
    run_python("save_report.py", &["delete", &id_str])
}

#[command]
async fn delete_chat_reports(report_ids: String) -> Result<String, String> {
    // report_ids is a JSON array string, passed as a single CLI argument
    run_python("save_report.py", &["delete_bulk", &report_ids])
}

#[command]
async fn toggle_report_pin(report_id: i64) -> Result<String, String> {
    let id_str = report_id.to_string();
    run_python("save_report.py", &["pin", &id_str])
}

#[command]
async fn set_report_tags(report_id: i64, tags: String) -> Result<String, String> {
    // tags is a JSON array string, passed as a single CLI argument
    let id_str = report_id.to_string();
    run_python("save_report.py", &["tags", &id_str, &tags])
}

// ==========================================
// Application entry point
// ==========================================

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_graph_data,
            get_vendors,
            global_search,
            generate_mitigation,
            chat_with_agent,
            get_available_models,
            save_chat_report,
            get_chat_reports,
            load_chat_report,
            delete_chat_report,
            delete_chat_reports,
            toggle_report_pin,
            set_report_tags,
            export_markdown,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}