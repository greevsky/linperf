use std::fs;
use std::process::Command;

use serde_json::Value;

#[derive(Clone)]
pub struct Inventory {
    pub tool: String,
    pub note: String,
    pub containers: Vec<Container>,
    pub volumes: Vec<Asset>,
    pub networks: Vec<Asset>,
    pub images: Vec<Asset>,
    pub volume_note: String,
    pub network_note: String,
    pub image_note: String,
}

#[derive(Clone)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub state: String,
    pub command: String,
    pub image: String,
}

#[derive(Clone)]
pub struct Asset {
    pub name: String,
    pub state: String,
    pub detail: String,
}

#[derive(Clone, PartialEq, Eq)]
pub enum Pick {
    Container { id: String },
    Volume { name: String },
    Network { name: String },
    Image { name: String },
}

impl Inventory {
    pub fn empty(note: impl Into<String>) -> Self {
        Self {
            tool: String::new(),
            note: note.into(),
            containers: Vec::new(),
            volumes: Vec::new(),
            networks: Vec::new(),
            images: Vec::new(),
            volume_note: String::new(),
            network_note: String::new(),
            image_note: String::new(),
        }
    }
}

pub fn load() -> Inventory {
    let mut installed = Vec::new();
    let mut errors = Vec::new();
    for tool in ["docker", "podman", "nerdctl", "crictl"] {
        if !command_exists(tool) {
            continue;
        }
        installed.push(tool);
        match load_tool(tool) {
            Ok(inventory) => return inventory,
            Err(err) => errors.push(format!("{tool}: {err}")),
        }
    }
    let mut inventory = from_cgroup();
    inventory.note = if installed.is_empty() {
        if inventory.containers.is_empty() {
            "这台机器没有 docker、podman、nerdctl 或 crictl，也没有从 cgroup 识别到容器。存储卷、网络和镜像都列不出来。".into()
        } else {
            "没有容器命令。下面只是 cgroup 里正在跑的容器，存储卷、网络和镜像需要 docker、podman 或 nerdctl。".into()
        }
    } else if inventory.containers.is_empty() {
        format!(
            "容器命令已安装，但运行时没有响应。{} 存储卷、网络和镜像因此也列不出来。",
            errors.join(" ")
        )
    } else {
        format!(
            "容器命令没有响应，下面只是 cgroup 里正在跑的容器。{}",
            errors.join(" ")
        )
    };
    if inventory.volume_note.is_empty() {
        inventory.volume_note = "没有可用的容器命令".into();
        inventory.network_note = "没有可用的容器命令".into();
        inventory.image_note = "没有可用的容器命令".into();
    }
    inventory
}

pub fn demo() -> Inventory {
    Inventory {
        tool: "docker".into(),
        note: String::new(),
        containers: vec![
            Container {
                id: "a247dff2ff6d".into(),
                name: "minio".into(),
                state: "running".into(),
                command: "/usr/bin/minio server /data".into(),
                image: "minio/minio".into(),
            },
            Container {
                id: "b19c0e11aa20".into(),
                name: "nginx".into(),
                state: "exited".into(),
                command: "nginx -g 'daemon off;'".into(),
                image: "nginx:1.25".into(),
            },
        ],
        volumes: vec![
            Asset {
                name: "minio-data".into(),
                state: "in-use".into(),
                detail: "local  /var/lib/docker/volumes/minio-data/_data".into(),
            },
            Asset {
                name: "spare".into(),
                state: "unused".into(),
                detail: "local".into(),
            },
        ],
        networks: vec![
            Asset {
                name: "bridge".into(),
                state: "active".into(),
                detail: "bridge".into(),
            },
            Asset {
                name: "demo".into(),
                state: "idle".into(),
                detail: "bridge".into(),
            },
        ],
        images: vec![
            Asset {
                name: "minio/minio:latest".into(),
                state: "in-use".into(),
                detail: "160MB".into(),
            },
            Asset {
                name: "<none>:<none>".into(),
                state: "dangling".into(),
                detail: "10MB".into(),
            },
        ],
        volume_note: String::new(),
        network_note: String::new(),
        image_note: String::new(),
    }
}

pub fn count_text(label: &str, states: &[String]) -> String {
    if states.is_empty() {
        return format!("{label}  0");
    }
    format!("{label}  {}  {}", states.len(), tally(states))
}

pub fn tally(states: &[String]) -> String {
    let mut rows: Vec<(String, usize)> = Vec::new();
    for state in states {
        if state.is_empty() {
            continue;
        }
        if let Some(slot) = rows.iter_mut().find(|(name, _)| name == state) {
            slot.1 += 1;
        } else {
            rows.push((state.clone(), 1));
        }
    }
    rows.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
    rows.iter()
        .map(|(state, count)| format!("{state} {count}"))
        .collect::<Vec<_>>()
        .join("  ")
}

fn load_tool(tool: &str) -> Result<Inventory, String> {
    if tool == "crictl" {
        return load_crictl();
    }
    let ps = run(tool, &["ps", "-a", "--no-trunc", "--format", "{{json .}}"])?;
    let containers = parse_docker_ps(&ps);
    let mounts = mount_names(&containers);
    let networks_used = network_names(&containers);
    let (volumes, volume_note) = match run(tool, &["volume", "ls", "--format", "{{json .}}"]) {
        Ok(text) => (parse_docker_volumes(&text, &mounts), String::new()),
        Err(err) => (Vec::new(), err),
    };
    let (networks, network_note) = match run(tool, &["network", "ls", "--format", "{{json .}}"]) {
        Ok(text) => (parse_docker_networks(&text, &networks_used), String::new()),
        Err(err) => (Vec::new(), err),
    };
    let (images, image_note) = match run(tool, &["images", "--format", "{{json .}}"]) {
        Ok(text) => (parse_docker_images(&text, &containers), String::new()),
        Err(err) => (Vec::new(), err),
    };
    Ok(Inventory {
        tool: tool.into(),
        note: String::new(),
        containers: containers.into_iter().map(Container::from).collect(),
        volumes,
        networks,
        images,
        volume_note,
        network_note,
        image_note,
    })
}

fn load_crictl() -> Result<Inventory, String> {
    let ps = run("crictl", &["ps", "-a", "-o", "json"])?;
    let containers = parse_crictl_ps(&ps);
    let (images, image_note) = match run("crictl", &["images", "-o", "json"]) {
        Ok(text) => (parse_crictl_images(&text, &containers), String::new()),
        Err(err) => (Vec::new(), err),
    };
    let containers = containers.into_iter().map(Container::from).collect();
    Ok(Inventory {
        tool: "crictl".into(),
        note: String::new(),
        containers,
        volumes: Vec::new(),
        networks: Vec::new(),
        images,
        volume_note: "crictl 没有存储卷命令".into(),
        network_note: "crictl 没有网络组命令".into(),
        image_note,
    })
}

struct RawContainer {
    container: Container,
    mounts: Vec<String>,
    networks: Vec<String>,
}

impl From<RawContainer> for Container {
    fn from(raw: RawContainer) -> Self {
        raw.container
    }
}

fn parse_docker_ps(text: &str) -> Vec<RawContainer> {
    json_rows(text)
        .into_iter()
        .filter_map(|row| {
            let id = short_id(&json_str(&row, &["ID", "Id"]));
            if id.is_empty() {
                return None;
            }
            let name = first_name(&json_str(&row, &["Names", "Name"]));
            let state = json_str(&row, &["State"]);
            let state = if state.is_empty() { "unknown".into() } else { state };
            let command = clean_command(&json_str(&row, &["Command"]));
            let image = json_str(&row, &["Image"]);
            let mounts = split_list(&json_str(&row, &["Mounts"]));
            let networks = split_list(&json_str(&row, &["Networks"]));
            Some(RawContainer {
                container: Container {
                    id,
                    name,
                    state,
                    command,
                    image,
                },
                mounts,
                networks,
            })
        })
        .collect()
}

fn parse_docker_volumes(text: &str, mounts: &[String]) -> Vec<Asset> {
    json_rows(text)
        .into_iter()
        .filter_map(|row| {
            let name = json_str(&row, &["Name"]);
            if name.is_empty() {
                return None;
            }
            let links = json_str(&row, &["Links", "Containers"]);
            let linked = links.parse::<u64>().ok().unwrap_or(0) > 0 || mounts.iter().any(|item| item == &name);
            let status = json_str(&row, &["Status"]);
            let state = if linked {
                "in-use".into()
            } else if !status.is_empty() && status != "N/A" {
                status
            } else {
                "unused".into()
            };
            let driver = json_str(&row, &["Driver"]);
            let mount = json_str(&row, &["Mountpoint"]);
            let detail = match (driver.is_empty(), mount.is_empty()) {
                (false, false) => format!("{driver}  {mount}"),
                (false, true) => driver,
                (true, false) => mount,
                (true, true) => String::new(),
            };
            Some(Asset { name, state, detail })
        })
        .collect()
}

fn parse_docker_networks(text: &str, used: &[String]) -> Vec<Asset> {
    json_rows(text)
        .into_iter()
        .filter_map(|row| {
            let name = json_str(&row, &["Name"]);
            if name.is_empty() {
                return None;
            }
            let driver = json_str(&row, &["Driver"]);
            let state = if used.iter().any(|item| item == &name) {
                "active".into()
            } else {
                "idle".into()
            };
            Some(Asset {
                name,
                state,
                detail: driver,
            })
        })
        .collect()
}

fn parse_docker_images(text: &str, containers: &[RawContainer]) -> Vec<Asset> {
    json_rows(text)
        .into_iter()
        .filter_map(|row| {
            let repo = json_str(&row, &["Repository"]);
            let tag = json_str(&row, &["Tag"]);
            let id = json_str(&row, &["ID", "Id"]);
            if repo.is_empty() && id.is_empty() {
                return None;
            }
            let name = if repo.is_empty() {
                short_id(&id)
            } else if tag.is_empty() || tag == "<none>" {
                repo.clone()
            } else {
                format!("{repo}:{tag}")
            };
            let containers_field = json_str(&row, &["Containers"]);
            let referenced = containers.iter().any(|item| image_matches(&item.container.image, &repo, &tag, &id));
            let state = if containers_field.parse::<u64>().ok().unwrap_or(0) > 0 || referenced {
                "in-use".into()
            } else if repo == "<none>" || tag == "<none>" {
                "dangling".into()
            } else {
                "unused".into()
            };
            let size = json_str(&row, &["Size", "VirtualSize"]);
            Some(Asset {
                name,
                state,
                detail: size,
            })
        })
        .collect()
}

fn parse_crictl_ps(text: &str) -> Vec<RawContainer> {
    let value: Value = serde_json::from_str(text).unwrap_or(Value::Null);
    let rows = value.get("containers").and_then(Value::as_array).cloned().unwrap_or_default();
    rows.into_iter()
        .filter_map(|row| {
            let id = short_id(&json_str(&row, &["id"]));
            if id.is_empty() {
                return None;
            }
            let name = row
                .get("metadata")
                .map(|meta| json_str(meta, &["name"]))
                .unwrap_or_default();
            let state = crictl_state(&json_str(&row, &["state"]));
            let image = row
                .get("image")
                .map(|image| json_str(image, &["image"]))
                .unwrap_or_default();
            Some(RawContainer {
                container: Container {
                    id,
                    name,
                    state,
                    command: String::new(),
                    image,
                },
                mounts: Vec::new(),
                networks: Vec::new(),
            })
        })
        .collect()
}

fn parse_crictl_images(text: &str, containers: &[RawContainer]) -> Vec<Asset> {
    let value: Value = serde_json::from_str(text).unwrap_or(Value::Null);
    let rows = value.get("images").and_then(Value::as_array).cloned().unwrap_or_default();
    rows.into_iter()
        .filter_map(|row| {
            let id = json_str(&row, &["id"]);
            let tags = row.get("repoTags").and_then(Value::as_array).cloned().unwrap_or_default();
            let tag = tags
                .first()
                .and_then(Value::as_str)
                .unwrap_or("<none>")
                .to_string();
            if id.is_empty() && tag == "<none>" {
                return None;
            }
            let referenced = containers.iter().any(|item| {
                image_matches(&item.container.image, tag.split(':').next().unwrap_or(""), tag.split(':').nth(1).unwrap_or(""), &id)
                    || (!id.is_empty() && item.container.image.contains(&short_id(&id)))
            });
            let state = if referenced {
                "in-use".into()
            } else if tag == "<none>" || tag.contains("<none>") {
                "dangling".into()
            } else {
                "unused".into()
            };
            let size = json_str(&row, &["size"]);
            Some(Asset {
                name: if tag == "<none>" { short_id(&id) } else { tag },
                state,
                detail: size,
            })
        })
        .collect()
}

fn from_cgroup() -> Inventory {
    let mut groups: Vec<Container> = Vec::new();
    let Ok(dir) = fs::read_dir("/proc") else {
        return Inventory::empty("");
    };
    for entry in dir.flatten() {
        let pid = entry.file_name();
        let pid = pid.to_string_lossy();
        if !pid.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .ok()
            .and_then(|text| crate::parse::parse_cgroup_path(&text))
            .unwrap_or_default();
        let Some((runtime, id)) = crate::procs::container_identity(&cgroup) else {
            continue;
        };
        let command = cmdline(&pid);
        let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        if let Some(slot) = groups.iter_mut().find(|item| item.id == id && item.image == runtime) {
            if command.len() > slot.command.len() && !is_shim(&command) {
                slot.command = command;
            }
            if !comm.is_empty() && !slot.name.contains(&comm) {
                if slot.name.is_empty() {
                    slot.name = comm;
                } else if slot.name.split('、').count() < 4 {
                    slot.name.push('、');
                    slot.name.push_str(&comm);
                }
            }
        } else {
            groups.push(Container {
                id,
                name: comm,
                state: "running".into(),
                command: if is_shim(&command) { String::new() } else { command },
                image: runtime.into(),
            });
        }
    }
    groups.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));
    Inventory {
        tool: String::new(),
        note: String::new(),
        containers: groups,
        volumes: Vec::new(),
        networks: Vec::new(),
        images: Vec::new(),
        volume_note: String::new(),
        network_note: String::new(),
        image_note: String::new(),
    }
}

fn cmdline(pid: &str) -> String {
    let bytes = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    String::from_utf8_lossy(&bytes).replace('\0', " ").trim().to_string()
}

fn is_shim(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    lower.contains("containerd-shim") || lower.contains("conmon") || lower.contains("/pause")
}

fn mount_names(containers: &[RawContainer]) -> Vec<String> {
    let mut names = Vec::new();
    for container in containers {
        for mount in &container.mounts {
            if !mount.is_empty() && !names.contains(mount) {
                names.push(mount.clone());
            }
        }
    }
    names
}

fn network_names(containers: &[RawContainer]) -> Vec<String> {
    let mut names = Vec::new();
    for container in containers {
        for name in &container.networks {
            if !name.is_empty() && !names.contains(name) {
                names.push(name.clone());
            }
        }
    }
    names
}

fn image_matches(image: &str, repo: &str, tag: &str, id: &str) -> bool {
    if image.is_empty() {
        return false;
    }
    if !repo.is_empty() && repo != "<none>" {
        let tagged = if tag.is_empty() || tag == "<none>" {
            repo.to_string()
        } else {
            format!("{repo}:{tag}")
        };
        if image == tagged || image == repo || image.ends_with(&format!("/{tagged}")) {
            return true;
        }
    }
    let short = short_id(id);
    !short.is_empty() && (image == id || image.contains(&short))
}

fn json_rows(text: &str) -> Vec<Value> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if trimmed.starts_with('[') {
        return serde_json::from_str(trimmed).unwrap_or_default();
    }
    if trimmed.starts_with('{') && trimmed.lines().count() == 1 {
        if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
            if let Some(rows) = value.as_array() {
                return rows.clone();
            }
            return vec![value];
        }
    }
    trimmed.lines().filter_map(|line| serde_json::from_str(line).ok()).collect()
}

fn json_str(value: &Value, keys: &[&str]) -> String {
    for key in keys {
        if let Some(item) = value.get(*key) {
            return json_string(item);
        }
    }
    String::new()
}

fn json_string(value: &Value) -> String {
    match value {
        Value::String(text) => text.trim().to_string(),
        Value::Array(items) => items
            .iter()
            .map(json_string)
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join(","),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        _ => String::new(),
    }
}

fn first_name(text: &str) -> String {
    text.split(',').next().unwrap_or("").trim().trim_start_matches('/').to_string()
}

fn split_list(text: &str) -> Vec<String> {
    text.split(',')
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

fn short_id(id: &str) -> String {
    let id = id.trim().trim_start_matches("sha256:");
    if id.len() > 12 {
        id[..12].to_string()
    } else {
        id.to_string()
    }
}

fn clean_command(raw: &str) -> String {
    let mut text = raw.trim().to_string();
    if text.len() >= 2 && text.starts_with('"') && text.ends_with('"') {
        text = text[1..text.len() - 1].to_string();
    }
    text.replace("\\\"", "\"").replace("\\'", "'")
}

fn crictl_state(state: &str) -> String {
    match state {
        "CONTAINER_RUNNING" => "running".into(),
        "CONTAINER_EXITED" => "exited".into(),
        "CONTAINER_CREATED" => "created".into(),
        "CONTAINER_UNKNOWN" => "unknown".into(),
        other if other.is_empty() => "unknown".into(),
        other => other.trim_start_matches("CONTAINER_").to_ascii_lowercase(),
    }
}

fn run(tool: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(tool)
        .args(args)
        .env("TERM", "dumb")
        .output()
        .map_err(|err| format!("无法运行 {tool}: {err}"))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }
    let err = String::from_utf8_lossy(&output.stderr);
    let err = err.trim();
    if err.is_empty() {
        Err(format!("{tool} 退出码 {}", output.status))
    } else {
        Err(err.to_string())
    }
}

fn command_exists(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).any(|dir| dir.join(name).is_file()))
        .unwrap_or(false)
}

pub fn safe_ref(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 200
        && !text.starts_with('-')
        && text
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':' | '/' | '@'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_rows_keep_state_command_and_asset_counts() {
        let ps = r#"{"ID":"a247dff2ff6d","Names":"minio","State":"running","Command":"\"/usr/bin/minio server /data\"","Image":"minio/minio","Mounts":"minio-data","Networks":"bridge"}
{"ID":"b19c0e11aa20","Names":"nginx","State":"exited","Command":"\"nginx -g 'daemon off;'\"","Image":"nginx:1.25","Mounts":"","Networks":""}
"#;
        let containers = parse_docker_ps(ps);
        assert_eq!(containers[0].container.command, "/usr/bin/minio server /data");
        assert_eq!(containers[0].container.state, "running");
        assert_eq!(containers[1].container.state, "exited");
        let mounts = mount_names(&containers);
        let volumes = parse_docker_volumes(
            r#"{"Name":"minio-data","Driver":"local","Links":"1","Mountpoint":"/var/lib/docker/volumes/minio-data/_data","Status":"N/A"}
{"Name":"spare","Driver":"local","Links":"0","Status":"N/A"}"#,
            &mounts,
        );
        assert_eq!(volumes[0].state, "in-use");
        assert_eq!(volumes[1].state, "unused");
        let networks = parse_docker_networks(
            r#"{"Name":"bridge","Driver":"bridge"}
{"Name":"demo","Driver":"bridge"}"#,
            &network_names(&containers),
        );
        assert_eq!(networks[0].state, "active");
        assert_eq!(networks[1].state, "idle");
        let images = parse_docker_images(
            r#"{"Repository":"minio/minio","Tag":"latest","ID":"sha256:abcdef1234567890","Size":"160MB","Containers":"1"}
{"Repository":"<none>","Tag":"<none>","ID":"sha256:ffffff123456","Size":"10MB","Containers":"0"}"#,
            &containers,
        );
        assert_eq!(images[0].name, "minio/minio:latest");
        assert_eq!(images[0].state, "in-use");
        assert_eq!(images[1].state, "dangling");
        let states: Vec<_> = containers.iter().map(|item| item.container.state.clone()).collect();
        assert_eq!(count_text("容器", &states), "容器  2  exited 1  running 1");
    }

    #[test]
    fn crictl_state_and_missing_resources_are_explicit() {
        let containers = parse_crictl_ps(
            r#"{"containers":[{"id":"abc123456789ffff","metadata":{"name":"nginx"},"state":"CONTAINER_RUNNING","image":{"image":"nginx:latest"}}]}"#,
        );
        assert_eq!(containers[0].container.state, "running");
        assert_eq!(containers[0].container.name, "nginx");
        assert_eq!(containers[0].container.id, "abc123456789");
    }
}
