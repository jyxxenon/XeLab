use std::fs;
use uuid::Uuid;
use xelab_kernel::api::App;

// Capture the task PID and start time to distinguish a restart from PID reuse.
pub(super) async fn running(app: &App, instance: Uuid) -> (u32, String) {
    let tasks = String::from_utf8(
        app.runtime
            .ctr(&["tasks".into(), "list".into()])
            .await
            .unwrap(),
    )
    .unwrap();
    let id = instance.to_string();
    let pid = tasks
        .lines()
        .find_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            (fields.len() >= 3 && fields[0] == id && fields[2] == "RUNNING")
                .then(|| fields[1].parse::<u32>().unwrap())
        })
        .expect("a healthy provider must have a real running OCI task");
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    (pid, started_at(&stat).to_owned())
}

pub(super) fn exited(process: &(u32, String)) -> bool {
    match fs::read_to_string(format!("/proc/{}/stat", process.0)) {
        Ok(stat) => started_at(&stat) != process.1,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => panic!("cannot verify the old OCI process: {error}"),
    }
}

fn started_at(stat: &str) -> &str {
    // Field 22 follows the parenthesized executable name and 19 other fields.
    stat.rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
}
