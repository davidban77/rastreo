mod common;

use std::process::Output;

fn discover(args: &[&str]) -> Output {
    common::rastreo()
        .arg("discover")
        .args(args)
        .output()
        .expect("spawn rastreo")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("utf-8 stderr")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("utf-8 stdout")
}

fn plan(args: &[&str]) -> String {
    let mut argv = vec!["--target", "127.0.0.1", "--dry-run"];
    argv.extend_from_slice(args);
    let output = discover(&argv);
    assert!(
        output.status.success(),
        "dry-run {argv:?} failed: {}",
        stderr_of(&output)
    );
    stdout_of(&output)
}

/// The kinds this binary reports as compiled in, read back from its own error message.
fn available_kinds() -> Vec<String> {
    let output = discover(&["--target", "127.0.0.1", "--probe", "no-such-probe-kind"]);
    let stderr = stderr_of(&output);
    let list = stderr
        .split_once("available in this build: ")
        .unwrap_or_else(|| panic!("no availability list in: {stderr}"))
        .1
        .lines()
        .next()
        .expect("availability list line");
    list.split(", ")
        .map(|kind| kind.trim().to_string())
        .collect()
}

#[test]
fn discover_runs_without_a_port_flag() {
    let plan = plan(&[]);
    assert!(
        plan.contains("tcp_connect (ports 22, 23, 80, 443, 830, 8080)"),
        "{plan}"
    );
    assert!(plan.contains("reverse_dns"), "{plan}");
}

fn planned_kinds(plan: &str) -> Vec<String> {
    plan.lines()
        .find_map(|line| line.trim().strip_prefix("probers: "))
        .unwrap_or_else(|| panic!("no probers line in {plan}"))
        .split(", ")
        .filter_map(|entry| entry.split_once(" (").map(|(kind, _)| kind.to_string()))
        .collect()
}

#[test]
fn the_default_set_leaves_out_the_kinds_that_need_a_parameter_or_a_link() {
    let kinds = planned_kinds(&plan(&[]));
    for absent in ["udp", "dns", "arp", "ndp", "lldp", "gnmi"] {
        assert!(
            !kinds.iter().any(|kind| kind == absent),
            "default set must not run {absent}: {kinds:?}"
        );
    }
}

#[test]
fn discover_help_documents_the_probe_flags() {
    let output = common::rastreo()
        .args(["discover", "--help"])
        .output()
        .expect("spawn rastreo");
    assert!(output.status.success());
    let help = stdout_of(&output);
    for needle in ["--probe", "--probe-ports", "--udp-protocol", "--dns-query"] {
        assert!(
            help.contains(needle),
            "discover --help missing {needle}:\n{help}"
        );
    }
    assert!(
        help.contains("reverse_dns") && help.contains("--features gnmi"),
        "--probe long help must list every kind and its feature:\n{help}"
    );
}

#[test]
fn an_unknown_probe_kind_exits_one_and_lists_what_this_build_offers() {
    let output = discover(&["--target", "127.0.0.1", "--probe", "nonsense"]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr_of(&output);
    assert!(stderr.contains("unknown probe kind 'nonsense'"), "{stderr}");
    assert!(stderr.contains("tcp_connect"), "{stderr}");
}

#[test]
fn udp_without_a_protocol_exits_one_and_the_hint_names_the_flag() {
    let output = discover(&["--target", "127.0.0.1", "--probe", "udp"]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr_of(&output);
    assert!(stderr.contains("probe kind 'udp' requires"), "{stderr}");
    assert!(stderr.contains("--udp-protocol"), "{stderr}");
}

#[test]
fn dns_without_a_query_name_exits_one_and_the_hint_names_the_flag() {
    let output = discover(&["--target", "127.0.0.1", "--probe", "dns"]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr_of(&output);
    assert!(stderr.contains("probe kind 'dns' requires"), "{stderr}");
    assert!(stderr.contains("--dns-query"), "{stderr}");
}

const ALL_PROBE_KINDS: &[&str] = &[
    "tcp_connect",
    "udp",
    "http",
    "dns",
    "snmp",
    "arp",
    "ndp",
    "ssh",
    "icmp",
    "tls",
    "reverse_dns",
    "gnmi",
    "lldp",
];

// Derived from the binary, not `cfg!(feature = ...)`: a --workspace build unifies xtask's
// rastreo-core feature requests onto the CLI, so the package's own flags say nothing here.
fn kinds_this_build_omits() -> Vec<&'static str> {
    let available = available_kinds();
    ALL_PROBE_KINDS
        .iter()
        .copied()
        .filter(|kind| !available.iter().any(|have| have == kind))
        .collect()
}

#[test]
fn every_kind_this_build_carries_is_never_refused_for_a_missing_feature() {
    let available = available_kinds();
    let carried: Vec<&String> = available
        .iter()
        .filter(|kind| ALL_PROBE_KINDS.contains(&kind.as_str()))
        .collect();
    assert!(!carried.is_empty(), "availability list: {available:?}");
    for kind in carried {
        let stderr = stderr_of(&discover(&[
            "--target",
            "127.0.0.1",
            "--probe",
            kind,
            "--dry-run",
        ]));
        assert!(
            !stderr.contains("Cargo feature"),
            "{kind} is listed as available yet refused as uncompiled: {stderr}"
        );
    }
}

#[test]
fn every_kind_this_build_left_out_names_its_cargo_feature() {
    for kind in kinds_this_build_omits() {
        let output = discover(&["--target", "127.0.0.1", "--probe", kind]);
        assert_eq!(output.status.code(), Some(1), "{kind} must be refused");
        let stderr = stderr_of(&output);
        assert!(
            stderr.contains(&format!("probe kind '{kind}' requires the")),
            "{kind}: {stderr}"
        );
        assert!(
            stderr.contains(&format!("--features {kind}")),
            "{kind} must name its rebuild feature: {stderr}"
        );
    }
}

#[test]
fn a_per_kind_port_override_answers_a_missing_kind_exactly_as_the_probe_flag_does() {
    for kind in kinds_this_build_omits() {
        let by_probe = discover(&["--target", "127.0.0.1", "--probe", kind]);
        let by_ports = discover(&[
            "--target",
            "127.0.0.1",
            "--probe-ports",
            &format!("{kind}=1"),
        ]);
        assert_eq!(
            by_ports.status.code(),
            by_probe.status.code(),
            "{kind}: --probe-ports and --probe must agree on the exit code"
        );
        let stderr = stderr_of(&by_ports);
        assert!(
            stderr.contains(&format!("probe kind '{kind}' requires the")),
            "{kind}: {stderr}"
        );
        assert!(
            stderr.contains(&format!("--features {kind}")),
            "{kind}: {stderr}"
        );
    }
}

#[test]
fn a_parameter_flag_whose_kind_does_not_run_says_so() {
    let output = discover(&[
        "--target",
        "127.0.0.1",
        "--dns-query",
        "example.com",
        "--dry-run",
    ]);
    assert!(output.status.success(), "{}", stderr_of(&output));
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("note: --dns-query had no effect — no dns probe in this run"),
        "{stderr}"
    );
    assert!(stderr.contains("Add --probe dns."), "{stderr}");
}

#[test]
fn a_per_kind_port_override_whose_kind_does_not_run_says_so() {
    let output = discover(&[
        "--target",
        "127.0.0.1",
        "--probe",
        "tcp_connect",
        "--probe-ports",
        "dns=5353",
        "--dry-run",
    ]);
    assert!(output.status.success(), "{}", stderr_of(&output));
    assert!(
        stderr_of(&output).contains("note: --probe-ports dns=5353 had no effect"),
        "{}",
        stderr_of(&output)
    );
}

#[test]
fn shared_ports_do_not_retarget_a_prober_with_a_protocol_port() {
    let plan = plan(&[
        "--probe",
        "dns",
        "--dns-query",
        "example.com",
        "--port",
        "1161",
    ]);
    assert!(
        plan.contains("dns (ports 53, queries example.com)"),
        "{plan}"
    );
}

#[test]
fn a_per_kind_override_retargets_a_prober_with_a_protocol_port() {
    let plan = plan(&[
        "--probe",
        "dns",
        "--dns-query",
        "example.com",
        "--probe-ports",
        "dns=5353",
    ]);
    assert!(
        plan.contains("dns (ports 5353, queries example.com)"),
        "{plan}"
    );
}

#[test]
fn snmp_keeps_its_own_port_under_port_and_moves_under_probe_ports() {
    if !available_kinds().iter().any(|kind| kind == "snmp") {
        let output = discover(&["--target", "127.0.0.1", "--probe", "snmp"]);
        assert_eq!(output.status.code(), Some(1));
        assert!(
            stderr_of(&output).contains("--features snmp"),
            "a build without snmp must say so: {}",
            stderr_of(&output)
        );
        return;
    }
    let shared = plan(&["--probe", "snmp", "--port", "1161"]);
    assert!(shared.contains("snmp (ports 161"), "{shared}");
    let overridden = plan(&["--probe", "snmp", "--probe-ports", "snmp=1161"]);
    assert!(overridden.contains("snmp (ports 1161"), "{overridden}");
}

#[test]
fn default_and_a_named_kind_select_the_same_run_in_either_order() {
    let before = plan(&["--probe", "default,udp", "--udp-protocol", "ntp"]);
    let after = plan(&["--probe", "udp,default", "--udp-protocol", "ntp"]);
    assert_eq!(before, after);
    assert!(before.contains("udp (ports 123"), "{before}");
    assert!(before.contains("tcp_connect ("), "{before}");
}

#[test]
fn port_without_probe_prints_the_scope_note() {
    let output = discover(&["--target", "127.0.0.1", "--port", "8080", "--dry-run"]);
    assert!(output.status.success(), "{}", stderr_of(&output));
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("note: --port applies to tcp_connect"),
        "{stderr}"
    );
    assert!(
        stderr.contains("--probe tcp_connect for a port-only scan"),
        "{stderr}"
    );
}

#[test]
fn port_with_an_explicit_probe_prints_no_scope_note() {
    let output = discover(&[
        "--target",
        "127.0.0.1",
        "--probe",
        "tcp_connect",
        "--port",
        "8080",
        "--dry-run",
    ]);
    assert!(output.status.success(), "{}", stderr_of(&output));
    assert!(
        !stderr_of(&output).contains("--port applies to"),
        "{}",
        stderr_of(&output)
    );
}

#[test]
fn port_that_reaches_no_selected_prober_is_reported_as_a_no_op() {
    let output = discover(&[
        "--target",
        "127.0.0.1",
        "--probe",
        "reverse_dns",
        "--port",
        "8080",
        "--dry-run",
    ]);
    assert!(output.status.success(), "{}", stderr_of(&output));
    let stderr = stderr_of(&output);
    assert!(stderr.contains("--port had no effect"), "{stderr}");
    assert!(stderr.contains("(reverse_dns)"), "{stderr}");
}

#[test]
fn quiet_suppresses_the_selection_notes_and_keeps_the_plan() {
    let output = discover(&["--target", "127.0.0.1", "--port", "8080", "--dry-run", "-q"]);
    assert!(output.status.success(), "{}", stderr_of(&output));
    assert!(stderr_of(&output).is_empty(), "{}", stderr_of(&output));
    let stdout = stdout_of(&output);
    assert!(
        stdout.contains("[dry-run] would run 1 scenario") && stdout.contains("total probes:"),
        "the plan is the only channel carrying what the run would do: {stdout}"
    );
}

#[cfg(all(feature = "config", feature = "snmp"))]
#[test]
fn an_exported_snmp_community_does_not_conflict_with_file() {
    let output = common::rastreo()
        .env("RASTREO_SNMP_COMMUNITY", "lab-ro")
        .args(["discover", "--file", "/tmp/rastreo-no-such-scenario.yml"])
        .output()
        .expect("spawn rastreo");
    let stderr = stderr_of(&output);
    assert!(
        !stderr.contains("cannot be used with"),
        "the environment form must never trip the --file conflict: {stderr}"
    );
    assert!(
        stderr.contains("failed to read scenario file"),
        "the run must fail on the missing file, not on argument parsing: {stderr}"
    );
}

#[cfg(all(feature = "config", feature = "snmp"))]
#[test]
fn the_snmp_community_flag_still_conflicts_with_file() {
    let output = discover(&[
        "--file",
        "/tmp/rastreo-no-such-scenario.yml",
        "--snmp-community",
        "lab-ro",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr_of(&output).contains("cannot be used with"),
        "{}",
        stderr_of(&output)
    );
}

#[cfg(feature = "config")]
#[test]
fn probe_and_file_are_mutually_exclusive() {
    let output = discover(&[
        "--file",
        "/tmp/does-not-exist.yml",
        "--probe",
        "tcp_connect",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr_of(&output).contains("--probe"),
        "clap must name the conflicting flag: {}",
        stderr_of(&output)
    );
}
