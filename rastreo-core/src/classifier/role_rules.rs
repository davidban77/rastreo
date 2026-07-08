use super::RoleRule;

/// Curated role-detection rules shipped with rastreo. Matched in the order returned.
/// Currently ships port-heuristic rules only; user-supplied `sys_object_id_prefix` rules
/// still run before these when merged via `merge_mode: extend`.
pub fn baked_role_rules() -> Vec<RoleRule> {
    vec![
        RoleRule::PortsOpen {
            ports: vec![22, 179],
            role: "router".to_string(),
        },
        RoleRule::PortsOpen {
            ports: vec![22, 443, 830],
            role: "router".to_string(),
        },
        RoleRule::PortsOpen {
            ports: vec![443],
            role: "web_server".to_string(),
        },
        RoleRule::PortsOpen {
            ports: vec![80],
            role: "web_server".to_string(),
        },
        RoleRule::PortsOpen {
            ports: vec![22],
            role: "host".to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baked_rules_are_non_empty() {
        assert!(!baked_role_rules().is_empty());
    }

    #[test]
    fn baked_rules_sys_object_id_precedes_ports_open() {
        let rules = baked_role_rules();
        let mut seen_ports = false;
        for rule in &rules {
            match rule {
                RoleRule::SysObjectIdPrefix { .. } => {
                    assert!(
                        !seen_ports,
                        "sys_object_id_prefix rule appeared after a ports_open rule"
                    );
                }
                RoleRule::PortsOpen { .. } => {
                    seen_ports = true;
                }
            }
        }
    }

    #[test]
    fn baked_ports_open_rules_have_non_empty_port_lists() {
        for rule in baked_role_rules() {
            if let RoleRule::PortsOpen { ports, .. } = rule {
                assert!(!ports.is_empty(), "baked ports_open rule has empty ports");
            }
        }
    }
}
