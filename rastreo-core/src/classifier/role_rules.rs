use super::RoleRule;

/// Role rules applied by default, in match order: multi-port evidence only, because a guessed role overwrites a curated one downstream.
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
    ]
}

/// The default rules followed by the opt-in single-port heuristics (`443` / `80` → `web_server`, `22` → `host`), in match order.
pub fn baked_role_rules_with_port_heuristics() -> Vec<RoleRule> {
    let mut rules = baked_role_rules();
    rules.extend([
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
    ]);
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baked_rules_are_non_empty() {
        assert!(!baked_role_rules().is_empty());
    }

    #[test]
    fn baked_rules_ship_no_vendor_oid_or_signal_table() {
        for rule in baked_role_rules_with_port_heuristics() {
            assert!(
                matches!(rule, RoleRule::PortsOpen { .. }),
                "the shipped tables are port-evidence only; a curated vendor table belongs in a user's scenario"
            );
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

    #[test]
    fn baked_rules_carry_no_single_port_rule() {
        for rule in baked_role_rules() {
            if let RoleRule::PortsOpen { ports, role } = rule {
                assert!(
                    ports.len() > 1,
                    "default rule `{role}` fires on the single port {ports:?}; single-port evidence is a guess and belongs in baked_role_rules_with_port_heuristics"
                );
            }
        }
    }

    #[test]
    fn port_heuristics_follow_the_baked_rules() {
        let baked = baked_role_rules();
        let extended = baked_role_rules_with_port_heuristics();
        assert_eq!(
            extended[..baked.len()],
            baked[..],
            "the heuristics must trail the default rules, or a router with 22 open classifies as host"
        );
        for rule in &extended[baked.len()..] {
            let RoleRule::PortsOpen { ports, .. } = rule else {
                panic!("port heuristics are ports_open rules");
            };
            assert_eq!(ports.len(), 1);
        }
    }
}
