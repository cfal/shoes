use std::io;

use super::{Config, ConfigSelection, RuleConfig, RuleGroupRules, ServerProxyConfig};
use crate::option_util::NoneOrSome;
use crate::rules::Compiler;

fn rules(
    rules: &mut NoneOrSome<ConfigSelection<RuleConfig>>,
    visitor: &mut dyn FnMut(&mut RuleConfig) -> io::Result<()>,
    group: &mut dyn FnMut(&str) -> io::Result<()>,
) -> io::Result<()> {
    for rule in rules.iter_mut() {
        match rule {
            ConfigSelection::Config(rule) => visitor(rule)?,
            ConfigSelection::GroupName(name) => group(name)?,
        }
    }
    Ok(())
}

fn protocol(
    protocol: &mut ServerProxyConfig,
    visitor: &mut dyn FnMut(&mut RuleConfig) -> io::Result<()>,
    group: &mut dyn FnMut(&str) -> io::Result<()>,
) -> io::Result<()> {
    match protocol {
        ServerProxyConfig::Tls {
            tls_targets,
            default_tls_target,
            shadowtls_targets,
            reality_targets,
            ..
        } => {
            for target in tls_targets
                .values_mut()
                .chain(default_tls_target.iter_mut().map(|t| t.as_mut()))
            {
                rules(&mut target.override_rules, visitor, group)?;
                self::protocol(&mut target.protocol, visitor, group)?;
            }
            for target in shadowtls_targets.values_mut() {
                rules(&mut target.override_rules, visitor, group)?;
                self::protocol(&mut target.protocol, visitor, group)?;
            }
            for target in reality_targets.values_mut() {
                rules(&mut target.override_rules, visitor, group)?;
                self::protocol(&mut target.protocol, visitor, group)?;
            }
        }
        ServerProxyConfig::Websocket { targets } => {
            for target in targets.iter_mut() {
                rules(&mut target.override_rules, visitor, group)?;
                self::protocol(&mut target.protocol, visitor, group)?;
            }
        }
        ServerProxyConfig::Xhttp(config) => self::protocol(&mut config.protocol, visitor, group)?,
        _ => {}
    }
    Ok(())
}

pub(crate) fn compile(configs: &mut [Config], compiler: &mut Compiler) -> io::Result<()> {
    visit(configs, &mut |rule| rule.compile(compiler), &mut |_| Ok(()))
}

pub(crate) fn visit(
    configs: &mut [Config],
    visitor: &mut dyn FnMut(&mut RuleConfig) -> io::Result<()>,
    group: &mut dyn FnMut(&str) -> io::Result<()>,
) -> io::Result<()> {
    for config in configs {
        match config {
            Config::Server(server) => {
                rules(&mut server.rules, visitor, group)?;
                protocol(&mut server.protocol, visitor, group)?;
            }
            Config::TunServer(tun) => rules(&mut tun.rules, visitor, group)?,
            Config::RuleConfigGroup(group) => {
                if let RuleGroupRules::Policies(rules) = &mut group.rules {
                    for rule in rules.iter_mut() {
                        visitor(rule)?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn generated_defaults_are_compiled_during_validation() {
        for rules in ["[]", "block-all", "allow-all-direct"] {
            let configs = serde_yaml::from_str(&format!(
                "- address: '127.0.0.1:1080'\n  protocol: {{type: socks}}\n  rules: {rules}\n"
            ))
            .unwrap();
            let validated = crate::config::create_server_configs(configs).unwrap();
            let Config::Server(server) = &validated.configs[0] else {
                panic!("expected server")
            };
            let ConfigSelection::Config(rule) = server.rules.iter().next().unwrap() else {
                panic!("expected generated default rule")
            };
            let predicate = rule
                .criteria
                .compiled
                .as_ref()
                .unwrap_or_else(|| panic!("uncompiled validation-generated rule: {rules}"));
            assert_eq!(
                predicate.evaluate(Some("example.com"), None, 443),
                crate::rules::Outcome::Match,
                "rules: {rules}"
            );
        }
    }

    #[test]
    fn group_predicates_are_shared_before_listener_expansion() {
        let configs = serde_yaml::from_str(
            "\
- rule_group: shared\n  rules: [{masks: {domain_suffix: [example.com]}, action: block}]\n\
- address: '127.0.0.1:1080'\n  protocol: {type: socks}\n  rules: shared\n\
- address: '127.0.0.1:1081'\n  protocol: {type: socks}\n  rules: shared\n",
        )
        .unwrap();
        let validated = crate::config::create_server_configs(configs).unwrap();
        let predicates: Vec<_> = validated
            .configs
            .iter()
            .filter_map(|config| {
                if let Config::Server(server) = config {
                    let ConfigSelection::Config(rule) = server.rules.iter().next().unwrap() else {
                        panic!("unexpanded group")
                    };
                    Some(rule.criteria.compiled.as_ref().unwrap().clone())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(predicates.len(), 2);
        assert!(Arc::ptr_eq(&predicates[0], &predicates[1]));
    }
}
