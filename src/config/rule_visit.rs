use std::io;

use super::{Config, ConfigSelection, RuleConfig, ServerProxyConfig};
use crate::option_util::NoneOrSome;
use crate::rules::Compiler;

fn rules(
    rules: &mut NoneOrSome<ConfigSelection<RuleConfig>>,
    compiler: &mut Compiler,
) -> io::Result<()> {
    for rule in rules.iter_mut() {
        if let ConfigSelection::Config(rule) = rule {
            rule.compile(compiler)?;
        }
    }
    Ok(())
}

fn protocol(protocol: &mut ServerProxyConfig, compiler: &mut Compiler) -> io::Result<()> {
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
                rules(&mut target.override_rules, compiler)?;
                self::protocol(&mut target.protocol, compiler)?;
            }
            for target in shadowtls_targets.values_mut() {
                rules(&mut target.override_rules, compiler)?;
                self::protocol(&mut target.protocol, compiler)?;
            }
            for target in reality_targets.values_mut() {
                rules(&mut target.override_rules, compiler)?;
                self::protocol(&mut target.protocol, compiler)?;
            }
        }
        ServerProxyConfig::Websocket { targets } => {
            for target in targets.iter_mut() {
                rules(&mut target.override_rules, compiler)?;
                self::protocol(&mut target.protocol, compiler)?;
            }
        }
        ServerProxyConfig::Xhttp(config) => self::protocol(&mut config.protocol, compiler)?,
        _ => {}
    }
    Ok(())
}

pub(super) fn compile(configs: &mut [Config], compiler: &mut Compiler) -> io::Result<()> {
    for config in configs {
        match config {
            Config::Server(server) => {
                rules(&mut server.rules, compiler)?;
                protocol(&mut server.protocol, compiler)?;
            }
            Config::TunServer(tun) => rules(&mut tun.rules, compiler)?,
            Config::RuleConfigGroup(group) => {
                for rule in group.rules.iter_mut() {
                    rule.compile(compiler)?;
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
    fn generated_default_is_compiled_during_validation() {
        let configs =
            serde_yaml::from_str("- address: '127.0.0.1:1080'\n  protocol: {type: socks}\n")
                .unwrap();
        let validated = crate::config::create_server_configs(configs).unwrap();
        let Config::Server(server) = &validated.configs[0] else {
            panic!("expected server")
        };
        let ConfigSelection::Config(rule) = server.rules.iter().next().unwrap() else {
            panic!("expected generated default rule")
        };
        let predicate = rule.criteria.compiled.as_ref().unwrap();
        assert_eq!(
            predicate.evaluate(Some("example.com"), None, 443),
            crate::rules::Outcome::Match
        );
    }

    #[test]
    fn group_predicates_are_shared_before_listener_expansion() {
        let configs = serde_yaml::from_str(
            "\
- rule_group: shared\n  rules: [{match: {domain_suffix: [example.com]}, action: block}]\n\
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
