use std::sync::Arc;

pub(crate) fn use_bbr_congestion_control(
    transport_config: &mut quinn::TransportConfig,
) -> &mut quinn::TransportConfig {
    transport_config
        .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()))
}
