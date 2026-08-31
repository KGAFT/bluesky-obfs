use crate::strategy::ConnectionPattern;
#[derive(Clone)]
pub struct FakeCodecRateLimiterCfg {
    pub bandwidth_max_derivation_percent: f64,
    pub packet_count_max_derivation_percent: f64,
    pub out_of_pattern_packets_max_ratio_percent: f64,
    pub client_pattern: ConnectionPattern
}

impl Default for FakeCodecRateLimiterCfg {
    fn default() -> Self {
        Self {
            //30%
            bandwidth_max_derivation_percent: 0.3f64,
            //20%
            packet_count_max_derivation_percent: 0.2f64,
            //50%
            out_of_pattern_packets_max_ratio_percent: 0.5f64,
            client_pattern: Default::default(),
        }
    }
}

pub struct FakeCodecRateLimiter {
    client_pattern: ConnectionPattern,
    bandwidth_counter: usize,
    packet_counter: usize,
    out_of_pattern_packet: Vec<usize>,
    cfg: FakeCodecRateLimiterCfg,
}

impl FakeCodecRateLimiter {
    pub fn new( security_cfg: FakeCodecRateLimiterCfg) -> Self {
        Self {
            client_pattern: security_cfg.client_pattern.clone(),
            bandwidth_counter: 0,
            packet_counter: 0,
            out_of_pattern_packet: vec![],
            cfg: security_cfg,
        }
    }

    pub fn register_client_packet(&mut self, packet: &[u8]) {
        self.bandwidth_counter += packet.len();
        self.packet_counter += 1;
        if !self.client_pattern.check_if_size_exists(packet.len()) {
            self.out_of_pattern_packet.push(self.packet_counter);
        }
    }
    pub fn check_if_valid(&self) -> bool {
        if self.packet_counter as f64/ self.client_pattern.order_overall_len() as f64  -1f64
            > self.cfg.packet_count_max_derivation_percent
        {
            return false;
        }
        if self.bandwidth_counter as f64 / self.client_pattern.bandwidth_overall_len()  as f64 -1f64
            > self.cfg.bandwidth_max_derivation_percent
        {
            return false;
        }
        if self.out_of_pattern_packet.len() as f64 / self.client_pattern.order_overall_len() as f64
            > self.cfg.out_of_pattern_packets_max_ratio_percent
        {
            return false;
        }
        return true;
    }
}
