use crate::strategy::ConnectionPattern;
#[derive(Clone)]
pub struct FakeCodecRateLimiterCfg {
    pub bandwidth_max_derivation_percent: f64,
    pub packet_count_max_derivation_percent: f64,
    pub out_of_pattern_packets_max_ratio_percent: f64,
    /// Absolute allowances added on top of the percentage limits. A captured
    /// pattern can be only a handful of records, and a percentage of a handful
    /// is less than one record — a single HTTP/2 ACK the capture happened to
    /// miss would otherwise get a legitimate client dropped.
    pub packet_count_slack: usize,
    pub bandwidth_slack_bytes: usize,
    pub out_of_pattern_packets_slack: usize,
    pub client_pattern: ConnectionPattern,
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
            packet_count_slack: 4,
            bandwidth_slack_bytes: 2048,
            out_of_pattern_packets_slack: 2,
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
    pub fn new(security_cfg: FakeCodecRateLimiterCfg) -> Self {
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
   
        let order_len = self.client_pattern.order_overall_len();
        let bandwidth_len = self.client_pattern.bandwidth_overall_len();

        if order_len != 0 {
            let max_packets = order_len as f64
                * (1f64 + self.cfg.packet_count_max_derivation_percent)
                + self.cfg.packet_count_slack as f64;
            if self.packet_counter as f64 > max_packets {
                return false;
            }

            let max_out_of_pattern = order_len as f64
                * self.cfg.out_of_pattern_packets_max_ratio_percent
                + self.cfg.out_of_pattern_packets_slack as f64;
            if self.out_of_pattern_packet.len() as f64 > max_out_of_pattern {
                return false;
            }
        }

        if bandwidth_len != 0 {
            let max_bandwidth = bandwidth_len as f64
                * (1f64 + self.cfg.bandwidth_max_derivation_percent)
                + self.cfg.bandwidth_slack_bytes as f64;
            if self.bandwidth_counter as f64 > max_bandwidth {
                return false;
            }
        }

        return true;
    }
}
