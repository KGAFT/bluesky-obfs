use std::collections::HashMap;
use std::ops::Range;
use rand::Rng;
use rkyv::{Archive, Deserialize, Serialize};
use tfserver::structures::s_type::{StrongType, StructureType};
use crate::util::ob_s_type::ObSType;

#[derive(Default, Clone, Debug, Serialize, Deserialize, Archive)]
pub struct UsedPacketSize{
    pub size: usize,
    pub repeat_times: usize,

}
#[derive(Serialize, Deserialize, Debug, Archive, Clone)]
pub struct ConnectionPattern {
    s_type: ObSType,
    ///packets sorted by size in descending order, the repeat_times represent how much packet was repeated at all time
    known_packet_sizes: HashMap<usize, usize>,
    ///packets are ordered as they coming after connect after last ChangeCipherSpec,
    /// maybe needed when needed to pick in which place inject target packet
    order: Vec<UsedPacketSize>,
    sorted_packet_sizes: Vec<usize>,
    order_overall_len: usize,
    bandwidth_overall_len: usize,
}

impl StrongType for ConnectionPattern {
    fn get_s_type(&self) -> &dyn StructureType {
        &self.s_type
    }
}

impl Default for ConnectionPattern {
    fn default() -> Self {
        Self{
            s_type: ObSType::ConnectionPatternE,
            known_packet_sizes: HashMap::new(),
            order: Vec::new(),
            sorted_packet_sizes: vec![],
            order_overall_len: 0,
            bandwidth_overall_len: 0,
        }
    }
}

impl ConnectionPattern {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert_packet(&mut self, mut packet: UsedPacketSize){
        // The caller's `repeat_times` used to be overwritten with 1 before it was
        // read, so a caller reporting N consecutive records of one size was
        // counted as a single record: run lengths in `order`, the known-size
        // histogram and the bandwidth total all under-counted every repeat.
        let repeat = packet.repeat_times.max(1);
        packet.repeat_times = repeat;

        self.order_overall_len += repeat;
        self.bandwidth_overall_len += packet.size * repeat;

        let found_known =
            if let Some(known_size_repeat) = self.known_packet_sizes.get_mut(&packet.size) {
                *known_size_repeat += repeat;
                true
            } else {
                false
            };

        if let Some(last) = self.order.last_mut() {
            if last.size == packet.size {
                last.repeat_times += repeat;
            } else {
                self.order.push(packet.clone());
            }
        } else {
            self.order.push(packet.clone());
        }

        if !found_known {
            self.known_packet_sizes.insert(packet.size, repeat);
        }
    }

    pub fn finalize(&mut self){
        self.sorted_packet_sizes.clear();
        self.sorted_packet_sizes.extend(self.known_packet_sizes.keys());
        self.sorted_packet_sizes.sort_unstable();
    }

    pub fn overall_idx_to_order_idx(&self, idx: usize) -> usize {
        let mut counter: usize = 0;
        for i in 0..self.order.len() {
            counter += self.order[i].repeat_times;
            if idx < counter {
                return i;
            }
        }
        self.order.len().saturating_sub(1)
    }
    pub fn overall_idx_to_order_idx_backwards(&self, end_offset: usize) -> usize {
        let target = self.order_overall_len.saturating_sub(1 + end_offset);
        self.overall_idx_to_order_idx(target)
    }

    pub fn order_idx_to_overall_idx(&self, order_idx: usize) -> usize {
        let mut counter = 0;
        for i in 0..order_idx.min(self.order.len()) {
            counter += self.order[i].repeat_times;
        }
        counter
    }

    pub fn known_packet_sizes(&self) -> &HashMap<usize, usize> {
        &self.known_packet_sizes
    }

    pub fn check_if_size_exists(&self, size: usize) ->bool{
        self.known_packet_sizes.contains_key(&size)
    }

    pub fn select_packet_size(&self, size: usize, max_derivation_percent: f64) -> Option<usize> {
        if size == 0{
            return None;
        }
        for packet in self.sorted_packet_sizes.iter() {
            if *packet >= size{
                if *packet as f64/size as f64  - 1f64 < max_derivation_percent{
                    return Some(*packet);
                } else {
                    break;
                }
            }
        }
        None
    }

    /// Like [`Self::select_packet_size`], but picks uniformly among **all**
    /// acceptable sizes rather than always returning the smallest.
    ///
    /// `select_packet_size` is a pure function of its input, so a message whose
    /// serialized length is fixed — every `ClientBegin` and `ServerBegin` is,
    /// they have no variable-length field — gets the same target on every
    /// connection, and therefore the same wire length every time. Two
    /// fixed-length records at a fixed point in the flow are a fingerprint, so
    /// the handshake path picks from the whole acceptable run instead.
    ///
    /// Every candidate is still a size the cover site genuinely emits; this only
    /// changes *which* of them is chosen.
    pub fn select_packet_size_randomized(
        &self,
        size: usize,
        max_derivation_percent: f64,
    ) -> Option<usize> {
        if size == 0 {
            return None;
        }
        let mut candidates = Vec::new();
        for packet in self.sorted_packet_sizes.iter() {
            if *packet >= size {
                if *packet as f64 / size as f64 - 1f64 < max_derivation_percent {
                    candidates.push(*packet);
                } else {
                    // Ascending order, so everything beyond this is further out
                    // of bounds too.
                    break;
                }
            }
        }
        if candidates.is_empty() {
            return None;
        }
        let idx = rand::rng().random_range(0..candidates.len());
        Some(candidates[idx])
    }

    pub fn select_packet_size_with_random_padding_fallback(&self, size: usize, max_derivation_percent: f64, random_padding: Range<usize>) -> usize {
        if let Some(size) = self.select_packet_size(size, max_derivation_percent) {
            size
        } else {
            let mut rng = rand::rng();
            rng.random_range(random_padding.clone()) + size
        }
    }

    pub fn clear(&mut self) {
        self.order.clear();
        self.known_packet_sizes.clear();
        self.sorted_packet_sizes.clear();
        self.order_overall_len = 0;
        self.bandwidth_overall_len = 0;
    }

    pub fn order(&self) -> &Vec<UsedPacketSize> {
        &self.order
    }

    pub fn order_overall_len(&self) -> usize {
        self.order_overall_len
    }

    pub fn bandwidth_overall_len(&self) -> usize {
        self.bandwidth_overall_len
    }
}