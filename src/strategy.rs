use std::cmp::Reverse;
use std::collections::HashMap;
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
        let mut found_known = false;
        packet.repeat_times = 1;

        self.order_overall_len += packet.repeat_times;
        self.bandwidth_overall_len+=packet.size*packet.repeat_times;
        if let Some(known_size_repeat) = self.known_packet_sizes.get_mut(&packet.size) {
            found_known = true;
            *known_size_repeat+=1;
        }
        if !self.order.is_empty(){
            let order_max_idx = self.order.len()-1;
            if self.order[order_max_idx].size == packet.size{
                self.order[order_max_idx].repeat_times+=1;

            }else {
                self.order.push(packet.clone());
            }
        } else {
            self.order.push(packet.clone());
        }

        if !found_known {

            self.known_packet_sizes.insert(packet.size, packet.repeat_times);
        }
    }
    pub fn finalize(&mut self){
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
    
    pub fn clear(&mut self) {
        self.order.clear();
        self.known_packet_sizes.clear();
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