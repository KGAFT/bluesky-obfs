use std::cmp::Reverse;
use std::collections::HashMap;
#[derive(Default, Clone, Debug)]
pub struct UsedPacketSize{
    pub size: usize,
    pub repeat_times: usize,

}
#[derive(Clone, Default)]
pub struct ConnectionPattern {
    ///packets sorted by size in descending order, the repeat_times represent how much packet was repeated at all time
    known_packet_sizes: Vec<UsedPacketSize>,
    ///packets are ordered as they coming after connect after last ChangeCipherSpec,
    /// maybe needed when needed to pick in which place inject target packet
    order: Vec<UsedPacketSize>,
    order_overall_len: usize,
}

impl ConnectionPattern {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert_packet(&mut self, mut packet: UsedPacketSize){
        let mut found_known = false;
        for i in 0..self.known_packet_sizes.len() {
            if self.known_packet_sizes[i].size == packet.size{
                found_known = true;
                self.known_packet_sizes[i].repeat_times+=1;
                break;
            }
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
            packet.repeat_times = 1;
            self.known_packet_sizes.push(packet);
        }
    }
    pub fn finalize(&mut self){
        self.known_packet_sizes.sort_unstable_by_key(|el| Reverse(el.repeat_times));
        for x in self.order.iter() {
            self.order_overall_len += x.repeat_times
        }
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

    pub fn known_packet_sizes(&self) -> &Vec<UsedPacketSize> {
        &self.known_packet_sizes
    }
    
    pub fn clear(&mut self) {
        self.order.clear();
        self.known_packet_sizes.clear();
    }

    pub fn order(&self) -> &Vec<UsedPacketSize> {
        &self.order
    }
}