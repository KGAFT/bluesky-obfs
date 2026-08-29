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
    order: Vec<UsedPacketSize>
}

impl ConnectionPattern {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert_packet(&mut self, mut packet: UsedPacketSize){
        let mut found = false;
        for i in 0..self.known_packet_sizes.len() {
            if self.order[i].size == packet.size{
                found = true;
                self.order[i].repeat_times+=1;
                self.known_packet_sizes[i].repeat_times+=1;
                break;
            }
        }
        if !found{
            packet.repeat_times = 1;
            self.order.push(packet.clone());
            self.known_packet_sizes.push(packet);
        }
    }
    pub fn finalize(&mut self){
        self.known_packet_sizes.sort_unstable_by_key(|el| Reverse(el.repeat_times));
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