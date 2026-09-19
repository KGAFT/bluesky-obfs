use std::time::{Duration, Instant};
use crate::util::rand_util::generate_random_u8_vec;
#[derive(Clone)]
pub enum DelayType{
    ArraySort((usize, usize)),
    SpinLoop(Duration),
}

pub struct DelayGenerator {

}

impl DelayGenerator {
    pub fn pick_and_perform_delay(delays: &[DelayType]){
        if !delays.is_empty(){
            let delay_idx = rand::random_range(..delays.len());
            Self::perform_delay(&delays[delay_idx])
        }
    }
    
    /// Async variant, for every call site that can await.
    ///
    /// The synchronous versions below burn the calling thread: `spin_loop_delay`
    /// spins and `array_sort_delay` sorts. Called from a tokio worker they stall
    /// every other connection scheduled on that worker, which is both a
    /// throughput problem and a timing side channel across connections. Here a
    /// `SpinLoop` becomes a real timer, and the deliberate CPU burn of
    /// `ArraySort` moves to the blocking pool where it belongs.
    pub async fn pick_and_perform_delay_async(delays: &[DelayType]) {
        if delays.is_empty() {
            return;
        }
        let delay_idx = rand::random_range(..delays.len());
        match delays[delay_idx].clone() {
            DelayType::SpinLoop(dur) => {
                tokio::time::sleep(dur).await;
            }
            DelayType::ArraySort((array_size, amount)) => {
                let _ = tokio::task::spawn_blocking(move || {
                    Self::array_sort_delay(array_size, amount);
                })
                .await;
            }
        }
    }

    pub fn perform_delay(delay: &DelayType){
        match delay {
            DelayType::ArraySort(times) => {
                Self::array_sort_delay(times.0, times.1);
            }
            DelayType::SpinLoop(dur) => {
                Self::spin_loop_delay(dur.clone());
            }
        }
    }

    fn array_sort_delay(array_size: usize, amount: usize){
        let mut i: usize = 0;
        while i < amount{
            let mut arr = generate_random_u8_vec(array_size);
            arr.sort_unstable();
            i+=1
        }
    }

    fn spin_loop_delay(spin_duration: Duration){
        let start = Instant::now();

        while start.elapsed() < spin_duration {
            std::hint::spin_loop();
        }
    }
}