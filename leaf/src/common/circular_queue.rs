use std::sync::{Arc, Mutex};
use std::thread;
use lazy_static::lazy_static;

lazy_static! {
    static ref QUEUE: Arc<CircularQueue<i32>> = Arc::new(CircularQueue::new(10));
}

struct CircularQueue<T> where T:Clone {
    data: Vec<Option<T>>,
    capacity: usize,
    read_index: usize,
    write_index: usize,
    push_lock: Mutex<()>,
    pop_lock: Mutex<()>,
}

impl<T> CircularQueue<T> where T:Clone {
    fn new(capacity: usize) -> Self {
        CircularQueue {
            data: vec![None; capacity],
            capacity,
            read_index: 0,
            write_index: 0,
            push_lock: Mutex::new(()),
            pop_lock: Mutex::new(()),
        }
    }

    fn push(&mut self, item: T) {
        let _lock = self.push_lock.lock().unwrap();
        self.data[self.write_index] = Some(item);
        self.write_index = (self.write_index + 1) % self.capacity;
    }

    fn pop(&mut self) -> Option<T> {
        let _lock = self.pop_lock.lock().unwrap();
        if let Some(item) = self.data[self.read_index].take() {
            self.read_index = (self.read_index + 1) % self.capacity;
            Some(item)
        } else {
            None
        }
    }
}

fn main() {
    // let mut producer = Arc::clone(&QUEUE);
    // let mut consumer = Arc::clone(&QUEUE);
    //
    // // Producer thread
    // let producer_thread = thread::spawn(move || {
    //     for i in 0..20 {
    //         producer.push(i);
    //     }
    // });
    //
    // // Consumer thread
    // let consumer_thread = thread::spawn(move || {
    //     for _ in 0..20 {
    //         if let Some(item) = consumer.pop() {
    //             println!("Consumed: {}", item);
    //         }
    //     }
    // });
    //
    // producer_thread.join().unwrap();
    // consumer_thread.join().unwrap();
}
