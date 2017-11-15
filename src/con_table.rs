use ::con::Con;
use mio::Token;

pub struct ConTable {
    cons: Vec<Con>,
    empty_slots: usize,
}

impl ConTable {
    pub fn new() -> ConTable {
        ConTable {
            cons: Vec::with_capacity(4),
            empty_slots: 0,
        }
    }

    pub fn get_con(&mut self, id: usize) -> Option<&mut Con> {
        if id < self.cons.len() {
            let c = &mut self.cons[id];
            return Some(c);
        }
        None
    }

    pub fn push_con(&mut self, mut c: Con) -> Option<u16> {
        if self.cons.len() == (u16::max_value() as usize) {
            return None;
        }
        if self.empty_slots*4 <= self.cons.len() {
            c.token = Token::from(c.token.0 + self.cons.len());
            self.cons.push(c);
            Some((self.cons.len()-1) as u16)
        } else {
            for i in 0..self.cons.len() {
                if self.cons[i].closed() {
                    c.token = Token::from(c.token.0 + i);
                    self.cons[i] = c;
                    self.empty_slots -= 1;
                    return Some(i as u16);
                }
            }
            return None;
        }
    }

    pub fn close_con(&mut self, pos: u16) {
        let pos = pos as usize;
        self.cons[pos].close();
        self.empty_slots += 1;
        loop {
            if self.cons.last().is_some() {
                if self.cons.last().unwrap().closed() {
                    let _ = self.cons.pop();
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }
}

// append new cons
// when last one closed, shorten vec.