use std::sync::Once;

use async_channel::{bounded, Receiver, Sender};

use crate::error::Error;

use super::session::Session;

#[derive(Debug)]
pub enum Msg {
    Tx(),
    Rx(),
    NewSession(Session),
}

#[derive(Clone)]
pub struct WorkQ {
    tx: Sender<Msg>,
}

static mut G_WQ: Option<WorkQ> = None;
static INIT: Once = Once::new();

impl WorkQ {
    pub fn init() -> Result<Receiver<Msg>, Error> {
        let (tx, rx) = bounded::<Msg>(3);
        WorkQ::configure(tx);
        Ok(rx)
    }

    fn configure(tx: Sender<Msg>) {
        unsafe {
            INIT.call_once(|| {
                G_WQ = Some(WorkQ { tx });
            });
        }
    }

    pub fn get() -> Result<WorkQ, Error> {
        unsafe { G_WQ.as_ref().map(|t| t.clone()).ok_or(Error::Invalid) }
    }

    pub fn sync_send(&self, msg: Msg) -> Result<(), Error> {
        smol::block_on(self.send(msg))
    }

    pub async fn send(&self, msg: Msg) -> Result<(), Error> {
        self.tx.send(msg).await.map_err(|e| e.into())
    }
}
