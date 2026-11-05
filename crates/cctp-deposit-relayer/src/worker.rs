use crate::{
    arc::ArcSender,
    circle::{now, Iris, Reply},
    config::{Config, Network},
    discovery::{evm, solana},
    rpc::Rpc,
    store::Store,
};
use anyhow::{ensure, Result};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use usdcx_kms_signer::Signer;

pub(crate) struct Worker {
    pub config: Config,
    pub store: Store,
    pub arc: ArcSender,
    pub iris: Iris,
    pub signer: Box<dyn Signer>,
    source_index: usize,
    source_due: Vec<i64>,
}
impl Worker {
    pub async fn new(config: Config, store: Store, signer: Box<dyn Signer>) -> Result<Self> {
        ensure!(
            signer.public_key().await?.address()? == config.signer,
            "loaded signer mismatch"
        );
        let mut arc = ArcSender::new(&config)?;
        arc.verify(&config).await?;
        let iris = Iris::new(config.circle_url.clone())?;
        let source_due = vec![0; config.sources.len()];
        Ok(Self {
            config,
            store,
            arc,
            iris,
            signer,
            source_index: 0,
            source_due,
        })
    }
    pub async fn run(mut self, shutdown: CancellationToken) -> Result<()> {
        loop {
            tokio::select! {biased;
                _=shutdown.cancelled()=>return Ok(()),
                result=self.cycle()=>result?,
            }
            tokio::select! {_=shutdown.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_millis(250))=>{}}
        }
    }
    pub async fn cycle(&mut self) -> Result<()> {
        let time = now();
        if let Some(p) = self.store.pending()? {
            if let Err(error) = self
                .arc
                .reconcile(&self.config, &mut self.store, &p, time)
                .await
            {
                if error.chain().any(|e| e.is::<rusqlite::Error>()) {
                    return Err(error);
                }
                if unavailable(&error) {
                    tracing::warn!(
                        "saved transaction reconciliation unavailable; nonce remains owned"
                    );
                } else {
                    self.store
                        .halt("invalid pending evidence; manual recovery required")?;
                }
            }
        }
        let index = self.source_index;
        self.source_index = (index + 1) % self.config.sources.len();
        if time >= self.source_due[index] && self.store.capacity(&self.config)? {
            self.source_due[index] = time + 5;
            let source = &self.config.sources[index];
            if let Some(cursor) = self.store.cursor(source.domain)? {
                let rpc = Rpc::new(source.rpc.clone())?;
                let result = match source.network {
                    Network::Evm { .. } => tokio::time::timeout(
                        Duration::from_secs(10),
                        evm::scan(&self.config, source, &rpc, &cursor),
                    )
                    .await
                    .unwrap_or(Ok(None)),
                    // Solana returns a bounded examined prefix itself. Cancelling the whole
                    // page here would repeatedly discard progress on a healthy slow provider.
                    Network::Solana { .. } => {
                        solana::scan(&self.config, source, &rpc, &cursor).await
                    }
                };
                match result {
                    Ok(Some(page)) => {
                        if !self.store.page(&self.config, source.domain, &page)? {
                            tracing::warn!(domain=source.domain,"source page exceeds queue capacity; cursor retained, admitted work continues");
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        if unavailable(&error) {
                            tracing::warn!(
                                domain = source.domain,
                                "source temporarily unavailable"
                            );
                        } else {
                            self.store.source_halt(source.domain, &error.to_string())?;
                            tracing::error!(domain = source.domain, "source history halted");
                        }
                    }
                }
            }
        }
        if let Some(job) = self.store.due(time)? {
            let source = self.config.source(job.domain)?;
            match self.iris.get(&self.config, source, &job.transaction).await {
                Ok(Reply::Messages(messages)) => self.store.admit(&job, &messages, time)?,
                Ok(Reply::Limited(delay)) => {
                    self.store.cooldown(time + delay as i64)?;
                    self.store.postpone(&job, time + delay as i64)?;
                }
                Ok(Reply::Pending) => self.store.postpone(&job, time + 15)?,
                Err(error) if unavailable(&error) => self.store.postpone(&job, time + 15)?,
                Err(_) => {
                    self.store.manual(&job, "invalid Circle response")?;
                    tracing::error!(
                        domain = job.domain,
                        "Circle response requires manual review"
                    );
                }
            }
        }
        if self.store.pending()?.is_none() && !self.store.halted()? {
            if let Some(message) = self.store.ready(time)? {
                let next = self.store.next_nonce()?;
                let nonces = match self.arc.nonces(&self.config).await {
                    Ok(n) => n,
                    Err(_) => return Ok(()),
                };
                if nonces != (next, next) {
                    self.store
                        .halt("unexplained sender nonce; manual recovery required")?;
                    return Ok(());
                }
                match self.arc.used(message.nonce).await {
                    Ok(true) => self.store.received(message.nonce)?,
                    Ok(false) => match self
                        .arc
                        .prepare(&self.config, &message, next, self.signer.as_ref(), time)
                        .await
                    {
                        Ok(p) => {
                            // A failed send still leaves the committed pending row owning N.
                            if let Err(error) =
                                self.arc.submit(&self.config, &mut self.store, &p).await
                            {
                                if error.chain().any(|e| e.is::<rusqlite::Error>()) {
                                    return Err(error);
                                }
                                ensure!(
                                    self.store.pending()?.is_some(),
                                    "pending persistence failed before send"
                                );
                                tracing::warn!("broadcast uncertain; saved bytes retained");
                            }
                        }
                        Err(_) => self.store.postpone_message(message.nonce, time + 30)?,
                    },
                    Err(_) => self.store.postpone_message(message.nonce, time + 15)?,
                }
            }
        }
        Ok(())
    }
}
fn unavailable(error: &anyhow::Error) -> bool {
    error.chain().any(|e| {
        e.is::<reqwest::Error>()
            || matches!(
                e.to_string().as_str(),
                "upstream unavailable" | "RPC HTTP failure" | "RPC method failed"
            )
    })
}
