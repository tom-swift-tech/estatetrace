use anyhow::{Context, Result};
use keyring::Entry;

const SERVICE: &str = "EstateTrace";

pub fn store_secret(account: &str, secret: &str) -> Result<()> {
    let entry = Entry::new(SERVICE, account).context("credential entry")?;
    entry.set_password(secret).context("store credential")?;
    Ok(())
}

pub fn read_secret(account: &str) -> Result<Option<String>> {
    let entry = Entry::new(SERVICE, account).context("credential entry")?;
    match entry.get_password() {
        Ok(p) => Ok(Some(p)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn delete_secret(account: &str) -> Result<()> {
    let entry = Entry::new(SERVICE, account).context("credential entry")?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

pub fn snow_account(instance_url: &str) -> String {
    format!("servicenow:{instance_url}")
}

pub fn chat_account(gateway_url: &str) -> String {
    format!("chat:{gateway_url}")
}