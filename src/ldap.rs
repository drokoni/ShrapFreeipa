use ldap3::{LdapConnAsync, LdapConnSettings};
use ldap3::Ldap;
use crate::errors::Result;

/// Создание LDAP-соединения с учётом LDAPS и параметров безопасности
pub async fn create_ldap_connection(ldaps: bool, url: &str) -> Result<(ldap3::Ldap, LdapConnAsync)> {
    let (conn, mut ldap) = LdapConnAsync::new(&url).await?;


    //let consettings = LdapConnSettings::new().set_no_tls_verify(true);
    //let (conn, ldap) = LdapConnAsync::with_settings(consettings, url).await?;
    Ok((ldap, conn))
}

/// Установка соединения через simple_bind
pub async fn ldap_simple_bind(ldap: &mut Ldap, username: &str, password: &str, domain: &str) -> Result<()> {
    use colored::Colorize;
    use log::{info, error};

    let res = ldap.simple_bind(username, password).await?.success();
    match res {
        Ok(_) => {
            info!("Connected to {} Active Directory!", domain.to_uppercase().bold().green());
            info!("Starting data collection...");
        },
        Err(err) => {
            error!("Failed to authenticate to {} Active Directory. Reason: {}", domain.to_uppercase().bold().red(), err);
            std::process::exit(0x0100);
        }
    }
    Ok(())
}

/// Установка соединения через GSSAPI (Kerberos)
#[cfg(not(feature = "nogssapi"))]
pub async fn ldap_kerberos_bind(ldap: &mut Ldap, ldapfqdn: &str, domain: &str) -> Result<()> {
    use colored::Colorize;
    use log::{info, error};

    let res = ldap.sasl_gssapi_bind(ldapfqdn).await?.success();
    match res {
        Ok(_) => {
            info!("Connected to {} Active Directory!", domain.to_uppercase().bold().green());
            info!("Starting data collection...");
        },
        Err(err) => {
            error!("Failed to authenticate to {} Active Directory. Reason: {}", domain.to_uppercase().bold().red(), err);
            std::process::exit(0x0100);
        }
    }
    Ok(())
}


