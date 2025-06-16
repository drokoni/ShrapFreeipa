mod errors;
mod utils;
mod ldap;
mod collect;

use clap::Parser;
use colored::*;
use ldap3::{LdapConnAsync, LdapConnSettings};
use log::{info, error};
use rpassword::prompt_password;
use crate::errors::Result;
use ldap::*;
use collect::*;

#[derive(Parser, Debug)]
#[command(author = "123", version = "0.1", about = "ПC для сбора данных в freeipa для BloodHound", long_about = None)]
pub struct Args {
    /// IP-адрес или FQDN контроллера домена (например, 192.168.0.111)
    #[arg(short = 'H', long)]
    pub host: String,

    /// Порт подключения (389 — LDAP, 636 — LDAPS)
    #[arg(short = 'P', long, default_value = "389")]
    pub port: String,

    /// Домен, например kurs.ru
    #[arg(short, long)]
    pub domain: String,

    /// Полный FQDN контроллера, например dc01.kurs.ru
    #[arg(short, long)]
    pub fqdn: String,

    /// Имя пользователя для simple_bind (если не используется Kerberos)
    #[arg(short, long, default_value = "not set")]
    pub username: String,

    /// Пароль (если не указан, будет запрошен)
    #[arg(short, long, default_value = "not set")]
    pub password: String,

    /// Использовать Kerberos (требует kinit default - false )
    #[arg(long, default_value_t = false)]
    pub kerberos: bool
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init(); 
    let args = Args::parse();

    let password = if args.password == "not set" && !args.kerberos {
        prompt_password("Введите пароль: ").unwrap_or_default()
    } else {
        args.password.clone()
    };

    let full_user = format!("uid={},cn=users,cn=accounts,dc=kurs,dc=ru", args.username); 
    
    let ldaps = args.port == "636";
    
    let url = format!(
        "{}://{}:{}",
        if args.port == "636" { "ldaps" } else { "ldap" },
        args.host,
        args.port
    );
    let (mut ldap, conn) = create_ldap_connection(ldaps,&url).await?;
    //ldap_simple_bind();
    //let consettings = LdapConnSettings::new().set_no_tls_verify(true);
    //let (conn, mut ldap) = LdapConnAsync::with_settings(consettings, &url).await?;
    //ldap3::drive!(conn);
    //let (conn, mut ldap) = LdapConnAsync::new(&url).await?;
    let drive_task = tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            eprintln!("Ldap con error: {}", e);
        }
    });

    if args.kerberos {
        #[cfg(feature = "gssapi")]
        {
            let res = ldap.sasl_gssapi_bind(&args.fqdn).await?.success();
            match res {
                Ok(_) => info!("✅ Kerberos-аутентификация успешна: {}", args.domain.to_uppercase().green()),
                Err(err) => {
                    error!("❌ Ошибка Kerberos: {err}");
                    std::process::exit(1);
                }
            }
        }
        #[cfg(not(feature = "gssapi"))]
        {
            error!(" GSSAPI не включена при сборке!");
            std::process::exit(1);
        }
    } else {
        let res = ldap.simple_bind(&full_user, &password).await?.success();
        match res {
            Ok(_) => info!(" simple_bind успешен: {}", full_user.green()),
            Err(err) => {
                error!(" Ошибка simple_bind: {err}");
                std::process::exit(1);
            }
        }
    }

    // Основной блок
    collect(&mut ldap, &args.domain.to_uppercase()).await?;

    ldap.unbind().await?;
    drive_task.abort();
    Ok(())
}

