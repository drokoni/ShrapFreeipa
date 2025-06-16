use ldap3::{Ldap, Scope, SearchEntry}; 
use serde_json::{json, to_string_pretty, Value};
use std::{collections::HashMap, fs::File, io::Write};
use zip::{write::FileOptions, CompressionMethod, ZipWriter};
use chrono::{FixedOffset, TimeZone, Utc};
use std::error::Error;
use regex::Regex;

pub async fn query_ldap(ldap: &mut ldap3::Ldap, base: &str, filter: &str, attrs: Vec<&str>) -> Result<Vec<SearchEntry>, Box<dyn std::error::Error>> {
    let (res, _) = ldap.search(base, Scope::Subtree, filter, attrs).await?.success()?;
    Ok(res.into_iter().map(SearchEntry::construct).collect())
}

pub fn save_json_to_zip(zip: &mut ZipWriter<File>, filename: &str, content: Value, options: FileOptions) -> Result<(), Box<dyn std::error::Error>> {
    zip.start_file(filename, options)?;
    zip.write_all(to_string_pretty(&content)?.as_bytes())?;
    Ok(())
}

pub fn get_attr(attrs: &HashMap<String, Vec<String>>, attr: &str) -> String {
    attrs.get(attr).and_then(|v| v.first().cloned()).unwrap_or_default().trim().to_string()
}

pub fn convert_ipa_time(ipa_time: &str) -> Result<i64, Box<dyn Error>> {
    if !ipa_time.ends_with('Z') || ipa_time.len() != 15 {
        return Err("Invalid IPA time format".into());
    }
    let dt = FixedOffset::east_opt(0).unwrap()
        .with_ymd_and_hms(
            ipa_time[0..4].parse()?, ipa_time[4..6].parse()?, ipa_time[6..8].parse()?,
            ipa_time[8..10].parse()?, ipa_time[10..12].parse()?, ipa_time[12..14].parse()?
        )
        .single().ok_or("Invalid date/time components")?;
    Ok(dt.with_timezone(&Utc).timestamp())
}

pub fn get_ipa_timestamp(attrs: &HashMap<String, Vec<String>>, attr: &str) -> i64 {
    attrs.get(attr).and_then(|v| v.first()).and_then(|t| convert_ipa_time(t).ok()).unwrap_or(-1)
}

pub fn is_child(child_dn: &str, parent_dn: &str) -> bool {
    child_dn.to_lowercase().ends_with(&format!(",{}", parent_dn.to_lowercase()))
}

/// Промежуточная структура для ACI-записи
 pub struct AciEntry {
    pub right_name: String, 
    pub principal_dn: String,
    pub is_inherited: bool,
}

/// Разбирает сырые строки ACI в структурированные записи AciEntry
pub fn parse_domain_acis(aci_strings: &[String]) -> Vec<AciEntry> {
    // Регекс для извлечения имени права: acl "permission:..."
    let re_acl = Regex::new(r#"acl\s+\"permission:(?P<perm>[^\"]+)\""#).unwrap();
    // Регекс для извлечения DN группы: groupdn = "ldap:///..."
    let re_group = Regex::new(r#"groupdn\s*=\s*\"ldap:///(?P<dn>[^\"]+)\""#).unwrap();

    let mut entries = Vec::new();
    for raw in aci_strings {
        // Ищем право
        let perm = re_acl
            .captures(raw)
            .and_then(|cap| cap.name("perm").map(|m| m.as_str().to_string()))
            .unwrap_or_else(|| String::from(""));
        // Ищем DN группы
        let dn = re_group
            .captures(raw)
            .and_then(|cap| cap.name("dn").map(|m| m.as_str().to_string()))
            .unwrap_or_else(|| String::from(""));
        
        entries.push(AciEntry {
            right_name: perm,
            principal_dn: dn,
            is_inherited: false, // для FreeIPA PBAC всегда явные ACL
        });
    }
    entries
}

/// Маппинг текстового имени права на формат BloodHound RightName
fn map_permission(perm: &str) -> &str {
    let p = perm.to_lowercase();
    if p.contains("allextendedrights") {
        "AllExtendedRights"
    } else if p.contains("getchangesall") {
        "GetChangesAll"
    } else if p.contains("getchangesinfilteredset") {
        "GetChangesInFilteredSet"
    } else if p.contains("getchanges") {
        "GetChanges"
    } else if p.contains("writeowner") {
        "WriteOwner"
    } else if p.contains("writedacl") {
        "WriteDacl"
    } else if p.contains("genericwrite") || p.contains("write ") {
        "GenericWrite"
    } else if p.contains("genericall") || p.contains("all") {
        "GenericAll"
    } else {
        // по умолчанию
        "GenericAll"
    }
}

/// Конвертирует распарсенные ACI-записи в JSON-ACE для BloodHound
pub fn parsed_aci_to_aces_json(
    entries: Vec<AciEntry>,
    group_map: &HashMap<String, String>,
) -> Vec<Value> {
    let mut aces = Vec::new();
    for entry in entries {
        // Ищем SID группы по DN
        let sid = group_map
            .get(&entry.principal_dn)
            .cloned()
            .unwrap_or_default();
        if sid.is_empty() {
            // группы нет в мапе — пропускаем
            continue;
        }
        let right = map_permission(&entry.right_name);
        aces.push(json!({
            "RightName": right,
            "IsInherited": entry.is_inherited,
            "PrincipalSID": sid,
            "PrincipalType": "Group"
        }));
    }
    aces
}


/// Строит ACE-записи из memberOf любого объекта (User/Group/Computer/...).
/// - `entry` — запись, для которой генерим ACEs
/// - `groups` — вектор всех групп (PBAC-группы), чтобы по DN найти SID и имя
pub fn build_aces_from_memberof(
    entry: &SearchEntry,
    groups: &[SearchEntry],
) -> Vec<Value> {
    let mut aces = Vec::new();
    let member_of = match entry.attrs.get("memberOf") {
        Some(v) => v,
        None => return aces,
    };

    for group_dn in member_of {
        if let Some(group) = groups.iter().find(|g| &g.dn == group_dn) {
            let sid        = get_attr(&group.attrs, "ipaNTSecurityIdentifier");
            let name_lc    = get_attr(&group.attrs, "cn").to_lowercase();

            // логика маппинга имен в права
            let right = if name_lc.contains("administrator") {
                Some("GenericAll")
            } else if name_lc.starts_with("read ")
                   || name_lc.contains("system: read") {
                Some("GenericRead")
            } else if name_lc.starts_with("add ")
                   || name_lc.starts_with("modify ")
                   || name_lc.starts_with("remove ")
                   || name_lc.starts_with("write ")
                   || name_lc.contains("system: add")
                   || name_lc.contains("system: modify")
                   || name_lc.contains("system: remove") {
                Some("GenericWrite")
            } else if name_lc.contains("manage") {
                Some("WriteOwner")
            } else {
                None
            };

            if let Some(r) = right {
                aces.push(json!({
                    "PrincipalSID": sid,
                    "PrincipalType": "Group",  // т.к. memberOf всегда группы
                    "RightName": r,
                    "IsInherited": false
                }));
            }
        }
    }

    aces
}

pub fn build_aces_from_memberof_users(entry: &SearchEntry, groups: &Vec<SearchEntry>) -> Vec<Value> {
    let mut aces = Vec::new();

    let member_of = match entry.attrs.get("memberOf") {
        Some(m) => m,
        None => return aces,
    };

    for group_dn in member_of {
        if let Some(group) = groups.iter().find(|g| g.dn == *group_dn) {
            let group_sid = get_attr(&group.attrs, "ipaNTSecurityIdentifier");
            let group_name = get_attr(&group.attrs, "cn").to_lowercase();

            let right = if group_name.contains("admins") || group_name.contains("domain_admins") {
                Some("GenericAll")
            } else if group_name.contains("editors") {
                Some("GenericWrite")
            } else if group_name.contains("trust admins") {
                Some("WriteDacl")
            } else if group_name.contains("ipausers") {
                Some("GenericRead")
            } else if group_name.contains("replication") {
                Some("GenericWrite")
            } else if group_name.contains("manage") {
                Some("WriteOwner")
            } else if group_name.contains("enroll") || group_name.contains("host enrollment") {
                Some("GenericWrite")
            } else if group_name.contains("topology") {
                Some("WriteDacl")
            } else {
                None
            };


            if let Some(right) = right {
                aces.push(json!({
                    "PrincipalSID": group_sid,
                    "PrincipalType": "Group",
                    "RightName": right,
                    "IsInherited": false
                }));
            }
        }
    }

    aces
}

pub fn build_user_properties(user: &SearchEntry, domain_name: &str, domain_sid: &str) -> Value {
    let disabled = is_preauth_disabled(user);
    json!({
        "domain": domain_name,
        "name": format!("{}@{}", get_attr(&user.attrs, "uid"), domain_name),
        "samaccountname": get_attr(&user.attrs, "uid"),
        "enabled": get_attr(&user.attrs, "nsAccountLock") != "true",
        "domainsid": domain_sid,
        "distinguishedname": user.dn,
        "pwdneverexpires": true,
        "lastlogon": get_ipa_timestamp(&user.attrs, "lastLogonTimestamp"),
        "pwdlastset": get_ipa_timestamp(&user.attrs, "krbLastPwdChange"),
        "serviceprincipalnames": user.attrs.get("krbPrincipalName").cloned().unwrap_or_default(),
        "hasspn": user.attrs.get("krbPrincipalName").map(|v| !v.is_empty()).unwrap_or(false),
        "dontreqpreauth": disabled
    })
}

pub fn build_group_properties(group: &SearchEntry, domain_name: &str, domain_sid: &str) -> Value {
    json!({
        "domain": domain_name,
        "name":format!("{}@{}", get_attr(&group.attrs, "cn"), domain_name),
        "samaccountname": get_attr(&group.attrs, "cn"),
        "domainsid": domain_sid,
        "distinguishedname": group.dn,
        "description": get_attr(&group.attrs, "description")
    })
}

pub fn build_computer_properties(computer: &SearchEntry, domain_name: &str, domain_sid: &str) -> Value {
    json!({
        "domain": domain_name,
        "name": format!("{}.{}", get_attr(&computer.attrs, "cn"), domain_name),
        "samaccountname": format!("{}$", get_attr(&computer.attrs, "cn")),
        "domainsid": domain_sid,
        "distinguishedname": computer.dn,
        "enabled": get_attr(&computer.attrs, "nsAccountLock") != "true",
        "lastlogon": get_ipa_timestamp(&computer.attrs, "lastLogonTimestamp"),
        "pwdlastset": get_ipa_timestamp(&computer.attrs, "krbLastPwdChange"),
        "operatingsystem": get_attr(&computer.attrs, "nsHardwarePlatform"),
        "operatingsystemversion": get_attr(&computer.attrs, "nsOsVersion"),
        "serviceprincipalnames": computer.attrs.get("krbPrincipalName").cloned().unwrap_or_default(),
        "hasspn": computer.attrs.get("krbPrincipalName").map(|v| !v.is_empty()).unwrap_or(false),

    })
}

/// Base DN из domain_name (например, "kurs.ru" → "dc=kurs,dc=ru2
pub fn make_base_dn(domain_name: &str) -> String {
    domain_name
        .split('.')
        .map(|part| format!("dc={}", part))
        .collect::<Vec<_>>()
        .join(",")
}


pub async fn fetch_entries(
    ldap: &mut Ldap,
    base: &str,
    filter: &str,
    attrs: Vec<&str>,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    Ok(query_ldap(ldap, base, filter, attrs).await?)
}


/// Проверяет, отключена ли у пользователя предусловная аутентификация (dontreqpreauth).
///
/// Возвращает:
/// - `true`,  если бит REQUIRE_PRE_AUTH НЕ установлен (т.е. preauth отключена),
/// - `false` в противном случае (и если атрибут не найден/невалиден).
fn is_preauth_disabled(u: &SearchEntry) -> bool {
    // Маска бита REQUIRE_PRE_AUTH в krbExtraData
    const KRB5_KDB_REQUIRES_PRE_AUTH: u16 = 0x0002;

    // Ищем бинарный атрибут krbExtraData;binary
    if let Some(raw_vals) = u.bin_attrs.get("krbExtraData") {
        if let Some(raw) = raw_vals.get(0) {
            // второй байт — длина блока флагов
            let len = raw.get(1).copied().unwrap_or(0) as usize;
            // флаги лежат в третьем и четвёртом байтах блока
            if raw.len() >= 2 + len && len >= 2 {
                let hi = raw[2];
                let lo = raw[3];
                let flags = u16::from_be_bytes([hi, lo]);
                let requires_preauth = (flags & KRB5_KDB_REQUIRES_PRE_AUTH) != 0;
                // если флаг REQUIRE_PRE_AUTH не установлен — preauth отключена
                return !requires_preauth;
            }
        }
    }
    // по умолчанию считаем, что preauth не отключена
    false
}
