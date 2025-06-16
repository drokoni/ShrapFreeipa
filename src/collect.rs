use crate::utils::*;
use serde_json::{json, Value};
use ldap3::Ldap;
use std::{collections::HashMap, error::Error, fs::File};
use zip::{write::FileOptions, CompressionMethod, ZipWriter};
use tokio::try_join;

/// Кэш для SID-lookup по DN
struct SidCache {
    map: HashMap<String, String>,
}

impl SidCache {
    /// Создает новый пустой кэш
    fn new() -> Self {
        SidCache { map: HashMap::new() }
    }

    /// Возвращает SID для DN, кэшируя результат
    fn get(&mut self, dn: &str, attrs: &HashMap<String, Vec<String>>) -> String {
        self.map.entry(dn.to_string()).or_insert_with(|| {
            get_attr(attrs, "ipaNTSecurityIdentifier")
        }).clone()
    }
}

/// Собирает данные из LDAP и сохраняет их в ZIP-файл для BloodHound
///
/// # Arguments
/// * `ldap` – клиент LDAP
/// * `domain_name` – имя домена (например, "kurs.ru")
pub async fn collect(ldap: &mut Ldap, domain_name: &str) -> Result<(), Box<dyn Error>> {
    // 1) Вычисляем базовый DN
    let base_dn = make_base_dn(domain_name);

    // 2) Последовательно запрашиваем все категории объектов
        let domain_entries = fetch_entries(
        ldap,
        &base_dn,
        "(objectClass=domain)",
        vec!["dc","objectSid","entryUUID","createTimestamp","msDS-Behavior-Version","description","aci"],
    ).await?;
    let ous = fetch_entries(
        ldap,
        &base_dn,
        "(objectClass=organizationalUnit)",
        vec!["cn","entryUUID"],
    ).await?;
    let users = fetch_entries(
        ldap,
        &format!("cn=users,cn=accounts,{}", base_dn),
        "(|(objectClass=posixAccount)(objectClass=krbprincipalaux))",
        vec!["*","uid","krbPrincipalData;binary"],
    ).await?;

    //eprintln!("Debug users: {:#?}", users);

    let groups = fetch_entries(
        ldap,
        &format!("cn=accounts,{}", base_dn),
        "(objectClass=*)",
        vec!["*"],
    ).await?;
    let computers = fetch_entries(
        ldap,
        &format!("cn=computers,cn=accounts,{}", base_dn),
        "(objectClass=IpaHost)",
        vec![
            "cn","fqdn","ipaUniqueID","objectGUID","whenCreated","memberOf",
            "krbLastSuccessTime","krbPasswordExpiration",
            "memberPrincipal", "ipaAllowedTarget", "memberPrincipal",
        ],
    ).await?;

    let containers = fetch_entries(
        ldap,
        &base_dn,
        "(objectClass=container)",
        vec!["cn","entryUUID"],
    ).await?;

    let gpos = fetch_entries(
        ldap,
        &base_dn,
        "(|(objectClass=ipaHBACRule)(objectClass=ipaSudoRule)(objectClass=ipacertprofile))",
        vec!["cn",
            "ipaCertSubject",
            "ipaCertIssuerSerial",
            "ipaConfigString",
            "cACertificate;binary",
            "ipaKeyTrust",
            "ipaKeyUsage",
            "ipacertprofileID",        // ID профиля
            "ipacertprofileDescription", // описание
            "ipacertprofileSubjectDN", // subject DN шаблона
            "ipacertprofileExtensions;binary", // бинарные расширения (опционально)
        ],
    ).await?;
    //eprintln!("Debug gpos: {:#?}", gpos);

    // 3) Настраиваем SID-кэш и вычисляем SID домена
    let mut sid_cache = SidCache::new();
    let empty_attrs: HashMap<String, Vec<String>> = HashMap::new();
    let admin_attrs = groups.iter()
        .find(|g| get_attr(&g.attrs, "cn").eq_ignore_ascii_case("admins"))
        .map(|g| &g.attrs)
        .unwrap_or(&empty_attrs);
    let admin_sid = get_attr(admin_attrs, "ipaNTSecurityIdentifier");
    let domain_sid = admin_sid.rsplit_once('-')
        .map(|(base, _)| base.to_string())
        .unwrap_or_else(|| admin_sid.clone());

    // 4) Карты DN → SID для всех категорий
    let mut user_map      = HashMap::new();
    let mut group_map     = HashMap::new();
    let mut computer_map  = HashMap::new();
    let mut ou_map        = HashMap::new();
    let mut container_map = HashMap::new();

    // Заполняем карты UID для OU и контейнеров
    for ou in &ous {
        ou_map.insert(ou.dn.clone(), get_attr(&ou.attrs, "ipaUniqueID"));
    }
    for c in &containers {
        container_map.insert(c.dn.clone(), get_attr(&c.attrs, "ipaUniqueID"));
    }

    // 5) Обработка пользователей
    let mut users_data = Vec::new();
    for u in &users {
        let sid = sid_cache.get(&u.dn, &u.attrs);
        user_map.insert(u.dn.clone(), sid.clone());
        users_data.push(json!({
            "ObjectIdentifier": sid,
            "IsDeleted": false,
            "IsACLProtected": false,
            "Properties": build_user_properties(u, domain_name, &domain_sid),
            "PrimaryGroupSID": domain_sid,
            "Aces": build_aces_from_memberof_users(u, &groups),
            "AllowedToDelegate": u.attrs.get("ipaAllowedToDelegateTo").cloned().unwrap_or_default(),
            "HasSIDHistory": u.attrs.get("sIDHistory").cloned().unwrap_or_default(),
        }));
    }

    // 6) Обработка групп
    let mut groups_data = Vec::new();
    for g in &groups {
        let mut sid = sid_cache.get(&g.dn, &g.attrs);
        if sid.is_empty() {
            sid = get_attr(&g.attrs, "entryUUID");
        }
        group_map.insert(g.dn.clone(), sid.clone());
        let members = g.attrs.get("member").cloned().unwrap_or_default()
            .into_iter()
            .filter_map(|dn| {
                user_map.get(&dn).map(|s| json!({"ObjectIdentifier": s, "ObjectType": "User"}))
                    .or_else(|| group_map.get(&dn).map(|s| json!({"ObjectIdentifier": s, "ObjectType": "Group"})))
                    .or_else(|| computer_map.get(&dn).map(|s| json!({"ObjectIdentifier": s, "ObjectType": "Computer"})))
            })
            .collect::<Vec<_>>();
        groups_data.push(json!({
            "ObjectIdentifier": sid,
            "IsDeleted": false,
            "IsACLProtected": false,
            "Properties": build_group_properties(g, domain_name, &domain_sid),
            "Members": members,
            "Aces": build_aces_from_memberof_users(g, &groups),
            "AllowedToDelegate": [],
            "HasSIDHistory": [],
        }));
    }

    // 7) Обработка компьютеров
    let mut computers_data = Vec::new();
    for c in &computers {
        let mut sid = sid_cache.get(&c.dn, &c.attrs);
        if sid.is_empty() {
            sid = get_attr(&c.attrs, "entryUUID");
        }
        computer_map.insert(c.dn.clone(), sid.clone());

     
        let allowed_to_delegate = c.attrs.get("ipaAllowedTarget")
            .cloned().unwrap_or_default()
            .into_iter()
            .map(|spn| json!({"ObjectIdentifier": spn, "ObjectType": "Service"}))
            .collect::<Vec<_>>();

        computers_data.push(json!({
            "ObjectIdentifier": sid,
            "IsDeleted": false,
            "IsACLProtected": false,
            "Properties": build_computer_properties(c, domain_name, &domain_sid),
            "PrimaryGroupSID": domain_sid,
            "Aces": build_aces_from_memberof(c, &groups),
            "AllowedToDelegate": allowed_to_delegate,
            "AllowedToAct": [],
            "Status": null,
            "HasSIDHistory": c.attrs.get("sIDHistory").cloned().unwrap_or_default(),
            "Sessions":           {"Results":[],"Collected":false,"FailureReason":null},
            "PrivilegedSessions": {"Results":[],"Collected":false,"FailureReason":null},
            "RegistrySessions":   {"Results":[],"Collected":false,"FailureReason":null},
            "LocalAdmins":        {"Results":[],"Collected":false,"FailureReason":null},
            "RemoteDesktopUsers": {"Results":[],"Collected":false,"FailureReason":null},
            "DcomUsers":          {"Results":[],"Collected":false,"FailureReason":null},
            "PSRemoteUsers":      {"Results":[],"Collected":false,"FailureReason":null},
        }));
    }

    // 8) Обработка контейнеров
    let mut containers_data = Vec::new();
    for cnt in &containers {
        let mut sid = sid_cache.get(&cnt.dn, &cnt.attrs);
        if sid.is_empty() {
            sid = get_attr(&cnt.attrs, "entryUUID");
        }
        container_map.insert(cnt.dn.clone(), sid.clone());
        let name = {
            let ou = get_attr(&cnt.attrs, "ou");
            if !ou.is_empty() { ou } else { get_attr(&cnt.attrs, "cn") }
        };
        let mut children = Vec::new();
        for (dn, s) in &user_map{ 
            if is_child(dn, &cnt.dn){ 
                children.push(json!({"ObjectIdentifier": s, "ObjectType": "User"})); 
            } 
        }
        for (dn, s) in &group_map{ 
            if is_child(dn, &cnt.dn){ 
                children.push(json!({"ObjectIdentifier": s, "ObjectType": "Group"})); 
            } 
        }
        for (dn, s) in &computer_map{ 
            if is_child(dn, &cnt.dn){ 
                children.push(json!({"ObjectIdentifier": s, "ObjectType": "Computer"})); 
            } 
        }
        for (dn, s) in &ou_map{ 
            if is_child(dn, &cnt.dn){ 
                children.push(json!({"ObjectIdentifier": s, "ObjectType": "Container"})); 
            } 
        }

        containers_data.push(json!({
            "ObjectIdentifier": sid,
            "IsDeleted": false,
            "IsACLProtected": false,
            "Properties": {"distinguishedname": cnt.dn, "name": name},
            "ChildObjects": children,
            "Aces": build_aces_from_memberof(cnt, &groups),
        }));
    }

    // ) Обработка OU
    let mut ous_data = Vec::new();
    for ou in &ous {
        let sid = sid_cache.get(&ou.dn, &ou.attrs);
        let ou_name = get_attr(&ou.attrs, "ou");
        let name = if !ou_name.is_empty() { ou_name } else { get_attr(&ou.attrs, "cn") };
        let description = get_attr(&ou.attrs, "description");
        let whencreated = get_ipa_timestamp(&ou.attrs, "createTimestamp");
        let mut children = Vec::new();
        for (dn, s) in &user_map      { if is_child(dn, &ou.dn) { children.push(json!({"ObjectIdentifier": s, "ObjectType": "User"})); } }
        for (dn, s) in &group_map     { if is_child(dn, &ou.dn) { children.push(json!({"ObjectIdentifier": s, "ObjectType": "Group"})); } }
        for (dn, s) in &computer_map  { if is_child(dn, &ou.dn) { children.push(json!({"ObjectIdentifier": s, "ObjectType": "Computer"})); } }
        for (dn, s) in &container_map { if is_child(dn, &ou.dn) { children.push(json!({"ObjectIdentifier": s, "ObjectType": "Container"})); } }
        let gpo_computers = children.iter()
            .filter(|c| c["ObjectType"] == "Computer")
            .cloned()
            .collect::<Vec<_>>();
        ous_data.push(json!({
            "ObjectIdentifier": sid,
            "IsDeleted": false,
            "IsACLProtected": false,
            "Properties": {
                "name": name,
                "domain": domain_name,
                "domainsid": domain_sid,
                "distinguishedname": ou.dn,
                "description": description,
                "whencreated": whencreated,
                "highvalue": false,
                "blocksinheritance": false
            },
            "Links": [],
            "ChildObjects": children,
            "Aces": build_aces_from_memberof(ou, &groups),
            "GPOChanges": {
                "LocalAdmins": [],
                "RemoteDesktopUsers": [],
                "DcomUsers": [],
                "PSRemoteUsers": [],
                "AffectedComputers": gpo_computers
            }
        }));
    }

    // 10) Обработка GPO (HBAC и sudo)
    let mut gpo_data = Vec::new();
    for rule in &gpos {

        let sid = sid_cache.get(&rule.dn, &rule.attrs);
        let dn          = rule.dn.clone();
        let name        = get_attr(&rule.attrs, "cn");
        let profile_id  = get_attr(&rule.attrs, "ipacertprofileID");
        let description = get_attr(&rule.attrs, "ipacertprofileDescription");
        let subject_dn  = get_attr(&rule.attrs, "ipacertprofileSubjectDN");

        gpo_data.push(json!({
            /*
            "ObjectIdentifier": sid,
            "Properties": {
                "name": get_attr(&rule.attrs, "cn"),
                "distinguishedname": rule.dn,
                "domain": domain_name,
                "description": get_attr(&rule.attrs, "description"),
            },
            "IsACLProtected": true,
            "Aces": build_aces_from_memberof(rule, &groups),
            "IsDeleted": false,
            */
            "ObjectIdentifier": sid,
            "IsDeleted": false,
            "IsACLProtected": false,
            "Properties": {
                "name": name,
                "distinguishedname": dn,
                "domain": domain_name,
                "type": "Certificate Template",
                "profileID": profile_id,
                "description": description,
                "subjectDN": subject_dn
            },
            "Aces": [],
            "Links": [],
            "IsDeleted": false
        }));
    }

    let mut domain_data = Vec::new();
    for entry in &domain_entries {
        let dc          = get_attr(&entry.attrs, "dc");
        let guid        = get_attr(&entry.attrs, "entryUUID");
        // возьмите objectSid, а не SID группы admins
        let sid         = domain_sid.clone();
        let dn          = entry.dn.clone();
        let whencreated = get_ipa_timestamp(&entry.attrs, "createTimestamp");
        let func_lvl    = get_attr(&entry.attrs, "msDS-Behavior-Version");
        //let descr       = entry.attrs.get("description").map(|v| v.join("; ")).unwrap_or_default();
        let aci_raw     = entry.attrs.get("aci").cloned().unwrap_or_default();
        let description = entry
            .attrs
            .get("description")
            .and_then(|v| v.first().cloned())
            .unwrap_or_default();
            //eprintln!("Debug aci_raw: {:#?}", aci_raw);

        // парсим ACI-строки в ACEs
        let parsed = parse_domain_acis(&aci_raw);
        let aces   = parsed_aci_to_aces_json(parsed, &group_map);

        // дети OU и контейнеры
        let mut children = Vec::new();
        for (dn_child, guid) in &ou_map {
            if is_child(dn_child, &dn) {
                children.push(json!({ "ObjectIdentifier": guid, "ObjectType": "OU" }));
            }
        }
        for (dn_child, guid) in &container_map {
            if is_child(dn_child, &dn) {
                children.push(json!({ "ObjectIdentifier": guid, "ObjectType": "Container" }));
            }
        }

        domain_data.push(json!({
            "ObjectIdentifier": guid,            
            "IsDeleted": false,
            "IsACLProtected": false,
            "Properties": {
                "name":              dc,
                "objectsid":         sid,
                "distinguishedname": dn,
                "functionallevel":   func_lvl,
                "trusts":            [],        // нет 
                "description":       if description.is_empty() { Value::Null } else { json!(description) },
                "highvalue":         true,
                "whencreated":       whencreated,
                "domain":            dc,
                "domainsid":         sid
            },
            "Links":       [],
            "Trusts":       [],                 
            "ChildObjects": children,            
            "Aces":         aces,
            "GPOChanges": {              // нужно обязательно для предоставление в BloodHound в FreeIPA
                                     // нет 
                "LocalAdmins":         [],
                "RemoteDesktopUsers":  [],
                "DcomUsers":           [],
                "PSRemoteUsers":       [],
                "AffectedComputers":   [] 
            }
    }));
}


    // 11) Сохранение в ZIP
    let wrap = |data: Vec<Value>, kind: &str| {
        json!({"data": data, "meta": {"methods": 0, "type": kind, "count": data.len(), "version": 5}})
    };
    let mut zip = ZipWriter::new(File::create("shraphound_data.zip")?);
    let opts = FileOptions::default().compression_method(CompressionMethod::Stored).unix_permissions(0o755);
    save_json_to_zip(&mut zip, "users.json", wrap(users_data, "users"), opts)?;
    save_json_to_zip(&mut zip, "groups.json", wrap(groups_data, "groups"), opts)?;
    save_json_to_zip(&mut zip, "computers.json", wrap(computers_data, "computers"), opts)?;
    save_json_to_zip(&mut zip, "containers.json", wrap(containers_data, "containers"), opts)?;
    save_json_to_zip(&mut zip, "ous.json", wrap(ous_data, "ous"), opts)?;
    save_json_to_zip(&mut zip, "gpos.json", wrap(gpo_data, "gpos"), opts)?;
    save_json_to_zip(&mut zip, "domains.json", wrap(domain_data, "domains"), opts)?;
    zip.finish()?;

    println!("Данные экспортированы в shraphound_data.zip для BloodHound.");
    Ok(())
}

