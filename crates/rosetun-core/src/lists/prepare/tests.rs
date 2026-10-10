use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use rosetun_config::{
    Node, NodeId, Outbound, Rule, RuleMatcher, RuleSet, RuleSetId, RuleTarget, Selection, Settings,
    StreamSettings, SubscriptionId, TrojanParams,
};
use rosetun_ipc::HelperError;

use super::*;
use crate::add_list_from_bytes;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "rosetun-list-preparation-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn store(&self) -> Store {
        Store::at(self.0.join("config.json"))
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn request() -> ConnectRequest {
    ConnectRequest {
        selection: Selection {
            subscription: SubscriptionId::new("example"),
            node: NodeId::new("node"),
        },
        node: Node {
            id: NodeId::new("node"),
            name: "Example node".into(),
            server: "203.0.113.10".into(),
            port: 443,
            outbound: Outbound::Trojan(TrojanParams {
                password: "test-secret".into(),
            }),
            stream: StreamSettings::default(),
            raw: None,
        },
        rule_set: RuleSet::new(RuleSetId::new("example"), "Example", RuleTarget::Proxy),
        temporary_rules: Vec::new(),
        lists: Vec::new(),
        settings: Settings::default(),
    }
}

fn list_rule(id: &str, list: ListId, category: Option<&str>) -> Rule {
    Rule {
        id: RuleId::new(id),
        enabled: true,
        matcher: RuleMatcher::List {
            list,
            category: category.map(str::to_owned),
        },
        target: RuleTarget::Direct,
    }
}

fn field(number: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![(number << 3) | 2, value.len() as u8];
    bytes.extend_from_slice(value);
    bytes
}

fn site_dat(category: &[u8], hostname: &[u8], with_cn: bool) -> Vec<u8> {
    let mut domain = [0x08, 2].to_vec();
    domain.extend(field(2, hostname));
    if with_cn {
        let mut attribute = field(1, b"cn");
        attribute.extend([0x10, 1]);
        domain.extend(field(3, &attribute));
    }
    let mut entry = field(1, category);
    entry.extend(field(2, &domain));
    field(1, &entry)
}

fn site_dat_with_category(category: &[u8]) -> Vec<u8> {
    site_dat(category, b"example.com", true)
}

fn example_site_dat() -> Vec<u8> {
    site_dat_with_category(b"EXAMPLE")
}

#[test]
fn enabled_rules_deduplicate_refs_and_payloads_including_temporary_rules() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let list = add_list_from_bytes(&store, "Example", "example.txt", b"example.com\n").unwrap();
    let mut request = request();
    request
        .rule_set
        .rules
        .push(list_rule("one", list.id.clone(), None));
    request
        .rule_set
        .rules
        .push(list_rule("two", list.id.clone(), None));
    request
        .temporary_rules
        .push(list_rule("temporary", list.id.clone(), None));
    request.rule_set.rules.push(Rule {
        enabled: false,
        matcher: RuleMatcher::List {
            list: ListId::new("missing"),
            category: None,
        },
        ..list_rule("disabled", list.id.clone(), None)
    });

    let prepared = prepare_lists(&store, request).unwrap();
    assert_eq!(prepared.request.lists.len(), 1);
    assert_eq!(prepared.payloads.len(), 1);
    assert!(prepared.missing_categories.is_empty());
    let reference = &prepared.request.lists[0];
    assert_eq!(reference.tag, list_tag(&list.id, None));
    assert_eq!(
        reference.sha256,
        format!("{:x}", Sha256::digest(&prepared.payloads[0].bytes))
    );
    assert_eq!(reference.format, UploadedListFormat::Source);
    assert!(!format!("{prepared:?}").contains("example.com"));
}

#[test]
fn vanished_and_empty_dat_categories_skip_only_their_rules() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let dat = add_list_from_bytes(&store, "Geosite", "geosite.dat", &example_site_dat()).unwrap();
    let text = add_list_from_bytes(&store, "Text", "example.txt", b"example.org\n").unwrap();
    let mut request = request();
    request
        .rule_set
        .rules
        .push(list_rule("vanished", dat.id.clone(), Some("removed")));
    request.rule_set.rules.push(list_rule(
        "empty-filter",
        dat.id.clone(),
        Some("example@!cn"),
    ));
    request
        .rule_set
        .rules
        .push(list_rule("working", text.id.clone(), None));
    request
        .rule_set
        .rules
        .push(list_rule("working-dat", dat.id.clone(), Some("example@cn")));

    let prepared = prepare_lists(&store, request).unwrap();
    assert_eq!(
        prepared.missing_categories,
        [RuleId::new("vanished"), RuleId::new("empty-filter")]
    );
    assert_eq!(prepared.skipped_categories, prepared.missing_categories);
    assert!(!prepared.request.rule_set.rules[0].enabled);
    assert!(!prepared.request.rule_set.rules[1].enabled);
    assert!(prepared.request.rule_set.rules[2].enabled);
    assert!(prepared.request.rule_set.rules[3].enabled);
    assert!(
        prepared
            .request
            .rule_set
            .rules
            .iter()
            .all(|rule| rule.target == RuleTarget::Direct)
    );
    assert_eq!(prepared.request.lists.len(), 2);
    assert_eq!(prepared.request.lists[0].tag, list_tag(&text.id, None));
    assert_eq!(
        prepared.request.lists[1].tag,
        list_tag(&dat.id, Some("example@cn"))
    );
    assert_eq!(prepared.payloads.len(), 2);
}

#[test]
fn updating_a_dat_can_remove_a_used_category_without_breaking_connect() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let dat = add_list_from_bytes(&store, "Geosite", "geosite.dat", &example_site_dat()).unwrap();
    let rules = crate::create_rule_set(&store, "Example", RuleTarget::Proxy).unwrap();
    crate::add_rule(
        &store,
        &rules.id,
        RuleMatcher::List {
            list: dat.id.clone(),
            category: Some("example@cn".into()),
        },
        RuleTarget::Direct,
    )
    .unwrap();
    let replacement = site_dat_with_category(b"OTHER");
    super::super::update_list(
        &store,
        &dat.id,
        Some(("geosite.dat", &replacement)),
        crate::Timeouts::default(),
    )
    .unwrap();
    let config = store
        .load()
        .expect("list updates keep saved rules loadable");
    let mut request = request();
    request.rule_set = config.rule_sets[0].clone();

    let prepared = prepare_lists(&store, request).unwrap();
    assert_eq!(prepared.missing_categories.len(), 1);
    assert_eq!(prepared.skipped_categories, prepared.missing_categories);
    assert!(!prepared.request.rule_set.rules[0].enabled);
    assert_eq!(
        prepared.request.rule_set.rules[0].target,
        RuleTarget::Direct
    );
    assert!(prepared.request.lists.is_empty());
    assert!(prepared.payloads.is_empty());

    fs::write(
        directory.0.join("lists").join(format!("{}.dat", dat.id)),
        b"damaged",
    )
    .unwrap();
    let mut after_damage = self::request();
    after_damage.rule_set = config.rule_sets[0].clone();
    assert!(matches!(
        prepare_lists(&store, after_damage),
        Err(ListPreparationError::List(ListError::Integrity))
    ));

    let corrupted = b"not-a-dat";
    fs::write(
        directory.0.join("lists").join(format!("{}.dat", dat.id)),
        corrupted,
    )
    .unwrap();
    store
        .modify(|config| {
            config.lists[0].size = Some(corrupted.len() as u64);
            config.lists[0].sha256 = Some(format!("{:x}", Sha256::digest(corrupted)));
            Ok::<_, crate::StoreError>(())
        })
        .unwrap();
    let mut matching_checksum = self::request();
    matching_checksum.rule_set = config.rule_sets[0].clone();
    assert!(matches!(
        prepare_lists(&store, matching_checksum),
        Err(ListPreparationError::List(ListError::Parse(_)))
    ));
}

#[test]
fn vanished_category_uses_last_good_payload_and_keeps_other_lists() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let dat = add_list_from_bytes(&store, "Geosite", "geosite.dat", &example_site_dat()).unwrap();
    let text = add_list_from_bytes(&store, "Text", "example.txt", b"example.org\n").unwrap();
    let mut request = request();
    request
        .rule_set
        .rules
        .push(list_rule("cached", dat.id.clone(), Some("example@cn")));
    request
        .rule_set
        .rules
        .push(list_rule("working", text.id.clone(), None));

    let original = prepare_lists(&store, request.clone()).unwrap();
    let tag = list_tag(&dat.id, Some("example@cn"));
    let cache_path = directory
        .0
        .join("lists")
        .join("last-good")
        .join(format!("{tag}.json"));
    assert_eq!(fs::read(&cache_path).unwrap(), original.payloads[0].bytes);
    super::super::update_list(
        &store,
        &dat.id,
        Some(("geosite.dat", &site_dat_with_category(b"OTHER"))),
        crate::Timeouts::default(),
    )
    .unwrap();

    let prepared = prepare_lists(&store, request).unwrap();
    assert_eq!(prepared.missing_categories, [RuleId::new("cached")]);
    assert!(prepared.skipped_categories.is_empty());
    assert!(
        prepared
            .request
            .rule_set
            .rules
            .iter()
            .all(|rule| rule.enabled)
    );
    assert!(
        prepared
            .request
            .rule_set
            .rules
            .iter()
            .all(|rule| rule.target == RuleTarget::Direct)
    );
    assert_eq!(prepared.request.lists.len(), 2);
    assert_eq!(prepared.request.lists[0], original.request.lists[0]);
    assert_eq!(prepared.payloads[0].bytes, original.payloads[0].bytes);
    assert_eq!(prepared.request.lists[1].tag, list_tag(&text.id, None));
}

#[test]
fn empty_filtered_category_uses_last_good_and_current_category_overwrites_it() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let dat = add_list_from_bytes(&store, "Geosite", "geosite.dat", &example_site_dat()).unwrap();
    let mut request = request();
    request
        .rule_set
        .rules
        .push(list_rule("filtered", dat.id.clone(), Some("example@cn")));
    let original = prepare_lists(&store, request.clone()).unwrap();
    let tag = list_tag(&dat.id, Some("example@cn"));
    let cache_path = directory
        .0
        .join("lists")
        .join("last-good")
        .join(format!("{tag}.json"));

    super::super::update_list(
        &store,
        &dat.id,
        Some(("geosite.dat", &site_dat(b"EXAMPLE", b"example.org", false))),
        crate::Timeouts::default(),
    )
    .unwrap();
    let fallback = prepare_lists(&store, request.clone()).unwrap();
    assert_eq!(fallback.missing_categories, [RuleId::new("filtered")]);
    assert!(fallback.skipped_categories.is_empty());
    assert!(fallback.request.rule_set.rules[0].enabled);
    assert_eq!(fallback.request.lists, original.request.lists);
    assert_eq!(fs::read(&cache_path).unwrap(), original.payloads[0].bytes);

    super::super::update_list(
        &store,
        &dat.id,
        Some(("geosite.dat", &site_dat(b"EXAMPLE", b"example.org", true))),
        crate::Timeouts::default(),
    )
    .unwrap();
    let refreshed = prepare_lists(&store, request).unwrap();
    assert!(refreshed.missing_categories.is_empty());
    assert_ne!(refreshed.request.lists, original.request.lists);
    assert_eq!(fs::read(cache_path).unwrap(), refreshed.payloads[0].bytes);
}

#[test]
fn last_good_copy_is_pruned_when_no_rule_references_its_tag() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let dat = add_list_from_bytes(&store, "Geosite", "geosite.dat", &example_site_dat()).unwrap();
    let set = crate::create_rule_set(&store, "Stored", RuleTarget::Proxy).unwrap();
    crate::add_rule(
        &store,
        &set.id,
        RuleMatcher::List {
            list: dat.id.clone(),
            category: Some("example".into()),
        },
        RuleTarget::Direct,
    )
    .unwrap();
    let mut with_rule = request();
    with_rule.rule_set = store.load().unwrap().rule_sets[0].clone();
    prepare_lists(&store, with_rule).unwrap();
    let tag = list_tag(&dat.id, Some("example"));
    let cache_path = directory
        .0
        .join("lists")
        .join("last-good")
        .join(format!("{tag}.json"));
    assert!(cache_path.exists());

    prepare_lists(&store, request()).unwrap();
    assert!(
        cache_path.exists(),
        "another stored rule set still references the tag"
    );
    store
        .modify(|config| {
            config.rule_sets[0].rules.clear();
            Ok::<_, crate::StoreError>(())
        })
        .unwrap();
    prepare_lists(&store, request()).unwrap();
    assert!(!cache_path.exists());
}

#[test]
fn damaged_last_good_copy_is_an_error_before_transport() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let dat = add_list_from_bytes(&store, "Geosite", "geosite.dat", &example_site_dat()).unwrap();
    let mut request = request();
    request
        .rule_set
        .rules
        .push(list_rule("cached", dat.id.clone(), Some("example")));
    prepare_lists(&store, request.clone()).unwrap();
    super::super::update_list(
        &store,
        &dat.id,
        Some(("geosite.dat", &site_dat_with_category(b"OTHER"))),
        crate::Timeouts::default(),
    )
    .unwrap();
    let tag = list_tag(&dat.id, Some("example"));
    fs::write(
        directory
            .0
            .join("lists")
            .join("last-good")
            .join(format!("{tag}.json")),
        b"invalid json",
    )
    .unwrap();
    assert!(matches!(
        prepare_lists(&store, request),
        Err(ListPreparationError::List(ListError::Parse(
            ListParseError::InvalidJson
        )))
    ));
}

#[test]
fn damaged_list_and_dat_without_category_are_errors_before_transport() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let dat = add_list_from_bytes(&store, "Geosite", "geosite.dat", &example_site_dat()).unwrap();
    let mut without_category = request();
    without_category
        .rule_set
        .rules
        .push(list_rule("invalid", dat.id.clone(), None));
    assert!(matches!(
        prepare_lists(&store, without_category),
        Err(ListPreparationError::List(ListError::Category(
            ListCategoryError::Required
        )))
    ));

    let text = add_list_from_bytes(&store, "Text", "example.txt", b"example.org\n").unwrap();
    let path = directory.0.join("lists").join(format!("{}.txt", text.id));
    fs::write(path, b"changed.example.invalid\n").unwrap();
    let mut damaged = request();
    damaged
        .rule_set
        .rules
        .push(list_rule("damaged", text.id, None));
    assert!(matches!(
        prepare_lists(&store, damaged),
        Err(ListPreparationError::List(ListError::Integrity))
    ));
}

#[derive(Default)]
struct MockClient {
    calls: Vec<&'static str>,
    status_count: usize,
    attempts: usize,
    chunks: Vec<(u64, usize)>,
    missing: String,
    always_missing: bool,
}

impl ListClient for MockClient {
    fn list_status(&mut self, hashes: Vec<String>) -> Result<Vec<String>, ClientError> {
        self.calls.push("status");
        self.status_count += 1;
        assert_eq!(hashes.as_slice(), std::slice::from_ref(&self.missing));
        Ok(vec![self.missing.clone()])
    }

    fn put_chunk(
        &mut self,
        hash: &str,
        format: ListFormat,
        total_size: u64,
        offset: u64,
        data: String,
    ) -> Result<(), ClientError> {
        self.calls.push("chunk");
        assert_eq!(hash, self.missing);
        assert_eq!(format, UploadedListFormat::Source);
        assert_eq!(total_size, 10 * 1024 * 1024 + 1);
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(data)
            .unwrap();
        assert!(!bytes.is_empty() && bytes.len() <= MAX_LIST_CHUNK_BYTES);
        self.chunks.push((offset, bytes.len()));
        Ok(())
    }

    fn connect(&mut self, _: ConnectRequest) -> Result<(), ClientError> {
        self.calls.push("connect");
        self.attempts += 1;
        if self.attempts == 1 || self.always_missing {
            Err(ClientError::Helper(HelperError::new(
                ErrorCode::ListMissing,
                "evicted",
            )))
        } else {
            Ok(())
        }
    }

    fn apply(&mut self, request: ConnectRequest) -> Result<(), ClientError> {
        self.calls.push("apply");
        self.connect(request)
    }
}

#[test]
fn upload_uses_one_client_and_retries_only_one_list_missing() {
    let bytes = vec![b'x'; 10 * 1024 * 1024 + 1];
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let payload = PreparedListPayload {
        sha256: digest.clone(),
        format: UploadedListFormat::Source,
        bytes,
    };
    let prepared = PreparedConnection {
        request: request(),
        payloads: vec![payload],
        missing_categories: Vec::new(),
        skipped_categories: Vec::new(),
    };
    let mut client = MockClient {
        missing: digest,
        ..MockClient::default()
    };
    send_with(&mut client, &prepared, ListOperation::Connect).unwrap();
    assert_eq!(client.status_count, 2);
    assert_eq!(client.attempts, 2);
    assert_eq!(client.chunks.len(), 22);
    assert_eq!(client.calls[0], "status");
    assert_eq!(client.calls[12], "connect");
    assert_eq!(client.chunks[10], (10 * 1024 * 1024, 1));
    assert_eq!(client.chunks[21], (10 * 1024 * 1024, 1));

    let mut apply_client = MockClient {
        missing: client.missing,
        ..MockClient::default()
    };
    send_with(&mut apply_client, &prepared, ListOperation::Apply).unwrap();
    assert_eq!(apply_client.attempts, 2);
    assert_eq!(apply_client.calls[12], "apply");

    let mut twice_missing = MockClient {
        missing: prepared.payloads[0].sha256.clone(),
        always_missing: true,
        ..MockClient::default()
    };
    assert!(matches!(
        send_with(&mut twice_missing, &prepared, ListOperation::Connect),
        Err(ClientError::Helper(HelperError {
            code: ErrorCode::ListMissing,
            ..
        }))
    ));
    assert_eq!(twice_missing.status_count, 2);
    assert_eq!(twice_missing.attempts, 2);
}
