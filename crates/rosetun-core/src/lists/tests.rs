use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rosetun_config::{
    ListSource, Rule, RuleId, RuleMatcher, RuleSet, RuleSetId, RuleTarget, list_tag,
};

use super::*;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

fn field(number: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![(number << 3) | 2, value.len() as u8];
    bytes.extend_from_slice(value);
    bytes
}

fn number(field: u8, value: u8) -> [u8; 2] {
    [field << 3, value]
}

fn example_site_dat() -> Vec<u8> {
    let mut attribute = field(1, b"cn");
    attribute.extend(number(2, 1));
    let mut domain = number(1, 2).to_vec();
    domain.extend(field(2, b"example.com"));
    domain.extend(field(3, &attribute));
    let mut entry = field(1, b"EXAMPLE");
    entry.extend(field(2, &domain));
    field(1, &entry)
}

fn example_ip_dat(reverse: bool) -> Vec<u8> {
    let mut cidr = field(1, &[192, 0, 2, 0]);
    cidr.extend(number(2, 24));
    let mut entry = field(1, b"EXAMPLE");
    entry.extend(field(2, &cidr));
    if reverse {
        entry.extend(number(3, 1));
    }
    field(1, &entry)
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "rosetun-lists-test-{}-{}",
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

#[test]
fn local_import_is_copied_without_storing_its_original_path() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let bytes = b"example.com\n";
    let list = add_list_from_bytes(&store, " Example ", "folder/example.txt", bytes).unwrap();
    assert_eq!(list.id, ListId::new("1"));
    assert_eq!(list.name, "Example");
    assert_eq!(
        list.source,
        ListSource::File {
            original_name: "example.txt".to_owned()
        }
    );
    assert_eq!(list.size, Some(bytes.len() as u64));
    assert_eq!(list.sha256.as_deref(), Some(checksum(bytes).as_str()));
    assert_eq!(
        fs::read(list_path(&directory.0.join("lists"), &list)).unwrap(),
        bytes
    );
    assert!(
        !String::from_utf8(fs::read(store.path()).unwrap())
            .unwrap()
            .contains("folder/")
    );
}

#[test]
fn text_entry_count_is_transient_and_uses_verified_contents() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let list = add_list_from_bytes(
        &store,
        "Example",
        "example.txt",
        b"example.com\n# comment\n192.0.2.0/24\n",
    )
    .unwrap();
    assert_eq!(text_entry_count(&store, &list.id).unwrap(), Some(2));
    assert!(
        !fs::read_to_string(store.path())
            .unwrap()
            .contains("entry_count")
    );
}

#[test]
fn missing_category_inspection_covers_every_set_and_temporary_rule_without_writing() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let list = add_list_from_bytes(&store, "Example", "geosite.dat", &example_site_dat()).unwrap();
    let rule = Rule {
        id: RuleId::new("same-id"),
        enabled: true,
        matcher: RuleMatcher::List {
            list: list.id.clone(),
            category: Some("example@cn".into()),
        },
        target: RuleTarget::Direct,
        exit: None,
    };
    let mut config = store.load().unwrap();
    config.rule_sets = ["first", "second"]
        .map(|id| {
            let mut set = RuleSet::new(RuleSetId::new(id), id, RuleTarget::Proxy);
            set.rules.push(rule.clone());
            set
        })
        .to_vec();
    assert!(
        inspect_missing_categories(&store, &config, std::slice::from_ref(&rule))
            .unwrap()
            .is_empty()
    );

    config.lists[0].categories.clear();
    let missing = inspect_missing_categories(&store, &config, std::slice::from_ref(&rule)).unwrap();
    assert_eq!(missing.len(), 3);
    assert!(!missing.iter().any(|item| item.last_good));
    assert_eq!(missing[0].set, Some(RuleSetId::new("first")));
    assert_eq!(missing[1].set, Some(RuleSetId::new("second")));
    assert_eq!(missing[2].set, None);

    let payload = list_payload(&store, &list.id, Some("example@cn")).unwrap();
    last_good::save(
        &store,
        &list_tag(&list.id, Some("example@cn")),
        payload.format,
        &payload.bytes,
    )
    .unwrap();
    let fallback = inspect_missing_categories(&store, &config, &[rule]).unwrap();
    assert!(fallback.iter().all(|item| item.last_good));
}

#[test]
fn dat_categories_are_stored_once_and_rendered_only_when_selected() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let bytes = example_site_dat();
    let list = add_list_from_bytes(&store, "Example", "download.txt", &bytes).unwrap();
    assert_eq!(list.format, rosetun_config::ListFormat::GeoSite);
    assert_eq!(list.categories, ["example"]);
    assert_eq!(
        list.source,
        ListSource::File {
            original_name: "download.txt".to_owned()
        }
    );
    assert_eq!(
        fs::read(list_path(&directory.0.join("lists"), &list)).unwrap(),
        bytes
    );
    let payload = list_payload(&store, &list.id, Some("example@cn")).unwrap();
    assert_eq!(payload.format, PayloadFormat::Source);
    let json: serde_json::Value = serde_json::from_slice(&payload.bytes).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "version": 3,
            "rules": [{"domain_suffix": ["example.com"]}]
        })
    );
    assert!(matches!(
        list_payload(&store, &list.id, Some("example@!cn")),
        Err(ListError::Parse(ListParseError::EmptyResult))
    ));
    let set = crate::create_rule_set(&store, "Example", RuleTarget::Proxy).unwrap();
    assert!(matches!(
        crate::add_rule(
            &store,
            &set.id,
            RuleMatcher::List {
                list: list.id.clone(),
                category: None
            },
            RuleTarget::Direct
        ),
        Err(crate::RuleSetError::ListCategory(
            ListCategoryError::Required
        ))
    ));
    crate::add_rule(
        &store,
        &set.id,
        RuleMatcher::List {
            list: list.id.clone(),
            category: Some("example@cn".to_owned()),
        },
        RuleTarget::Direct,
    )
    .unwrap();
}

#[test]
fn reverse_match_geoip_is_loaded_but_refused_when_selected() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let list = add_list_from_bytes(&store, "Example", "geoip.dat", &example_ip_dat(true)).unwrap();
    assert_eq!(list.format, rosetun_config::ListFormat::GeoIp);
    assert_eq!(list.categories, ["example"]);
    assert!(matches!(
        list_payload(&store, &list.id, Some("example")),
        Err(ListError::Parse(ListParseError::ReverseMatch))
    ));
}

#[test]
fn source_json_is_normalized_before_it_is_saved() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let source = br#" { "rules": [{"domain_suffix":["example.com"]}], "version":3 } "#;
    let list = add_list_from_bytes(&store, "Example", "rules.json", source).unwrap();
    let saved = fs::read(list_path(&directory.0.join("lists"), &list)).unwrap();
    assert_ne!(saved, source);
    assert_eq!(list.size, Some(saved.len() as u64));
    assert_eq!(list.sha256.as_deref(), Some(checksum(&saved).as_str()));
    let payload = list_payload(&store, &list.id, None).unwrap();
    assert_eq!(payload.bytes, saved);
}

fn url_list(store: &Store) -> List {
    let list = add_list_from_bytes(store, "Example", "example.txt", b"example.com\n").unwrap();
    store
        .modify(|config| {
            config.lists[0].source =
                ListSource::Url("https://lists.example.com/example.txt".to_owned());
            Ok::<_, StoreError>(())
        })
        .unwrap();
    store
        .load()
        .unwrap()
        .lists
        .into_iter()
        .find(|item| item.id == list.id)
        .unwrap()
}

fn url_list_with_http(store: &Store, validators: &ListValidators) -> (List, PathBuf) {
    let list = url_list(store);
    let path = list_path(&list_dir(store).unwrap(), &list);
    write_http_metadata(
        &http_path(&path),
        validators,
        list.sha256.as_deref().unwrap(),
    )
    .unwrap();
    (list, path)
}

#[test]
fn updating_a_url_list_repairs_a_missing_file() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let list = url_list(&store);
    let path = list_path(&directory.0.join("lists"), &list);
    fs::remove_file(&path).unwrap();

    let updated = update_list_with(
        &store,
        &list.id,
        None,
        Timeouts::default(),
        &mut |_, _, _| {
            Ok(ListFetch::Modified {
                bytes: b"example.invalid\n".to_vec(),
                validators: ListValidators::default(),
            })
        },
    )
    .unwrap();

    assert_eq!(fs::read(&path).unwrap(), b"example.invalid\n");
    assert_eq!(
        updated.sha256.as_deref(),
        Some(checksum(b"example.invalid\n").as_str())
    );
    assert_eq!(store.load().unwrap().lists, vec![updated]);
    assert!(!previous_path(&path).exists());
}

#[test]
fn updating_a_url_list_repairs_a_damaged_file() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let list = url_list(&store);
    let path = list_path(&directory.0.join("lists"), &list);
    fs::write(&path, b"damaged\n").unwrap();

    let updated = update_list_with(
        &store,
        &list.id,
        None,
        Timeouts::default(),
        &mut |_, _, _| {
            Ok(ListFetch::Modified {
                bytes: b"example.invalid\n".to_vec(),
                validators: ListValidators::default(),
            })
        },
    )
    .unwrap();

    assert_eq!(fs::read(&path).unwrap(), b"example.invalid\n");
    assert_eq!(store.load().unwrap().lists, vec![updated]);
    assert!(!previous_path(&path).exists());
}

#[test]
fn unchanged_url_list_updates_only_its_check_time() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let validators = ListValidators {
        etag: Some("W/\"first\"".into()),
        last_modified: None,
    };
    let (list, path) = url_list_with_http(&store, &validators);
    let before = fs::metadata(&path).unwrap().modified().unwrap();
    store
        .modify(|config| {
            config.lists[0].updated_at = None;
            Ok::<_, StoreError>(())
        })
        .unwrap();
    let original = store.load().unwrap().lists[0].clone();

    let updated = update_list_with(
        &store,
        &list.id,
        None,
        Timeouts::default(),
        &mut |_, _, sent| {
            assert_eq!(sent, Some(&validators));
            Ok(ListFetch::NotModified)
        },
    )
    .unwrap();

    assert!(updated.updated_at.is_some());
    let mut expected = original;
    expected.updated_at = updated.updated_at;
    assert_eq!(updated, expected);
    assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), before);
    assert_eq!(fs::read(&path).unwrap(), b"example.com\n");
    assert_eq!(
        read_http_metadata(&http_path(&path), updated.sha256.as_deref().unwrap()),
        Some(validators)
    );
}

#[test]
fn a_new_etag_replaces_the_list_and_its_http_metadata() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let old = ListValidators {
        etag: Some("\"first\"".into()),
        last_modified: None,
    };
    let (list, path) = url_list_with_http(&store, &old);
    let new = ListValidators {
        etag: Some("\"second\"".into()),
        last_modified: None,
    };
    let updated = update_list_with(
        &store,
        &list.id,
        None,
        Timeouts::default(),
        &mut |_, _, sent| {
            assert_eq!(sent, Some(&old));
            Ok(ListFetch::Modified {
                bytes: b"example.invalid\n".to_vec(),
                validators: new.clone(),
            })
        },
    )
    .unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"example.invalid\n");
    assert_eq!(
        read_http_metadata(&http_path(&path), updated.sha256.as_deref().unwrap()),
        Some(new)
    );
    assert!(!previous_path(&http_path(&path)).exists());
}

#[test]
fn a_damaged_list_forces_an_unconditional_fetch() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let old = ListValidators {
        etag: Some("\"old\"".into()),
        last_modified: None,
    };
    let (list, path) = url_list_with_http(&store, &old);
    fs::write(&path, b"damaged\n").unwrap();
    let updated = update_list_with(
        &store,
        &list.id,
        None,
        Timeouts::default(),
        &mut |_, _, sent| {
            assert!(sent.is_none());
            Ok(ListFetch::Modified {
                bytes: b"example.invalid\n".to_vec(),
                validators: ListValidators {
                    etag: Some("\"new\"".into()),
                    last_modified: None,
                },
            })
        },
    )
    .unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"example.invalid\n");
    assert_eq!(
        read_http_metadata(&http_path(&path), updated.sha256.as_deref().unwrap())
            .unwrap()
            .etag
            .as_deref(),
        Some("\"new\"")
    );
}

#[test]
fn last_modified_alone_can_validate_a_list() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let validators = ListValidators {
        etag: None,
        last_modified: Some("Wed, 21 Oct 2015 07:28:00 GMT".into()),
    };
    let (list, path) = url_list_with_http(&store, &validators);
    update_list_with(
        &store,
        &list.id,
        None,
        Timeouts::default(),
        &mut |_, _, sent| {
            assert_eq!(sent, Some(&validators));
            Ok(ListFetch::NotModified)
        },
    )
    .unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"example.com\n");
}

#[test]
fn invalid_http_metadata_or_no_response_headers_forces_full_fetch() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let validators = ListValidators {
        etag: Some("\"stale\"".into()),
        last_modified: None,
    };
    let (list, path) = url_list_with_http(&store, &validators);
    fs::write(http_path(&path), b"invalid json").unwrap();
    update_list_with(
        &store,
        &list.id,
        None,
        Timeouts::default(),
        &mut |_, _, sent| {
            assert!(sent.is_none());
            Ok(ListFetch::Modified {
                bytes: b"example.com\n".to_vec(),
                validators: ListValidators::default(),
            })
        },
    )
    .unwrap();
    assert!(!http_path(&path).exists());
    write_http_metadata(
        &http_path(&path),
        &validators,
        &checksum(b"example.invalid\n"),
    )
    .unwrap();
    update_list_with(
        &store,
        &list.id,
        None,
        Timeouts::default(),
        &mut |_, _, sent| {
            assert!(sent.is_none());
            Ok(ListFetch::Modified {
                bytes: b"example.com\n".to_vec(),
                validators: ListValidators::default(),
            })
        },
    )
    .unwrap();
    assert!(!http_path(&path).exists());
}

#[test]
fn removing_a_list_also_removes_http_metadata() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let validators = ListValidators {
        etag: Some("\"first\"".into()),
        last_modified: None,
    };
    let (list, path) = url_list_with_http(&store, &validators);
    remove_list(&store, &list.id).unwrap();
    assert!(!path.exists());
    assert!(!http_path(&path).exists());
    assert!(!previous_path(&http_path(&path)).exists());
}

#[test]
fn failed_download_preserves_the_old_url_list() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let list = url_list(&store);
    let path = list_path(&directory.0.join("lists"), &list);
    let original_config = fs::read(store.path()).unwrap();

    assert!(matches!(
        update_list_with(
            &store,
            &list.id,
            None,
            Timeouts::default(),
            &mut |_, _, _| { Err(FetchError::Timeout) }
        ),
        Err(ListError::Fetch(FetchError::Timeout))
    ));
    assert_eq!(fs::read(&path).unwrap(), b"example.com\n");
    assert_eq!(fs::read(store.path()).unwrap(), original_config);
    assert!(!previous_path(&path).exists());
}

#[test]
fn update_rolls_back_file_if_configuration_save_fails() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let first = b"example.com\n";
    let list = add_list_from_bytes(&store, "Example", "example.txt", first).unwrap();
    let path = list_path(&directory.0.join("lists"), &list);
    let original_config = fs::read(store.path()).unwrap();
    store.fail_next_save_for_test();

    assert!(matches!(
        update_list(
            &store,
            &list.id,
            Some(("example.txt", b"example.invalid\n")),
            Timeouts::default()
        ),
        Err(ListError::Store(StoreError::Io { .. }))
    ));
    assert_eq!(fs::read(&path).unwrap(), first);
    assert_eq!(fs::read(store.path()).unwrap(), original_config);
    assert!(!previous_path(&path).exists());
}

#[test]
fn removal_restores_file_if_configuration_save_fails() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let list = add_list_from_bytes(&store, "Example", "example.txt", b"example.com\n").unwrap();
    let path = list_path(&directory.0.join("lists"), &list);
    store.fail_next_save_for_test();

    assert!(matches!(
        remove_list(&store, &list.id),
        Err(ListError::Store(StoreError::Io { .. }))
    ));
    assert_eq!(fs::read(&path).unwrap(), b"example.com\n");
    assert!(!previous_path(&path).exists());
    assert_eq!(store.load().unwrap().lists, vec![list]);
}

#[test]
fn removing_an_in_use_list_names_all_rule_sets() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let list = add_list_from_bytes(&store, "Example", "example.txt", b"example.com\n").unwrap();
    let first = crate::create_rule_set(&store, "One", RuleTarget::Proxy).unwrap();
    let second = crate::create_rule_set(&store, "Two", RuleTarget::Direct).unwrap();
    for id in [&first.id, &second.id] {
        crate::add_rule(
            &store,
            id,
            RuleMatcher::List {
                list: list.id.clone(),
                category: None,
            },
            RuleTarget::Direct,
        )
        .unwrap();
    }
    match remove_list(&store, &list.id) {
        Err(ListError::InUse { sets }) => assert_eq!(sets, ["One", "Two"]),
        other => panic!("expected in-use error: {other:?}"),
    }
    let path = list_path(&directory.0.join("lists"), &list);
    assert!(path.exists());
    for id in [&first.id, &second.id] {
        let rule = store
            .load()
            .unwrap()
            .rule_sets
            .iter()
            .find(|set| &set.id == id)
            .unwrap()
            .rules[0]
            .id
            .clone();
        crate::remove_rule(&store, id, &rule).unwrap();
    }
    remove_list(&store, &list.id).unwrap();
    assert!(!path.exists());
    assert!(store.load().unwrap().lists.is_empty());
}

#[test]
fn start_reconciles_orphans_and_interrupted_file_replacement() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let list = add_list_from_bytes(&store, "Example", "example.txt", b"example.com\n").unwrap();
    let path = list_path(&directory.0.join("lists"), &list);
    let orphan = directory.0.join("lists/2.txt");
    fs::write(&orphan, b"example.invalid\n").unwrap();
    fs::rename(&path, previous_path(&path)).unwrap();
    fs::write(&path, b"example.invalid\n").unwrap();

    reconcile_lists(&store).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"example.com\n");
    assert!(!orphan.exists());
    assert!(!previous_path(&path).exists());
}

#[test]
fn checksum_mismatch_blocks_a_payload_without_deleting_it() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let list = add_list_from_bytes(&store, "Example", "example.txt", b"example.com\n").unwrap();
    let path = list_path(&directory.0.join("lists"), &list);
    fs::write(&path, b"example.invalid\n").unwrap();
    assert!(matches!(
        list_payload(&store, &list.id, None),
        Err(ListError::Integrity)
    ));
    assert!(matches!(reconcile_lists(&store), Err(ListError::Integrity)));
}

#[test]
fn a_new_list_cannot_exceed_the_input_limit() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let bytes = vec![b'x'; MAX_LIST_BYTES + 1];
    assert!(matches!(
        add_list_from_bytes(&store, "Example", "example.txt", &bytes),
        Err(ListError::TooLarge)
    ));
    assert!(!store.path().exists());
}

#[test]
fn stale_download_cannot_replace_a_changed_list_source() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let bytes = b"example.com\n";
    store
        .modify(|config| {
            config.lists.push(List {
                id: ListId::new("1"),
                name: "Example".to_owned(),
                source: ListSource::Url("https://lists.example.com/one.txt".to_owned()),
                format: rosetun_config::ListFormat::Text,
                updated_at: None,
                size: Some(bytes.len() as u64),
                sha256: Some(checksum(bytes)),
                categories: Vec::new(),
            });
            Ok::<_, StoreError>(())
        })
        .unwrap();
    let list = store.load().unwrap().lists[0].clone();
    let path = list_path(&directory.0.join("lists"), &list);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    let result = update_list_with(
        &store,
        &list.id,
        None,
        Timeouts::default(),
        &mut |_, _, _| {
            store
                .modify(|config| {
                    config.lists[0].source =
                        ListSource::Url("https://lists.example.com/two.txt".to_owned());
                    Ok::<_, StoreError>(())
                })
                .unwrap();
            Ok(ListFetch::Modified {
                bytes: b"example.invalid\n".to_vec(),
                validators: ListValidators::default(),
            })
        },
    );
    assert!(matches!(result, Err(ListError::ChangedDuringUpdate)));
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(store.load().unwrap().lists[0].sha256, list.sha256);
}

#[test]
fn unchanged_response_still_rejects_a_list_changed_during_fetch() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let validators = ListValidators {
        etag: Some("\"first\"".into()),
        last_modified: None,
    };
    let (list, path) = url_list_with_http(&store, &validators);
    let result = update_list_with(
        &store,
        &list.id,
        None,
        Timeouts::default(),
        &mut |_, _, sent| {
            assert_eq!(sent, Some(&validators));
            store
                .modify(|config| {
                    config.lists[0].source =
                        ListSource::Url("https://lists.example.com/new.txt".into());
                    Ok::<_, StoreError>(())
                })
                .unwrap();
            Ok(ListFetch::NotModified)
        },
    );
    assert!(matches!(result, Err(ListError::ChangedDuringUpdate)));
    assert_eq!(fs::read(&path).unwrap(), b"example.com\n");
    assert_eq!(store.load().unwrap().lists[0].updated_at, list.updated_at);
}

#[test]
fn http_metadata_rolls_back_when_config_save_fails() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let original = ListValidators {
        etag: Some("\"first\"".into()),
        last_modified: None,
    };
    let (list, path) = url_list_with_http(&store, &original);
    store.fail_next_save_for_test();
    let result = update_list_with(
        &store,
        &list.id,
        None,
        Timeouts::default(),
        &mut |_, _, sent| {
            assert_eq!(sent, Some(&original));
            Ok(ListFetch::Modified {
                bytes: b"example.invalid\n".to_vec(),
                validators: ListValidators {
                    etag: Some("\"second\"".into()),
                    last_modified: None,
                },
            })
        },
    );
    assert!(matches!(
        result,
        Err(ListError::Store(StoreError::Io { .. }))
    ));
    assert_eq!(fs::read(&path).unwrap(), b"example.com\n");
    assert_eq!(
        read_http_metadata(&http_path(&path), list.sha256.as_deref().unwrap()),
        Some(original)
    );
    assert!(!previous_path(&http_path(&path)).exists());
}

#[test]
fn http_metadata_is_restored_when_removal_rolls_back() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let validators = ListValidators {
        etag: Some("\"first\"".into()),
        last_modified: None,
    };
    let (list, path) = url_list_with_http(&store, &validators);
    store.fail_next_save_for_test();
    assert!(matches!(
        remove_list(&store, &list.id),
        Err(ListError::Store(StoreError::Io { .. }))
    ));
    assert_eq!(fs::read(&path).unwrap(), b"example.com\n");
    assert_eq!(
        read_http_metadata(&http_path(&path), list.sha256.as_deref().unwrap()),
        Some(validators)
    );
    assert!(!previous_path(&http_path(&path)).exists());
}

#[test]
fn refresh_keeps_a_name_changed_during_download() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let bytes = b"example.com\n";
    store
        .modify(|config| {
            config.lists.push(List {
                id: ListId::new("1"),
                name: "Old".to_owned(),
                source: ListSource::Url("https://lists.example.com/one.txt".to_owned()),
                format: rosetun_config::ListFormat::Text,
                updated_at: None,
                size: Some(bytes.len() as u64),
                sha256: Some(checksum(bytes)),
                categories: Vec::new(),
            });
            Ok::<_, StoreError>(())
        })
        .unwrap();
    let list = store.load().unwrap().lists[0].clone();
    let path = list_path(&directory.0.join("lists"), &list);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    let result = update_list_with(
        &store,
        &list.id,
        None,
        Timeouts::default(),
        &mut |_, _, _| {
            rename_list(&store, &list.id, "New").unwrap();
            Ok(ListFetch::Modified {
                bytes: b"example.invalid\n".to_vec(),
                validators: ListValidators::default(),
            })
        },
    )
    .unwrap();
    assert_eq!(result.name, "New");
    assert_eq!(store.load().unwrap().lists[0].name, "New");
}

#[test]
fn updating_all_skips_files_and_continues_after_a_url_failure() {
    let directory = TestDirectory::new();
    let store = directory.store();
    add_list_from_bytes(&store, "Local", "example.txt", b"example.com\n").unwrap();
    let original = b"example.com\n";
    store
        .modify(|config| {
            for id in ["2", "3"] {
                config.lists.push(List {
                    id: ListId::new(id),
                    name: format!("Remote {id}"),
                    source: ListSource::Url(format!("https://lists.example.com/{id}.txt")),
                    format: rosetun_config::ListFormat::Text,
                    updated_at: None,
                    size: Some(original.len() as u64),
                    sha256: Some(checksum(original)),
                    categories: Vec::new(),
                });
            }
            Ok::<_, StoreError>(())
        })
        .unwrap();
    for list in &store.load().unwrap().lists[1..] {
        fs::write(list_path(&directory.0.join("lists"), list), original).unwrap();
    }
    let mut requested = Vec::new();
    let result = update_all_lists_with(&store, Timeouts::default(), &mut |url, _, _| {
        requested.push(url.to_owned());
        if url.ends_with("/2.txt") {
            Err(FetchError::Timeout)
        } else {
            Ok(ListFetch::Modified {
                bytes: b"example.invalid\n".to_vec(),
                validators: ListValidators::default(),
            })
        }
    })
    .unwrap();
    assert_eq!(requested.len(), 2);
    assert_eq!(result.len(), 2);
    assert!(matches!(
        result[0].1,
        Err(ListError::Fetch(FetchError::Timeout))
    ));
    assert!(result[1].1.is_ok());
    assert_eq!(store.load().unwrap().lists[0].name, "Local");
    assert_eq!(
        store.load().unwrap().lists[1].sha256.as_deref(),
        Some(checksum(original).as_str())
    );
    assert_eq!(
        store.load().unwrap().lists[2].sha256.as_deref(),
        Some(checksum(b"example.invalid\n").as_str())
    );
}

#[test]
fn invalid_url_errors_do_not_echo_tokens() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let error = add_list_from_url(
        &store,
        "bad://user:secret@lists.example.com/private?token=secret",
        "Example",
        Timeouts::default(),
    )
    .unwrap_err();
    assert!(matches!(error, ListError::InvalidUrl));
    assert!(!error.to_string().contains("secret"));
    assert!(!format!("{error:?}").contains("secret"));
}

#[test]
fn list_rule_validation_rejects_a_missing_id() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let set = crate::create_rule_set(&store, "Example", RuleTarget::Proxy).unwrap();
    let error = crate::add_rule(
        &store,
        &set.id,
        RuleMatcher::List {
            list: ListId::new("42"),
            category: None,
        },
        RuleTarget::Direct,
    )
    .unwrap_err();
    assert!(matches!(error, crate::RuleSetError::ListNotFound));
    assert!(store.load().unwrap().rule_sets[0].rules.is_empty());
}
