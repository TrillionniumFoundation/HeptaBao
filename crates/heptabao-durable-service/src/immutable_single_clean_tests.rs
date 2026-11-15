//! Real file transitions for the shared single/batch temporary-name hint.
//! No source Actor, application root or publication cursor is minted here.
use super::*;

fn staged_pin(stage: ImmutableBlobStage) -> ImmutableBlobReadPin {
    match stage {
        ImmutableBlobStage::Published(pin) | ImmutableBlobStage::AlreadyExists(pin) => pin,
    }
}

fn assert_no_reserved_temporary(root: &Root) {
    for name in std::iter::once(TEMPORARY_LEAF).chain(BATCH_TEMPORARIES) {
        assert!(
            matches!(
                fs::symlink_metadata(root.0.join(name)),
                Err(error) if error.kind() == io::ErrorKind::NotFound
            ),
            "a completed publication retained a reserved temporary"
        );
    }
}

#[test]
fn immutable_single_clean_mixed_success_preserves_ciphertext_and_cold_owner() -> TestResult {
    let root = Root::new()?;
    let mut owner = FileBackend::create_new(&root.0)?;
    let initial = initial()?;
    owner.initialize_empty(&initial)?;
    let bytes = vec![0x61; 64 * 1024];
    let alternate = vec![0x62; bytes.len()];
    let mut pins = Vec::new();
    for cycle in 0..3 {
        let a = locator(0x20 + cycle * 3)?;
        let b = locator(0x21 + cycle * 3)?;
        let c = locator(0x22 + cycle * 3)?;
        pins.push(published(owner.stage_immutable_ciphertext(a, &bytes)?)?);
        assert!(owner.immutable_batch_temps_known_clean);
        let ImmutableBlobStage::AlreadyExists(existing) =
            owner.stage_immutable_ciphertext(a, &alternate)?
        else {
            return Err("same locator was replaced by a fresh seal".into());
        };
        assert_eq!(existing.read_ciphertext()?.as_slice(), bytes.as_slice());
        assert!(owner.immutable_batch_temps_known_clean);
        let batch = [(b, bytes.as_slice()), (c, bytes.as_slice())];
        for stage in owner.stage_immutable_ciphertext_batch_checked(&batch, &mut || Ok(()))? {
            pins.push(published(stage)?);
        }
        assert!(owner.immutable_batch_temps_known_clean);
        assert_no_reserved_temporary(&root);
        assert_eq!(owner.load()?, initial);
    }
    for pin in &pins {
        assert_eq!(pin.read_ciphertext()?.as_slice(), bytes.as_slice());
        assert_eq!(pin.0.file.metadata()?.nlink(), 1);
    }
    drop(owner);
    let mut reopened = FileBackend::open(&root.0)?;
    assert!(reopened.immutable_batch_temps_known_clean);
    assert_no_reserved_temporary(&root);
    for old in pins {
        assert!(matches!(
            old.read_ciphertext(),
            Err(BackendError::Unavailable)
        ));
        let fresh = reopened.pin_immutable_ciphertext(old.locator(), bytes.len())?;
        assert_eq!(fresh.read_ciphertext()?.as_slice(), bytes.as_slice());
    }
    assert_eq!(reopened.load()?, initial);
    Ok(())
}

#[test]
fn immutable_single_clean_post_link_refusal_recovers_for_single_and_batch() -> TestResult {
    for recover_with_batch in [false, true] {
        let root = Root::new()?;
        let mut owner = FileBackend::create_new(&root.0)?;
        let old = published(owner.stage_immutable_ciphertext(locator(0x31)?, b"old-object")?)?;
        assert!(owner.immutable_batch_temps_known_clean);
        let address = locator(0x32)?;
        let target = root.0.join(address.leaf());
        let refusal =
            owner.stage_immutable_ciphertext_checked(address, b"first-object", &mut || {
                if target.exists() {
                    Err(BackendError::Unavailable)
                } else {
                    Ok(())
                }
            });
        assert!(matches!(refusal, Err(BackendError::Unavailable)));
        assert!(!owner.immutable_batch_temps_known_clean);
        assert_eq!(fs::metadata(&target)?.nlink(), 2);
        assert!(root.0.join(TEMPORARY_LEAF).exists());
        assert!(owner.immutable_blob_profile()?.is_live());
        assert_eq!(old.read_ciphertext()?.as_slice(), b"old-object");
        let stage = if recover_with_batch {
            let input = [(address, b"other-object".as_slice())];
            owner
                .stage_immutable_ciphertext_batch_checked(&input, &mut || Ok(()))?
                .into_iter()
                .next()
                .ok_or("missing recovery stage")?
        } else {
            owner.stage_immutable_ciphertext(address, b"other-object")?
        };
        let ImmutableBlobStage::AlreadyExists(pin) = stage else {
            return Err("linked but unadmitted ciphertext was overwritten".into());
        };
        assert_eq!(pin.read_ciphertext()?.as_slice(), b"first-object");
        assert_eq!(pin.0.file.metadata()?.nlink(), 1);
        assert!(owner.immutable_batch_temps_known_clean);
        assert_no_reserved_temporary(&root);
    }
    Ok(())
}

#[test]
fn immutable_single_clean_write_and_batch_refusals_recover_cross_mode() -> TestResult {
    let root = Root::new()?;
    let mut owner = FileBackend::create_new(&root.0)?;
    let bytes = vec![0x63; 8192];
    let first = published(owner.stage_immutable_ciphertext(locator(0x41)?, &bytes)?)?;
    let single = locator(0x42)?;
    let temporary = root.0.join(TEMPORARY_LEAF);
    let failed = owner.stage_immutable_ciphertext_checked(single, &bytes, &mut || {
        if fs::metadata(&temporary).is_ok_and(|metadata| metadata.len() > 0) {
            Err(BackendError::Unavailable)
        } else {
            Ok(())
        }
    });
    assert!(matches!(failed, Err(BackendError::Unavailable)));
    assert!(temporary.exists());
    assert!(!root.0.join(single.leaf()).exists());
    assert!(!owner.immutable_batch_temps_known_clean);
    let recovered = owner
        .stage_immutable_ciphertext_batch_checked(&[(single, bytes.as_slice())], &mut || Ok(()))?;
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        staged_pin(
            recovered
                .into_iter()
                .next()
                .ok_or("missing recovered object")?
        )
        .read_ciphertext()?
        .as_slice(),
        bytes.as_slice()
    );
    assert_no_reserved_temporary(&root);
    assert!(owner.immutable_batch_temps_known_clean);

    let batch_address = locator(0x43)?;
    let batch_temporary = root.0.join(BATCH_TEMPORARIES[0]);
    let failed = owner.stage_immutable_ciphertext_batch_checked(
        &[(batch_address, bytes.as_slice())],
        &mut || {
            if batch_temporary.exists() {
                Err(BackendError::Unavailable)
            } else {
                Ok(())
            }
        },
    );
    assert!(matches!(failed, Err(BackendError::Unavailable)));
    assert!(batch_temporary.exists());
    assert!(!owner.immutable_batch_temps_known_clean);
    assert!(!root.0.join(batch_address.leaf()).exists());
    let next = published(owner.stage_immutable_ciphertext(batch_address, &bytes)?)?;
    assert_eq!(next.read_ciphertext()?.as_slice(), bytes.as_slice());
    assert_eq!(first.read_ciphertext()?.as_slice(), bytes.as_slice());
    assert_no_reserved_temporary(&root);
    assert!(owner.immutable_batch_temps_known_clean);
    Ok(())
}

#[test]
fn immutable_single_clean_external_temporary_refuses_and_ack_loss_requires_cold_owner() -> TestResult
{
    let root = Root::new()?;
    let mut owner = FileBackend::create_new(&root.0)?;
    let initial = initial()?;
    owner.initialize_empty(&initial)?;
    let first = published(owner.stage_immutable_ciphertext(locator(0x51)?, b"old-object")?)?;
    assert!(owner.immutable_batch_temps_known_clean);
    let protected = root.0.join("protected-external");
    fs::write(&protected, b"preserve")?;
    let temporary = root.0.join(TEMPORARY_LEAF);
    symlink("protected-external", &temporary)?;
    let address = locator(0x52)?;
    assert!(
        owner
            .stage_immutable_ciphertext(address, b"new-object")
            .is_err()
    );
    assert!(!owner.immutable_batch_temps_known_clean);
    assert!(temporary.is_symlink());
    assert!(!root.0.join(address.leaf()).exists());
    assert_eq!(fs::read(&protected)?, b"preserve");
    let next = published(owner.stage_immutable_ciphertext(address, b"new-object")?)?;
    assert_eq!(next.read_ciphertext()?.as_slice(), b"new-object");
    assert_eq!(fs::read(&protected)?, b"preserve");
    assert_no_reserved_temporary(&root);
    assert!(owner.immutable_batch_temps_known_clean);

    let lost = locator(0x53)?;
    assert!(matches!(
        owner.stage_immutable_ciphertext_with_ack_hook(
            lost,
            b"ack-lost-object",
            &mut || Ok(()),
            || Err(BackendError::Io),
        ),
        Err(BackendError::OutcomeUnknown)
    ));
    assert!(!owner.immutable_batch_temps_known_clean);
    assert_eq!(fs::read(root.0.join(lost.leaf()))?, b"ack-lost-object");
    assert!(matches!(
        first.read_ciphertext(),
        Err(BackendError::Unavailable)
    ));
    assert!(matches!(
        next.read_ciphertext(),
        Err(BackendError::Unavailable)
    ));
    assert!(
        owner
            .stage_immutable_ciphertext(locator(0x54)?, b"forbidden")
            .is_err()
    );
    drop(owner);
    let mut reopened = FileBackend::open(&root.0)?;
    assert!(reopened.immutable_batch_temps_known_clean);
    assert_no_reserved_temporary(&root);
    assert_eq!(
        reopened
            .pin_immutable_ciphertext(lost, 15)?
            .read_ciphertext()?
            .as_slice(),
        b"ack-lost-object"
    );
    assert_eq!(reopened.load()?, initial);
    Ok(())
}
