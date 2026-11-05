//! Build a new detached index once from a complete ordered record set.
//! No existing root is changed and no object is published by this codec.
use super::*;

pub(super) fn build(
    address_key: Arc<AddressKey>,
    records: BTreeMap<Kv1Key, Zeroizing<Vec<u8>>>,
    check: &impl Fn() -> Result<()>,
) -> Result<Kv1Index> {
    check()?;
    if records.len() > MAX_OBJECTS {
        return Err(RecordError::TooLarge);
    }
    let mut leaves = Vec::new();
    let mut entries = Vec::new();
    for (key, bytes) in records {
        check()?;
        let stored = codec::value(&address_key, &bytes, &mut Vec::new())?;
        entries.push((key, stored));
        if entries.len() > MAX_CHILDREN || codec::leaf_length(&entries) > PAGE_BYTES {
            let last = entries.pop().ok_or(RecordError::Corrupt)?;
            if entries.is_empty() {
                return Err(RecordError::TooLarge);
            }
            check()?;
            leaves.push(codec::page(
                &address_key,
                PageData::Leaf(std::mem::take(&mut entries)),
                &mut Vec::new(),
            )?);
            entries.push(last);
            if codec::leaf_length(&entries) > PAGE_BYTES {
                return Err(RecordError::TooLarge);
            }
        }
        check()?;
    }
    if !entries.is_empty() {
        check()?;
        leaves.push(codec::page(
            &address_key,
            PageData::Leaf(entries),
            &mut Vec::new(),
        )?);
    }
    if leaves.is_empty() {
        check()?;
        return Ok(Kv1Index::empty(address_key));
    }
    let mut height = 1_u8;
    while leaves.len() > 1 {
        check()?;
        height = height.checked_add(1).ok_or(RecordError::TooLarge)?;
        if height > MAX_HEIGHT {
            return Err(RecordError::TooLarge);
        }
        let mut next = Vec::new();
        let mut children = Vec::new();
        for child in leaves {
            check()?;
            children.push(child);
            if children.len() > MAX_CHILDREN || codec::branch_length(&children) > PAGE_BYTES {
                let last = children.pop().ok_or(RecordError::Corrupt)?;
                if children.is_empty() {
                    return Err(RecordError::TooLarge);
                }
                next.push(codec::page(
                    &address_key,
                    PageData::Branch(std::mem::take(&mut children)),
                    &mut Vec::new(),
                )?);
                children.push(last);
                if codec::branch_length(&children) > PAGE_BYTES {
                    return Err(RecordError::TooLarge);
                }
            }
        }
        if !children.is_empty() {
            check()?;
            next.push(codec::page(
                &address_key,
                PageData::Branch(children),
                &mut Vec::new(),
            )?);
        }
        leaves = next;
    }
    let index = Kv1Index {
        address_key,
        root: leaves.pop(),
        height,
    };
    // Apply the same complete closure bounds as the cold decoder. Deduplicated
    // content addresses count once; no partially built root escapes on failure.
    let mut objects = 0_usize;
    let mut bytes = 0_usize;
    index.visit_objects(|object| {
        check()?;
        objects = objects.checked_add(1).ok_or(RecordError::TooLarge)?;
        bytes = bytes
            .checked_add(object.bytes().len())
            .ok_or(RecordError::TooLarge)?;
        if objects > MAX_OBJECTS || bytes > MAX_GRAPH_BYTES {
            return Err(RecordError::TooLarge);
        }
        Ok(())
    })?;
    check()?;
    Ok(index)
}
