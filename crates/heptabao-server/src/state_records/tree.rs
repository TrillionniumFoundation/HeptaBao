use super::*;

fn child_index(children: &[Arc<Page>], key: &Kv1Key) -> usize {
    children
        .partition_point(|child| child.first() <= key)
        .saturating_sub(1)
}
pub(super) fn get<'a>(page: &'a Page, key: &Kv1Key) -> Option<&'a StoredValue> {
    match &page.data {
        PageData::Leaf(entries) => entries
            .binary_search_by(|(candidate, _)| candidate.cmp(key))
            .ok()
            .map(|i| entries[i].1.as_ref()),
        PageData::Branch(children) => get(&children[child_index(children, key)], key),
    }
}
fn leaf_pages(
    key: &AddressKey,
    mut entries: Vec<(Kv1Key, Arc<StoredValue>)>,
    staged: &mut Vec<Arc<StagedObject>>,
) -> Result<Vec<Arc<Page>>> {
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    if entries.len() <= MAX_CHILDREN && codec::leaf_length(&entries) <= PAGE_BYTES {
        return Ok(vec![codec::page(key, PageData::Leaf(entries), staged)?]);
    }
    let pivot = (1..entries.len())
        .filter(|&i| i <= MAX_CHILDREN && entries.len() - i <= MAX_CHILDREN)
        .map(|i| {
            (
                i,
                codec::leaf_length(&entries[..i]),
                codec::leaf_length(&entries[i..]),
            )
        })
        .filter(|(_, a, b)| *a <= PAGE_BYTES && *b <= PAGE_BYTES)
        .min_by_key(|(_, a, b)| a.abs_diff(*b))
        .map(|(i, _, _)| i)
        .ok_or(RecordError::TooLarge)?;
    let right = entries.split_off(pivot);
    Ok(vec![
        codec::page(key, PageData::Leaf(entries), staged)?,
        codec::page(key, PageData::Leaf(right), staged)?,
    ])
}
fn branch_pages(
    key: &AddressKey,
    mut children: Vec<Arc<Page>>,
    staged: &mut Vec<Arc<StagedObject>>,
) -> Result<Vec<Arc<Page>>> {
    if children.is_empty() {
        return Ok(Vec::new());
    }
    if children.len() <= MAX_CHILDREN && codec::branch_length(&children) <= PAGE_BYTES {
        return Ok(vec![codec::page(key, PageData::Branch(children), staged)?]);
    }
    let pivot = (1..children.len())
        .filter(|&i| i <= MAX_CHILDREN && children.len() - i <= MAX_CHILDREN)
        .map(|i| {
            (
                i,
                codec::branch_length(&children[..i]),
                codec::branch_length(&children[i..]),
            )
        })
        .filter(|(_, a, b)| *a <= PAGE_BYTES && *b <= PAGE_BYTES)
        .min_by_key(|(_, a, b)| a.abs_diff(*b))
        .map(|(i, _, _)| i)
        .ok_or(RecordError::TooLarge)?;
    let right = children.split_off(pivot);
    Ok(vec![
        codec::page(key, PageData::Branch(children), staged)?,
        codec::page(key, PageData::Branch(right), staged)?,
    ])
}
fn edit_page(
    page: &Page,
    address: &AddressKey,
    key: &Kv1Key,
    value: Option<&Arc<StoredValue>>,
    staged: &mut Vec<Arc<StagedObject>>,
) -> Result<Vec<Arc<Page>>> {
    match &page.data {
        PageData::Leaf(entries) => {
            let mut next = entries.clone();
            match (
                next.binary_search_by(|(candidate, _)| candidate.cmp(key)),
                value,
            ) {
                (Ok(index), Some(value)) => next[index].1 = value.clone(),
                (Err(index), Some(value)) => next.insert(index, (key.clone(), value.clone())),
                (Ok(index), None) => {
                    next.remove(index);
                }
                (Err(_), None) => return Err(RecordError::Invalid),
            }
            leaf_pages(address, next, staged)
        }
        PageData::Branch(children) => {
            let index = child_index(children, key);
            let replacement = edit_page(&children[index], address, key, value, staged)?;
            let mut next = Vec::with_capacity(children.len() + 1);
            next.extend(children[..index].iter().cloned());
            next.extend(replacement);
            next.extend(children[index + 1..].iter().cloned());
            branch_pages(address, next, staged)
        }
    }
}
fn reachable_staged(
    reference: &ObjectRef,
    staged: &BTreeMap<ObjectId, Arc<StagedObject>>,
    seen: &mut BTreeSet<ObjectId>,
    out: &mut Vec<Arc<StagedObject>>,
) -> Result<()> {
    let Some(object) = staged.get(&reference.id) else {
        return Ok(());
    };
    if object.reference != *reference {
        return Err(RecordError::Corrupt);
    }
    if !seen.insert(reference.id) {
        return Ok(());
    }
    for child in &object.children {
        reachable_staged(child, staged, seen, out)?;
    }
    out.push(object.clone());
    Ok(())
}
pub(super) fn edit(index: &Kv1Index, key: Kv1Key, value: Option<&[u8]>) -> Result<Kv1Edit> {
    if index.get(&key) == value {
        return Ok(Kv1Edit {
            next: index.clone(),
            objects: Vec::new(),
            changed: false,
        });
    }
    let mut objects = Vec::new();
    let stored = value
        .map(|bytes| codec::value(&index.address_key, bytes, &mut objects))
        .transpose()?;
    let mut pages = match &index.root {
        Some(page) => edit_page(
            page,
            &index.address_key,
            &key,
            stored.as_ref(),
            &mut objects,
        )?,
        None => leaf_pages(
            &index.address_key,
            vec![(key, stored.ok_or(RecordError::Invalid)?)],
            &mut objects,
        )?,
    };
    let mut height = index.height.max(1);
    let mut root = match pages.len() {
        0 => {
            height = 0;
            None
        }
        1 => pages.pop(),
        2 => {
            height = height.checked_add(1).ok_or(RecordError::TooLarge)?;
            if height > MAX_HEIGHT {
                return Err(RecordError::TooLarge);
            }
            Some(codec::page(
                &index.address_key,
                PageData::Branch(pages),
                &mut objects,
            )?)
        }
        _ => return Err(RecordError::Corrupt),
    };
    while let Some(page) = root.as_ref() {
        match &page.data {
            PageData::Branch(children) if children.len() == 1 => {
                root = Some(children[0].clone());
                height -= 1;
            }
            _ => break,
        }
    }
    let next = Kv1Index {
        address_key: index.address_key.clone(),
        root,
        height,
    };
    let mut staged = BTreeMap::new();
    for object in objects {
        if let Some(old) = staged.insert(object.reference.id, object.clone())
            && (old.reference != object.reference || old.bytes() != object.bytes())
        {
            return Err(RecordError::Corrupt);
        }
    }
    let mut objects = Vec::new();
    if let Some(root) = &next.root {
        reachable_staged(
            &root.object.reference,
            &staged,
            &mut BTreeSet::new(),
            &mut objects,
        )?;
    }
    Ok(Kv1Edit {
        next,
        objects,
        changed: true,
    })
}

struct Cursor<'a> {
    stack: Vec<(&'a [Arc<Page>], usize)>,
    entries: &'a [(Kv1Key, Arc<StoredValue>)],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn seek(root: &'a Page, key: &Kv1Key, inclusive: bool) -> Self {
        let mut cursor = Self {
            stack: Vec::with_capacity(MAX_HEIGHT as usize),
            entries: &[],
            offset: 0,
        };
        let mut page = root;
        loop {
            match &page.data {
                PageData::Leaf(entries) => {
                    cursor.entries = entries;
                    cursor.offset = entries.partition_point(|(candidate, _)| {
                        if inclusive {
                            candidate < key
                        } else {
                            candidate <= key
                        }
                    });
                    return cursor;
                }
                PageData::Branch(children) => {
                    let index = child_index(children, key);
                    cursor.stack.push((children, index + 1));
                    page = &children[index];
                }
            }
        }
    }
    fn next(&mut self) -> Option<&'a Kv1Key> {
        loop {
            if let Some((key, _)) = self.entries.get(self.offset) {
                self.offset += 1;
                return Some(key);
            }
            let (children, index) = self.stack.pop()?;
            if index >= children.len() {
                continue;
            }
            self.stack.push((children, index + 1));
            let mut page = children[index].as_ref();
            loop {
                match &page.data {
                    PageData::Leaf(entries) => {
                        self.entries = entries;
                        self.offset = 0;
                        break;
                    }
                    PageData::Branch(children) => {
                        self.stack.push((children, 1));
                        page = &children[0];
                    }
                }
            }
        }
    }
}

pub(super) fn scan(
    index: &Kv1Index,
    scope: &Kv1Scope,
    prefix: &str,
    after: Option<&str>,
    limit: usize,
    recursive: bool,
) -> Result<KeyPage> {
    if limit == 0
        || limit > 4096
        || prefix.len() > 1024
        || prefix.contains('\0')
        || after.is_some_and(|a| a.len() > 1024 || a.contains('\0'))
    {
        return Err(RecordError::Invalid);
    }
    let Some(root) = index.root.as_deref() else {
        return Ok(KeyPage {
            keys: Vec::new(),
            next_after: None,
        });
    };
    let prefix = Zeroizing::new(if prefix.is_empty() {
        String::new()
    } else {
        format!("{}/", prefix.trim_end_matches('/'))
    });
    let after = after.unwrap_or("");
    let (seek_path, inclusive) = if !recursive && after.ends_with('/') {
        (
            Zeroizing::new(format!("{}{}0", prefix.as_str(), &after[..after.len() - 1])),
            true,
        )
    } else {
        (
            Zeroizing::new(format!("{}{after}", prefix.as_str())),
            after.is_empty(),
        )
    };
    let mut cursor = Cursor::seek(root, &Kv1Key::probe(scope, &seek_path), inclusive);
    let mut keys = Vec::with_capacity(limit.min(256));
    while let Some(key) = cursor.next() {
        if !key.in_scope(scope) {
            break;
        }
        let Some(rest) = key.path.strip_prefix(prefix.as_str()) else {
            break;
        };
        if rest.is_empty() {
            continue;
        }
        let found = if !recursive {
            if let Some((directory, _)) = rest.split_once('/') {
                let next = Zeroizing::new(format!("{}{directory}0", prefix.as_str()));
                cursor = Cursor::seek(root, &Kv1Key::probe(scope, &next), true);
                format!("{directory}/")
            } else {
                rest.to_owned()
            }
        } else {
            rest.to_owned()
        };
        if found.as_str() <= after {
            continue;
        }
        if keys.len() == limit {
            let next_after = keys.last().cloned();
            return Ok(KeyPage { keys, next_after });
        }
        keys.push(found);
    }
    Ok(KeyPage {
        keys,
        next_after: None,
    })
}

pub(super) fn visit(
    page: &Page,
    seen: &mut BTreeSet<ObjectId>,
    visitor: &mut impl FnMut(&Arc<StagedObject>) -> Result<()>,
) -> Result<()> {
    if !seen.insert(page.object.reference.id) {
        return Ok(());
    }
    match &page.data {
        PageData::Leaf(entries) => {
            for (_, value) in entries {
                let StoredValue::Referenced(value) = value.as_ref() else {
                    continue;
                };
                if !seen.insert(value.object.reference.id) {
                    continue;
                }
                for block in &value.blocks {
                    if seen.insert(block.reference.id) {
                        visitor(block)?;
                    }
                }
                visitor(&value.object)?;
            }
        }
        PageData::Branch(children) => {
            for child in children {
                visit(child, seen, visitor)?;
            }
        }
    }
    visitor(&page.object)
}

pub(super) fn visit_keys(
    page: &Page,
    visitor: &mut impl FnMut(&Kv1Key) -> Result<()>,
) -> Result<()> {
    match &page.data {
        PageData::Leaf(entries) => {
            for (key, _) in entries {
                visitor(key)?;
            }
        }
        PageData::Branch(children) => {
            for child in children {
                visit_keys(child, visitor)?;
            }
        }
    }
    Ok(())
}
