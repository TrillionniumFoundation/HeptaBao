use super::*;

fn kind(byte: u8) -> Result<ObjectKind> {
    match byte {
        1 => Ok(ObjectKind::Block),
        2 => Ok(ObjectKind::Value),
        3 => Ok(ObjectKind::Leaf),
        4 => Ok(ObjectKind::Branch),
        5 => Ok(ObjectKind::OwnerChunk),
        6 => Ok(ObjectKind::PackedLeaf),
        _ => Err(RecordError::Corrupt),
    }
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or(RecordError::TooLarge)
}
fn maximum(kind: ObjectKind) -> usize {
    match kind {
        ObjectKind::Block | ObjectKind::OwnerChunk => BLOCK_BYTES + HEADER_BYTES,
        ObjectKind::Value => HEADER_BYTES + 2 + 64 * REF_BYTES,
        ObjectKind::Leaf | ObjectKind::Branch | ObjectKind::PackedLeaf => PAGE_BYTES,
    }
}
struct Writer {
    bytes: Zeroizing<Vec<u8>>,
    bound: usize,
}
impl Writer {
    fn new(kind: ObjectKind, records: u64, payload: u64, length: usize) -> Result<Self> {
        if length > maximum(kind) {
            return Err(RecordError::TooLarge);
        }
        let mut this = Self {
            bytes: Zeroizing::new(Vec::with_capacity(length)),
            bound: length,
        };
        this.raw(MAGIC)?;
        this.raw(&[kind as u8])?;
        this.u64(records)?;
        this.u64(payload)?;
        Ok(this)
    }
    fn raw(&mut self, bytes: &[u8]) -> Result<()> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > self.bound)
        {
            return Err(RecordError::TooLarge);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn u16(&mut self, n: usize) -> Result<()> {
        self.raw(
            &u16::try_from(n)
                .map_err(|_| RecordError::TooLarge)?
                .to_be_bytes(),
        )
    }
    fn u64(&mut self, n: u64) -> Result<()> {
        self.raw(&n.to_be_bytes())
    }
    fn key(&mut self, key: &Kv1Key) -> Result<()> {
        for text in [&key.namespace, &key.mount] {
            self.u16(text.len())?;
            self.raw(text.as_bytes())?;
        }
        self.u64(key.incarnation)?;
        self.u16(key.path.len())?;
        self.raw(key.path.as_bytes())
    }
    fn reference(&mut self, value: &ObjectRef) -> Result<()> {
        self.raw(value.id.bytes())?;
        self.raw(&[value.kind as u8])?;
        self.raw(&value.encoded_bytes.to_be_bytes())?;
        self.u64(value.record_count)?;
        self.u64(value.payload_bytes)
    }
    fn finish(
        self,
        key: &AddressKey,
        kind: ObjectKind,
        records: u64,
        payload: u64,
        children: Vec<ObjectRef>,
    ) -> Result<Arc<StagedObject>> {
        if self.bytes.len() != self.bound {
            return Err(RecordError::Corrupt);
        }
        let reference = ObjectRef {
            id: ObjectId(key.digest(b"object", &self.bytes)?),
            kind,
            encoded_bytes: u32::try_from(self.bytes.len()).map_err(|_| RecordError::TooLarge)?,
            record_count: records,
            payload_bytes: payload,
        };
        Ok(Arc::new(StagedObject {
            reference,
            children,
            bytes: self.bytes,
        }))
    }
}
struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Decoder<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(len).ok_or(RecordError::Corrupt)?;
        let out = self
            .bytes
            .get(self.offset..end)
            .ok_or(RecordError::Corrupt)?;
        self.offset = end;
        Ok(out)
    }
    fn u16(&mut self) -> Result<usize> {
        Ok(usize::from(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| RecordError::Corrupt)?,
        )))
    }
    fn tag(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn inline(&mut self) -> Result<&'a [u8]> {
        let length = self.u16()?;
        if length > INLINE_VALUE_BYTES {
            return Err(RecordError::Corrupt);
        }
        self.take(length)
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| RecordError::Corrupt)?,
        ))
    }
    fn text(&mut self) -> Result<&'a str> {
        let n = self.u16()?;
        if n > 1024 {
            return Err(RecordError::Corrupt);
        }
        std::str::from_utf8(self.take(n)?).map_err(|_| RecordError::Corrupt)
    }
    fn key(&mut self) -> Result<Kv1Key> {
        let namespace = self.text()?;
        let mount = self.text()?;
        let incarnation = self.u64()?;
        let path = self.text()?;
        Kv1Key::new(namespace, mount, incarnation, path).map_err(|_| RecordError::Corrupt)
    }
    fn reference(&mut self) -> Result<ObjectRef> {
        let id = ObjectId(
            self.take(32)?
                .try_into()
                .map_err(|_| RecordError::Corrupt)?,
        );
        let kind = kind(self.take(1)?[0])?;
        let encoded_bytes =
            u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| RecordError::Corrupt)?);
        let record_count = self.u64()?;
        let payload_bytes = self.u64()?;
        Ok(ObjectRef {
            id,
            kind,
            encoded_bytes,
            record_count,
            payload_bytes,
        })
    }
    fn done(&self) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(RecordError::Corrupt)
        }
    }
}

pub(super) fn verify_object(reference: &ObjectRef, key: &AddressKey, bytes: &[u8]) -> Result<()> {
    if bytes.len() != reference.encoded_bytes as usize
        || bytes.len() < HEADER_BYTES
        || bytes.len() > maximum(reference.kind)
    {
        return Err(RecordError::Corrupt);
    }
    let mut mac = key.mac(b"object")?;
    mac.update(bytes);
    mac.verify_slice(reference.id.bytes())
        .map_err(|_| RecordError::Corrupt)?;
    let mut decoder = Decoder { bytes, offset: 0 };
    if decoder.take(8)? != MAGIC
        || kind(decoder.take(1)?[0])? != reference.kind
        || decoder.u64()? != reference.record_count
        || decoder.u64()? != reference.payload_bytes
    {
        return Err(RecordError::Corrupt);
    }
    match reference.kind {
        ObjectKind::Block | ObjectKind::OwnerChunk => {
            if reference.record_count != 0
                || reference.payload_bytes != (bytes.len() - HEADER_BYTES) as u64
            {
                return Err(RecordError::Corrupt);
            }
        }
        ObjectKind::Value => {
            if reference.record_count != 1 || reference.payload_bytes > MAX_VALUE_BYTES as u64 {
                return Err(RecordError::Corrupt);
            }
        }
        ObjectKind::Leaf | ObjectKind::Branch | ObjectKind::PackedLeaf => {
            if reference.record_count == 0 {
                return Err(RecordError::Corrupt);
            }
        }
    }
    Ok(())
}

pub(super) fn block(key: &AddressKey, kind: ObjectKind, bytes: &[u8]) -> Result<Arc<StagedObject>> {
    if !matches!(kind, ObjectKind::Block | ObjectKind::OwnerChunk) || bytes.len() > BLOCK_BYTES {
        return Err(RecordError::TooLarge);
    }
    let mut writer = Writer::new(kind, 0, bytes.len() as u64, HEADER_BYTES + bytes.len())?;
    writer.raw(bytes)?;
    writer.finish(key, kind, 0, bytes.len() as u64, Vec::new())
}

pub(super) fn value(
    key: &AddressKey,
    bytes: &[u8],
    staged: &mut Vec<Arc<StagedObject>>,
) -> Result<Arc<StoredValue>> {
    if bytes.len() <= INLINE_VALUE_BYTES {
        return Ok(Arc::new(StoredValue::Inline(Zeroizing::new(
            bytes.to_vec(),
        ))));
    }
    referenced_value(key, bytes, staged)
}

pub(super) fn referenced_value(
    key: &AddressKey,
    bytes: &[u8],
    staged: &mut Vec<Arc<StagedObject>>,
) -> Result<Arc<StoredValue>> {
    if bytes.len() > MAX_VALUE_BYTES {
        return Err(RecordError::TooLarge);
    }
    let mut blocks = Vec::with_capacity(bytes.len().div_ceil(BLOCK_BYTES));
    for chunk in bytes.chunks(BLOCK_BYTES) {
        let object = block(key, ObjectKind::Block, chunk)?;
        staged.push(object.clone());
        blocks.push(object);
    }
    let refs: Vec<_> = blocks.iter().map(|b| b.reference.clone()).collect();
    let mut writer = Writer::new(
        ObjectKind::Value,
        1,
        bytes.len() as u64,
        HEADER_BYTES + 2 + refs.len() * REF_BYTES,
    )?;
    writer.u16(refs.len())?;
    for reference in &refs {
        writer.reference(reference)?;
    }
    let object = writer.finish(key, ObjectKind::Value, 1, bytes.len() as u64, refs)?;
    staged.push(object.clone());
    Ok(Arc::new(StoredValue::Referenced(ReferencedValue {
        object,
        blocks,
        encoded: Zeroizing::new(bytes.to_vec()),
    })))
}
fn key_length(key: &Kv1Key) -> usize {
    14 + key.namespace.len() + key.mount.len() + key.path.len()
}
pub(super) fn leaf_length(entries: &[(Kv1Key, Arc<StoredValue>)]) -> usize {
    let packed = entries.iter().any(|(_, value)| value.reference().is_none());
    HEADER_BYTES
        + 2
        + entries
            .iter()
            .map(|(key, value)| {
                key_length(key)
                    + if packed {
                        1 + value
                            .reference()
                            .map_or(2 + value.encoded().len(), |_| REF_BYTES)
                    } else {
                        REF_BYTES
                    }
            })
            .sum::<usize>()
}
pub(super) fn branch_length(children: &[Arc<Page>]) -> usize {
    HEADER_BYTES
        + 2
        + children
            .iter()
            .map(|child| key_length(child.first()) + REF_BYTES)
            .sum::<usize>()
}
pub(super) fn page(
    key: &AddressKey,
    data: PageData,
    staged: &mut Vec<Arc<StagedObject>>,
) -> Result<Arc<Page>> {
    let (kind, count, length, records, payload, refs) = match &data {
        PageData::Leaf(entries) => {
            if entries.is_empty()
                || entries.len() > MAX_CHILDREN
                || entries.windows(2).any(|pair| pair[0].0 >= pair[1].0)
            {
                return Err(RecordError::Corrupt);
            }
            let bytes = entries
                .iter()
                .try_fold(0, |sum, (_, v)| add(sum, v.encoded().len() as u64))?;
            if entries.iter().any(|(_, value)| {
                value.reference().is_none() && value.encoded().len() > INLINE_VALUE_BYTES
            }) {
                return Err(RecordError::TooLarge);
            }
            let packed = entries.iter().any(|(_, value)| value.reference().is_none());
            (
                if packed {
                    ObjectKind::PackedLeaf
                } else {
                    ObjectKind::Leaf
                },
                entries.len(),
                leaf_length(entries),
                entries.len() as u64,
                bytes,
                entries
                    .iter()
                    .filter_map(|(_, v)| v.reference().cloned())
                    .collect::<Vec<_>>(),
            )
        }
        PageData::Branch(children) => {
            if children.is_empty()
                || children.len() > MAX_CHILDREN
                || children
                    .windows(2)
                    .any(|pair| pair[0].last() >= pair[1].first())
            {
                return Err(RecordError::Corrupt);
            }
            let records = children
                .iter()
                .try_fold(0, |sum, p| add(sum, p.object.reference.record_count))?;
            let bytes = children
                .iter()
                .try_fold(0, |sum, p| add(sum, p.object.reference.payload_bytes))?;
            (
                ObjectKind::Branch,
                children.len(),
                branch_length(children),
                records,
                bytes,
                children
                    .iter()
                    .map(|p| p.object.reference.clone())
                    .collect::<Vec<_>>(),
            )
        }
    };
    let mut writer = Writer::new(kind, records, payload, length)?;
    writer.u16(count)?;
    match &data {
        PageData::Leaf(entries) => {
            for (key, value) in entries {
                writer.key(key)?;
                match value.as_ref() {
                    StoredValue::Inline(bytes) => {
                        writer.raw(&[0])?;
                        writer.u16(bytes.len())?;
                        writer.raw(bytes)?;
                    }
                    StoredValue::Referenced(value) => {
                        if kind == ObjectKind::PackedLeaf {
                            writer.raw(&[1])?;
                        }
                        writer.reference(&value.object.reference)?;
                    }
                }
            }
        }
        PageData::Branch(children) => {
            for child in children {
                writer.key(child.first())?;
                writer.reference(&child.object.reference)?;
            }
        }
    }
    let object = writer.finish(key, kind, records, payload, refs)?;
    staged.push(object.clone());
    Ok(Arc::new(Page::checked(object, data)?))
}

struct Loader<'a, R> {
    key: &'a AddressKey,
    reader: &'a R,
    total_bytes: usize,
    objects: BTreeMap<ObjectId, Arc<StagedObject>>,
    values: BTreeMap<ObjectId, Arc<StoredValue>>,
    pages: BTreeMap<ObjectId, (u8, Arc<Page>)>,
    visiting: BTreeSet<ObjectId>,
}
impl<R: RecordReader> Loader<'_, R> {
    fn object(&mut self, reference: &ObjectRef) -> Result<Arc<StagedObject>> {
        if let Some(object) = self.objects.get(&reference.id) {
            if &object.reference != reference {
                return Err(RecordError::Corrupt);
            }
            return Ok(object.clone());
        }
        if self.objects.len() >= MAX_OBJECTS {
            return Err(RecordError::TooLarge);
        }
        let bytes = self.reader.read_object(reference)?;
        reference.verify(self.key, &bytes)?;
        self.total_bytes = self
            .total_bytes
            .checked_add(bytes.len())
            .ok_or(RecordError::TooLarge)?;
        if self.total_bytes > MAX_GRAPH_BYTES {
            return Err(RecordError::TooLarge);
        }
        let mut decoder = Decoder {
            bytes: &bytes,
            offset: HEADER_BYTES,
        };
        let mut children = Vec::new();
        if matches!(
            reference.kind,
            ObjectKind::Value | ObjectKind::Leaf | ObjectKind::Branch | ObjectKind::PackedLeaf
        ) {
            let count = decoder.u16()?;
            let maximum = if reference.kind == ObjectKind::Value {
                64
            } else {
                MAX_CHILDREN
            };
            if count > maximum || (count == 0 && reference.kind != ObjectKind::Value) {
                return Err(RecordError::Corrupt);
            }
            children.reserve_exact(count);
            let mut inline = false;
            for _ in 0..count {
                if reference.kind != ObjectKind::Value {
                    drop(decoder.key()?);
                }
                if reference.kind == ObjectKind::PackedLeaf {
                    match decoder.tag()? {
                        0 => {
                            decoder.inline()?;
                            inline = true;
                        }
                        1 => children.push(decoder.reference()?),
                        _ => return Err(RecordError::Corrupt),
                    }
                } else {
                    children.push(decoder.reference()?);
                }
            }
            decoder.done()?;
            if reference.kind == ObjectKind::PackedLeaf && !inline {
                return Err(RecordError::Corrupt);
            }
        }
        let object = Arc::new(StagedObject {
            reference: reference.clone(),
            children,
            bytes,
        });
        self.objects.insert(reference.id, object.clone());
        Ok(object)
    }
    fn value(&mut self, reference: &ObjectRef) -> Result<Arc<StoredValue>> {
        if reference.kind != ObjectKind::Value {
            return Err(RecordError::Corrupt);
        }
        if let Some(value) = self.values.get(&reference.id) {
            if value.reference() != Some(reference) {
                return Err(RecordError::Corrupt);
            }
            return Ok(value.clone());
        }
        let object = self.object(reference)?;
        let length = usize::try_from(reference.payload_bytes).map_err(|_| RecordError::Corrupt)?;
        let expected_count = length.div_ceil(BLOCK_BYTES);
        if object.children.len() != expected_count {
            return Err(RecordError::Corrupt);
        }
        let mut encoded = Zeroizing::new(Vec::with_capacity(length));
        let mut blocks = Vec::with_capacity(expected_count);
        for (index, child) in object.children.iter().enumerate() {
            if child.kind != ObjectKind::Block {
                return Err(RecordError::Corrupt);
            }
            let block = self.object(child)?;
            let expected_len = (length - index * BLOCK_BYTES).min(BLOCK_BYTES);
            if child.payload_bytes != expected_len as u64 {
                return Err(RecordError::Corrupt);
            }
            encoded.extend_from_slice(&block.bytes[HEADER_BYTES..]);
            blocks.push(block);
        }
        if encoded.len() != length {
            return Err(RecordError::Corrupt);
        }
        let value = Arc::new(StoredValue::Referenced(ReferencedValue {
            object,
            blocks,
            encoded,
        }));
        self.values.insert(reference.id, value.clone());
        Ok(value)
    }
    fn page(&mut self, reference: &ObjectRef, height: u8) -> Result<Arc<Page>> {
        if height == 0
            || height > MAX_HEIGHT
            || (height == 1 && !matches!(reference.kind, ObjectKind::Leaf | ObjectKind::PackedLeaf))
            || (height > 1 && reference.kind != ObjectKind::Branch)
        {
            return Err(RecordError::Corrupt);
        }
        if let Some((observed_height, page)) = self.pages.get(&reference.id) {
            if *observed_height != height || page.object.reference != *reference {
                return Err(RecordError::Corrupt);
            }
            return Ok(page.clone());
        }
        if !self.visiting.insert(reference.id) {
            return Err(RecordError::Corrupt);
        }
        let object = self.object(reference)?;
        let mut decoder = Decoder {
            bytes: &object.bytes,
            offset: HEADER_BYTES,
        };
        let count = decoder.u16()?;
        let mut records = 0;
        let mut payload = 0;
        let data = if height == 1 {
            let mut entries: Vec<(Kv1Key, Arc<StoredValue>)> = Vec::with_capacity(count);
            for _ in 0..count {
                let key = decoder.key()?;
                if entries.last().is_some_and(|(prior, _)| prior >= &key) {
                    return Err(RecordError::Corrupt);
                }
                let value = if reference.kind == ObjectKind::PackedLeaf {
                    match decoder.tag()? {
                        0 => Arc::new(StoredValue::Inline(Zeroizing::new(
                            decoder.inline()?.to_vec(),
                        ))),
                        1 => self.value(&decoder.reference()?)?,
                        _ => return Err(RecordError::Corrupt),
                    }
                } else {
                    self.value(&decoder.reference()?)?
                };
                records = add(records, 1)?;
                payload = add(payload, value.encoded().len() as u64)?;
                entries.push((key, value));
            }
            PageData::Leaf(entries)
        } else {
            let mut children: Vec<Arc<Page>> = Vec::with_capacity(count);
            for _ in 0..count {
                let key = decoder.key()?;
                let child = decoder.reference()?;
                let page = self.page(&child, height - 1)?;
                if page.first() != &key
                    || children
                        .last()
                        .is_some_and(|prior| prior.last() >= page.first())
                {
                    return Err(RecordError::Corrupt);
                }
                records = add(records, child.record_count)?;
                payload = add(payload, child.payload_bytes)?;
                children.push(page);
            }
            PageData::Branch(children)
        };
        decoder.done()?;
        if records != reference.record_count || payload != reference.payload_bytes {
            return Err(RecordError::Corrupt);
        }
        let page = Arc::new(Page::checked(object, data)?);
        self.visiting.remove(&reference.id);
        self.pages.insert(reference.id, (height, page.clone()));
        Ok(page)
    }
}

pub(super) fn open(
    address_key: Arc<AddressKey>,
    root: Kv1Root,
    reader: &impl RecordReader,
) -> Result<Kv1Index> {
    let Some(reference) = root.reference else {
        return if root.height == 0 {
            Ok(Kv1Index::empty(address_key))
        } else {
            Err(RecordError::Corrupt)
        };
    };
    let mut loader = Loader {
        key: &address_key,
        reader,
        total_bytes: 0,
        objects: BTreeMap::new(),
        values: BTreeMap::new(),
        pages: BTreeMap::new(),
        visiting: BTreeSet::new(),
    };
    let page = loader.page(&reference, root.height)?;
    if matches!(&page.data, PageData::Branch(children) if children.len() == 1) {
        return Err(RecordError::Corrupt);
    }
    Ok(Kv1Index {
        address_key,
        root: Some(page),
        height: root.height,
    })
}
