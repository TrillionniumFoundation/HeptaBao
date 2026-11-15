//! Read-only live Identity evidence for deferred approval.
use super::*;
impl IdentityState {
    pub(crate) fn control_group_ids(
        &self,
        ids: &BTreeSet<String>,
        names: &BTreeSet<String>,
    ) -> Result<BTreeSet<String>> {
        let mut result = ids.clone();
        for name in names {
            result.insert(
                self.group_names
                    .get(name)
                    .ok_or_else(|| error(403, "control group is unavailable"))?
                    .clone(),
            );
        }
        if result.is_empty() || result.iter().any(|id| !self.groups.contains_key(id)) {
            return Err(error(403, "control group is unavailable"));
        }
        Ok(result)
    }
    pub(crate) fn control_group_entity(
        &self,
        id: &str,
        namespace_id: &str,
        mount_type: impl Fn(&str) -> Option<String>,
    ) -> Result<Value> {
        let entity = self
            .entities
            .get(id)
            .ok_or_else(|| error(403, "control group entity is unavailable"))?;
        if entity.disabled {
            return Err(error(403, "control group entity is disabled"));
        }
        let aliases = entity.aliases.iter().map(|id| {
            let alias = self.aliases.get(id).ok_or_else(|| error(503, "control group entity alias is unavailable"))?;
            let kind = mount_type(&alias.mount_accessor).ok_or_else(|| error(403, "control group alias mount is unavailable"))?;
            Ok(json!({"ID":alias.id,"mount_accessor":alias.mount_accessor,"mount_type":kind,"name":alias.name,"namespace_id":namespace_id}))
        }).collect::<Result<Vec<_>>>()?;
        Ok(json!({"ID":entity.id,"name":entity.name,"namespace_id":namespace_id,"aliases":aliases}))
    }
}
