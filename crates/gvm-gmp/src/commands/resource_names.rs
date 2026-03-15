//! Resource-name command builders.

/// Re-export of the system `get_resource_names` helpers.
pub use crate::commands::system::{get_resource_names, GetResourceNamesOpts};

#[cfg(test)]
mod tests {
    use crate::commands::resource_names::{get_resource_names, GetResourceNamesOpts};
    use crate::common::xml;
    use crate::enums::EntityType;
    use crate::types::EntityId;

    #[test]
    fn resource_names_command_builds_xml() {
        let rendered = xml(get_resource_names(GetResourceNamesOpts {
            resource_type: Some(EntityType::Target),
            resource_id: Some(EntityId::new("t1").expect("valid id")),
            ..Default::default()
        }));
        assert!(rendered.contains("type=\"target\""));
        assert!(rendered.contains("resource_id=\"t1\""));
    }
}
