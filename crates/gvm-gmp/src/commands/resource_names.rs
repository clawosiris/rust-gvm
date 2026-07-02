// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Resource-name command builders.

/// Re-export of the system resource-name helpers.
pub use crate::commands::system::{get_resource_name, get_resource_names, GetResourceNamesOpts};
pub use crate::enums::ResourceType;

#[cfg(test)]
mod tests {
    use crate::commands::resource_names::{
        get_resource_name, get_resource_names, GetResourceNamesOpts, ResourceType,
    };
    use crate::common::xml;
    use crate::types::EntityId;

    #[test]
    fn resource_names_command_builds_xml() {
        let rendered = xml(get_resource_names(GetResourceNamesOpts {
            resource_type: Some(ResourceType::Target),
            resource_id: Some(EntityId::new("t1").expect("valid id")),
            ..Default::default()
        }));
        assert!(rendered.contains("type=\"TARGET\""));
        assert!(rendered.contains("resource_id=\"t1\""));
    }

    #[test]
    fn resource_name_command_builds_xml() {
        assert_eq!(
            xml(get_resource_name(
                &EntityId::new("t1").expect("valid id"),
                ResourceType::Task,
            )),
            "<get_resource_names resource_id=\"t1\" type=\"TASK\"/>"
        );
    }
}
