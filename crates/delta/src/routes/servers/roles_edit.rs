use revolt_quark::{
    models::{
        server::{FieldsRole, PartialRole, Role},
        User,
    },
    perms,
    util::regex::RE_COLOUR,
    Db, Error, Permission, Ref, Result,
};

use rocket::serde::json::Json;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use validator::Validate;

/// # Role Data
#[derive(Validate, Serialize, Deserialize, JsonSchema)]
pub struct DataEditRole {
    /// Role name
    #[validate(length(min = 1, max = 32))]
    name: Option<String>,
    /// Role colour
    #[validate(length(min = 1, max = 128), regex = "RE_COLOUR")]
    colour: Option<String>,
    /// Whether this role should be displayed separately
    hoist: Option<bool>,
    /// Ranking position
    ///
    /// Smaller values take priority.
    rank: Option<i64>,
    /// Fields to remove from role object
    #[validate(length(min = 1))]
    remove: Option<Vec<FieldsRole>>,

    ///role_requestable
    role_requestable: Option<bool>,

    /// Info required flag
    info_required: Option<bool>,

    /// Payment required flag
    payment_required: Option<bool>,

    /// Approvement required flag
    approvement_required: Option<bool>,

    /// Whether the role expires
    expires: Option<bool>,

    // /// Cost
    cost: Option<i64>,
    // /// Duration
    duration: Option<i64>,
    /// Duration type (e.g., months, years)
    duration_type: Option<String>,

    /// Approval roles
    approval_roles: Option<Vec<String>>,

    /// Custom fields (name, value name, field type)
    fields: Option<HashMap<String, (String, String)>>,
}

/// # Edit Role
///
/// Edit a role by its id.
#[openapi(tag = "Server Permissions")]
#[patch("/<target>/roles/<role_id>", data = "<data>")]
pub async fn req(
    db: &Db,
    user: User,
    target: Ref,
    role_id: String,
    data: Json<DataEditRole>,
) -> Result<Json<Role>> {
    let data = data.into_inner();
    data.validate()
        .map_err(|error| Error::FailedValidation { error })?;

    let mut server = target.as_server(db).await?;
    let mut permissions = perms(&user).server(&server);

    permissions
        .throw_permission(db, Permission::ManageRole)
        .await?;

    let member_rank = permissions.get_member_rank().unwrap_or(i64::MIN);

    if let Some(mut role) = server.roles.remove(&role_id) {
        let DataEditRole {
            name,
            colour,
            hoist,
            rank,
            remove,
            cost,
            //add reamining fields
            role_requestable,
            info_required,
            payment_required,
            approvement_required,
            expires,
            duration,
            duration_type,
            approval_roles,
            fields,
        } = data;

        if let Some(rank) = &rank {
            if rank <= &member_rank {
                return Err(Error::NotElevated);
            }
        }

        let partial = PartialRole {
            name,
            colour,
            hoist,
            rank,
            cost,
            info_required,
            payment_required,
            role_requestable,
            approvement_required,
            expires,
            duration,
            duration_type,
            approval_roles,
            fields,
            ..Default::default()
        };

        role.update(
            db,
            &server.id,
            &role_id,
            partial,
            remove.unwrap_or_default(),
        )
        .await?;

        Ok(Json(role))
    } else {
        Err(Error::NotFound)
    }
}
