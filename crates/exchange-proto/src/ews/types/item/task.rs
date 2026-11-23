/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::ews::{
    schema::{TaskDelegateState, TaskStatus},
    types::{
        recurrence::Recurrence,
        value::{DateTime, Strings, ews_fields},
    },
};
use std::borrow::Cow;

ews_fields! {
    pub struct TaskFields<'x> {
        actual_work: "ActualWork" => i32,
        assigned_time: "AssignedTime" => DateTime,
        billing_information: "BillingInformation" => Cow<'x, str>,
        change_count: "ChangeCount" => i32,
        companies: "Companies" => Strings<'x>,
        complete_date: "CompleteDate" => DateTime,
        contacts: "Contacts" => Strings<'x>,
        delegation_state: "DelegationState" => TaskDelegateState,
        delegator: "Delegator" => Cow<'x, str>,
        due_date: "DueDate" => DateTime,
        is_assignment_editable: "IsAssignmentEditable" => i32,
        is_complete: "IsComplete" => bool,
        is_recurring: "IsRecurring" => bool,
        is_team_task: "IsTeamTask" => bool,
        mileage: "Mileage" => Cow<'x, str>,
        owner: "Owner" => Cow<'x, str>,
        percent_complete: "PercentComplete" => f64,
        recurrence: "Recurrence" => Box<Recurrence>,
        start_date: "StartDate" => DateTime,
        status: "Status" => TaskStatus,
        status_description: "StatusDescription" => Cow<'x, str>,
        total_work: "TotalWork" => i32,
    }
}
