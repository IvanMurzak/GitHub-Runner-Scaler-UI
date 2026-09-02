# Runner workspace locations: acceptance evidence

Every gate the runner-workspace-locations work has to clear, and the named thing
that clears it.

This file is **machine-checked**. `crates/app/tests/workspace_acceptance_evidence.rs`
parses it and fails when:

- an item under `## Required evidence` names no evidence at all;
- a `test` entry names something that is not a test function in the repository —
  renamed, deleted, or no longer carrying `#[test]` (each is a gate that quietly
  stopped being one, and the attribute is checked rather than just the name so
  that a gate demoted to a helper cannot keep its record);
- a `pilot` entry names a command that is not in `.github/workflows/ci.yml`, so
  a privileged gate cannot be recorded here while being deleted from CI;
- the item list disagrees with the `Required evidence before merge` list in
  `.taskflow/2026-08-31-runner-workspace-locations/ROADMAP.md`, while that
  Taskflow is still present in the tree.

The format is fixed because it is parsed: `### <item>` introduces one gate, and
every following ``- test `name` `` / ``- pilot `command` `` line is its evidence
until the next `###`.

## What "pilot" means here

A `pilot` entry is a command that only a privileged, real host can run, so its
result is CI's answer and not a developer laptop's. The entries below are
`#[ignore]`d Windows tests driven by the `service-install` job. Their wiring —
that the job still exists, still names them, still builds the fixture host, and
still checks the real runner root was put back — is itself asserted by
`crates/platform/tests/privileged_tests_are_wired_into_ci.rs`, which is not
ignored.

**Not run on the machine that last edited this file.** Registering a Windows
service and re-permissioning `%SystemDrive%\rman` needs an elevated Windows host;
where that was unavailable the pilot rows record the command and the job that
runs it, and claim nothing about a local result.

## Required evidence

### Version-2 database migrates to version 3 without retaining any existing workspace.

- test `a_version_two_database_migrates_every_row_to_ephemeral`
- test `a_version_one_database_migrates_through_the_whole_chain`
- test `a_production_like_version_two_database_upgrades_without_touching_a_directory`

### Existing journal paths recover before new root allocation.

- test `a_production_like_version_two_database_upgrades_without_touching_a_directory`
- test `startup_adopts_a_live_process_and_refuses_launch_before_recovery`
- test `recovery_stays_closed_for_unknown_policy_and_unreachable_attempts`
- test `an_injected_partial_deletion_quarantines_the_slot_across_a_restart`

### Windows default derives from the system drive and creates `rman` with the intended ACL.

- test `the_windows_default_is_the_system_drive_plus_rman`
- test `the_windows_default_ignores_a_rewritten_system_drive_variable`
- test `the_windows_default_is_this_machines_system_drive`
- test `this_platform_keeps_its_default_root_and_leases_a_repository_slot`
- test `a_boot_root_admits_system_and_administrators_and_nothing_else`
- test `a_login_root_admits_the_selected_account_with_modify_rather_than_full_control`
- test `the_descriptor_this_module_writes_grants_no_broad_write`
- pilot `--test privileged_service_installer`
- pilot `Join-Path $env:SystemDrive 'rman'`

### Disposable success, failure, idle, and restart cases still remove the whole attempt directory.

- test `a_job_walks_every_state_and_cleans_every_artifact`
- test `two_attempts_never_share_a_workspace_even_after_failure`
- test `an_idle_exit_is_not_a_failure_in_the_journal_or_events`
- test `spawn_before_starting_crash_recovers_pid_then_completes_and_cleans`
- test `a_surplus_attempt_is_cleaned_as_an_idle_exit_and_not_as_a_failure`
- test `cleanup_dispatches_on_the_journalled_kind_and_not_on_what_the_directory_holds`
- test `an_injected_deletion_failure_leaves_a_disposable_attempt_uncleaned`

### Persistent sequential jobs reuse a stable slot and retain `_work`.

- test `two_sequential_allocations_at_capacity_one_reuse_s1_and_its_retained_work`
- test `two_sequential_jobs_keep_the_checkout_and_start_without_the_earlier_runner_state`
- test `changing_a_repository_back_to_ephemeral_leaves_every_old_slot_untouched`
- test `security_gate_persistent_retention_requires_both_directions`

### Persistent cleanup removes runner package copies, JIT handoff, process identity, runner registration identity, and lifecycle sidecars.

- test `a_scrub_retains_one_real_work_directory_and_removes_every_other_entry`
- test `verification_asks_the_filesystem_rather_than_the_listing_that_missed_an_entry`
- test `a_persistent_slot_is_scrubbed_only_after_the_process_is_signalled_and_gone`
- test `security_gate_persistent_retention_requires_both_directions`

### Concurrent attempts have unique slots before any GitHub effect.

- test `two_concurrent_allocations_never_share_a_slot`
- test `a_persistent_repository_leases_s1_and_journals_it_before_any_github_effect`
- test `slot_selection_fills_the_lowest_gap_and_stops_at_the_ceiling`
- test `this_platform_keeps_its_default_root_and_leases_a_repository_slot`

### A partial unique index rejects duplicate uncleaned persistent slot leases, including when the first attempt is terminal but cleanup is blocked.

- test `one_slot_is_leased_to_at_most_one_uncleaned_attempt`
- test `a_terminal_attempt_awaiting_cleanup_still_holds_its_slot`
- test `a_second_uncleaned_attempt_cannot_take_a_leased_slot_across_two_connections`
- test `the_database_is_the_final_fence_against_two_attempts_in_one_slot`
- test `the_slot_lease_index_guards_an_upgraded_database_immediately`

### Path overlap, root, traversal, symlink, junction, UNC, and unwritable cases fail closed.

- test `overlap_is_decided_component_by_component_on_both_platforms`
- test `a_root_that_collides_with_application_data_is_refused`
- test `two_roots_may_not_contain_one_another`
- test `filesystem_roots_are_rejected`
- test `traversal_is_rejected_rather_than_resolved`
- test `unc_paths_are_rejected`
- test `device_namespace_paths_are_rejected`
- test `a_linked_root_is_refused_rather_than_followed`
- test `a_remote_filesystem_is_refused`
- test `a_directory_this_account_cannot_write_is_reported_as_such`
- test `a_substituted_work_directory_quarantines_the_slot_and_deletes_nothing_outside_it`
- test `a_work_directory_replaced_by_a_junction_fails_closed_and_deletes_nothing_beyond_it`
- test `a_slot_replaced_by_a_link_out_of_its_root_is_refused_before_anything_is_read`
- test `a_slot_root_replaced_by_a_junction_is_refused_before_anything_is_read`
- test `every_adversarial_root_is_refused_by_both_commands_and_changes_nothing`
- test `a_repository_root_may_not_be_carved_out_of_the_host_runner_root`

### Host and repository path writes atomically fence uncleaned attempts and do not overwrite concurrent host or policy settings.

- test `the_host_root_mutation_writes_only_its_own_column`
- test `the_host_root_mutation_refuses_a_changed_expected_override`
- test `the_host_root_mutation_refuses_a_changed_uncleaned_ephemeral_count`
- test `the_policy_workspace_mutation_confirms_revision_and_uncleaned_count`
- test `a_host_root_change_does_not_roll_back_a_concurrent_capacity_change`
- test `a_repository_workspace_change_is_refused_by_an_uncleaned_attempt_alone`
- test `moving_a_persistent_root_is_non_destructive`

### CLI and TUI produce the same stored values and validation outcomes.

- test `tui_and_cli_store_byte_identical_workspace_values_and_render_one_message`
- test `every_validation_fixture_is_refused_with_the_same_reason_from_both_surfaces`
- test `the_human_and_json_renderings_identify_the_same_source`
- test `persistent_mode_previews_the_whole_trust_warning_and_the_retained_directories`

### README commands match generated help and use placeholder paths.

- test `the_generated_help_matches_the_four_reviewed_commands`
- test `the_customization_section_carries_every_complete_workspace_command`
- test `the_customization_section_states_the_platform_runner_root_defaults`
- test `the_persistent_guidance_states_the_trust_boundary_it_gives_up`
- test `the_customization_section_promises_no_directory_is_deleted_on_a_change`

### Full workspace tests and all existing README release gates remain green.

- pilot `cargo fmt --check`
- pilot `cargo clippy --all-targets -- -D warnings`
- pilot `cargo test --workspace`
- pilot `assert-no-shippable-mutants.sh --scan-only`

## Rollback gate

Not part of the ROADMAP list above, and asserted for the same reason: a rollback
that took a directory with it would be discovered by an operator rather than by
this repository.

### A backup taken before the upgrade restores the old database and leaves every workspace directory in place.

- test `a_backup_taken_before_the_upgrade_rolls_back_without_deleting_a_directory`

### An older build refuses a database from a newer one rather than guessing at it.

- test `a_database_from_a_newer_build_is_refused_with_both_numbers`
- test `a_database_from_a_newer_build_is_refused_rather_than_guessed_at`

## Secret posture

`04-security-recovery.md`'s security gates, which span the whole feature rather
than one of the items above.

### No JIT value, token, or credential reaches the database, a slot root, the logs, status JSON, a TUI frame, or a crash report.

- test `a_full_cycle_leaves_no_token_shaped_value_outside_the_store`
- test `no_secret_reaches_the_output_of_any_command`
- test `no_secret_reaches_the_diagnostics_at_trace_level`
- test `no_jit_config_reaches_the_logs`
- test `no_field_of_the_document_is_a_place_to_put_a_credential`
- test `no_secret_reaches_a_settings_frame`
- test `no_fixture_database_or_its_dump_holds_a_token_shaped_value`
- test `diagnostics_survive_cleanup_without_the_jit_or_a_token`
- test `an_abnormal_exit_writes_no_crash_report`

### Supported platforms keep their defaults and support repository persistent slots.

- test `the_macos_and_linux_defaults_are_the_existing_runtime_directory`
- test `the_application_runtime_directory_arm_changes_nothing`
- test `this_platform_keeps_its_default_root_and_leases_a_repository_slot`
