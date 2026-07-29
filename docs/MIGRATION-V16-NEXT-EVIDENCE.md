# MIGRATION-V16-NEXT-EVIDENCE — full verbatim gate output + the per-hunk tripwire ledger

Round-5 evidence for the V16-NOW migration (`docs/MIGRATION-V16-NEXT.md`). Diff base: `8a3fb04`
(the `feat/v16-now-migration` working tree; nothing committed). Gates run at the repo root.
Nothing below is summarized or elided: each fenced block is the complete stdout+stderr of the
command as captured by redirecting it to a file, with the process exit code appended as the
final `*_EXIT=` line.

## 1. Full verbatim gate output

Captured in round 5, on the final working-tree state (the only edit after this capture is this
file's own §1 block — the code, tests, and §2 ledger are exactly what these commands ran
against).

### 1.1 `cargo build --workspace --locked --release`

```
    Finished `release` profile [optimized] target(s) in 0.29s
BUILD_EXIT=0
```

### 1.2 `cargo test --workspace --locked --release`

```
   Compiling xusdc-encoding v0.0.0 (/home/agent/work/miden-usdcx/crates/xusdc-encoding)
    Finished `release` profile [optimized] target(s) in 1.10s
     Running unittests src/lib.rs (/home/agent/work/v16-scratch-target/release/deps/withdrawal_listener_attester-72bed5056ad7ea72)

running 3 tests
test idempotency::store::store_tests::claiming_the_same_burn_twice_yields_claimed_then_already_seen ... ok
test idempotency::store::store_tests::a_submitted_burn_cannot_be_walked_back_to_failed ... ok
test idempotency::store::store_tests::a_multi_burn_claim_that_hits_an_already_seen_burn_claims_nothing ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/auth_posture.rs (/home/agent/work/v16-scratch-target/release/deps/auth_posture-2a977f73052c6702)

running 10 tests
test an_out_of_band_key_is_configurable_without_the_scheme_being_presumed ... ok
test no_debug_or_display_rendering_can_print_the_key ... ok
test an_illegal_header_name_or_a_value_carrying_a_control_character_is_refused ... ok
test the_auth_module_records_q_api_auth_as_open_and_never_as_resolved ... ok
test the_credential_scanner_catches_a_planted_credential ... ok
test a_configured_credential_over_a_plaintext_base_url_is_refused_at_construction ... ok
test the_default_config_carries_no_credential_and_the_default_posture_sends_no_header ... ok
test the_documented_no_auth_contract_is_a_fully_usable_configuration ... ok
test no_authorization_scheme_is_named_anywhere_in_the_crate_source ... ok
test no_credential_literal_is_baked_into_the_crate_source ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/build_prepare_request.rs (/home/agent/work/v16-scratch-target/release/deps/build_prepare_request-0ded3c2fd3622c22)

running 11 tests
test exactly_one_value_field_is_set ... ok
test distinct_senders_yield_distinct_depositors ... ok
test happy_path_maps_every_field ... ok
test rejects_when_domains_are_equal ... ok
test remote_depositor_is_dc6_of_sender ... ok
test rebuild_is_stable_including_salt ... ok
test rejects_when_remote_domain_below_minimum ... ok
test salt_is_the_burn_payload_salt ... ok
test value_xor_rejects_both_and_neither ... ok
test serialized_request_has_no_source_depositor_key ... ok
test serialized_request_has_no_binary_or_response_artifacts ... ok

test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/build_withdraw_request.rs (/home/agent/work/v16-scratch-target/release/deps/build_withdraw_request-f1452717d55ebfb6)

running 9 tests
test batch_accepts_ten_burn_intents ... ok
test batch_rejects_zero_burn_intents ... ok
test batch_rejects_eleven_burn_intents ... ok
test builds_a_single_batch_request ... ok
test fixture_burn_intents_are_nonempty ... ok
test rejects_zero_batches ... ok
test builds_the_maximum_five_batches ... ok
test serialized_request_is_the_batches_wrapper_not_a_bare_array ... ok
test rejects_six_batches ... ok

test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/config_validation.rs (/home/agent/work/v16-scratch-target/release/deps/config_validation-f4a6dc03fef51f01)

running 14 tests
test a_config_file_carrying_a_credential_over_plaintext_http_is_refused ... ok
test a_header_name_without_a_token_is_harmless ... ok
test a_token_without_an_explicit_header_name_is_refused_on_both_paths ... ok
test a_plaintext_base_url_without_a_credential_is_still_allowed ... ok
test a_loaded_config_reserializes_with_its_key_intact_but_never_renders_it ... ok
test an_explicitly_named_header_carries_the_key_and_nothing_is_presumed ... ok
test the_baseline_config_file_loads_so_every_negative_below_isolates_one_rule ... ok
test the_builder_and_serde_refuse_exactly_the_same_invalid_states::case_1_plaintext_with_credential ... ok
test the_builder_and_serde_refuse_exactly_the_same_invalid_states::case_3_empty_url ... ok
test the_builder_and_serde_refuse_exactly_the_same_invalid_states::case_6_malformed_faucet_id ... ok
test the_builder_and_serde_refuse_exactly_the_same_invalid_states::case_4_unsupported_scheme ... ok
test the_builder_and_serde_refuse_exactly_the_same_invalid_states::case_2_not_a_url ... ok
test the_package_default_names_no_auth_header_at_all ... ok
test the_builder_and_serde_refuse_exactly_the_same_invalid_states::case_5_token_without_a_header_name ... ok

test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/conflict_evidence.rs (/home/agent/work/v16-scratch-target/release/deps/conflict_evidence-ca650331e6bca506)

running 9 tests
test a_recovered_status_mismatch_binds_the_id_only_to_the_conflict_named_burn ... ok
test a_201_binds_each_burn_to_its_own_returned_withdrawal_id ... ok
test a_non_finalized_recovery_binds_the_id_only_to_the_named_burn ... ok
test a_conflict_without_a_withdrawal_id_binds_none_to_any_burn ... ok
test a_failed_recovery_poll_binds_the_id_only_to_the_conflict_named_burn ... ok
test a_multi_burn_conflict_echo_mismatch_binds_its_withdrawal_id_to_no_burn ... ok
test a_conflict_echo_mismatch_binds_its_withdrawal_id_to_no_burn ... ok
test a_successful_recovery_binds_the_id_only_to_the_named_burn ... ok
test an_exhausted_retry_budget_binds_no_withdrawal_id ... ok

test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s

     Running tests/conflict_recovery.rs (/home/agent/work/v16-scratch-target/release/deps/conflict_recovery-c1304b6d93ff8c90)

running 17 tests
test a_409_recovered_to_a_non_finalized_status_is_not_success::case_2_expired ... ok
test a_409_recovered_to_finalized_settles_the_burn_as_finalized ... ok
test a_409_never_yields_the_submitted_success_variant::case_1_with_withdrawal_id ... ok
test a_409_never_yields_the_submitted_success_variant::case_2_burn_tx_id_only ... ok
test a_409_echoing_a_different_burn_tx_id_is_a_defect_not_a_recovery ... ok
test a_409_recovered_to_a_non_finalized_status_is_not_success::case_1_failed ... ok
test a_409_naming_one_burn_of_many_blocks_the_rest_without_claiming_their_state ... ok
test a_409_with_a_withdrawal_id_recovers_by_polling_and_never_reposts ... ok
test a_409_with_an_undecodable_body_is_an_exact_err_and_never_resubmits::case_1_no_burn_tx_id ... ok
test a_409_naming_one_burn_never_finalizes_the_other_burns ... ok
test a_409_with_an_undecodable_body_is_an_exact_err_and_never_resubmits::case_2_burn_tx_id_not_hex ... ok
test a_409_with_only_a_burn_tx_id_stops_and_marks_reconciliation_required ... ok
test a_recovery_poll_that_fails_leaves_the_burn_blocked_and_surfaces ... ok
test a_recovered_status_must_echo_the_burn_the_conflict_named_not_merely_any_submitted_burn ... ok
test a_409_without_a_withdrawal_id_blocks_every_burn_in_the_request ... ok
test a_409_with_an_undecodable_body_is_an_exact_err_and_never_resubmits::case_3_not_an_object ... ok
test a_recovered_status_for_another_burn_tx_id_is_a_defect ... ok

test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s

     Running tests/crate_posture.rs (/home/agent/work/v16-scratch-target/release/deps/crate_posture-4963f358fa6b0d70)

running 15 tests
test a_base_url_that_is_not_http_or_https_is_refused_at_construction::case_1_empty ... ok
test a_base_url_that_is_not_http_or_https_is_refused_at_construction::case_2_not_a_url ... ok
test an_attester_key_handle_is_an_identifier_and_never_key_material ... ok
test k256_is_a_library_dependency_because_the_attester_signs_in_production ... ok
test the_burn_payload_is_unit_04s_type_not_a_second_copy_of_it ... ok
test the_burn_tag_is_a_full_32_bit_value_carried_verbatim ... ok
test the_config_carries_the_five_static_parameters_the_spec_names ... ok
test the_evidence_package_labels_each_element_with_its_documented_proof_strength ... ok
test miden_client_is_absent_from_the_graph ... ok
test the_remote_depositor_encoding_is_unit_04s_account_id_codec_consumed_by_reference ... ok
test a_base_url_that_is_not_http_or_https_is_refused_at_construction::case_3_unsupported_scheme ... ok
test the_shared_dependencies_are_consumed_from_the_workspace_table ... ok
test the_config_round_trips_through_serde_with_the_faucet_id_as_hex ... ok
test no_implementation_file_carries_an_inline_test_module ... ok
test no_source_file_exceeds_the_governing_rust_line_ceiling ... ok

test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/evidence_structural_absence.rs (/home/agent/work/v16-scratch-target/release/deps/evidence_structural_absence-b5b46af41d52577a)

running 14 tests
test a_burn_tx_id_and_a_spend_observation_without_the_note_yield_no_evidence ... ok
test an_evidence_package_cannot_be_constructed_outside_the_crate ... ok
test an_invented_evidence_field_is_refused_by_the_withdraw_schema::case_4_evidence ... ok
test an_invented_evidence_field_is_refused_by_the_withdraw_schema::case_3_block_num ... ok
test an_invented_evidence_field_is_refused_by_the_withdraw_schema::case_2_nullifier ... ok
test an_invented_evidence_field_is_refused_by_the_withdraw_schema::case_1_note_id ... ok
test the_assembler_has_no_by_transaction_entry_point ... ok
test no_port_method_resolves_a_transaction_by_its_hash ... ok
test the_source_sweep_reads_declarations_and_not_prose ... ok
test the_deferred_upgrade_leaves_the_tx_linkage_node_trusted ... ok
test the_full_block_upgrade_returns_its_exact_deferral_error ... ok
test the_module_has_no_panicking_placeholder ... ok
test the_withdraw_wire_carries_burn_tx_id_and_no_other_evidence_field ... ok
test the_assembler_is_the_only_construction_site_for_a_package ... ok

test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/evidence_trust_labeling.rs (/home/agent/work/v16-scratch-target/release/deps/evidence_trust_labeling-9c9e7b69579019c6)

running 28 tests
test a_contradictory_row_is_caught_even_when_the_filter_would_have_dropped_it ... ok
test a_creation_fact_is_not_a_consumption_claim::case_1_creation ... ok
test a_creation_fact_is_not_a_consumption_claim::case_2_linkage ... ok
test a_creation_fact_is_not_a_consumption_claim::case_3_spend ... ok
test a_creation_proof_without_an_observed_spend_never_yields_a_package ... ok
test a_failing_read_surfaces_rather_than_reading_as_no_burn::case_1_note ... ok
test a_failing_read_surfaces_rather_than_reading_as_no_burn::case_2_transactions ... ok
test a_failing_read_surfaces_rather_than_reading_as_no_burn::case_3_nullifiers ... ok
test a_port_answering_about_a_different_nullifier_is_refused ... ok
test a_spend_at_or_before_the_creation_block_is_refused::case_1_same_block ... ok
test a_private_note_is_rejected_as_unobservable ... ok
test a_spend_block_that_disagrees_with_the_linkage_is_refused ... ok
test another_accounts_transaction_is_not_accepted_as_the_faucets_burn ... ok
test a_port_answering_about_a_different_note_is_refused ... ok
test block_num_is_read_from_the_inclusion_proof_not_from_the_node_trusted_linkage ... ok
test a_transaction_that_merely_created_the_note_is_never_accepted_as_the_burn ... ok
test a_spend_at_or_before_the_creation_block_is_refused::case_2_before ... ok
test conflicting_rows_for_one_transaction_id_are_refused_in_either_order::case_2_conflicting_row_first ... ok
test each_element_names_the_fact_it_actually_proves ... ok
test no_element_is_both_cryptographic_and_a_consumption_claim ... ok
test the_burn_happened_claim_is_node_trusted_however_strong_the_creation_proof_is ... ok
test the_burn_tx_id_is_the_consuming_transaction_not_the_creating_one ... ok
test the_package_and_its_labels_are_stable_across_reassembly ... ok
test the_package_carries_the_documented_per_element_proof_strengths ... ok
test the_package_carries_the_four_elements_it_read ... ok
test the_same_transaction_reported_twice_is_not_an_ambiguity ... ok
test conflicting_rows_for_one_transaction_id_are_refused_in_either_order::case_1_honest_row_first ... ok
test two_transactions_claiming_the_same_burn_are_refused_rather_than_picked_between ... ok

test result: ok. 28 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/fixture_fidelity.rs (/home/agent/work/v16-scratch-target/release/deps/fixture_fidelity-5d3a82c73d4af0bd)

running 10 tests
test exactly_the_thirteen_required_fixtures_are_present ... ok
test prepare_withdrawal_200_matches_the_prepare_withdrawal_response_schema ... ok
test no_request_side_fixture_carries_a_source_depositor_outside_a_circle_returned_spec ... ok
test the_malformed_body_violates_the_schema_in_the_three_ways_it_claims_to ... ok
test the_undocumented_error_bodies_stay_content_free ... ok
test the_two_prepare_error_fixtures_are_the_shapes_they_claim_to_be ... ok
test the_threshold_violating_fixture_is_a_well_formed_request_that_breaks_the_signature_rules ... ok
test withdraw_201_is_an_array_of_schema_exact_statuses ... ok
test withdraw_failed_status_is_the_terminal_failed_shape ... ok
test withdrawal_status_200_is_the_same_object_shape_not_an_array ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/listener_orchestration.rs (/home/agent/work/v16-scratch-target/release/deps/listener_orchestration-b38fd7d85c428050)

running 24 tests
test a_batch_carrying_no_burn_intent_is_refused_before_the_signer ... ok
test a_batch_carrying_the_burn_intent_more_than_once_is_refused_before_the_signer::case_3_the_schema_maximum ... ok
test a_b5_spec_mismatch_produces_no_signature_and_no_withdraw::case_1_amount ... ok
test a_batch_carrying_the_burn_intent_more_than_once_is_refused_before_the_signer::case_2_three_intents ... ok
test a_b5_spec_mismatch_produces_no_signature_and_no_withdraw::case_2_destination_domain ... ok
test a_b5_spec_mismatch_produces_no_signature_and_no_withdraw::case_3_destination_recipient ... ok
test a_batch_carrying_the_burn_intent_more_than_once_is_refused_before_the_signer::case_1_two_intents ... ok
test a_failed_prepare_never_reaches_the_signer::case_1_bad_request ... ok
test a_failed_prepare_never_reaches_the_signer::case_2_server_error ... ok
test a_non_finalized_poll_answer_never_settles_the_burn::case_1_expired ... ok
test a_finalized_poll_settles_the_burn_in_the_ledger ... ok
test a_signer_whose_sets_do_not_line_up_with_the_batches_never_submits::case_2_too_many ... ok
test a_non_signable_digest_is_refused_before_the_signer::case_2_short ... ok
test a_signer_whose_sets_do_not_line_up_with_the_batches_never_submits::case_1_too_few ... ok
test a_non_signable_digest_is_refused_before_the_signer::case_1_empty ... ok
test a_non_finalized_poll_answer_never_settles_the_burn::case_2_failed ... ok
test an_empty_prepare_response_is_refused_before_the_signer ... ok
test a_two_batch_prepare_response_is_refused_before_the_signer ... ok
test the_submitted_batch_carries_exactly_one_burn_intent ... ok
test re_running_a_mismatching_burn_aborts_again_and_still_never_signs ... ok
test the_wire_burn_tx_id_is_the_assembled_evidence_burn_tx_id ... ok
test happy_path_b3_to_b10_submits_exactly_one_withdrawal_with_two_signatures ... ok
test the_submitted_signatures_carry_the_on_chain_quorum_shape ... ok
test a_non_finalized_poll_answer_never_settles_the_burn::case_3_created ... ok

test result: ok. 24 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s

     Running tests/listener_quorum_and_conflict.rs (/home/agent/work/v16-scratch-target/release/deps/listener_quorum_and_conflict-57ff3fe2d17860d2)

running 18 tests
test a_private_note_is_refused_before_circle_is_touched ... ok
test a_signature_set_that_is_not_the_on_chain_shape_never_reaches_the_wire::case_1_below_threshold ... ok
test a_409_recovers_via_poll_and_never_re_sends ... ok
test a_descending_signature_set_never_reaches_the_wire ... ok
test a_failed_evidence_read_never_submits ... ok
test a_restarted_process_does_not_re_submit_a_claimed_burn ... ok
test a_409_echoing_another_burn_is_a_defect_and_is_not_chased ... ok
test a_409_naming_no_withdrawal_stops_and_requires_reconciliation ... ok
test a_signature_set_that_is_not_the_on_chain_shape_never_reaches_the_wire::case_2_above_threshold ... ok
test a_signature_that_does_not_verify_to_its_claimed_signer_never_reaches_the_wire ... ok
test a_signature_set_that_is_not_the_on_chain_shape_never_reaches_the_wire::case_3_duplicate_signer ... ok
test a_wrong_tag_note_is_refused_before_circle_is_touched ... ok
test an_empty_allowlist_fails_closed_and_never_submits ... ok
test evidence_with_no_observed_spend_blocks_the_burn_and_never_submits ... ok
test the_happy_path_emits_a_step_trace_in_flow_order ... ok
test re_running_an_already_withdrawn_burn_does_not_double_submit ... ok
test an_unregistered_signer_is_refused_after_signing_and_before_any_submit ... ok
test no_emitted_event_carries_key_material_or_a_credential ... ok

test result: ok. 18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s

     Running tests/listener_structural_absence.rs (/home/agent/work/v16-scratch-target/release/deps/listener_structural_absence-195a4bcc62ac047d)

running 11 tests
test the_bare_call_sweep_distinguishes_a_call_from_a_longer_identifier ... ok
test the_orchestration_never_calls_the_raw_signer ... ok
test the_orchestration_has_no_panicking_placeholder ... ok
test the_orchestration_never_constructs_a_batch_beside_the_quorum ... ok
test the_source_sweep_reads_declarations_and_not_prose ... ok
test the_batch_builder_cannot_express_an_intent_set ... ok
test there_is_no_independent_argument_prepare_request_builder ... ok
test the_wire_type_alone_would_accept_a_shape_circle_rejects ... ok
test the_assembler_mints_a_bundle_for_the_honest_shape ... ok
test the_orchestration_passes_the_discovered_burn_whole ... ok
test the_assembler_is_the_only_construction_site_for_a_quorum_bundle ... ok

test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/note_decode.rs (/home/agent/work/v16-scratch-target/release/deps/note_decode-61d4db78c1b39b2e)

running 21 tests
test t_la_01_decode_golden_items_field_by_field ... ok
test t_la_01_malformed_items_are_refused_exactly::case_3 ... ok
test t_la_01_decodes_the_boundary_payload ... ok
test t_la_01_decode_round_trips_to_the_golden_felts ... ok
test t_la_01_decode_is_the_unit_04_codec_by_reference ... ok
test t_la_01_malformed_items_are_refused_exactly::case_1 ... ok
test t_la_01_malformed_items_are_refused_exactly::case_2 ... ok
test t_la_01_felt_count_boundaries_are_refused ... ok
test t_la_01_unit_04_error_is_preserved_as_the_source ... ok
test t_la_01_malformed_items_are_refused_exactly::case_4 ... ok
test t_la_04_absent_sender_is_refused ... ok
test t_la_04_canonical_raw_sender_reads_back ... ok
test t_la_04_sender_feeds_remote_depositor ... ok
test t_la_01_malformed_items_are_refused_exactly::case_5 ... ok
test t_la_01_malformed_items_are_refused_exactly::case_6 ... ok
test t_la_04_non_canonical_sender_is_refused::case_1_zero_prefix_unknown_version ... ok
test t_la_04_zero_sender_is_refused ... ok
test t_la_04_non_canonical_sender_is_refused::case_2_version_two_prefix ... ok
test t_la_01_recipient_and_salt_are_not_interchangeable ... ok
test t_la_04_sender_is_read_from_metadata ... ok
test t_la_04_sender_with_invalid_suffix_is_refused ... ok

test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/offchain_signing.rs (/home/agent/work/v16-scratch-target/release/deps/offchain_signing-e4f45c022f882340)

running 22 tests
test evm_v_mapping_rejects_x_reduced_recovery_ids::case_1 ... ok
test evm_v_mapping_rejects_x_reduced_recovery_ids::case_3 ... ok
test evm_v_mapping_rejects_x_reduced_recovery_ids::case_2 ... ok
test non_32_byte_digest_is_rejected::case_2_one_short ... ok
test non_32_byte_digest_is_rejected::case_4_double ... ok
test signature65_from_bytes_round_trips_exactly_65 ... ok
test distinct_signers_produce_distinct_signatures ... ok
test sign_produces_65_bytes_that_verify_against_the_pubkey ... ok
test sign_signs_the_digest_opaquely_recoverable_to_the_signer ... ok
test non_32_byte_digest_is_rejected::case_3_one_long ... ok
test evm_v_mapping_rejects_x_reduced_recovery_ids::case_4 ... ok
test non_32_byte_digest_is_rejected::case_1_empty ... ok
test signature65_rejects_non_65_byte_forms::case_2_r_s_only ... ok
test signature65_rejects_non_65_byte_forms::case_1_empty ... ok
test signature65_rejects_non_65_byte_forms::case_3_der_ish ... ok
test signature65_rejects_non_65_byte_forms::case_4_one_long ... ok
test signature_wire_form_is_r_s_v_hex ... ok
test signature_does_not_verify_under_a_foreign_pubkey ... ok
test signature_over_one_hash_does_not_verify_against_another ... ok
test signature_is_low_s_normalized ... ok
test signature_v_is_evm_27_or_28 ... ok
test signing_is_deterministic ... ok

test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/quorum_assembly.rs (/home/agent/work/v16-scratch-target/release/deps/quorum_assembly-432df5d0c5c72ea4)

running 19 tests
test recover_address_rejects_x_reduced_v::case_1_v29 ... ok
test one_signature_is_below_threshold ... ok
test recover_address_accepts_a_real_evm_signature ... ok
test recover_address_rejects_x_reduced_v::case_2_v30 ... ok
test descending_addresses_are_rejected ... ok
test signature_with_non_evm_v_does_not_verify::case_1_raw_zero ... ok
test signature_not_from_claimed_signer_is_rejected ... ok
test signature_over_a_different_digest_does_not_verify ... ok
test signature_with_non_evm_v_does_not_verify::case_2_raw_one ... ok
test signature_with_non_evm_v_does_not_verify::case_3_just_below ... ok
test signature_with_non_evm_v_does_not_verify::case_5_x_reduced_30 ... ok
test zero_signatures_is_below_threshold ... ok
test signature_with_non_evm_v_does_not_verify::case_6_just_above ... ok
test signature_with_non_evm_v_does_not_verify::case_7_max ... ok
test signature_with_non_evm_v_does_not_verify::case_4_x_reduced_29 ... ok
test duplicate_signer_is_rejected ... ok
test assembles_exactly_two_ascending_verifying_signatures ... ok
test three_signatures_are_above_threshold ... ok
test assembly_is_deterministic ... ok

test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/rate_ceilings.rs (/home/agent/work/v16-scratch-target/release/deps/rate_ceilings-63708da6ec038f0f)

running 12 tests
test a_zero_ceiling_is_clamped_so_a_window_can_never_fail_to_open ... ok
test the_documented_ceilings_are_five_per_ip_and_thirty_five_global ... ok
test the_prepare_driver_takes_a_rate_permit ... ok
test every_request_the_withdrawal_flow_makes_takes_exactly_one_permit ... ok
test a_409_recovery_poll_takes_a_rate_permit_for_every_get ... ok
test a_retried_attempt_takes_exactly_one_permit_per_attempt ... ok
test clients_sharing_a_governor_share_one_budget ... ok
test the_per_ip_window_is_keyed_by_host ... ok
test the_rate_governor_enforces_the_global_ceiling_across_hosts ... ok
test the_rate_governor_enforces_the_per_ip_ceiling ... ok
test a_409_recovery_poll_waits_for_the_ceiling ... ok
test the_submit_retries_take_a_rate_permit_for_every_attempt ... ok

test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.02s

     Running tests/retry_policy.rs (/home/agent/work/v16-scratch-target/release/deps/retry_policy-e76b81bd2059df75)

running 27 tests
test a_409_is_never_retried ... ok
test a_zero_attempt_budget_is_clamped_so_the_request_is_still_tried_once ... ok
test a_201_echoing_a_burn_that_was_not_submitted_is_a_defect ... ok
test neither_a_status_less_failure_nor_a_malformed_body_is_retryable ... ok
test a_status_less_transport_failure_is_attempted_exactly_once_and_surfaced ... ok
test a_201_body_that_does_not_decode_is_rejected_and_nothing_is_acted_on ... ok
test a_deterministic_400_is_not_retried ... ok
test a_400_leaves_the_burn_re_claimable_for_a_fixed_request ... ok
test the_backoff_grows_exponentially_from_the_base_and_saturates ... ok
test the_retry_classification_matches_the_spec::case_01_http_500 ... ok
test the_retry_classification_matches_the_spec::case_02_http_502 ... ok
test the_retry_classification_matches_the_spec::case_03_http_503 ... ok
test the_retry_classification_matches_the_spec::case_04_http_599 ... ok
test the_retry_classification_matches_the_spec::case_05_http_400 ... ok
test the_retry_classification_matches_the_spec::case_06_http_404 ... ok
test the_retry_classification_matches_the_spec::case_07_http_409 ... ok
test the_retry_classification_matches_the_spec::case_08_http_418 ... ok
test the_retry_classification_matches_the_spec::case_09_too_large ... ok
test the_retry_classification_matches_the_spec::case_10_cardinality ... ok
test the_retry_classification_matches_the_spec::case_11_poll_exhausted ... ok
test an_undocumented_status_is_an_exact_err_surfaced_without_retry ... ok
test the_5xx_attempt_count_is_exactly_the_configured_bound::case_1_one ... ok
test a_5xx_that_recovers_within_the_budget_succeeds ... ok
test a_5xx_is_retried_within_bounds_and_then_surfaced ... ok
test the_5xx_attempt_count_is_exactly_the_configured_bound::case_2_two ... ok
test the_5xx_attempt_count_is_exactly_the_configured_bound::case_3_five ... ok
test the_backoff_delay_is_actually_waited_between_attempts ... ok

test result: ok. 27 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.48s

     Running tests/schema_constraints.rs (/home/agent/work/v16-scratch-target/release/deps/schema_constraints-e0a98b732dae0988)

running 79 tests
test a_32_byte_forwarding_contract_address_is_refused_in_the_json_hook_data ... ok
test a_forwarding_fee_accepts_at_most_six_decimals::case_1_whole ... ok
test a_forwarding_fee_rejects_everything_else_as_bad_forwarding_fee::case_3_not_a_number ... ok
test a_malformed_32_byte_field_on_the_prepare_input_is_refused::case_1_remote_depositor ... ok
test a_forwarding_fee_accepts_at_most_six_decimals::case_2_six_places ... ok
test a_malformed_32_byte_field_on_the_prepare_input_is_refused::case_2_final_destination_recipient ... ok
test a_malformed_32_byte_field_on_the_prepare_input_is_refused::case_3_final_destination_caller ... ok
test a_forwarding_fee_rejects_everything_else_as_bad_forwarding_fee::case_2_no_places_after_dot ... ok
test a_malformed_32_byte_field_on_the_prepare_input_is_refused::case_4_salt ... ok
test a_forwarding_fee_with_seven_decimals_is_refused_inside_the_nested_options ... ok
test a_malformed_required_response_field_is_refused_in_isolation::case_1_transaction_hash ... ok
test a_forwarding_fee_rejects_everything_else_as_bad_forwarding_fee::case_1_seven_places ... ok
test a_malformed_required_response_field_is_refused_in_isolation::case_2_burn_tx_id ... ok
test a_non_usdc_token_is_refused ... ok
test a_batch_below_the_two_signature_threshold_is_refused_at_the_wire ... ok
test a_malformed_required_response_field_is_refused_in_isolation::case_3_withdrawal_id ... ok
test a_remote_domain_below_the_documented_minimum_is_refused ... ok
test a_remote_domain_equal_to_the_final_destination_is_refused ... ok
test a_response_burn_tx_id_must_carry_at_least_one_digit ... ok
test a_transfer_spec_hash_of_the_wrong_length_is_refused_in_isolation ... ok
test a_transfer_spec_value_in_the_decimal_form_is_refused ... ok
test a_withdraw_batch_carries_one_to_ten_burn_intents::case_1_none ... ok
test a_withdraw_batch_carries_one_to_ten_burn_intents::case_2_one ... ok
test a_withdraw_request_carries_one_to_five_batches::case_1_empty ... ok
test a_withdraw_request_carries_one_to_five_batches::case_2_one ... ok
test a_withdrawal_id_accepts_a_uuid ... ok
test a_withdraw_batch_carries_one_to_ten_burn_intents::case_3_ten ... ok
test a_withdrawal_id_rejects_everything_else_as_bad_uuid::case_1_wrong_group_lengths ... ok
test a_withdraw_request_carries_one_to_five_batches::case_3_five ... ok
test a_withdrawal_id_rejects_everything_else_as_bad_uuid::case_3_not_hex ... ok
test a_withdraw_batch_carries_one_to_ten_burn_intents::case_4_eleven ... ok
test a_withdrawal_id_rejects_everything_else_as_bad_uuid::case_2_missing_hyphens ... ok
test both_fee_fields_at_once_violate_the_documented_xor ... ok
test calldata_accepts_empty_or_a_selector_plus_optional_data::case_1_not_forwarding ... ok
test a_withdraw_request_carries_one_to_five_batches::case_4_six ... ok
test a_withdrawal_id_rejects_everything_else_as_bad_uuid::case_4_empty ... ok
test calldata_accepts_empty_or_a_selector_plus_optional_data::case_2_bare_selector ... ok
test calldata_accepts_empty_or_a_selector_plus_optional_data::case_3_selector_plus_data ... ok
test calldata_rejects_everything_else_as_bad_calldata::case_1_short_of_a_selector ... ok
test calldata_rejects_everything_else_as_bad_calldata::case_2_non_hex ... ok
test calldata_rejects_everything_else_as_bad_calldata::case_3_no_prefix ... ok
test decimal_amount_accepts_the_request_side_decimal_form::case_1_whole ... ok
test decimal_amount_accepts_the_request_side_decimal_form::case_2_two_places ... ok
test decimal_amount_accepts_the_request_side_decimal_form::case_3_many_places ... ok
test decimal_amount_rejects_everything_else_as_bad_decimal_amount::case_1_trailing_dot ... ok
test decimal_amount_rejects_everything_else_as_bad_decimal_amount::case_2_leading_dot ... ok
test decimal_amount_rejects_everything_else_as_bad_decimal_amount::case_3_not_a_number ... ok
test decimal_amount_rejects_everything_else_as_bad_decimal_amount::case_4_empty ... ok
test decimal_uint_accepts_the_smallest_unit_form::case_1_zero ... ok
test decimal_uint_accepts_the_smallest_unit_form::case_2_smallest_unit ... ok
test decimal_uint_rejects_everything_else_as_bad_decimal_uint::case_1_the_decimal_form ... ok
test decimal_uint_rejects_everything_else_as_bad_decimal_uint::case_2_negative ... ok
test decimal_uint_rejects_everything_else_as_bad_decimal_uint::case_3_scientific ... ok
test decimal_uint_rejects_everything_else_as_bad_decimal_uint::case_4_empty ... ok
test hex20_accepts_the_json_forwarding_address::case_1_exact_40 ... ok
test hex20_accepts_the_json_forwarding_address::case_2_zero_address_40_digits ... ok
test hex20_rejects_the_binary_form_and_the_prose_form_as_bad_hex20::case_1_prose_form_0x0 ... ok
test every_schema_valid_fixture_still_decodes_under_the_new_constraints ... ok
test hex20_rejects_the_binary_form_and_the_prose_form_as_bad_hex20::case_2_binary_32_byte_form ... ok
test hex32_accepts_the_32_byte_form::case_1_exact_64_lowercase ... ok
test hex20_rejects_the_binary_form_and_the_prose_form_as_bad_hex20::case_3_empty ... ok
test hex32_rejects_everything_else_as_bad_hex32::case_1_missing_0x_prefix ... ok
test hex32_accepts_the_32_byte_form::case_2_exact_64_uppercase ... ok
test hex32_rejects_everything_else_as_bad_hex32::case_2_one_digit_short ... ok
test hex32_rejects_everything_else_as_bad_hex32::case_4_non_hex_digit ... ok
test hex32_rejects_everything_else_as_bad_hex32::case_5_empty ... ok
test hex32_rejects_everything_else_as_bad_hex32::case_3_one_digit_long ... ok
test hex32_rejects_everything_else_as_bad_hex32::case_6_bare_prefix ... ok
test hex_bytes_accepts_an_unbounded_hex_string::case_1_empty_body ... ok
test hex_bytes_accepts_an_unbounded_hex_string::case_2_a_signature ... ok
test hex_bytes_rejects_everything_else_as_bad_hex::case_1_no_prefix ... ok
test hex_bytes_rejects_everything_else_as_bad_hex::case_2_non_hex ... ok
test hex_bytes_rejects_everything_else_as_bad_hex::case_3_empty ... ok
test neither_fee_field_violates_the_documented_xor ... ok
test the_baseline_prepare_input_decodes_so_every_negative_below_isolates_one_rule ... ok
test the_token_enum_has_exactly_one_member ... ok
test the_baseline_withdraw_request_decodes ... ok
test the_threshold_violating_fixture_is_refused_as_a_whole_and_its_ordering_variants_survive_decode ... ok
test the_undocumented_string_fields_are_not_given_an_invented_pattern ... ok

test result: ok. 79 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/schema_strictness.rs (/home/agent/work/v16-scratch-target/release/deps/schema_strictness-1b0a178d4dab1962)

running 32 tests
test a_null_required_response_field_is_refused::case_1_withdrawal_id ... ok
test a_null_required_response_field_is_refused::case_2_burn_tx_id ... ok
test a_null_required_response_field_is_refused::case_4_transfer_spec_hashes ... ok
test a_null_required_response_field_is_refused::case_3_status ... ok
test an_explicit_null_conditional_response_field_is_refused::case_1_attestation_payload ... ok
test an_explicit_null_conditional_response_field_is_refused::case_2_attestation ... ok
test an_explicit_null_conditional_response_field_is_refused::case_3_transaction_hash ... ok
test an_explicit_null_conditional_response_field_is_refused::case_4_failure_reason ... ok
test an_explicit_null_inside_forwarding_options_is_refused_too::case_1_max_fee ... ok
test an_explicit_null_inside_forwarding_options_is_refused_too::case_2_hook_data ... ok
test an_explicit_null_inside_forwarding_options_is_refused_too::case_3_uses_fast_finality ... ok
test an_explicit_null_optional_is_refused_rather_than_read_as_absent::case_2_value_including_fees ... ok
test an_explicit_null_optional_is_refused_rather_than_read_as_absent::case_4_salt ... ok
test omitting_a_required_prepare_field_is_refused_and_never_defaulted::case_1_token ... ok
test an_explicit_null_optional_is_refused_rather_than_read_as_absent::case_1_value_excluding_fees ... ok
test an_explicit_null_optional_is_refused_rather_than_read_as_absent::case_3_final_destination_caller ... ok
test an_omitted_token_is_not_quietly_turned_into_usdc ... ok
test omitting_a_required_prepare_field_is_refused_and_never_defaulted::case_4_final_destination_domain ... ok
test omitting_a_required_prepare_field_is_refused_and_never_defaulted::case_5_final_destination_recipient ... ok
test omitting_a_required_prepare_field_is_refused_and_never_defaulted::case_6_use_circle_forwarding ... ok
test omitting_a_required_response_field_is_refused::case_2_burn_tx_id ... ok
test omitting_a_required_prepare_field_is_refused_and_never_defaulted::case_2_remote_domain ... ok
test omitting_a_required_response_field_is_refused::case_1_withdrawal_id ... ok
test omitting_a_required_response_field_is_refused::case_3_status ... ok
test an_explicit_null_optional_is_refused_rather_than_read_as_absent::case_5_forwarding_options ... ok
test omitting_a_required_response_field_is_refused::case_5_transfer_spec_hashes ... ok
test omitting_a_required_response_field_is_refused::case_4_use_circle_forwarding ... ok
test omitting_a_required_prepare_field_is_refused_and_never_defaulted::case_3_remote_depositor ... ok
test omitting_those_same_optionals_is_perfectly_legal ... ok
test the_amount_null_cases_would_decode_cleanly_if_nullability_regressed ... ok
test the_baseline_prepare_input_decodes_so_every_negative_below_isolates_one_field ... ok
test the_conditional_response_fields_may_still_be_omitted ... ok

test result: ok. 32 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/status_poll.rs (/home/agent/work/v16-scratch-target/release/deps/status_poll-cafd97a9c4bdde1a)

running 16 tests
test a_404_is_its_own_not_found_variant_not_a_generic_http_error ... ok
test a_status_for_a_different_withdrawal_id_is_refused_not_reported_as_this_ones ... ok
test poll_returns_expired_as_a_retryable_resubmit_outcome_not_a_terminal_success ... ok
test poll_stops_at_failed_and_surfaces_the_failure_reason ... ok
test a_500_on_a_poll_is_a_generic_http_error ... ok
test an_unknown_status_string_is_a_hard_error_not_a_default ... ok
test poll_continues_until_finalized_and_stops_there ... ok
test the_get_carries_the_withdrawal_id_in_the_path_and_no_body ... ok
test the_withdrawal_id_type_rejects_route_altering_strings ... ok
test polling_the_same_id_repeatedly_returns_the_current_status ... ok
test the_poll_loop_does_not_swallow_an_unknown_status_as_non_terminal ... ok
test the_poll_loop_is_bounded_and_exhausts_on_a_never_terminal_status ... ok
test the_poll_object_matches_the_withdraw_response_shape ... ok
test the_poll_loop_surfaces_a_404_rather_than_looping ... ok
test the_poll_loop_surfaces_an_id_mismatch_rather_than_looping ... ok
test every_status_enum_value_round_trips_through_a_single_poll ... ok

test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s

     Running tests/submit_idempotency.rs (/home/agent/work/v16-scratch-target/release/deps/submit_idempotency-533f1d1549c35d3a)

running 19 tests
test every_status_but_failed_blocks_resubmission::case_1_submitted ... ok
test every_status_but_failed_blocks_resubmission::case_2_finalized ... ok
test every_status_but_failed_blocks_resubmission::case_3_reconciliation ... ok
test every_status_but_failed_blocks_resubmission::case_4_pending ... ok
test no_public_api_can_post_a_withdrawal_without_the_ledger ... ok
test only_a_failed_burn_is_re_claimable ... ok
test the_ledger_refuses_an_ephemeral_path::case_1_memory ... ok
test the_ledger_refuses_an_ephemeral_path::case_2_memory_upper ... ok
test the_ledger_refuses_an_ephemeral_path::case_3_empty ... ok
test the_ledgers_reopening_transitions_are_not_callable_from_outside_the_crate ... ok
test the_ledger_refuses_a_memory_uri_because_sqlite_interprets_it ... ok
test recording_against_an_unclaimed_burn_is_refused ... ok
test a_different_burn_is_submitted_normally ... ok
test the_same_burn_is_never_submitted_twice ... ok
test a_multi_burn_request_touching_one_seen_burn_makes_no_call_and_strands_nothing ... ok
test a_restarted_process_reopens_the_ledger_and_still_refuses_the_same_burn ... ok
test a_request_carrying_the_same_burn_twice_is_refused_before_any_call ... ok
test the_same_burn_in_different_hex_case_is_the_same_burn ... ok
test a_burn_that_hit_a_409_is_blocked_from_a_later_resubmission ... ok

test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s

     Running tests/submit_withdraw.rs (/home/agent/work/v16-scratch-target/release/deps/submit_withdraw-5884437a101b511e)

running 21 tests
test a_non_65_byte_signature_in_the_batch_is_refused ... ok
test a_batch_digest_count_mismatch_is_refused ... ok
test a_non_allowlisted_signer_refuses_the_submission_with_zero_withdraw_calls ... ok
test an_empty_config_allowlist_fails_closed ... ok
test an_odd_hex_signature_in_the_batch_is_refused ... ok
test a_malformed_prepare_200_body_is_rejected_not_coerced ... ok
test a_withdraw_400_is_a_generic_http_error ... ok
test a_configured_key_is_injected_under_its_header_at_the_transport_seam ... ok
test a_withdraw_201_object_body_fails_to_decode_as_the_array ... ok
test the_default_config_allowlist_is_empty_so_the_gate_fails_closed ... ok
test no_auth_configured_sends_no_credential_header ... ok
test signatures_are_bound_to_the_validated_digest_not_a_claimed_address ... ok
test prepare_500_is_a_generic_http_error ... ok
test prepare_400_is_a_generic_http_error_with_no_body_parsed ... ok
test a_withdraw_409_is_never_reported_as_success ... ok
test all_signers_registered_authorizes_and_submits_exactly_once ... ok
test prepare_posts_the_batches_wrapper_and_decodes_the_response ... ok
test withdraw_rejects_a_response_with_more_elements_than_batches ... ok
test withdraw_submits_the_wrapper_and_decodes_the_201_array ... ok
test withdraw_decodes_a_two_element_array_for_a_two_batch_submission ... ok
test withdraw_rejects_an_empty_response_array ... ok

test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s

     Running tests/transport_bounds.rs (/home/agent/work/v16-scratch-target/release/deps/transport_bounds-cd13aa4478c242f1)

running 8 tests
test a_content_length_over_the_ceiling_is_refused_before_reading_a_byte ... ok
test collect_bounded_refuses_an_endless_unbounded_body_while_reading ... ok
test collect_bounded_accepts_a_body_within_the_ceiling ... ok
test collect_bounded_enforces_a_ceiling_below_and_accepts_one_above_the_default ... ok
test a_caller_supplied_transport_owns_its_own_limits ... ok
test the_reqwest_transport_carries_the_ceiling_it_was_built_with ... ok
test a_body_over_the_configured_ceiling_is_refused_and_one_under_a_raised_ceiling_is_not ... ok
test a_custom_ceiling_is_propagated_to_the_default_production_transport ... ok

test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s

     Running tests/validate.rs (/home/agent/work/v16-scratch-target/release/deps/validate-a9bd01f105e50f5b)

running 28 tests
test abort_is_idempotent_on_retry ... ok
test discovery_rejects_a_prefix_only_tag_match ... ok
test discovery_ok_on_matching_public_note ... ok
test discovery_rejects_a_private_note ... ok
test discovery_rejects_a_zero_sender ... ok
test each_spec_mismatch_class_aborts::case_2_domain ... ok
test discovery_rejects_a_wrong_tag ... ok
test empty_message_hash_class_aborts ... ok
test each_spec_mismatch_class_aborts::case_3_recipient ... ok
test mismatch_aborts_and_produces_no_signature ... ok
test empty_burn_intents_aborts_the_signing_flow ... ok
test missing_message_hash_fails_to_parse ... ok
test discovery_rejects_malformed_items ... ok
test validate_returned_is_deterministic ... ok
test validate_returned_ok_on_full_match ... ok
test each_spec_mismatch_class_aborts::case_1_amount ... ok
test full_match_reaches_signing ... ok
test validate_returned_does_not_depend_on_the_encoded_blob ... ok
test validate_returned_rejects_a_later_empty_burn_intents_batch ... ok
test validate_returned_rejects_amount_mismatch ... ok
test validate_returned_rejects_an_empty_burn_intents_batch ... ok
test validate_returned_rejects_a_later_batch_mismatch ... ok
test validate_returned_rejects_destination_domain_mismatch ... ok
test validate_returned_rejects_empty_message_hash ... ok
test validate_returned_rejects_malformed_message_hash ... ok
test validate_returned_rejects_no_batches ... ok
test validate_returned_rejects_the_mismatch_fixture ... ok
test validate_returned_rejects_destination_recipient_mismatch ... ok

test result: ok. 28 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/wire_roundtrip.rs (/home/agent/work/v16-scratch-target/release/deps/wire_roundtrip-e78fe5e0bfe2068a)

running 22 tests
test a_200_missing_message_hash_to_sign_is_rejected_by_name ... ok
test a_flattened_bare_batch_is_not_a_prepare_withdrawal_request ... ok
test a_flattened_bare_batch_is_not_a_prepare_withdrawal_response ... ok
test a_fully_populated_request_round_trips_every_optional_field ... ok
test a_request_carrying_a_source_depositor_is_refused_rather_than_silently_ignored ... ok
test a_malformed_body_never_decodes_as_a_withdrawal_status ... ok
test a_flattened_bare_batch_is_not_a_withdraw_request ... ok
test a_snake_case_key_does_not_satisfy_a_camel_case_required_field ... ok
test a_withdraw_batch_carries_its_intents_and_signatures_verbatim ... ok
test a_validation_mismatch_is_a_well_formed_200_that_only_semantics_can_catch ... ok
test an_error_body_never_decodes_as_the_endpoints_success_shape ... ok
test an_off_enum_status_is_rejected_and_the_six_documented_ones_are_not ... ok
test circles_returned_transfer_spec_does_carry_the_source_depositor_it_assigned ... ok
test the_409_conflict_body_carries_the_two_recovery_hints_as_raw_json ... ok
test prepare_withdrawal_200_round_trips_through_the_batches_wrapper ... ok
test the_optional_request_fields_are_omitted_from_the_wire_not_sent_as_null ... ok
test the_prepare_request_serializes_with_no_source_depositor_key_at_any_depth ... ok
test the_terminal_and_retryable_status_partitions_match_the_documented_contract ... ok
test the_withdraw_response_modelled_as_an_object_is_not_the_withdraw_response ... ok
test withdraw_201_round_trips_as_an_array_of_statuses ... ok
test withdraw_failed_status_round_trips_with_its_failure_reason_and_no_transaction_hash ... ok
test withdrawal_status_200_round_trips_as_the_same_object_withdraw_returns ... ok

test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running unittests src/lib.rs (/home/agent/work/v16-scratch-target/release/deps/xreserve_deposit_relayer-974d9ca04a7a7873)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running unittests src/main.rs (/home/agent/work/v16-scratch-target/release/deps/xreserve_deposit_relayer-4a1c87cc155e1e5e)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/circle_auth_contract.rs (/home/agent/work/v16-scratch-target/release/deps/circle_auth_contract-4e251ccb9eb6a936)

running 15 tests
test t_rly_10_a_configured_key_does_not_leak_through_relayer_config_debug ... ok
test t_rly_10_a_configured_key_is_refused_over_a_plaintext_base_url::case_2_plain_http_localhost ... ok
test t_rly_10_a_configured_key_over_a_plaintext_base_url_is_refused_from_config ... ok
test t_rly_10_a_configured_key_is_refused_over_a_plaintext_base_url::case_1_plain_http ... ok
test t_rly_10_an_invalid_auth_header_is_rejected_at_construction::case_1_bad_name ... ok
test t_rly_10_an_invalid_auth_header_is_rejected_at_construction::case_3_newline_in_value ... ok
test t_rly_10_an_invalid_auth_header_is_rejected_at_construction::case_2_empty_name ... ok
test t_rly_10_no_credential_is_hardcoded_anywhere_in_the_crate ... ok
test t_rly_10_a_configured_key_is_accepted_over_https ... ok
test t_rly_10_a_plaintext_base_url_is_allowed_when_there_is_no_credential ... ok
test t_rly_10_debug_redacts_the_configured_key ... ok
test t_rly_10_a_configured_out_of_band_key_is_injected_as_a_header ... ok
test t_rly_10_the_auth_header_name_is_configurable ... ok
test t_rly_10_with_no_key_configured_no_auth_header_is_sent_and_the_request_still_succeeds ... ok
test t_rly_10_a_redacted_config_still_injects_the_real_key_on_the_wire ... ok

test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

     Running tests/circle_fetch_contract.rs (/home/agent/work/v16-scratch-target/release/deps/circle_fetch_contract-487cab3650618599)

running 25 tests
test t_rly_02_rejects_a_malformed_tx_hash_client_side_without_issuing_a_request::case_1_missing_0x_prefix ... ok
test t_rly_01_by_hash_accepts_the_response_that_answers_the_requested_hash ... ok
test t_rly_02_accepts_a_mixed_case_tx_hash ... ok
test t_rly_01_by_hash_rejects_a_malformed_hash_client_side_without_issuing_a_request ... ok
test t_rly_01_by_hash_rejects_a_response_carrying_a_hash_other_than_the_one_requested ... ok
test t_rly_01_by_hash_flattens_the_wrapper_and_binds_the_raw_keccak_digest ... ok
test t_rly_02_by_tx_hash_returns_the_list_shape_with_remote_domain ... ok
test t_rly_01_by_hash_rejects_an_unwrapped_top_level_attestation_object ... ok
test t_rly_02_rejects_a_malformed_tx_hash_client_side_without_issuing_a_request::case_4_non_hex_digit ... ok
test t_rly_02_rejects_a_malformed_tx_hash_client_side_without_issuing_a_request::case_5_uppercase_0x_prefix ... ok
test t_rly_02_rejects_a_malformed_tx_hash_client_side_without_issuing_a_request::case_3_one_hex_digit_long ... ok
test t_rly_02_rejects_a_malformed_tx_hash_client_side_without_issuing_a_request::case_6_empty ... ok
test t_rly_02_rejects_a_malformed_tx_hash_client_side_without_issuing_a_request::case_7_bare_0x ... ok
test t_rly_02_rejects_a_malformed_tx_hash_client_side_without_issuing_a_request::case_8_leading_whitespace ... ok
test t_rly_02_rejects_a_malformed_tx_hash_client_side_without_issuing_a_request::case_2_one_hex_digit_short ... ok
test t_rly_02_rejects_a_remote_domain_below_the_documented_minimum ... ok
test t_rly_05_message_hash_that_does_not_bind_the_payload_aborts_and_alerts ... ok
test t_rly_06_reject_attestation_not_65_bytes ... ok
test t_rly_06_reject_missing_message_hash ... ok
test t_rly_06_reject_missing_payload ... ok
test t_rly_06_reject_non_hex_message_hash ... ok
test t_rly_06_reject_non_json_body ... ok
test t_rly_06_reject_wrong_length_message_hash ... ok
test t_rly_06_reject_non_hex_payload ... ok
test t_rly_06_reject_wrong_payload_field ... ok

test result: ok. 25 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s

     Running tests/circle_pagination_contract.rs (/home/agent/work/v16-scratch-target/release/deps/circle_pagination_contract-c095c9ff410eaed1)

running 19 tests
test t_rly_03_a_page_without_a_link_header_terminates_the_scan ... ok
test t_rly_03_an_absent_link_header_remains_the_terminal_case ... ok
test t_rly_03_a_batch_page_element_with_a_broken_binding_is_rejected ... ok
test t_rly_03_a_link_with_no_recognized_relation_is_rejected ... ok
test t_rly_03_batch_query_enforces_the_documented_page_size_bounds::case_1_zero ... ok
test t_rly_03_batch_query_enforces_the_documented_page_size_bounds::case_2_min ... ok
test t_rly_03_batch_query_enforces_the_documented_page_size_bounds::case_3_max ... ok
test t_rly_03_a_garbage_link_header_is_rejected_not_read_as_end_of_scan ... ok
test t_rly_03_batch_query_enforces_the_documented_page_size_bounds::case_4_over_max ... ok
test t_rly_03_a_link_with_an_unparseable_href_is_rejected ... ok
test t_rly_03_a_non_utf8_link_header_is_rejected ... ok
test t_rly_03_a_next_link_without_a_cursor_is_rejected ... ok
test t_rly_03_batch_poll_puts_the_full_documented_query_surface_on_the_wire ... ok
test t_rly_03_the_two_cursors_are_mutually_exclusive::case_1_after_then_before ... ok
test t_rly_03_forward_poll_advances_the_next_cursor_until_it_is_absent ... ok
test t_rly_03_the_two_cursors_are_mutually_exclusive::case_2_before_then_after ... ok
test t_rly_04_info_is_fetched_with_no_domain_param_and_both_domain_lists_decode ... ok
test t_rly_03_link_header_with_a_relative_href_still_yields_the_cursor ... ok
test t_rly_04_info_retries_a_500_then_succeeds ... ok

test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s

     Running tests/circle_production_transport.rs (/home/agent/work/v16-scratch-target/release/deps/circle_production_transport-840fe941679e3db1)

running 16 tests
test a_response_that_came_from_a_url_we_did_not_request_is_refused::case_5_different_query ... ok
test a_response_that_came_from_a_url_we_did_not_request_is_refused::case_3_different_scheme ... ok
test a_response_that_came_from_a_url_we_did_not_request_is_refused::case_1_same_url ... ok
test a_followed_redirect_is_permanent_and_never_retried ... ok
test collect_bounded_accepts_a_body_within_the_ceiling::case_2_one_chunk_short ... ok
test a_response_that_came_from_a_url_we_did_not_request_is_refused::case_2_different_host ... ok
test collect_bounded_accepts_a_body_within_the_ceiling::case_3_single_byte_body ... ok
test collect_bounded_rejects_an_advertised_oversize_without_reading_a_byte ... ok
test collect_bounded_rejects_a_body_whose_content_length_lied ... ok
test a_response_that_came_from_a_url_we_did_not_request_is_refused::case_4_different_path ... ok
test collect_bounded_accepts_an_empty_body ... ok
test collect_bounded_stops_reading_once_the_ceiling_is_crossed ... ok
test collect_bounded_accepts_a_body_within_the_ceiling::case_1_exactly_at_the_ceiling ... ok
test collect_bounded_propagates_a_stream_failure ... ok
test the_production_redirect_policy_follows_nothing ... ok
test the_crate_builds_exactly_one_http_client_and_it_takes_the_no_redirect_policy ... ok

test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/circle_status_policy_contract.rs (/home/agent/work/v16-scratch-target/release/deps/circle_status_policy_contract-f99661b25f206b8f)

running 29 tests
test status_policy_classifies_every_documented_code::case_02_created ... ok
test status_policy_classifies_every_documented_code::case_03_bad_request ... ok
test status_policy_classifies_every_documented_code::case_04_unauthorized ... ok
test status_policy_classifies_every_documented_code::case_05_forbidden ... ok
test status_policy_classifies_every_documented_code::case_06_not_found ... ok
test status_policy_classifies_every_documented_code::case_09_too_many_requests ... ok
test status_policy_classifies_every_documented_code::case_01_ok ... ok
test status_policy_classifies_every_documented_code::case_07_conflict ... ok
test status_policy_classifies_every_documented_code::case_08_teapot ... ok
test status_policy_classifies_every_documented_code::case_10_server_error ... ok
test status_policy_classifies_every_documented_code::case_11_bad_gateway ... ok
test status_policy_classifies_every_documented_code::case_12_unavailable ... ok
test a_redirect_is_rejected_and_never_followed::case_2_found ... ok
test t_rly_17_400_error_body_is_never_parsed ... ok
test a_redirect_is_rejected_and_never_followed::case_1_moved_permanently ... ok
test a_redirect_is_rejected_and_never_followed::case_3_temporary_redirect ... ok
test a_redirect_is_rejected_and_never_followed::case_4_permanent_redirect ... ok
test t_rly_17_400_is_not_retried_on_the_batch_endpoint_either ... ok
test the_status_policy_classifies_every_3xx_as_a_permanent_rejection::case_1_moved_permanently ... ok
test the_status_policy_classifies_every_3xx_as_a_permanent_rejection::case_2_found ... ok
test the_status_policy_classifies_every_3xx_as_a_permanent_rejection::case_3_not_modified ... ok
test the_status_policy_classifies_every_3xx_as_a_permanent_rejection::case_4_temporary_redirect ... ok
test t_rly_17_400_is_rejected_without_a_retry_and_alerts ... ok
test t_rly_18_429_backs_off_and_retries ... ok
test t_rly_18_a_single_500_below_the_threshold_does_not_alert ... ok
test t_rly_07_404_that_never_resolves_exhausts_attempts_and_is_surfaced ... ok
test t_rly_07_404_retries_with_exponential_backoff_then_succeeds ... ok
test t_rly_18_500_retries_with_backoff_alerts_after_the_threshold_then_succeeds ... ok
test t_rly_18_500_that_never_clears_exhausts_attempts_and_alerts ... ok

test result: ok. 29 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.20s

     Running tests/circle_transport_contract.rs (/home/agent/work/v16-scratch-target/release/deps/circle_transport_contract-b317c1e19895fcb3)

running 23 tests
test body_limit_rejects_before_and_during_the_read ... ok
test client_rejects_a_malformed_base_url ... ok
test an_oversized_response_body_is_rejected_not_buffered ... ok
test a_response_within_the_size_ceiling_is_accepted ... ok
test rate_governor_rejects_a_zero_ceiling::case_1_zero_per_ip ... ok
test rate_governor_rejects_a_zero_ceiling::case_2_zero_global ... ok
test rate_governor_rejects_a_zero_ceiling::case_3_both_zero ... ok
test client_from_config_wires_the_transport_limits ... ok
test client_from_config_wires_the_documented_rate_ceilings_and_no_auth ... ok
test retry_policy_rejects_an_impossible_configuration::case_1_zero_attempts ... ok
test retry_policy_rejects_an_impossible_configuration::case_2_zero_alert_threshold ... ok
test transport_limits_reject_an_impossible_configuration::case_1_zero_connect_timeout ... ok
test transport_limits_reject_an_impossible_configuration::case_2_zero_request_timeout ... ok
test transport_limits_reject_an_impossible_configuration::case_3_zero_body_ceiling ... ok
test with_backoff_does_not_retry_a_permanent_error ... ok
test the_default_event_sink_is_the_noop_sink ... ok
test reqwest_transport_maps_a_failed_request_to_transport ... ok
test a_transport_failure_is_retried_and_surfaces_as_transport ... ok
test with_backoff_retries_exponentially_and_stops_at_max_attempts ... ok
test a_hung_request_hits_the_deadline_on_every_attempt_and_is_surfaced ... ok
test rate_governor_enforces_the_5_qps_per_ip_ceiling ... ok
test rate_governor_enforces_the_35_qps_global_ceiling_across_hosts ... ok
test rate_governor_keys_the_per_ip_window_by_host ... ok

test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.01s

     Running tests/config_recovery_validation.rs (/home/agent/work/v16-scratch-target/release/deps/config_recovery_validation-25c8bf56cf3d12d7)

running 9 tests
test a_zero_stale_claim_threshold_is_refused ... ok
test a_zero_retry_batch_size_is_refused ... ok
test the_constructor_enforces_the_absolute_floor_regardless_of_the_caller_minimum ... ok
test the_absolute_floor_is_enforced_when_the_envelope_is_small ... ok
test the_constructor_enforces_a_caller_minimum_above_the_floor ... ok
test a_zero_submit_deadline_is_refused ... ok
test the_submit_envelope_includes_the_backoff_term_exactly ... ok
test the_default_config_yields_a_valid_recovery_policy ... ok
test the_stale_threshold_must_exceed_the_backoff_inclusive_envelope ... ok

test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/cycle_dedup.rs (/home/agent/work/v16-scratch-target/release/deps/cycle_dedup-78944801d3096a99)

running 2 tests
test duplicate_attestation_no_double_submit ... ok
test the_dedup_survives_a_restart ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s

     Running tests/cycle_fast_fail.rs (/home/agent/work/v16-scratch-target/release/deps/cycle_fast_fail-972fcbdb84c7041c)

running 9 tests
test a_domain_mismatch_is_reported_before_a_token_mismatch ... ok
test reject_remote_token_mismatch ... ok
test the_matching_domain_and_token_pass ... ok
test the_cycle_refuses_a_domain_mismatch_before_the_submit_port ... ok
test reject_remote_domain_mismatch ... ok
test a_configured_domain_circle_does_not_advertise_is_refused ... ok
test a_broken_info_fetch_fails_the_cycle_rather_than_disabling_the_check ... ok
test with_the_fast_fail_off_no_info_request_is_issued ... ok
test with_the_fast_fail_on_info_is_fetched_once_per_cycle ... ok

test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s

     Running tests/cycle_no_silent_drops.rs (/home/agent/work/v16-scratch-target/release/deps/cycle_no_silent_drops-473c064d8742ccdc)

running 11 tests
test no_disposition_can_render_an_empty_reason ... ok
test the_production_submit_port_refuses_rather_than_pretending ... ok
test the_outcome_slugs_are_distinct ... ok
test the_per_attestation_step_returns_a_disposition_not_a_result ... ok
test the_cycle_cannot_filter_the_page ... ok
test the_crate_has_no_miden_client_and_no_simulated_submit ... ok
test the_retry_driver_uses_the_atomic_conditional_touch ... ok
test the_source_sweep_reads_code_and_not_prose ... ok
test every_fetched_attestation_is_reported_with_a_reason ... ok
test the_dispositions_partition_the_fetched_attestations ... ok
test the_mixed_page_actually_produces_distinct_dispositions ... ok

test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s

     Running tests/cycle_pipeline.rs (/home/agent/work/v16-scratch-target/release/deps/cycle_pipeline-e94c814a44c41189)

running 12 tests
test a_400_on_the_page_fetch_fails_the_cycle_without_dropping_anything ... ok
test a_structural_deposit_intent_reject_never_reaches_submit ... ok
test a_nonce_already_minted_on_chain_is_recorded_not_retried ... ok
test a_fatal_submit_failure_records_rejected_and_does_not_retry ... ok
test a_second_attestation_for_a_claimed_nonce_is_left_for_reconciliation ... ok
test a_page_without_a_next_cursor_ends_the_scan ... ok
test the_cycle_duration_histogram_records_one_sample_per_cycle ... ok
test one_cycle_fetches_validates_builds_submits_records_and_advances ... ok
test a_transient_submit_failure_that_exhausts_the_budget_defers ... ok
test a_transient_submit_failure_retries_and_then_succeeds ... ok
test the_metrics_count_every_fetched_attestation_exactly_once ... ok
test the_next_cycle_polls_from_the_persisted_cursor ... ok

test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s

     Running tests/cycle_recovery.rs (/home/agent/work/v16-scratch-target/release/deps/cycle_recovery-67f9d63148dea6d3)

running 4 tests
test the_loop_emits_a_cycle_failure_event ... ok
test a_fatal_failure_is_terminal_and_not_resubmitted_on_a_final_page_repoll ... ok
test a_transient_failure_is_retried_across_cycles_not_stranded_behind_the_cursor ... ok
test a_retry_whose_refetch_fails_stays_retryable_and_is_reported ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s

     Running tests/cycle_recovery_lifecycle.rs (/home/agent/work/v16-scratch-target/release/deps/cycle_recovery_lifecycle-06924edec2f2327c)

running 5 tests
test an_invalid_recovery_config_fails_the_cycle_closed ... ok
test a_young_pending_claim_is_left_in_flight ... ok
test stale_reclamation_runs_before_a_broken_discovery_fetch ... ok
test a_stale_pending_claim_is_reclaimed_and_retried ... ok
test the_retry_queue_rotates_so_a_stuck_head_does_not_starve_the_tail ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.02s

     Running tests/deferred_dependencies_doc.rs (/home/agent/work/v16-scratch-target/release/deps/deferred_dependencies_doc-ebf5c86befad950d)

running 3 tests
test deferred_dependencies_doc_exists_and_is_complete ... ok
test cargo_manifest_cross_references_the_record_and_declares_reqwest_offline_correctly ... ok
test no_offline_hostile_mock_server_crate_is_declared ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/deposit_intent_validate.rs (/home/agent/work/v16-scratch-target/release/deps/deposit_intent_validate-b50c0404d1e186c3)

running 18 tests
test t_rly_08_empty_payload_is_short_header ... ok
test decoded_type_is_internally_consistent::case_1 ... ok
test t_rly_08_structural_reject::case_1_bad_magic ... ok
test t_rly_08_structural_reject::case_2_bad_version ... ok
test t_rly_08_structural_reject::case_5_zero_local_token ... ok
test t_rly_08_structural_reject::case_3_length_mismatch ... ok
test decoded_type_is_internally_consistent::case_2 ... ok
test t_rly_08_structural_reject::case_4_zero_amount ... ok
test t_rly_08_structural_reject::case_6_zero_local_depositor ... ok
test t_rly_11_preimage_exactly_1024_felts_accepted ... ok
test t_rly_11_oversized_preimage_rejected ... ok
test t_rly_12_decode_well_formed_all_offsets::case_2_empty_hookdata ... ok
test t_rly_08_structural_reject::case_7_truncated_header ... ok
test t_rly_13_amount_and_maxfee_carried_raw::case_1_with_hookdata ... ok
test t_rly_13_amount_and_maxfee_carried_raw::case_2_empty_hookdata ... ok
test t_rly_11_preimage_felt_count::case_1_empty_hookdata ... ok
test t_rly_11_preimage_felt_count::case_2_with_hookdata ... ok
test t_rly_12_decode_well_formed_all_offsets::case_1_with_hookdata ... ok

test result: ok. 18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/envelope_validate.rs (/home/agent/work/v16-scratch-target/release/deps/envelope_validate-a37544324b5f13e3)

running 44 tests
test t_rly_05_malformed_payload_hex::case_4_payload_whitespace_odd_count ... ok
test t_rly_05_message_hash_wrong_length::case_1_empty ... ok
test t_rly_05_malformed_message_hash_hex::case_1_message_hash_odd_length ... ok
test t_rly_05_malformed_payload_hex::case_2_payload_non_hex_char ... ok
test t_rly_05_malformed_payload_hex::case_1_payload_odd_length ... ok
test t_rly_05_malformed_message_hash_hex::case_2_message_hash_non_hex_char ... ok
test t_rly_05_malformed_payload_hex::case_3_payload_whitespace ... ok
test t_rly_05_message_hash_wrong_length::case_2_one_byte ... ok
test t_rly_05_payload_hex_error_takes_precedence ... ok
test t_rly_05_message_hash_wrong_length::case_4_oversized_33 ... ok
test t_rly_05_message_hash_wrong_length::case_3_truncated_31 ... ok
test t_rly_05_message_hash_wrong_length::case_5_doubled_64 ... ok
test t_rly_05_resized_payload_aborts::case_1_truncated ... ok
test t_rly_05_resized_payload_aborts::case_2_extended ... ok
test t_rly_05_tampered_payload_aborts::case_1_flipped_byte_first ... ok
test t_rly_06_reject_malformed_attestation_hex::case_1_odd_length ... ok
test t_rly_06_reject_malformed_attestation_hex::case_2_non_hex_char ... ok
test t_rly_05_single_bit_flip_in_any_digest_byte_aborts ... ok
test t_rly_05_tampered_payload_aborts::case_2_flipped_byte_middle ... ok
test t_rly_06_reject_wrong_length_attestation::case_1_empty ... ok
test t_rly_05_tampered_payload_aborts::case_3_flipped_byte_last ... ok
test t_rly_06_accept_65_byte_attestation ... ok
test t_rly_06_reject_wrong_length_attestation::case_3_half ... ok
test t_rly_06_reject_wrong_length_attestation::case_6_doubled ... ok
test t_rly_06_reject_wrong_length_attestation::case_4_missing_v_byte ... ok
test t_rly_06_reject_wrong_length_attestation::case_2_one_byte ... ok
test t_rly_20_accept_canonical_raw_keccak_vectors ... ok
test t_rly_06_reject_wrong_length_attestation::case_5_one_too_many ... ok
test t_rly_06_shape_only_never_verifies_ecdsa_offchain::case_1_all_zeros ... ok
test t_rly_06_foreign_key_signature_passes_shape_check ... ok
test t_rly_20_accept_partner_fixture::case_2_bare ... ok
test t_rly_06_shape_only_never_verifies_ecdsa_offchain::case_2_all_ones ... ok
test t_rly_20_accept_partner_fixture::case_1_prefixed ... ok
test t_rly_20_accept_partner_fixture::case_3_uppercase ... ok
test t_rly_20_binding_is_payload_specific ... ok
test t_rly_20_negative_comparators_are_distinct_constructions ... ok
test t_rly_20_fixture_signs_raw_keccak_for_arbitrary_payloads ... ok
test t_rly_20_partner_attester_identity_is_deterministic_and_canonically_keyed ... ok
test t_rly_20_reject_non_raw_keccak_digest::case_2_personal_sign_prefix ... ok
test t_rly_20_reject_non_raw_keccak_digest::case_1_eip712_typed_data ... ok
test t_rly_20_reject_non_raw_keccak_digest::case_3_poseidon2_word ... ok
test t_rly_20_test_vector_is_byte_pinned ... ok
test t_rly_20_signature_oracle_accepts_canonical_att_vectors ... ok
test t_rly_20_fixture_signature_cryptographically_covers_the_raw_keccak_digest ... ok

test result: ok. 44 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

     Running tests/idempotency_claim.rs (/home/agent/work/v16-scratch-target/release/deps/idempotency_claim-7c6d171407504277)

running 26 tests
test a_second_attestation_for_the_same_nonce_is_refused_in_every_status::case_4_already_minted ... ok
test a_failed_nonce_cannot_be_submitted_without_re_claiming_it ... ok
test a_re_observed_nonce_is_already_seen_and_the_record_is_not_rewritten ... ok
test a_failed_nonce_is_re_claimed_and_the_retry_can_commit ... ok
test a_second_attestation_for_the_same_nonce_is_refused_in_every_status::case_2_submitted ... ok
test a_nonce_re_observed_after_submission_is_already_seen_with_its_transaction ... ok
test a_second_attestation_for_the_same_nonce_is_refused_in_every_status::case_1_pending ... ok
test a_second_attestation_for_the_same_nonce_is_refused_in_every_status::case_3_committed ... ok
test a_second_attestation_for_the_same_nonce_is_refused_in_every_status::case_5_failed ... ok
test an_unseen_nonce_is_not_submitted_and_has_no_record ... ok
test is_nonce_submitted_blocks_every_status_except_failed::case_1_pending ... ok
test is_nonce_submitted_blocks_every_status_except_failed::case_2_submitted ... ok
test is_nonce_submitted_blocks_every_status_except_failed::case_4_already_minted ... ok
test is_nonce_submitted_blocks_every_status_except_failed::case_5_failed ... ok
test is_nonce_submitted_blocks_every_status_except_failed::case_3_committed ... ok
test a_stale_reclaimed_nonce_is_re_claimable_after_a_restart ... ok
test only_a_failed_nonce_is_re_claimed::case_1_pending ... ok
test only_a_failed_nonce_is_re_claimed::case_2_submitted ... ok
test only_a_failed_nonce_is_re_claimed::case_4_already_minted ... ok
test only_a_failed_nonce_is_re_claimed::case_3_committed ... ok
test only_a_failed_nonce_is_re_claimed::case_5_failed ... ok
test the_first_observation_claims_the_nonce_as_pending ... ok
test two_handles_on_the_same_file_share_one_log ... ok
test the_retryable_work_list_holds_exactly_the_failed_records_oldest_first ... ok
test only_one_of_many_concurrent_observers_re_claims_a_failed_nonce ... ok
test only_one_of_many_concurrent_observers_claims_a_fresh_nonce ... ok

test result: ok. 26 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s

     Running tests/idempotency_durable_path.rs (/home/agent/work/v16-scratch-target/release/deps/idempotency_durable_path-b36409dabaebaea1)

running 16 tests
test an_ephemeral_or_uri_store_path_is_refused::case_1_in_memory ... ok
test an_ephemeral_or_uri_store_path_is_refused::case_2_in_memory_uppercase ... ok
test an_ephemeral_or_uri_store_path_is_refused::case_3_in_memory_padded ... ok
test an_ephemeral_or_uri_store_path_is_refused::case_4_empty ... ok
test an_ephemeral_or_uri_store_path_is_refused::case_5_whitespace ... ok
test an_ephemeral_or_uri_store_path_is_refused::case_6_uri_shared_memory ... ok
test an_ephemeral_or_uri_store_path_is_refused::case_7_uri_named_memory ... ok
test an_ephemeral_or_uri_store_path_is_refused::case_8_uri_memory_shared_cache ... ok
test a_memory_uri_really_does_lose_everything_and_the_store_refuses_it ... ok
test an_ephemeral_or_uri_store_path_is_refused::case_9_uri_memory_with_a_real_looking_path ... ok
test an_in_memory_store_cannot_be_opened_at_all ... ok
test a_durable_file_whose_name_resembles_a_special_one_is_accepted::case_1_contains_memory ... ok
test a_durable_file_whose_name_resembles_a_special_one_is_accepted::case_2_mode_memory_in_the_name ... ok
test a_uri_that_names_a_real_file_is_accepted_and_is_durable ... ok
test a_durable_file_whose_name_resembles_a_special_one_is_accepted::case_3_colon_in_the_name ... ok
test a_real_file_path_is_accepted_and_keeps_the_cursor_across_a_restart ... ok

test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/idempotency_migration.rs (/home/agent/work/v16-scratch-target/release/deps/idempotency_migration-d961b830eaf28808)

running 3 tests
test a_future_schema_version_is_still_refused ... ok
test a_migrated_store_reopens_without_re_migrating ... ok
test a_populated_v1_store_migrates_and_preserves_its_records_and_cursor ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/idempotency_restart.rs (/home/agent/work/v16-scratch-target/release/deps/idempotency_restart-9bccff3c6657aa0a)

running 14 tests
test a_store_written_by_an_unknown_schema_version_is_refused_at_open ... ok
test a_fresh_store_has_no_cursor ... ok
test advance_cursor_persists_and_replaces_the_token ... ok
test an_empty_cursor_token_is_refused_and_does_not_clobber_the_stored_one::case_2_whitespace ... ok
test opening_the_store_under_a_missing_directory_is_a_typed_error ... ok
test an_empty_cursor_token_is_refused_and_does_not_clobber_the_stored_one::case_1_empty ... ok
test a_restart_resumes_at_the_persisted_cursor_instead_of_rescanning_the_window ... ok
test an_empty_cursor_token_is_refused_and_does_not_clobber_the_stored_one::case_3_newline ... ok
test a_store_written_by_this_build_reopens ... ok
test a_crash_before_the_cursor_advance_replays_the_page_with_no_second_mint_attempt ... ok
test cursors_are_isolated_per_remote_domain ... ok
test the_store_writes_to_the_file_it_was_given ... ok
test the_nonce_log_and_the_cursor_survive_a_restart ... ok
test an_unknown_status_string_is_a_typed_corruption_error ... ok

test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

     Running tests/idempotency_status_machine.rs (/home/agent/work/v16-scratch-target/release/deps/idempotency_status_machine-374bc096d6d705f7)

running 31 tests
test a_transition_on_an_unclaimed_nonce_is_refused::case_2_commit ... ok
test a_failure_can_be_recorded_from_pending_or_submitted::case_1_before_the_transaction_went_out ... ok
test a_second_reclaim_pass_finds_nothing_to_free ... ok
test a_transition_on_an_unclaimed_nonce_is_refused::case_3_already_minted ... ok
test a_transition_on_an_unclaimed_nonce_is_refused::case_1_submit ... ok
test a_transition_on_an_unclaimed_nonce_is_refused::case_4_fail ... ok
test a_failure_can_be_recorded_from_pending_or_submitted::case_2_after_the_transaction_went_out ... ok
test a_rejected_nonce_is_not_reclaimable ... ok
test already_minted_is_reachable_from_any_live_status_and_is_terminal::case_3_from_failed ... ok
test already_minted_is_reachable_from_any_live_status_and_is_terminal::case_1_from_pending ... ok
test already_minted_is_reachable_from_any_live_status_and_is_terminal::case_2_from_submitted ... ok
test an_illegal_transition_is_refused_and_leaves_the_record_untouched::case_02_committed_to_failed ... ok
test an_illegal_transition_is_refused_and_leaves_the_record_untouched::case_01_committed_to_submitted ... ok
test an_illegal_transition_is_refused_and_leaves_the_record_untouched::case_05_already_minted_to_failed ... ok
test an_illegal_transition_is_refused_and_leaves_the_record_untouched::case_03_committed_to_already_minted ... ok
test an_illegal_transition_is_refused_and_leaves_the_record_untouched::case_04_already_minted_to_submitted ... ok
test an_illegal_transition_is_refused_and_leaves_the_record_untouched::case_07_pending_to_committed ... ok
test an_illegal_transition_is_refused_and_leaves_the_record_untouched::case_06_already_minted_to_committed ... ok
test an_illegal_transition_is_refused_and_leaves_the_record_untouched::case_09_failed_to_submitted ... ok
test an_illegal_transition_is_refused_and_leaves_the_record_untouched::case_08_submitted_to_submitted ... ok
test an_illegal_transition_is_refused_and_leaves_the_record_untouched::case_11_rejected_to_submitted ... ok
test an_illegal_transition_is_refused_and_leaves_the_record_untouched::case_12_rejected_to_failed ... ok
test an_illegal_transition_is_refused_and_leaves_the_record_untouched::case_10_failed_to_committed ... ok
test an_illegal_transition_is_refused_and_leaves_the_record_untouched::case_13_rejected_to_already_minted ... ok
test an_illegal_transition_is_refused_and_leaves_the_record_untouched::case_14_rejected_to_rejected ... ok
test an_illegal_transition_is_refused_and_leaves_the_record_untouched::case_15_committed_to_rejected ... ok
test an_illegal_transition_is_refused_and_leaves_the_record_untouched::case_16_submitted_to_rejected ... ok
test rejected_is_terminal_and_blocks_resubmission ... ok
test reclaim_stale_pending_frees_only_stranded_claims ... ok
test the_happy_path_walks_pending_then_submitted_then_committed ... ok
test rejected_records_are_absent_from_the_retry_queue ... ok

test result: ok. 31 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

     Running tests/idempotency_touch.rs (/home/agent/work/v16-scratch-target/release/deps/idempotency_touch-f59a5b0f739ac1b3)

running 10 tests
test a_failed_row_is_restamped_and_reported_touched ... ok
test a_non_failed_row_is_left_untouched::case_4_already_minted ... ok
test a_non_failed_row_is_left_untouched::case_3_committed ... ok
test a_non_failed_row_is_left_untouched::case_5_rejected ... ok
test a_non_failed_row_is_left_untouched::case_2_submitted ... ok
test a_non_failed_row_is_left_untouched::case_1_pending ... ok
test touching_an_unknown_nonce_reports_false ... ok
test touch_does_not_overwrite_a_second_handles_live_claim ... ok
test touch_does_not_overwrite_a_second_handles_submitted_row ... ok
test touch_propagates_a_corrupt_row_error ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

     Running tests/idempotency_tx_id.rs (/home/agent/work/v16-scratch-target/release/deps/idempotency_tx_id-6fcb2fda913146e8)

running 10 tests
test a_non_hex_transaction_id_is_refused_with_its_cause_preserved ... ok
test a_transaction_id_of_the_wrong_length_is_refused::case_2_one_byte_short ... ok
test a_transaction_id_of_the_wrong_length_is_refused::case_1_too_short ... ok
test a_transaction_id_of_the_wrong_length_is_refused::case_4_empty ... ok
test a_transaction_id_round_trips_through_hex::case_1_prefixed_lowercase ... ok
test a_transaction_id_of_the_wrong_length_is_refused::case_3_one_byte_long ... ok
test a_transaction_id_round_trips_through_hex::case_3_prefixed_uppercase ... ok
test a_transaction_id_round_trips_through_hex::case_2_bare_lowercase ... ok
test a_transaction_id_round_trips_through_hex::case_4_bare_uppercase ... ok
test an_odd_length_transaction_id_is_refused_as_malformed_hex ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/loop_observability.rs (/home/agent/work/v16-scratch-target/release/deps/loop_observability-f1c43aa168c8bab5)

running 4 tests
test the_loop_surfaces_metrics_on_a_failed_cycle_too ... ok
test a_failed_cycle_still_records_its_duration ... ok
test the_assembled_loop_surfaces_events_and_metrics_into_one_shared_sink ... ok
test the_metrics_snapshot_accumulates_across_cycles ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s

     Running tests/main_wiring.rs (/home/agent/work/v16-scratch-target/release/deps/main_wiring-0b0fe830b6afa40e)

running 3 tests
test the_binary_installs_a_real_sink_into_the_client_and_context ... ok
test the_comment_stripper_reads_code_not_prose ... ok
test the_binary_shares_one_sink_between_the_client_and_the_context ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/metrics_histogram.rs (/home/agent/work/v16-scratch-target/release/deps/metrics_histogram-85d95b2cbb3c220c)

running 5 tests
test samples_under_the_top_bound_fill_the_finite_buckets ... ok
test the_render_distinguishes_the_top_bound_from_inf ... ok
test an_empty_histogram_still_renders_the_series ... ok
test the_top_finite_bucket_excludes_over_bound_samples ... ok
test the_snapshot_top_bucket_excludes_over_bound_samples ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/mint_note_boundaries.rs (/home/agent/work/v16-scratch-target/release/deps/mint_note_boundaries-d5e01cd0fefb1c4d)

running 19 tests
test t_a_non_hex_attester_key_is_refused ... ok
test t_a_payload_unit04_refuses_is_a_typed_build_error::case_1_bad_magic ... ok
test t_a_payload_unit04_refuses_is_a_typed_build_error::case_5_zero_local_depositor ... ok
test t_a_payload_unit04_refuses_is_a_typed_build_error::case_2_bad_version ... ok
test t_a_payload_unit04_refuses_is_a_typed_build_error::case_6_length_mismatch ... ok
test t_a_payload_unit04_refuses_is_a_typed_build_error::case_4_zero_local_token ... ok
test t_a_payload_unit04_refuses_is_a_typed_build_error::case_3_zero_amount ... ok
test t_a_payload_unit04_refuses_is_a_typed_build_error::case_7_truncated_header ... ok
test t_an_attester_key_of_the_wrong_length_is_refused::case_3_uncompressed_length ... ok
test t_an_attester_key_that_is_not_a_curve_point_is_refused::case_1_off_curve ... ok
test t_an_attester_key_of_the_wrong_length_is_refused::case_1_empty ... ok
test t_an_attester_key_that_is_not_a_curve_point_is_refused::case_2_bad_prefix ... ok
test t_an_attester_key_of_the_wrong_length_is_refused::case_2_too_short ... ok
test t_the_partner_key_round_trips_through_the_config_form ... ok
test t_the_reject_payloads_pass_the_envelope_boundary::case_2 ... ok
test t_the_reject_payloads_pass_the_envelope_boundary::case_1 ... ok
test t_the_reject_payloads_pass_the_envelope_boundary::case_3 ... ok
test t_a_payload_unit04_refuses_is_a_typed_build_error::case_8_hookdata_overflow ... ok
test t_a_private_faucet_id_is_refused ... ok

test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

     Running tests/mint_note_delegation.rs (/home/agent/work/v16-scratch-target/release/deps/mint_note_delegation-06b9f7714a086b61)

running 13 tests
test t_script_root_is_the_stock_mint_root ... ok
test t_routing_attachment_binds_the_faucet_network_account ... ok
test t_storage_embeds_the_attested_output ... ok
test t_note_carries_exactly_the_three_attachments ... ok
test t_note_is_public_assetless_and_addressed_to_the_faucet ... ok
test t_attestation_attachment_carries_the_validated_signature_and_configured_pubkey ... ok
test t_delegation_is_byte_for_byte_unit04_create ... ok
test t_each_build_draws_a_fresh_serial_number ... ok
test t_the_faucet_argument_drives_the_route_and_the_tag ... ok
test t_the_callers_rng_is_the_one_that_is_drawn_from ... ok
test t_the_configured_pubkey_is_the_one_that_travels ... ok
test t_the_validated_signature_is_the_one_that_travels ... ok
test t_the_intent_attachment_is_the_validated_payload ... ok

test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

     Running tests/observability_sink.rs (/home/agent/work/v16-scratch-target/release/deps/observability_sink-a60635160ff10a94)

running 4 tests
test the_rendered_lines_carry_the_identifying_fields ... ok
test the_write_sink_is_installable_as_a_dyn_event_sink ... ok
test the_write_sink_renders_every_event_kind_to_its_own_nonempty_line ... ok
test the_write_sink_drops_nothing_under_volume ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/persistence_choice_doc.rs (/home/agent/work/v16-scratch-target/release/deps/persistence_choice_doc-fb9de4589fa4c33a)

running 3 tests
test the_manifests_declare_the_recorded_engine ... ok
test no_offline_hostile_store_crate_is_declared ... ok
test the_persistence_choice_is_recorded_with_its_rationale ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/relayer_has_no_advice_surface.rs (/home/agent/work/v16-scratch-target/release/deps/relayer_has_no_advice_surface-51d121bb0d2a1ca4)

running 3 tests
test t_no_public_raw_bytes_side_door_into_the_builder ... ok
test t_the_crate_does_not_depend_on_miden_client ... ok
test t_the_crate_has_no_witness_staging_surface ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/scaffold_encapsulation.rs (/home/agent/work/v16-scratch-target/release/deps/scaffold_encapsulation-0be985f9499b1f87)

running 5 tests
test config_default_exposes_documented_values_via_accessors ... ok
test config_serde_round_trips ... ok
test metrics_start_at_zero_and_each_mutator_targets_its_own_counter ... ok
test rejection_record_round_trips_through_accessors ... ok
test secret_string_redacts_both_renderings_and_exposes_only_on_demand ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/submit_deadline.rs (/home/agent/work/v16-scratch-target/release/deps/submit_deadline-9ffed84bfc3077cc)

running 1 test
test a_hung_submit_is_bounded_by_the_deadline_and_deferred ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.33s

     Running tests/two_driver_reclaim_boundary.rs (/home/agent/work/v16-scratch-target/release/deps/two_driver_reclaim_boundary-07689ecd883f78ae)

running 4 tests
test a_live_submit_is_not_reclaimed_within_the_backoff_inclusive_envelope ... ok
test a_live_submit_cycle_is_not_reclaimed_by_a_second_driver_within_the_envelope ... ok
test a_crashed_live_submit_is_reclaimed_by_a_second_driver_past_the_boundary ... ok
test two_concurrent_drivers_do_not_clobber_a_live_claim ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.13s

     Running unittests src/lib.rs (/home/agent/work/v16-scratch-target/release/deps/xusdc_encoding-0df413dfedf1f6e3)

running 60 tests
test xreserve::encoding::account_id::tests::account_id_out_of_range_message_names_16_byte_region ... ok
test xreserve::encoding::account_id::tests::nonzero_pad_byte_rejects_at_every_index::case_06_b5 ... ok
test xreserve::encoding::account_id::tests::nonzero_pad_byte_rejects_at_every_index::case_02_b1 ... ok
test xreserve::encoding::account_id::tests::nonzero_pad_byte_rejects_at_every_index::case_01_b0 ... ok
test vectors::tests::artifact_guard ... ok
test xreserve::encoding::account_id::tests::nonzero_pad_byte_rejects_at_every_index::case_03_b2 ... ok
test xreserve::encoding::account_id::tests::nonzero_pad_byte_rejects_at_every_index::case_07_b6 ... ok
test xreserve::encoding::account_id::tests::nonzero_pad_byte_rejects_at_every_index::case_05_b4 ... ok
test xreserve::encoding::account_id::tests::nonzero_pad_byte_rejects_at_every_index::case_04_b3 ... ok
test xreserve::encoding::account_id::tests::nonzero_pad_byte_rejects_at_every_index::case_08_b7 ... ok
test xreserve::encoding::account_id::tests::nonzero_pad_byte_rejects_at_every_index::case_09_b8 ... ok
test xreserve::encoding::account_id::tests::nonzero_pad_byte_rejects_at_every_index::case_10_b9 ... ok
test xreserve::encoding::account_id::tests::nonzero_pad_byte_rejects_at_every_index::case_11_b10 ... ok
test xreserve::encoding::account_id::tests::nonzero_pad_byte_rejects_at_every_index::case_13_b12 ... ok
test xreserve::encoding::account_id::tests::nonzero_pad_byte_rejects_at_every_index::case_12_b11 ... ok
test xreserve::encoding::account_id::tests::nonzero_pad_byte_rejects_at_every_index::case_14_b13 ... ok
test xreserve::encoding::account_id::tests::nonzero_pad_byte_rejects_at_every_index::case_15_b14 ... ok
test xreserve::encoding::account_id::tests::nonzero_pad_byte_rejects_at_every_index::case_16_b15 ... ok
test xreserve::encoding::account_id::tests::tv_aid_1_roundtrip_lossless ... ok
test xreserve::encoding::account_id::tests::tv_aid_2_rejects::case_1_out_of_range ... ok
test xreserve::encoding::account_id::tests::tv_aid_2_rejects::case_2_non_canonical ... ok
test xreserve::encoding::account_id::tests::tv_aid_3_address_type_and_no_fallback ... ok
test xreserve::encoding::account_id::tests::tv_aid_4_two_felt_form ... ok
test xreserve::encoding::amount::tests::tv_amt_1_in_bound_scale6 ... ok
test xreserve::encoding::amount::tests::tv_amt_2_cap_boundary_accept ... ok
test xreserve::encoding::amount::tests::tv_amt_5_reduced_ge ... ok
test xreserve::encoding::amount::tests::tv_amt_6_dust_surfaced_rcc ... ok
test xreserve::encoding::attestation::tests::invalid_pubkey_rejects ... ok
test xreserve::encoding::amount::tests::tv_amt_rejects::case_1_tv_amt_3_cap_reject ... ok
test xreserve::encoding::attestation::tests::tv_att_1_felt_shapes ... ok
test xreserve::encoding::amount::tests::tv_amt_rejects::case_2_tv_amt_4_limb_overflow ... ok
test xreserve::encoding::attestation::tests::tv_att_2_commitment ... ok
test xreserve::encoding::burn_note::tests::tv_bn_2_destination_in_items ... ok
test xreserve::encoding::burn_note::tests::tv_bn_3_note_storage_placement ... ok
test xreserve::encoding::burn_note::tests::tv_bn_4_malformed_burn_items::case_2 ... ok
test xreserve::encoding::attestation::tests::tv_att_3_raw_keccak_not_eip712 ... ok
test xreserve::encoding::burn_note::tests::tv_bn_4_malformed_burn_items::case_3 ... ok
test xreserve::encoding::burn_note::tests::tv_bn_4_malformed_burn_items::case_1 ... ok
test xreserve::encoding::burn_note::tests::tv_bn_4_malformed_burn_items::case_4 ... ok
test xreserve::encoding::amount::tests::tv_amt_rejects::case_3_tv_amt_7_scale_overflow ... ok
test xreserve::encoding::burn_note::tests::tv_bn_4_malformed_burn_items::case_5 ... ok
test xreserve::encoding::burn_note::tests::tv_bn_4_malformed_burn_items::case_6 ... ok
test xreserve::encoding::bytes32::tests::tv_b32_1_hash_to_word_positive ... ok
test xreserve::encoding::burn_note::tests::tv_bn_1_round_trip ... ok
test xreserve::encoding::bytes32::tests::tv_b32_2_lossless_rejects_option_b_succeeds ... ok
test xreserve::encoding::bytes32::tests::tv_b32_3_determinism ... ok
test xreserve::encoding::deposit_intent::tests::tv_di_1_positive_parse ... ok
test xreserve::encoding::bytes32::tests::tv_b32_inverse_round_trip ... ok
test xreserve::encoding::deposit_intent::tests::tv_di_7_sixty_felts_and_1024_bound ... ok
test xreserve::encoding::bytes32::tests::tv_b32_inverse_rejects_non_u32 ... ok
test xreserve::encoding::deposit_intent::tests::tv_di_8_input_immutable ... ok
test xreserve::encoding::deposit_intent::tests::tv_di_rejects::case_2_tv_di_3_bad_version ... ok
test xreserve::encoding::deposit_intent::tests::tv_di_rejects::case_1_tv_di_2_bad_magic ... ok
test xreserve::encoding::deposit_intent::tests::tv_di_rejects::case_4_tv_di_5_zero_local_token ... ok
test xreserve::encoding::deposit_intent::tests::tv_di_rejects::case_5_tv_di_5_zero_local_depositor ... ok
test xreserve::encoding::deposit_intent::tests::tv_di_rejects::case_3_tv_di_4_zero_amount ... ok
test xreserve::encoding::deposit_intent::tests::tv_di_rejects::case_6_tv_di_6_length_mismatch ... ok
test xreserve::encoding::bytes32::tests::tv_b32_4_packing_is_8_felts_two_words ... ok
test xreserve::encoding::deposit_intent::tests::tv_di_9_offsets_table ... ok
test xreserve::encoding::deposit_intent::tests::tv_di_rejects::case_7_tv_di_6_truncated_header ... ok

test result: ok. 60 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/account_callable_surface.rs (/home/agent/work/v16-scratch-target/release/deps/account_callable_surface-f5c865961b7f8af9)

running 7 tests
test freeze_and_unfreeze_are_not_admissible_via_either_allowlist ... ok
test freeze_and_unfreeze_are_unreachable_from_every_allowlisted_note ... ok
test invoke_wrappers_are_live_and_the_asset_is_policed ... ok
test authority_freeze_and_unfreeze_are_present_on_the_account ... ok
test the_auth_component_rejects_a_non_allowlisted_note ... ok
test the_auth_component_rejects_non_expiration_tx_scripts_and_admits_expiration ... ok
test production_account_callable_surface_is_frozen ... ok

test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.76s

     Running tests/account_surface_unreachable.rs (/home/agent/work/v16-scratch-target/release/deps/account_surface_unreachable-a13d1218fefe1994)

running 8 tests
test set_role_admin_former_note_root_is_not_admissible_via_either_allowlist ... ok
test tier_b_fee_rows_are_not_referenced_by_any_allowlisted_note ... ok
test set_role_admin_is_unreachable_from_every_allowlisted_note ... ok
test tier_a_mutators_are_unreachable_from_every_allowlisted_note ... ok
test rbac_set_role_admin_is_present_on_the_account ... ok
test get_authority_is_read_only_on_the_account ... ok
test ratified_growth_rows_are_not_admissible_via_either_allowlist ... ok
test ratified_growth_rows_are_present_on_the_account ... ok

test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.88s

     Running tests/assembled_faucet_e2e.rs (/home/agent/work/v16-scratch-target/release/deps/assembled_faucet_e2e-5b46fcaf0f8d6e95)

running 2 tests
test second_mint_to_distinct_recipient ... ok
test assembled_faucet_full_lifecycle ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.59s

     Running tests/basic_asset_tripwire.rs (/home/agent/work/v16-scratch-target/release/deps/basic_asset_tripwire-59b3888befc8e5a1)

running 1 test
test production_build_wires_the_transfer_blocklist ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s

     Running tests/builder_api.rs (/home/agent/work/v16-scratch-target/release/deps/builder_api-2769eed15256c1bb)

running 27 tests
test build_rejects_immutable_max_supply ... ok
test build_accepts_matching_min_burn_override ... ok
test build_rejects_missing_domain_config ... ok
test build_rejects_min_burn_size_exceeding_max ... ok
test build_rejects_missing_xreserve_slot::case_1_domain ... ok
test build_rejects_missing_attestation_mint_policy ... ok
test build_produces_attestation_gated_public_faucet ... ok
test build_rejects_missing_xreserve_slot::case_2_identifier ... ok
test build_rejects_missing_xreserve_slot::case_4_xreserve_contract_hi ... ok
test build_rejects_missing_xreserve_slot::case_5_xreserve_contract_lo ... ok
test build_rejects_missing_xreserve_slot::case_7_xreserve_attesters ... ok
test build_rejects_missing_xreserve_slot::case_3_source_domain ... ok
test build_rejects_non_public_account_type ... ok
test build_rejects_missing_xreserve_slot::case_6_used_nonces ... ok
test build_rejects_non_min_burn_amount_burn_policy ... ok
test build_rejects_nonempty_identifier_seed ... ok
test build_rejects_wrong_decimals ... ok
test build_rejects_same_root_zero_seeded_min_burn_override ... ok
test build_rejects_wrong_token_symbol ... ok
test builder_installs_no_stock_pause_manager ... ok
test build_seeds_the_domain_config_slots ... ok
test build_rejects_zero_min_burn_size ... ok
test production_components_carry_mutability_config_slot ... ok
test production_components_carry_is_paused_slot ... ok
test production_composition_installs_one_xreserve_and_one_manager ... ok
test production_seeds_min_burn_size ... ok
test seam_rejects_a_smuggled_foreign_policy_companion ... ok

test result: ok. 27 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.29s

     Running tests/builder_isolation.rs (/home/agent/work/v16-scratch-target/release/deps/builder_isolation-31b321e63a7b3b95)

running 4 tests
test build_rejects_blk_manager_colliding_with_a_privileged_role::case_3_dom_manager ... ok
test build_rejects_blk_manager_colliding_with_a_privileged_role::case_1_owner ... ok
test build_accepts_isolated_blk_manager ... ok
test build_rejects_blk_manager_colliding_with_a_privileged_role::case_2_dom_pauser ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s

     Running tests/burn_policy.rs (/home/agent/work/v16-scratch-target/release/deps/burn_policy-e4d891796439e9c2)

running 10 tests
test burn_zero_amount_rejects_direct ... ok
test probe_stock_burn_policy_installed ... ok
test burn_valid_passes_and_decrements ... ok
test burn_zero_amount_rejects ... ok
test burn_below_min_rejects ... ok
test burn_at_min_passes_and_decrements ... ok
test burn_at_min_minus_one_rejects ... ok
test burn_below_min_passes_under_allow_all ... ok
test burn_paused_rejects ... ok
test zero_amount_burn_note_reachability ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.29s

     Running tests/config_note_absence.rs (/home/agent/work/v16-scratch-target/release/deps/config_note_absence-90548007121d0243)

running 3 tests
test config_note_root_is_not_in_the_builder_allowlist ... ok
test config_note_root_is_not_in_the_auth_components_allowlist ... ok
test config_note_root_is_absent_from_the_built_accounts_allowlist ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.69s

     Running tests/constant_parity.rs (/home/agent/work/v16-scratch-target/release/deps/constant_parity-8a8ec0b2e44664f9)

running 5 tests
test masm_rust_error_string_parity ... ok
test masm_constants_bidirectional ... ok
test masm_rust_constant_parity ... ok
test masm_shell_error_string_parity ... ok
test owner_controlled_authority_parity ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s

     Running tests/f5_admin_notes.rs (/home/agent/work/v16-scratch-target/release/deps/f5_admin_notes-a554031e857bdb42)

running 60 tests
test former_set_role_admin_note_script_still_compiles_to_the_former_root ... ok
test block_account_note_script_root_is_pinned ... ok
test accept_ownership_note_script_root_is_pinned ... ok
test grant_role_note_script_root_is_pinned ... ok
test grant_role_owner_on_delegated_role_traps ... ok
test grant_role_dom_manager_authorized ... ok
test grant_role_owner_authorized ... ok
test grant_role_note_args_are_inert ... ok
test identifier_init_note_script_root_is_pinned ... ok
test accept_ownership_current_owner_traps ... ok
test accept_ownership_third_party_traps ... ok
test accept_ownership_pending_owner_becomes_owner ... ok
test accept_ownership_note_args_are_inert ... ok
test identifier_init_note_args_are_inert ... ok
test pause_note_script_root_is_pinned ... ok
test identifier_init_dom_pauser_traps ... ok
test identifier_init_owner_writes_only_the_identifier_slot ... ok
test identifier_init_third_party_traps ... ok
test grant_role_third_party_traps ... ok
test revoke_role_note_script_root_is_pinned ... ok
test pause_dom_pauser_sets_is_paused ... ok
test identifier_init_reinit_traps_even_from_owner ... ok
test pause_note_args_are_inert ... ok
test set_attester_note_script_root_is_pinned ... ok
test pause_owner_traps ... ok
test pause_third_party_traps ... ok
test revoke_role_third_party_traps ... ok
test set_max_supply_note_script_root_is_pinned ... ok
test revoke_role_dom_manager_authorized ... ok
test set_max_supply_dom_manager_traps ... ok
test set_attester_admin_note_owner_writes_and_nonowner_traps ... ok
test revoke_role_owner_authorized ... ok
test revoke_role_note_args_are_inert ... ok
test set_min_burn_size_note_script_root_is_pinned ... ok
test set_max_supply_note_args_are_inert ... ok
test set_max_supply_dom_pauser_traps ... ok
test set_max_supply_owner_writes_cap ... ok
test set_max_supply_third_party_traps ... ok
test set_min_burn_size_dom_manager_traps ... ok
test set_min_burn_size_dom_pauser_traps ... ok
test set_min_burn_size_note_args_are_inert ... ok
test set_min_burn_size_owner_writes_slot ... ok
test set_min_burn_size_zero_floor_from_owner_traps ... ok
test set_min_burn_size_third_party_traps ... ok
test transfer_ownership_note_script_root_is_pinned ... ok
test set_role_admin_note_is_rejected_as_non_allowlisted ... ok
test transfer_ownership_dom_manager_traps ... ok
test unblock_account_note_script_root_is_pinned ... ok
test transfer_ownership_dom_pauser_traps ... ok
test set_role_admin_third_party_traps ... ok
test unpause_note_script_root_is_pinned ... ok
test set_role_admin_dom_manager_traps ... ok
test set_role_admin_note_is_rejected_regardless_of_note_args ... ok
test transfer_ownership_note_args_are_inert ... ok
test transfer_ownership_owner_nominates ... ok
test transfer_ownership_third_party_traps ... ok
test unpause_third_party_traps ... ok
test unpause_owner_traps ... ok
test unpause_dom_pauser_clears_is_paused ... ok
test unpause_note_args_are_inert ... ok

test result: ok. 60 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.34s

     Running tests/f5_network_account_auth.rs (/home/agent/work/v16-scratch-target/release/deps/f5_network_account_auth-11d884cf62c64a20)

running 8 tests
test production_faucet_note_allowlist_is_exactly_the_14_ratified_roots ... ok
test burn_note_carries_scheme2_target_to_faucet ... ok
test production_faucet_auth_component_is_stock_network_account ... ok
test mint_note_carries_the_three_xusdc_attachments ... ok
test production_faucet_tx_script_allowlist_is_exactly_the_expiration_root ... ok
test production_faucet_is_a_network_account ... ok
test non_allowlisted_note_is_rejected_by_auth ... ok
test non_expiration_tx_script_is_rejected_and_expiration_is_admitted ... ok

test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.85s

     Running tests/fee_policy_provisional_pin.rs (/home/agent/work/v16-scratch-target/release/deps/fee_policy_provisional_pin-906b32199b2aef76)

running 4 tests
test tbd_deploy_fee_faucet_id_is_pinned ... ok
test auth_component_fee_slots_hold_the_provisional_config ... ok
test fee_schedule_is_zero_for_exactly_the_allowlisted_roots ... ok
test built_account_fee_storage_matches_the_provisional_config ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.68s

     Running tests/identifier_init.rs (/home/agent/work/v16-scratch-target/release/deps/identifier_init-49b8b30b44e8e8ea)

running 10 tests
test identifier_init_note_binds_the_identifier_to_the_faucet ... ok
test probe_identifier_init_exports ... ok
test identifier_init_stranger_rejects ... ok
test identifier_init_empty_identifier_traps ... ok
test identifier_init_owner_writes_the_own_id_key ... ok
test production_build_seeds_the_domain_config ... ok
test identifier_init_succeeds_while_paused ... ok
test identifier_init_foreign_identifier_rejects ... ok
test identifier_init_reinit_traps_and_leaves_config_unchanged ... ok
test identifier_init_dom_pauser_rejects ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.42s

     Running tests/masm_dual.rs (/home/agent/work/v16-scratch-target/release/deps/masm_dual-09862b15fc7476c3)

running 9 tests
test probe_p4_packing_util ... ok
test probe_p1_exports ... ok
test probe_p2_script_executes ... ok
test harness_detects_wrong_vector ... ok
test tv_dual_5_pubkey_commitment ... ok
test tv_dual_1_bytes32_to_key ... ok
test tv_circle_differential_real_bytes ... ok
test tv_dual_2_uint256_reducer ... ok
test tv_dual_3_parse_deposit_intent ... ok

test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.33s

     Running tests/masm_mint_shell.rs (/home/agent/work/v16-scratch-target/release/deps/masm_mint_shell-6d21171acf657997)

running 35 tests
test d5b_fee_advice_missing ... ok
test d5b_fee_advice_malformed_limb ... ok
test d5b_amount_fee_rejects::case_2_r_mint_9_maxfee_overflow ... ok
test d5b_amount_fee_rejects::case_4_r_mint_10_amount_below_fee ... ok
test d5b_amount_fee_rejects::case_3_r_mint_9_fee_overflow ... ok
test d5b_amount_fee_rejects::case_6_fee_eq_maxfee ... ok
test d5b_amount_fee_rejects::case_5_r_mint_11_fee_over_maxfee ... ok
test d5b_amount_fee_rejects::case_1_r_mint_9_amount_overflow ... ok
test d5b_happy_amount_fee::case_1_fee_zero ... ok
test d5b_happy_amount_fee::case_2_amount_eq_maxfee ... ok
test d5c_replay_rejects::case_1_hookdata ... ok
test d5c_replay_rejects::case_2_empty_hookdata ... ok
test d5b_happy_amount_fee::case_3_cap_value ... ok
test d5c_happy_nonce_unused::case_1_hookdata ... ok
test d5c_happy_nonce_unused::case_2_empty_hookdata ... ok
test d5c_unrelated_seeded_nonce_passes ... ok
test d5d_forged_sig_rejects ... ok
test d5d_missing_advice_traps ... ok
test probe_attestation_verify_exports ... ok
test d5d_happy_attestation ... ok
test happy_path_mint_preconditions::case_1_hookdata ... ok
test d5d_non_allowlisted_rejects ... ok
test probe_mint_amounts_exports ... ok
test probe_nonce_unused_exports ... ok
test happy_path_mint_preconditions::case_2_empty_hookdata ... ok
test probe_shell_exports ... ok
test r_mint_rejects::case_1_r_mint_1_bad_magic ... ok
test d5d_seam_both_arrangements_reject ... ok
test r_mint_rejects::case_3_r_mint_3_zero_amount ... ok
test probe_slot_binding ... ok
test r_mint_rejects::case_4_r_mint_4_zero_local_token ... ok
test r_mint_rejects::case_2_r_mint_2_bad_version ... ok
test r_mint_rejects::case_6_r_mint_6_wrong_domain ... ok
test r_mint_rejects::case_5_r_mint_5_zero_local_depositor ... ok
test r_mint_rejects::case_7_r_mint_7_wrong_identifier ... ok

test result: ok. 35 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.50s

     Running tests/masm_structure.rs (/home/agent/work/v16-scratch-target/release/deps/masm_structure-842b0b2bea1051a3)

running 52 tests
test checker_accepts_brace_shorthand_where_definitions ... ok
test checker_accepts_conformant_component_proc ... ok
test checker_accepts_expression_and_array_stack_items ... ok
test checker_accepts_lowercase_and_non_letter_inline_comments ... ok
test checker_accepts_full_path_requires_bullet ... ok
test checker_flags_call_boundary_without_stack_list ... ok
test checker_flags_description_paragraph_without_sentence_end ... ok
test checker_flags_expression_with_trailing_operand ... ok
test checker_flags_inputs_marker_present_only_as_prose ... ok
test checker_flags_hyphenated_stack_item ... ok
test checker_flags_missing_storage_section_on_transport_note ... ok
test checker_flags_mixed_case_stack_item_name ... ok
test checker_flags_expression_with_double_operator ... ok
test checker_flags_non_verb_description_lead ... ok
test checker_flags_unparenthesized_span_junk ... ok
test checker_flags_open_ended_call_boundary_list ... ok
test checker_flags_panics_section_without_condition_bullets ... ok
test checker_flags_storage_section_on_storage_less_note ... ok
test checker_flags_pronoun_lead_description ... ok
test checker_flags_unregistered_note_storage_posture ... ok
test checker_flags_where_bullet_without_definition_verb ... ok
test checker_flags_where_definition_token_collision ... ok
test checker_flags_unresolvable_call_target_in_note ... ok
test checker_flags_trailing_junk_after_call_boundary_span ... ok
test checker_flags_wrong_module_in_requires_bullet ... ok
test checker_flags_where_section_missing_an_input_definition ... ok
test checker_flags_uppercase_inline_comment ... ok
test assertions_name_error_constants ... ok
test call_boundary_docs_span_sixteen_elements ... ok
test constants_precede_procedures ... ok
test constant_declarations_space_the_equals_sign ... ok
test error_constants_are_grouped_last_and_string_valued ... ok
test doc_bullets_are_terminated_sentences ... ok
test direct_assertions_are_documented_in_panics ... ok
test doc_sections_follow_canonical_order ... ok
test files_open_with_their_canonical_header ... ok
test files_are_whitespace_clean ... ok
test note_docs_describe_carried_storage ... ok
test inline_comments_start_lowercase ... ok
test note_docs_declare_required_account_procedures ... ok
test note_script_entry_docs_follow_protocol_shape ... ok
test invocation_docs_match_invocation_sites ... ok
test procedures_carry_complete_doc_blocks ... ok
test public_procedures_precede_helpers ... ok
test references_resolve_through_imports_not_absolute_paths ... ok
test use_block_is_contiguous ... ok
test stack_trackers_are_followed_by_a_blank_line ... ok
test section_banners_are_known_ordered_and_exhaustive ... ok
test stack_item_names_follow_the_capitalization_grammar ... ok
test use_lines_follow_protocol_group_order ... ok
test where_sections_define_the_documented_stack_items ... ok
test stack_trackers_are_well_formed ... ok

test result: ok. 52 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

     Running tests/migration_evidence_ledger.rs (/home/agent/work/v16-scratch-target/release/deps/migration_evidence_ledger-5aaaa40e2b5573a9)

running 5 tests
test hunk_free_files_are_listed_explicitly ... ok
test every_ledger_row_carries_file_hunk_and_one_class ... ok
test new_file_rows_are_present_and_verbatim ... ok
test ledger_totals_reconcile_with_the_rows ... ok
test ledger_rows_match_the_baseline_diff_exactly ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.12s

     Running tests/mint_policy_binding_e2e.rs (/home/agent/work/v16-scratch-target/release/deps/mint_policy_binding_e2e-8dba51816dcd5449)

running 16 tests
test mint_rejects_a_missing_routing_target ... ok
test mint_rejects_a_noncanonical_recipient::case_1_prefix ... ok
test mint_rejects_a_malformed_attested_recipient ... ok
test mint_rejects_a_fourth_attachment ... ok
test mint_halts_while_paused ... ok
test mint_rejects_a_missing_intent_attachment ... ok
test mint_note_routes_to_the_faucet_network_account ... ok
test mint_rejects_a_missing_attestation_attachment ... ok
test mint_rejects_a_noncanonical_recipient::case_2_suffix ... ok
test tx_script_mint_and_send_cannot_mint ... ok
test mint_rejects_a_truncated_intent ... ok
test mint_rejects_a_tag_mismatch ... ok
test mint_rejects_a_wrong_attestation_word_count ... ok
test mint_rejects_an_intent_length_mismatch ... ok
test mint_rejects_an_amount_mismatch ... ok
test mint_rejects_a_private_output_note ... ok

test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.20s

     Running tests/mint_policy_e2e.rs (/home/agent/work/v16-scratch-target/release/deps/mint_policy_e2e-815d9955e87537e1)

running 11 tests
test mint_rejects_a_non_allowlisted_attester ... ok
test mint_rejects_a_wrong_domain ... ok
test mint_rejects_a_forged_signature ... ok
test mint_rejects_a_wrong_identifier ... ok
test mint_rejects_after_the_owner_lowers_max_supply_below_the_amount ... ok
test mint_accepts_at_the_exact_raised_cap_boundary ... ok
test mint_rejects_a_removed_attester ... ok
test mint_accepts_after_the_owner_raises_max_supply ... ok
test mint_rejects_an_amount_below_max_fee ... ok
test mint_rejects_an_over_cap_amount ... ok
test mint_rotation_rejects_the_old_attester_and_accepts_the_new ... ok

test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.19s

     Running tests/mint_root_surface.rs (/home/agent/work/v16-scratch-target/release/deps/mint_root_surface-e37062db70c69207)

running 1 test
test production_xreserve_callable_root_set_is_frozen ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s

     Running tests/mint_scale_conformance.rs (/home/agent/work/v16-scratch-target/release/deps/mint_scale_conformance-f69e4a1e2ffe737d)

running 5 tests
test shipped_faucet_declares_identity_deposit_scale ... ok
test production_mint_leaves_no_fractional_remainder ... ok
test production_mint_delivers_the_circle_amount_unrescaled ... ok
test mint_to_a_blocked_recipient_succeeds_then_strands ... ok
test production_mint_is_an_identity_across_circle_amounts ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.06s

     Running tests/module_split_doc_hygiene.rs (/home/agent/work/v16-scratch-target/release/deps/module_split_doc_hygiene-95a45c26a9a8172e)

running 3 tests
test builder_error_intra_doc_links_are_module_qualified ... ok
test decision_record_names_the_current_admin_note_module ... ok
test dev5_stays_open_in_the_wave1_sources ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/ownable2step_admin.rs (/home/agent/work/v16-scratch-target/release/deps/ownable2step_admin-1c4a3fbb88cf01a9)

running 1 test
test owner_two_step_transfer_rotates_authority ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.27s

     Running tests/pause_admin.rs (/home/agent/work/v16-scratch-target/release/deps/pause_admin-9c03d65ed831dd6a)

running 18 tests
test dom_pauser_cannot_call_owner_setters ... ok
test non_dom_pauser_pause_rejects ... ok
test dom_pauser_pause_halts_burn ... ok
test is_paused_publicly_readable ... ok
test dom_pauser_production_pause_note_halts_burn ... ok
test owner_has_no_pause_path ... ok
test non_dom_pauser_unpause_rejects::case_1_stranger ... ok
test other_role_holder_cannot_pause ... ok
test non_dom_pauser_unpause_rejects::case_2_owner ... ok
test non_dom_pauser_unpause_rejects::case_3_dom_manager ... ok
test probe_pause_admin_exports ... ok
test owner_is_not_dom_pauser_on_custom_pause ... ok
test owner_has_no_unpause_path ... ok
test unpause_when_not_paused_is_idempotent ... ok
test pause_when_already_paused_is_idempotent ... ok
test dom_pauser_production_pause_note_halts_mint ... ok
test dom_pauser_pause_halts_mint ... ok
test dom_pauser_unpause_resumes_mint_and_burn ... ok

test result: ok. 18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.15s

     Running tests/role_admin.rs (/home/agent/work/v16-scratch-target/release/deps/role_admin-60df79d5c4ab8396)

running 18 tests
test dom_manager_cannot_administer_dom_manager ... ok
test dom_pauser_holder_cannot_grant_or_revoke ... ok
test owner_can_revoke_dom_manager_cutting_the_delegation_chain ... ok
test dom_manager_revokes_pauser_then_pause_rejects ... ok
test dom_pauser_can_renounce_own_role ... ok
test double_grant_pauser_leaves_no_ghost_member ... ok
test revoke_role_non_member_traps ... ok
test set_role_admin_dom_pauser_rejects ... ok
test set_role_admin_dom_manager_can_redelegate_pauser ... ok
test owner_reaches_set_role_admin_through_dom_manager ... ok
test owner_can_still_grant_pauser ... ok
test owner_can_still_revoke_pauser ... ok
test set_role_admin_owner_direct_rejects ... ok
test shipped_delegation_reads_back ... ok
test set_role_admin_stranger_rejects ... ok
test stranger_cannot_grant_or_revoke ... ok
test dom_manager_grants_pauser_then_new_pauser_halts_mint ... ok
test dom_manager_rotates_pauser_revoke_then_grant ... ok

test result: ok. 18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.99s

     Running tests/s12_expiration_tx_script_allowlist.rs (/home/agent/work/v16-scratch-target/release/deps/s12_expiration_tx_script_allowlist-71fa7dad8520d3fd)

running 3 tests
test auth_component_note_script_allowlist_is_untouched_by_s12 ... ok
test auth_component_tx_script_allowlist_is_exactly_the_expiration_root ... ok
test expiration_is_admitted_and_every_other_tx_script_is_rejected ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.75s

     Running tests/set_attester.rs (/home/agent/work/v16-scratch-target/release/deps/set_attester-fefe71fc3aef466d)

running 6 tests
test probe_attester_admin_exports ... ok
test production_build_gates_mint_on_the_attestation_policy ... ok
test set_attester_former_admin_dom_pauser_non_owner_rejects ... ok
test set_attester_dom_manager_non_owner_rejects ... ok
test set_attester_owner_succeeds ... ok
test set_attester_owner_succeeds_while_paused ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.27s

     Running tests/set_max_supply.rs (/home/agent/work/v16-scratch-target/release/deps/set_max_supply-9c248fcfa4088e5b)

running 6 tests
test set_max_supply_immutable_traps ... ok
test set_max_supply_dom_manager_non_owner_rejects ... ok
test set_max_supply_dom_pauser_non_owner_rejects ... ok
test set_max_supply_owner_succeeds ... ok
test set_max_supply_below_supply_rejects ... ok
test set_max_supply_paused_rejects ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.21s

     Running tests/set_min_burn.rs (/home/agent/work/v16-scratch-target/release/deps/set_min_burn-c0805279b2ccced5)

running 8 tests
test probe_stock_min_burn_setter_installed ... ok
test support_replica_carries_delegation_seed ... ok
test dom_non_member_reads_empty ... ok
test set_min_burn_dom_pauser_non_owner_rejects ... ok
test set_min_burn_dom_manager_non_owner_rejects ... ok
test set_min_burn_plain_non_owner_rejects ... ok
test set_min_burn_owner_succeeds ... ok
test set_min_burn_owner_succeeds_while_paused ... ok

test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.22s

     Running tests/surface_count_prose_conformance.rs (/home/agent/work/v16-scratch-target/release/deps/surface_count_prose_conformance-bf4f7441dd69665a)

running 1 test
test conformance_prose_counts_match_the_executable_surface ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.74s

     Running tests/transfer_blocklist_e2e.rs (/home/agent/work/v16-scratch-target/release/deps/transfer_blocklist_e2e-aaa9d135308c4c84)

running 9 tests
test block_by_non_blk_manager_is_rejected::case_2_owner ... ok
test block_by_non_blk_manager_is_rejected::case_1_stranger ... ok
test block_by_non_blk_manager_is_rejected::case_3_dom_manager ... ok
test block_by_blk_manager_holder_succeeds_and_writes_the_map ... ok
test former_blk_manager_holder_rejected_after_revoke ... ok
test unblock_by_non_blk_manager_is_rejected::case_2_owner ... ok
test unblock_by_non_blk_manager_is_rejected::case_1_stranger ... ok
test unblock_by_blk_manager_holder_succeeds_and_clears_the_map ... ok
test unblock_by_non_blk_manager_is_rejected::case_3_dom_manager ... ok

test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.31s

     Running tests/transfer_blocklist_semantics.rs (/home/agent/work/v16-scratch-target/release/deps/transfer_blocklist_semantics-1ca42a77503b5c44)

running 10 tests
test send_without_faucet_foreign_account_fails ... ok
test blocked_recipient_cannot_consume_and_the_note_strands ... ok
test transfer_to_a_blocked_recipient_strands_at_consume ... ok
test pause_halts_a_holder_to_holder_p2id_transfer ... ok
test blocked_holder_cannot_send_or_redeem ... ok
test pause_halts_a_holder_policed_transfer ... ok
test faucet_side_burn_consume_is_callback_unaffected ... ok
test unblock_restores_the_holder_send ... ok
test unblocked_holder_can_send_with_faucet_foreign ... ok
test unblock_restores_the_recipient_consume ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.50s

     Running tests/wave1_recomposition.rs (/home/agent/work/v16-scratch-target/release/deps/wave1_recomposition-d4be41cde9fa3286)

running 10 tests
test active_mint_policy_is_the_attestation_policy ... ok
test allowed_mint_policy_map_is_exactly_the_attestation_root ... ok
test builder_rejects_a_non_attestation_mint_policy ... ok
test builder_rejects_a_zero_min_burn_floor ... ok
test legacy_config_and_burn_masm_are_replaced ... ok
test burn_policy_is_stock_min_burn_amount_with_a_positive_floor ... ok
test min_burn_note_targets_the_stock_setter_with_a_floor_guard ... ok
test custom_mint_transport_masm_is_deleted ... ok
test mint_deny_guard_is_fully_dissolved ... ok
test note_allowlist_pins_the_stock_mint_note ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.98s

     Running tests/wave1_recomposition_e2e.rs (/home/agent/work/v16-scratch-target/release/deps/wave1_recomposition_e2e-97500facbb313c70)

running 5 tests
test min_burn_note_rejects_a_zero_floor_at_runtime ... ok
test stock_mint_note_rejects_a_nonzero_fee ... ok
test stock_mint_note_rejects_a_replay ... ok
test stock_mint_note_mints_the_attested_amount ... ok
test stock_mint_note_rejects_a_recipient_mismatch ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.59s

     Running tests/wave1_sec_hardening.rs (/home/agent/work/v16-scratch-target/release/deps/wave1_sec_hardening-4f65825bef3a58ea)

running 6 tests
test set_min_burn_above_the_asset_max_is_rejected ... ok
test block_account_targeting_the_faucet_itself_is_rejected ... ok
test block_account_targeting_a_different_account_still_succeeds ... ok
test set_min_burn_zero_still_rejected_by_the_floor ... ok
test set_min_burn_at_the_floor_still_succeeds ... ok
test set_min_burn_at_exactly_the_asset_max_is_accepted ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.32s

     Running tests/xreserve_burn.rs (/home/agent/work/v16-scratch-target/release/deps/xreserve_burn-717defbc1189f8c9)

running 8 tests
test burn_note_is_public_with_fixed_tag ... ok
test burn_note_payload_schema ... ok
test burn_note_is_never_private ... ok
test burn_note_insufficient_balance_rejects_create ... ok
test production_burn_note_same_block_consume_is_erased ... ok
test burn_note_consumed_by_faucet_decrements ... ok
test recipient_burns_full_balance ... ok
test burn_note_emitted_items_match_codec_vectors ... ok

test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.68s

     Running tests/xreserve_receive_and_burn.rs (/home/agent/work/v16-scratch-target/release/deps/xreserve_receive_and_burn-1efe169003376e4d)

running 14 tests
test pinned_standards_fixture_unchanged ... ok
test pinned_standards_rev_matches_cargo ... ok
test pinned_standards_single_faucet_burn_caller ... ok
test pinned_standards_single_supply_decrement_write ... ok
test rev_pin_binds_to_miden_standards_specifically ... ok
test only_receive_and_burn_lowers_supply ... ok
test xreserve_tree_has_no_supply_surface ... ok
test allow_all_active_burn_policy_fails_sole_decrement_audit ... ok
test burn_zero_rejected_through_composition ... ok
test burn_below_min_rejected_through_composition ... ok
test burn_consume_composition_decrements_once ... ok
test set_min_burn_raise_then_below_new_min_rejects ... ok
test set_min_burn_lower_then_at_new_min_passes ... ok
test burn_paused_rejected_through_composition ... ok

test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.25s

   Doc-tests withdrawal_listener_attester

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests xreserve_deposit_relayer

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests xusdc_encoding

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

TEST_EXIT=0
```

### 1.3 `cargo clippy --workspace --all-targets --locked --release`

```
    Checking xusdc-encoding v0.0.0 (/home/agent/work/miden-usdcx/crates/xusdc-encoding)
    Finished `release` profile [optimized] target(s) in 0.53s
CLIPPY_EXIT=0
```

### 1.4 `cargo clippy --workspace --locked -- -D warnings` (the house gate)

```
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.29s
CLIPPY_EXIT=0
```

### 1.5 `cargo fmt --all -- --check`

```
FMT_EXIT=0
```

## 2. Per-`@@`-hunk tripwire classification ledger

One row per `@@` hunk of `git diff --unified=3 8a3fb04 -- <file>` for every tripwire file and
every file on the Phase-0 ROOT_HEX enumeration, plus the sanctioned NEW test files (which are
intent-to-add staged, so git emits their whole-file `@@ -0,0 +1,N @@` headers — N is each file's
full line count). Every row carries the file, the FULL VERBATIM `@@` line exactly as git prints
it, and its single sanctioned class (the six classes of `MIGRATION-V16-NEXT.md` §3.1). A hunk
spanning two classes appears as TWO rows sharing one `@@` header, each marked SPLIT in the note.
`crates/xusdc-encoding/tests/migration_evidence_ledger.rs` guards this ledger executably: row
form, the new-file line counts, the totals reconciliation, and BYTE-FOR-BYTE correspondence of
every `(file, @@ header)` pair with the live `git diff --unified=3 8a3fb04` over the declared
scope.

| File | `@@` hunk (verbatim) | Class | Note |
|---|---|---|---|
| `crates/xusdc-encoding/tests/account_callable_surface.rs` | `@@ -41,7 +41,7 @@` | 3 |  |
| `crates/xusdc-encoding/tests/account_callable_surface.rs` | `@@ -102,7 +102,8 @@ const MAX_SUPPLY: u64 = 1_000_000;` | 3 |  |
| `crates/xusdc-encoding/tests/account_callable_surface.rs` | `@@ -120,7 +121,7 @@ const MAX_SUPPLY: u64 = 1_000_000;` | 3 |  |
| `crates/xusdc-encoding/tests/account_callable_surface.rs` | `@@ -138,7 +139,7 @@ const FROZEN_ACCOUNT_SURFACE: [&str; 64] = [` | 3 |  |
| `crates/xusdc-encoding/tests/account_callable_surface.rs` | `@@ -155,7 +156,25 @@ const FROZEN_ACCOUNT_SURFACE: [&str; 64] = [` | 3 |  |
| `crates/xusdc-encoding/tests/account_callable_surface.rs` | `@@ -194,6 +213,10 @@ const FROZEN_ACCOUNT_SURFACE: [&str; 64] = [` | 3 |  |
| `crates/xusdc-encoding/tests/account_callable_surface.rs` | `@@ -203,10 +226,9 @@ const FROZEN_ACCOUNT_SURFACE: [&str; 64] = [` | 6 | class-6: `components.push(auth.into())` -> `components.extend(auth)` in `production_components` |
| `crates/xusdc-encoding/tests/account_callable_surface.rs` | `@@ -284,8 +306,8 @@ fn production_account_callable_surface_is_frozen() -> Result<()> {` | 3 |  |
| `crates/xusdc-encoding/tests/account_callable_surface.rs` | `@@ -296,7 +318,7 @@ fn production_account_callable_surface_is_frozen() -> Result<()> {` | 3 |  |
| `crates/xusdc-encoding/tests/account_callable_surface.rs` | `@@ -320,7 +342,7 @@ fn production_account_callable_surface_is_frozen() -> Result<()> {` | 3 |  |
| `crates/xusdc-encoding/tests/account_callable_surface.rs` | `@@ -448,8 +470,8 @@ async fn the_auth_component_rejects_a_non_allowlisted_note() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/account_callable_surface.rs` | `@@ -478,8 +500,7 @@ async fn the_auth_component_rejects_non_expiration_tx_scripts_and_admits_expirat` | 5 |  |
| `crates/xusdc-encoding/tests/account_callable_surface.rs` | `@@ -495,8 +516,7 @@ async fn the_auth_component_rejects_non_expiration_tx_scripts_and_admits_expirat` | 5 |  |
| `crates/xusdc-encoding/tests/account_surface_unreachable.rs` | `@@ -7,7 +7,14 @@` | 3 | two-tier header addendum (round 3) |
| `crates/xusdc-encoding/tests/account_surface_unreachable.rs` | `@@ -20,10 +27,11 @@ use std::collections::BTreeSet;` | 3 | imports for the two-tier growth tests (`StorageSlotContent`, `AuthNetworkAccount`) |
| `crates/xusdc-encoding/tests/account_surface_unreachable.rs` | `@@ -45,10 +53,9 @@ const MAX_SUPPLY: u64 = 1_000_000;` | 6 | class-6: `components.push(auth.into())` -> `components.extend(auth)` in `production_components` |
| `crates/xusdc-encoding/tests/account_surface_unreachable.rs` | `@@ -118,7 +125,7 @@ fn allowlisted_note_scripts() -> Vec<(&'static str, NoteScript)> {` | 3 |  |
| `crates/xusdc-encoding/tests/account_surface_unreachable.rs` | `@@ -143,7 +150,8 @@ fn rbac_set_role_admin_proc_root() -> Result<Word> {` | 3 |  |
| `crates/xusdc-encoding/tests/account_surface_unreachable.rs` | `@@ -301,8 +309,8 @@ async fn get_authority_is_read_only_on_the_account() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/account_surface_unreachable.rs` | `@@ -324,3 +332,209 @@ async fn get_authority_is_read_only_on_the_account() -> Result<()> {` | 3 | SPLIT: class 3 = the appended two-tier growth section (tier consts + 4 proof tests); class 6 = the `.into_iter().next()` auth-component extraction inside `ratified_growth_rows_are_not_admissible_via_either_allowlist` |
| `crates/xusdc-encoding/tests/account_surface_unreachable.rs` | `@@ -324,3 +332,209 @@ async fn get_authority_is_read_only_on_the_account() -> Result<()> {` | 6 | SPLIT: class 3 = the appended two-tier growth section (tier consts + 4 proof tests); class 6 = the `.into_iter().next()` auth-component extraction inside `ratified_growth_rows_are_not_admissible_via_either_allowlist` |
| `crates/xusdc-encoding/tests/surface_count_prose_conformance.rs` | `@@ -37,10 +37,9 @@ const SOURCES: [(&str, &str); 3] = [` | 6 | class-6: `push(auth.into())` -> `extend(auth)` in `derive_surface_counts` |
| `crates/xusdc-encoding/tests/surface_count_prose_conformance.rs` | `@@ -66,7 +65,7 @@ fn conformance_prose_counts_match_the_executable_surface() -> Result<()> {` | 3 |  |
| `crates/xusdc-encoding/tests/surface_count_prose_conformance.rs` | `@@ -94,9 +93,13 @@ fn conformance_prose_counts_match_the_executable_surface() -> Result<()> {` | 3 |  |
| `crates/xusdc-encoding/tests/s12_expiration_tx_script_allowlist.rs` | `@@ -60,7 +60,9 @@ fn allowlisted_keys(component: &AccountComponent, slot: &StorageSlotName) -> BTr` | 6 | class-6: `.into()` -> `.into_iter().next()` |
| `crates/xusdc-encoding/tests/s12_expiration_tx_script_allowlist.rs` | `@@ -80,7 +82,9 @@ fn auth_component_tx_script_allowlist_is_exactly_the_expiration_root() -> Result` | 6 | class-6: `.into()` -> `.into_iter().next()` |
| `crates/xusdc-encoding/tests/s12_expiration_tx_script_allowlist.rs` | `@@ -107,8 +111,7 @@ async fn expiration_is_admitted_and_every_other_tx_script_is_rejected() -> Resul` | 5 |  |
| `crates/xusdc-encoding/tests/s12_expiration_tx_script_allowlist.rs` | `@@ -125,8 +128,7 @@ async fn expiration_is_admitted_and_every_other_tx_script_is_rejected() -> Resul` | 5 |  |
| `crates/xusdc-encoding/tests/f5_network_account_auth.rs` | `@@ -5,9 +5,11 @@` | 4 | header doc: the fixture-bypass description accompanying the class-4 support switch |
| `crates/xusdc-encoding/tests/f5_network_account_auth.rs` | `@@ -31,7 +33,6 @@` | 5 |  |
| `crates/xusdc-encoding/tests/f5_network_account_auth.rs` | `@@ -135,10 +136,14 @@ fn production_faucet() -> Result<(MockChain, Account)> {` | 5 | SPLIT: class 5 = `with_allowed_notes` (removed upstream) -> `custom(set, manager)` ctor adaptation; class 6 = `.into()` -> `.into_iter().next()` |
| `crates/xusdc-encoding/tests/f5_network_account_auth.rs` | `@@ -135,10 +136,14 @@ fn production_faucet() -> Result<(MockChain, Account)> {` | 6 | SPLIT: class 5 = `with_allowed_notes` (removed upstream) -> `custom(set, manager)` ctor adaptation; class 6 = `.into()` -> `.into_iter().next()` |
| `crates/xusdc-encoding/tests/f5_network_account_auth.rs` | `@@ -275,8 +280,8 @@ async fn non_allowlisted_note_is_rejected_by_auth() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_network_account_auth.rs` | `@@ -299,8 +304,7 @@ async fn non_expiration_tx_script_is_rejected_and_expiration_is_admitted() -> Re` | 5 |  |
| `crates/xusdc-encoding/tests/f5_network_account_auth.rs` | `@@ -315,8 +319,7 @@ async fn non_expiration_tx_script_is_rejected_and_expiration_is_admitted() -> Re` | 5 |  |
| `crates/xusdc-encoding/tests/mint_root_surface.rs` | `@@ -76,7 +76,7 @@ fn production_xreserve_callable_root_set_is_frozen() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/mint_root_surface.rs` | `@@ -97,7 +97,7 @@ fn production_xreserve_callable_root_set_is_frozen() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/config_note_absence.rs` | `@@ -0,0 +1,152 @@` | 4 | sanctioned NEW negative-assert file (whole file added) |
| `crates/xusdc-encoding/tests/fee_policy_provisional_pin.rs` | `@@ -0,0 +1,238 @@` | 4 | sanctioned NEW fee-pin file (whole file added; round 2 added the on-chain allowed-map assert, round 3 the tier-vocabulary comment) |
| `crates/xusdc-encoding/tests/migration_evidence_ledger.rs` | `@@ -0,0 +1,321 @@` | 4 | NEW doc-integrity tripwire for THIS evidence ledger, mandated by the round-4 test-first protocol (edits no tripwire file) |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -29,7 +29,7 @@ use miden_protocol::account::{` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -43,7 +43,6 @@ use miden_standards::account::wallets::BasicWallet;` | 4 | removed `ExpirationTransactionScript` import — fallout of the class-4 fixture switch (the fixture block was its only user) |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -403,7 +402,50 @@ pub fn add_faucet_account(` | 4 | SPLIT: class 4 = the new `add_network_faucet_account` helper (the sanctioned custom()-composition switch); class 5 = `assemble_xreserve_lib` -> `Result<Package>` in the same hunk |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -403,7 +402,50 @@ pub fn add_faucet_account(` | 5 | SPLIT: class 4 = the new `add_network_faucet_account` helper (the sanctioned custom()-composition switch); class 5 = `assemble_xreserve_lib` -> `Result<Package>` in the same hunk |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -561,7 +603,7 @@ pub fn setup_shell_account_with_nonce_seed(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -596,7 +638,7 @@ fn setup_shell_account_with_lib(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -636,15 +678,14 @@ pub async fn run_call_driver(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -817,7 +858,7 @@ pub async fn run_call_driver_with_advice(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -825,8 +866,7 @@ pub async fn run_call_driver_with_advice(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -964,7 +1004,7 @@ pub fn setup_attestation_account(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -1126,7 +1166,7 @@ pub fn set_attester_note(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -1158,8 +1198,8 @@ pub async fn run_set_attester_tx(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -1213,8 +1253,8 @@ pub async fn run_pause_tx(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -1281,7 +1321,7 @@ pub fn raw_self_block_note(sender: AccountId, seed: u64) -> Result<Note> {` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -1335,7 +1375,7 @@ pub fn identifier_init_note(sender: AccountId, identifier: Word, seed: u64) -> R` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -1368,8 +1408,8 @@ pub async fn run_identifier_init_tx(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -1450,8 +1490,8 @@ pub async fn run_set_min_burn_size_against(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -1534,8 +1574,8 @@ pub async fn run_set_max_supply_tx(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -1661,7 +1701,7 @@ pub fn setup_guarded_mint_account(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -2005,7 +2045,7 @@ fn oracle_burn_components(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -2346,7 +2386,7 @@ pub async fn try_emit_burn_note(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -2356,14 +2396,13 @@ pub async fn try_emit_burn_note(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -2403,8 +2442,8 @@ pub async fn run_burn_consume(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -2424,8 +2463,8 @@ pub async fn run_pause_against(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -2469,8 +2508,8 @@ pub async fn run_stock_unpause_against(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -2528,7 +2567,7 @@ fn dom_pauser_pause_admin_note(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -2571,8 +2610,8 @@ pub async fn run_dom_pauser_pause(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -2589,8 +2628,8 @@ pub async fn run_dom_pauser_unpause(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -2745,8 +2784,8 @@ async fn run_rbac_note_against(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -3148,24 +3187,15 @@ pub fn setup_production_faucet(` | 4 | the production-fixture switch: `Auth::NetworkAccount { … }` -> `add_network_faucet_account` (the `custom()` composition) |
| `crates/xusdc-encoding/tests/support/mod.rs` | `@@ -3358,13 +3388,13 @@ pub async fn emit_note_with_attachments(` | 5 |  |
| `crates/xusdc-encoding/tests/support/mint_transport.rs` | `@@ -329,8 +329,8 @@ pub async fn bring_up(pf: &mut ProductionFaucet, count: usize) -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/support/mint_transport.rs` | `@@ -362,8 +362,8 @@ pub async fn consume_note(` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -10,7 +10,6 @@` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -100,8 +99,8 @@ async fn set_attester_admin_note_owner_writes_and_nonowner_traps() -> Result<()>` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -146,8 +145,8 @@ async fn set_attester_admin_note_owner_writes_and_nonowner_traps() -> Result<()>` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -228,8 +227,8 @@ async fn identifier_init_owner_writes_only_the_identifier_slot() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -273,8 +272,8 @@ async fn assert_identifier_init_nonowner_traps(sender: AccountId, seed: u64) ->` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -312,8 +311,8 @@ async fn identifier_init_reinit_traps_even_from_owner() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -327,8 +326,8 @@ async fn identifier_init_reinit_traps_even_from_owner() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -354,8 +353,8 @@ async fn identifier_init_note_args_are_inert() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -409,8 +408,8 @@ async fn set_min_burn_size_owner_writes_slot() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -441,8 +440,8 @@ async fn assert_set_min_burn_nonowner_traps(sender: AccountId, seed: u64) -> Res` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -480,8 +479,8 @@ async fn set_min_burn_size_note_args_are_inert() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -518,8 +517,8 @@ async fn set_min_burn_size_zero_floor_from_owner_traps() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -564,8 +563,8 @@ async fn pause_dom_pauser_sets_is_paused() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -589,8 +588,8 @@ async fn assert_pause_nonpauser_traps(sender: AccountId, seed: u64) -> Result<()` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -621,8 +620,8 @@ async fn pause_note_args_are_inert() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -694,8 +693,8 @@ async fn paused_faucet() -> Result<(MockChain, AccountId)> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -714,8 +713,8 @@ async fn unpause_dom_pauser_clears_is_paused() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -738,8 +737,8 @@ async fn assert_unpause_nonpauser_traps(sender: AccountId, seed: u64) -> Result<` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -766,8 +765,8 @@ async fn unpause_note_args_are_inert() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -818,8 +817,8 @@ async fn assert_grant_role_authorized(` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -871,8 +870,8 @@ async fn grant_role_owner_on_delegated_role_traps() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -897,8 +896,8 @@ async fn grant_role_third_party_traps() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -926,8 +925,8 @@ async fn grant_role_note_args_are_inert() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -980,8 +979,8 @@ async fn set_max_supply_owner_writes_cap() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -1007,8 +1006,8 @@ async fn assert_set_max_supply_nonowner_traps(sender: AccountId, seed: u64) -> R` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -1048,8 +1047,8 @@ async fn set_max_supply_note_args_are_inert() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -1104,8 +1103,8 @@ async fn faucet_with_granted_role(` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -1140,8 +1139,8 @@ async fn assert_revoke_authorized(` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -1197,8 +1196,8 @@ async fn revoke_role_third_party_traps() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -1223,8 +1222,8 @@ async fn revoke_role_note_args_are_inert() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -1437,8 +1436,8 @@ async fn set_role_admin_note_is_rejected_as_non_allowlisted() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -1477,8 +1476,8 @@ async fn set_role_admin_note_is_rejected_regardless_of_note_args() -> Result<()>` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -1506,8 +1505,8 @@ async fn assert_set_role_admin_nonadmin_traps(sender: AccountId, seed: u64) -> R` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -1558,8 +1557,8 @@ async fn transfer_ownership_owner_nominates() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -1589,8 +1588,8 @@ async fn assert_transfer_ownership_nonowner_traps(sender: AccountId, seed: u64)` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -1631,8 +1630,8 @@ async fn transfer_ownership_note_args_are_inert() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -1689,8 +1688,8 @@ async fn faucet_with_pending_owner(` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -1722,8 +1721,8 @@ async fn accept_ownership_pending_owner_becomes_owner() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -1749,8 +1748,8 @@ async fn assert_accept_wrong_sender_traps(sender: AccountId, seed: u64) -> Resul` | 5 |  |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs` | `@@ -1778,8 +1777,8 @@ async fn accept_ownership_note_args_are_inert() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/xreserve_receive_and_burn.rs` | `@@ -236,7 +236,7 @@ fn pinned_standards_single_supply_decrement_write() {` | 1 | class-1: `POLICY_MANAGER_FNV1A` re-checksum |
| `crates/xusdc-encoding/tests/xreserve_receive_and_burn.rs` | `@@ -264,41 +264,37 @@ fn pinned_standards_fixture_unchanged() {` | 1 | class-1: fixture re-checksum context |
| `crates/xusdc-encoding/tests/xreserve_receive_and_burn.rs` | `@@ -309,15 +305,15 @@ fn pinned_standards_rev_matches_cargo() {` | 1 | class-1: the version -> rev provenance anchor re-key |
| `crates/xusdc-encoding/tests/xreserve_receive_and_burn.rs` | `@@ -447,7 +443,8 @@ async fn burn_paused_rejected_through_composition() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/xreserve_receive_and_burn.rs` | `@@ -505,7 +502,8 @@ async fn run_set_min_burn_then_consume(` | 5 |  |
| `crates/xusdc-encoding/tests/fixtures/pinned-standards/policy_manager.masm` | `@@ -7,12 +7,11 @@ use miden::standards::access::pausable` | 1 |  |
| `crates/xusdc-encoding/tests/fixtures/pinned-standards/policy_manager.masm` | `@@ -42,7 +41,7 @@ const ALLOWED_RECEIVE_POLICY_PROC_ROOTS_SLOT=word("miden::standards::faucets::po` | 1 |  |
| `crates/xusdc-encoding/tests/fixtures/pinned-standards/policy_manager.masm` | `@@ -62,240 +61,8 @@ const ERR_RECEIVE_POLICY_ROOT_IS_ZERO="receive policy root is zero"` | 1 |  |
| `crates/xusdc-encoding/tests/fixtures/pinned-standards/policy_manager.masm` | `@@ -329,9 +96,6 @@ pub proc set_mint_policy` | 1 |  |
| `crates/xusdc-encoding/tests/fixtures/pinned-standards/policy_manager.masm` | `@@ -339,42 +103,6 @@ pub proc set_mint_policy` | 1 |  |
| `crates/xusdc-encoding/tests/fixtures/pinned-standards/policy_manager.masm` | `@@ -407,9 +135,6 @@ pub proc set_burn_policy` | 1 |  |
| `crates/xusdc-encoding/tests/fixtures/pinned-standards/policy_manager.masm` | `@@ -417,63 +142,6 @@ pub proc set_burn_policy` | 1 |  |
| `crates/xusdc-encoding/tests/fixtures/pinned-standards/policy_manager.masm` | `@@ -536,9 +204,6 @@ pub proc set_send_policy` | 1 |  |
| `crates/xusdc-encoding/tests/fixtures/pinned-standards/policy_manager.masm` | `@@ -546,9 +211,6 @@ pub proc set_send_policy` | 1 |  |
| `crates/xusdc-encoding/tests/fixtures/pinned-standards/policy_manager.masm` | `@@ -613,12 +275,279 @@ pub proc set_receive_policy` | 1 |  |
| `crates/xusdc-encoding/tests/fixtures/pinned-standards/PROVENANCE.md` | `@@ -1,46 +1,47 @@` | 1 |  |
| `crates/xusdc-encoding/tests/mint_policy_binding_e2e.rs` | `@@ -498,8 +498,7 @@ async fn tx_script_mint_and_send_cannot_mint() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/mint_scale_conformance.rs` | `@@ -172,8 +172,8 @@ async fn bring_up(pf: &mut ProductionFaucet) -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/mint_scale_conformance.rs` | `@@ -199,8 +199,8 @@ async fn consume_mint_note(` | 5 |  |
| `crates/xusdc-encoding/tests/mint_scale_conformance.rs` | `@@ -353,8 +353,8 @@ async fn production_mint_delivers_the_circle_amount_unrescaled() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/mint_scale_conformance.rs` | `@@ -553,8 +553,8 @@ async fn mint_to_a_blocked_recipient_succeeds_then_strands() -> anyhow::Result<(` | 5 |  |
| `crates/xusdc-encoding/tests/xreserve_burn.rs` | `@@ -15,8 +15,6 @@` | 5 |  |
| `crates/xusdc-encoding/tests/xreserve_burn.rs` | `@@ -384,14 +382,14 @@ async fn production_burn_note_same_block_consume_is_erased() -> anyhow::Result<(` | 5 |  |
| `crates/xusdc-encoding/tests/xreserve_burn.rs` | `@@ -405,7 +403,8 @@ async fn production_burn_note_same_block_consume_is_erased() -> anyhow::Result<(` | 5 |  |
| `crates/xusdc-encoding/tests/burn_policy.rs` | `@@ -311,7 +311,8 @@ async fn burn_paused_rejects() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/masm_dual.rs` | `@@ -19,7 +19,7 @@ use miden_processor::operation::OperationError;` | 5 |  |
| `crates/xusdc-encoding/tests/masm_dual.rs` | `@@ -40,7 +40,7 @@ const INTENT_PTR: u64 = 1024;` | 5 |  |
| `crates/xusdc-encoding/tests/masm_dual.rs` | `@@ -61,7 +61,7 @@ fn assemble_xreserve_lib() -> Result<Library> {` | 5 |  |
| `crates/xusdc-encoding/tests/masm_dual.rs` | `@@ -93,13 +93,12 @@ async fn run_driver(` | 5 |  |
| `crates/xusdc-encoding/tests/assembled_faucet_e2e.rs` | `@@ -217,8 +217,8 @@ async fn consume_committed_note(` | 5 |  |
| `crates/xusdc-encoding/tests/assembled_faucet_e2e.rs` | `@@ -241,8 +241,8 @@ async fn consume_committed_note_with_faucet_foreign(` | 5 |  |
| `crates/xusdc-encoding/tests/assembled_faucet_e2e.rs` | `@@ -703,8 +703,7 @@ async fn assembled_faucet_full_lifecycle() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/pause_admin.rs` | `@@ -23,8 +23,6 @@` | 5 |  |
| `crates/xusdc-encoding/tests/pause_admin.rs` | `@@ -190,8 +188,8 @@ async fn bring_up(pf: &mut ProductionFaucet, count: usize) -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/pause_admin.rs` | `@@ -228,8 +226,8 @@ async fn emit_and_consume_mint(` | 5 |  |
| `crates/xusdc-encoding/tests/pause_admin.rs` | `@@ -368,8 +366,8 @@ async fn dom_pauser_production_pause_note_halts_mint() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/pause_admin.rs` | `@@ -387,8 +385,8 @@ async fn dom_pauser_production_pause_note_halts_mint() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/pause_admin.rs` | `@@ -428,8 +426,8 @@ async fn dom_pauser_production_pause_note_halts_burn() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/pause_admin.rs` | `@@ -440,7 +438,8 @@ async fn dom_pauser_production_pause_note_halts_burn() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/pause_admin.rs` | `@@ -487,7 +486,8 @@ async fn dom_pauser_pause_halts_burn() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/pause_admin.rs` | `@@ -568,7 +568,8 @@ async fn dom_pauser_unpause_resumes_mint_and_burn() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/role_admin.rs` | `@@ -243,8 +243,8 @@ async fn bring_up(pf: &mut ProductionFaucet, count: usize) -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/role_admin.rs` | `@@ -264,8 +264,8 @@ async fn consume_note(` | 5 |  |
| `crates/xusdc-encoding/tests/role_admin.rs` | `@@ -301,8 +301,8 @@ async fn emit_and_consume_mint(` | 5 |  |
| `crates/xusdc-encoding/tests/transfer_blocklist_e2e.rs` | `@@ -142,8 +142,8 @@ async fn run_block(` | 5 |  |
| `crates/xusdc-encoding/tests/transfer_blocklist_e2e.rs` | `@@ -162,8 +162,8 @@ async fn run_unblock(` | 5 |  |
| `crates/xusdc-encoding/tests/transfer_blocklist_semantics.rs` | `@@ -220,8 +220,8 @@ async fn consume_incoming_p2id(` | 5 |  |
| `crates/xusdc-encoding/tests/transfer_blocklist_semantics.rs` | `@@ -239,8 +239,8 @@ async fn commit_faucet_consume(` | 5 |  |
| `crates/xusdc-encoding/tests/transfer_blocklist_semantics.rs` | `@@ -283,7 +283,7 @@ async fn emit_without_faucet_foreign(` | 5 |  |
| `crates/xusdc-encoding/tests/transfer_blocklist_semantics.rs` | `@@ -297,11 +297,10 @@ async fn emit_without_faucet_foreign(` | 5 |  |
| `crates/xusdc-encoding/tests/transfer_blocklist_semantics.rs` | `@@ -611,8 +610,8 @@ async fn faucet_side_burn_consume_is_callback_unaffected() -> Result<()> {` | 5 |  |
| `crates/xusdc-encoding/tests/builder_api.rs` | `@@ -748,7 +748,7 @@ fn production_composition_installs_one_xreserve_and_one_manager() -> Result<()>` | 5 |  |
| `crates/xusdc-encoding/tests/builder_api.rs` | `@@ -780,15 +780,15 @@ fn production_composition_installs_one_xreserve_and_one_manager() -> Result<()>` | 5 |  |
| `crates/xusdc-encoding/src/note/xreserve_admin/ownership.rs` | `@@ -71,9 +71,14 @@ static ACCEPT_OWNERSHIP_NOTE_SCRIPT: LazyLock<NoteScript> =` | 1 | class-1: the ONE moved root (`accept_ownership`), provenance-commented |
| `crates/xusdc-encoding/src/note/xreserve_admin/mod.rs` | `@@ -59,7 +59,7 @@ pub(super) fn compile_admin_note_script(src: &str) -> NoteScript {` | 5 |  |

TOTAL: 168 data rows over 165 distinct `@@` hunks (3 hunks split into two class rows)

Files on the tripwire/ROOT_HEX enumeration with **no hunks** (`git diff 8a3fb04 -- <file>` empty):

- `crates/xusdc-encoding/tests/vectors` — the wire freeze: the Circle ground truth + golden vectors are byte-identical
- `crates/xusdc-encoding/tests/constant_parity.rs` — untouched tripwire
- `crates/xusdc-encoding/tests/basic_asset_tripwire.rs` — untouched tripwire (no class-5 hunk was ever needed)
- `crates/xusdc-encoding/tests/wave1_recomposition.rs` — untouched; `FORMER_CUSTOM_MINT_NOTE_ROOT_HEX` unchanged by design
- `crates/xusdc-encoding/tests/fixtures/pinned-standards/fungible.masm` — byte-identical at the pin; checksum unchanged
- `crates/xusdc-encoding/src/note/xreserve_admin/config.rs` — 6 root pins verified unmoved
- `crates/xusdc-encoding/src/note/xreserve_admin/roles.rs` — 2 root pins verified unmoved
- `crates/xusdc-encoding/src/note/xreserve_admin/blocklist.rs` — 2 root pins verified unmoved
- `asm/standards/xreserve/mint_policy.masm` — `P2ID_SCRIPT_ROOT` re-derived and verified unmoved — zero MASM edits
