//! Cross-layer release gate owned by H1: a revoked credential must make an
//! autoscale policy ineligible before a launcher can be consulted.

use runner_manager_domain::policy::{PolicyState, ScalePolicy};
use runner_manager_testkit::fixtures;

#[test]
fn authentication_failed_policy_is_ineligible_and_cannot_start_a_runner() {
    let mut policy: ScalePolicy = fixtures::active_policy();
    assert!(policy.may_start_runners());

    policy
        .authentication_failed()
        .expect("a revoked credential is terminal for the current authorization");

    assert_eq!(policy.state(), PolicyState::AuthenticationFailed);
    assert!(
        !policy.may_start_runners(),
        "an authentication_failed policy reached the runner-launch eligibility boundary"
    );
}
