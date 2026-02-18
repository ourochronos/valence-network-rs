//! Proposal lifecycle per §6.

/// Proposal status (local per-node view, no global state machine).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalStatus {
    /// Proposal exists, votes accumulating, deadline not reached.
    Open,
    /// Weighted endorsement exceeds local threshold.
    Converging,
    /// Node considers the proposal accepted by the network.
    Ratified,
    /// Weighted rejection exceeds threshold or deadline passed without ratification.
    Rejected,
    /// This node has applied the proposal locally.
    Adopted,
    /// Voting deadline passed.
    Expired,
    /// Author withdrew.
    Withdrawn,
}
