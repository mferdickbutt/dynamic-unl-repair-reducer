#!/usr/bin/env python3
"""
Dynamic UNL Explanation Repair Action Reducer

Consumes sanitized Dynamic UNL explanation classifications and repair evidence,
emits a deterministic public-repair action for each case.

No network calls, external services, live validator identities, credentials,
private keys, wallet-identifying data, dashboards, or L1 internals.
"""

import json
from dataclasses import dataclass, asdict
from typing import List


# ---------------------------------------------------------------------------
# Input / output schemas
# ---------------------------------------------------------------------------

@dataclass
class ExplanationClassification:
    case_id: str
    completeness_score: float       # 0.0-1.0, pre-computed by upstream reducer
    has_privacy_leak: bool
    has_credential_leak: bool
    has_contradiction: bool
    evidence_sufficient: bool
    reviewer_escalation_requested: bool
    explanation_text: str           # already sanitized / redacted upstream


@dataclass
class RepairEvidence:
    case_id: str
    contradiction_resolved: bool
    additional_evidence_available: bool
    privacy_flags: List[str]
    redaction_possible: bool


@dataclass
class RepairAction:
    case_id: str
    repair_action: str              # publish_unchanged | redact | request_evidence |
                                    # reconcile_contradiction | suppress | escalate
    rationale_code: str
    severity: str                   # low | medium | high | critical
    next_reviewer_queue: str


# ---------------------------------------------------------------------------
# Deterministic rule engine
# Priority order (highest first):
#   1. Credential leak               -> suppress               (critical)
#   2a. Privacy leak + redactable    -> redact                 (high)
#   2b. Privacy leak + not-redactable-> suppress               (critical)
#   3. Escalation flag               -> escalate               (high)
#   4. Unresolved contradiction      -> suppress               (high)
#   5. Resolved contradiction        -> reconcile_contradiction(medium)
#   6. Insufficient evidence         -> request_evidence       (medium)
#   7. All checks pass               -> publish_unchanged      (low)
# ---------------------------------------------------------------------------

def reduce(
    classification: ExplanationClassification,
    evidence: RepairEvidence,
) -> RepairAction:
    cid = classification.case_id

    if classification.has_credential_leak:
        return RepairAction(
            case_id=cid,
            repair_action="suppress",
            rationale_code="CRED_LEAK_DETECTED",
            severity="critical",
            next_reviewer_queue="security-review",
        )

    if classification.has_privacy_leak and evidence.redaction_possible:
        return RepairAction(
            case_id=cid,
            repair_action="redact",
            rationale_code="PRIVACY_LEAK_REDACTABLE",
            severity="high",
            next_reviewer_queue="privacy-review",
        )

    if classification.has_privacy_leak and not evidence.redaction_possible:
        return RepairAction(
            case_id=cid,
            repair_action="suppress",
            rationale_code="PRIVACY_LEAK_NOT_REDACTABLE",
            severity="critical",
            next_reviewer_queue="security-review",
        )

    if classification.reviewer_escalation_requested:
        return RepairAction(
            case_id=cid,
            repair_action="escalate",
            rationale_code="REVIEWER_ESCALATION_REQUESTED",
            severity="high",
            next_reviewer_queue="senior-review",
        )

    if classification.has_contradiction and not evidence.contradiction_resolved:
        return RepairAction(
            case_id=cid,
            repair_action="suppress",
            rationale_code="CONTRADICTION_UNRESOLVED",
            severity="high",
            next_reviewer_queue="evidence-review",
        )

    if classification.has_contradiction and evidence.contradiction_resolved:
        return RepairAction(
            case_id=cid,
            repair_action="reconcile_contradiction",
            rationale_code="CONTRADICTION_EVIDENCE_AVAILABLE",
            severity="medium",
            next_reviewer_queue="reconciliation-queue",
        )

    if not classification.evidence_sufficient:
        return RepairAction(
            case_id=cid,
            repair_action="request_evidence",
            rationale_code="EVIDENCE_INSUFFICIENT",
            severity="medium",
            next_reviewer_queue="evidence-collection",
        )

    return RepairAction(
        case_id=cid,
        repair_action="publish_unchanged",
        rationale_code="ALL_CHECKS_PASSED",
        severity="low",
        next_reviewer_queue="publication-queue",
    )


# ---------------------------------------------------------------------------
# Sanitized embedded fixtures  (no live identities, keys, or L1 internals)
# ---------------------------------------------------------------------------

FIXTURES: List[tuple] = [
    # CASE-001: clean explanation -- publish unchanged
    (
        ExplanationClassification(
            case_id="CASE-001",
            completeness_score=0.95,
            has_privacy_leak=False,
            has_credential_leak=False,
            has_contradiction=False,
            evidence_sufficient=True,
            reviewer_escalation_requested=False,
            explanation_text=(
                "Validator selected based on documented reliability metrics "
                "and measured network-diversity contribution."
            ),
        ),
        RepairEvidence(
            case_id="CASE-001",
            contradiction_resolved=False,
            additional_evidence_available=True,
            privacy_flags=[],
            redaction_possible=False,
        ),
    ),
    # CASE-002: privacy leak present but redaction is feasible -> redact
    (
        ExplanationClassification(
            case_id="CASE-002",
            completeness_score=0.70,
            has_privacy_leak=True,
            has_credential_leak=False,
            has_contradiction=False,
            evidence_sufficient=True,
            reviewer_escalation_requested=False,
            explanation_text="[SANITIZED -- contained operator contact details]",
        ),
        RepairEvidence(
            case_id="CASE-002",
            contradiction_resolved=False,
            additional_evidence_available=False,
            privacy_flags=["operator_contact_info"],
            redaction_possible=True,
        ),
    ),
    # CASE-003: evidence too thin -> request_evidence
    (
        ExplanationClassification(
            case_id="CASE-003",
            completeness_score=0.40,
            has_privacy_leak=False,
            has_credential_leak=False,
            has_contradiction=False,
            evidence_sufficient=False,
            reviewer_escalation_requested=False,
            explanation_text="Validator selected for unspecified performance reasons.",
        ),
        RepairEvidence(
            case_id="CASE-003",
            contradiction_resolved=False,
            additional_evidence_available=True,
            privacy_flags=[],
            redaction_possible=False,
        ),
    ),
    # CASE-004: contradiction resolved by new evidence -> reconcile_contradiction
    (
        ExplanationClassification(
            case_id="CASE-004",
            completeness_score=0.65,
            has_privacy_leak=False,
            has_credential_leak=False,
            has_contradiction=True,
            evidence_sufficient=True,
            reviewer_escalation_requested=False,
            explanation_text="[SANITIZED -- contained contradictory reliability claims]",
        ),
        RepairEvidence(
            case_id="CASE-004",
            contradiction_resolved=True,
            additional_evidence_available=True,
            privacy_flags=[],
            redaction_possible=False,
        ),
    ),
    # CASE-005: credential material detected -> suppress (critical)
    (
        ExplanationClassification(
            case_id="CASE-005",
            completeness_score=0.80,
            has_privacy_leak=False,
            has_credential_leak=True,
            has_contradiction=False,
            evidence_sufficient=True,
            reviewer_escalation_requested=False,
            explanation_text="[SANITIZED -- contained credential material]",
        ),
        RepairEvidence(
            case_id="CASE-005",
            contradiction_resolved=False,
            additional_evidence_available=False,
            privacy_flags=["credential_material"],
            redaction_possible=False,
        ),
    ),
    # CASE-006: governance edge-case -> escalate
    (
        ExplanationClassification(
            case_id="CASE-006",
            completeness_score=0.55,
            has_privacy_leak=False,
            has_credential_leak=False,
            has_contradiction=False,
            evidence_sufficient=True,
            reviewer_escalation_requested=True,
            explanation_text="[SANITIZED -- complex governance edge-case requiring senior review]",
        ),
        RepairEvidence(
            case_id="CASE-006",
            contradiction_resolved=False,
            additional_evidence_available=False,
            privacy_flags=[],
            redaction_possible=False,
        ),
    ),
    # CASE-007: privacy leak AND redaction not feasible -> suppress (critical)
    (
        ExplanationClassification(
            case_id="CASE-007",
            completeness_score=0.60,
            has_privacy_leak=True,
            has_credential_leak=False,
            has_contradiction=False,
            evidence_sufficient=True,
            reviewer_escalation_requested=False,
            explanation_text="[SANITIZED -- contained non-redactable personal data]",
        ),
        RepairEvidence(
            case_id="CASE-007",
            contradiction_resolved=False,
            additional_evidence_available=False,
            privacy_flags=["non_redactable_personal_data"],
            redaction_possible=False,
        ),
    ),
    # CASE-008: contradiction present but NOT yet resolved -> suppress
    (
        ExplanationClassification(
            case_id="CASE-008",
            completeness_score=0.50,
            has_privacy_leak=False,
            has_credential_leak=False,
            has_contradiction=True,
            evidence_sufficient=True,
            reviewer_escalation_requested=False,
            explanation_text="[SANITIZED -- contradictory uptime figures across two periods]",
        ),
        RepairEvidence(
            case_id="CASE-008",
            contradiction_resolved=False,
            additional_evidence_available=False,
            privacy_flags=[],
            redaction_possible=False,
        ),
    ),
]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    results = []
    for classification, evidence in FIXTURES:
        action = reduce(classification, evidence)
        results.append(asdict(action))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
