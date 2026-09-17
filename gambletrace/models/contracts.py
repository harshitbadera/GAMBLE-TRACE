"""Shared vocabulary for the data model defined in the architecture document.

Database-backed models are deliberately deferred to Project Plan Item 3.
"""

from enum import Enum


class CaseStatus(str, Enum):
    OPEN = "OPEN"
    COLLECTING = "COLLECTING"
    TRIAGE = "TRIAGE"
    MONITORING = "MONITORING"
    ESCALATED = "ESCALATED"
    CLOSED = "CLOSED"


class DomainAvailability(str, Enum):
    UNKNOWN = "UNKNOWN"
    ACTIVE = "ACTIVE"
    OFFLINE = "OFFLINE"
    UNRESOLVED = "UNRESOLVED"
    BLOCKED = "BLOCKED"
    PARKED = "PARKED"


class DomainRelevance(str, Enum):
    UNREVIEWED = "UNREVIEWED"
    HIGH_CONFIDENCE_SUSPECTED_GAMBLING = "HIGH_CONFIDENCE_SUSPECTED_GAMBLING"
    MEDIUM_CONFIDENCE_SUSPECTED_GAMBLING = "MEDIUM_CONFIDENCE_SUSPECTED_GAMBLING"
    RELATED_INFRASTRUCTURE = "RELATED_INFRASTRUCTURE"
    LOW_CONFIDENCE_CANDIDATE = "LOW_CONFIDENCE_CANDIDATE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    NOT_GAMBLING_RELATED = "NOT_GAMBLING_RELATED"


class ObservationOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
