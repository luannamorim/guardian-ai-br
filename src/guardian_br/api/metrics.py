from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

REGISTRY = CollectorRegistry()

SCAN_TOTAL = Counter(
    "guardian_scan_total",
    "Total scans by mode and outcome",
    ["mode", "outcome"],
    registry=REGISTRY,
)

DETECTION_TOTAL = Counter(
    "guardian_detection_total",
    "Total detections by entity type and LGPD article",
    ["entity_type", "lgpd_article"],
    registry=REGISTRY,
)

SCAN_LATENCY = Histogram(
    "guardian_scan_latency_seconds",
    "Scan handler wall-clock latency by mode",
    ["mode"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.5, 1.0),
    registry=REGISTRY,
)

AUTH_FAILURES = Counter(
    "guardian_auth_failures_total",
    "Auth failures by reason",
    ["reason"],
    registry=REGISTRY,
)

UNMASK_TOTAL = Counter(
    "guardian_unmask_total",
    "Unmask attempts by result",
    ["result"],
    registry=REGISTRY,
)

ADVERSARIAL_TOTAL = Counter(
    "guardian_adversarial_classification_total",
    "Adversarial classifications by label and source",
    ["label", "source"],
    registry=REGISTRY,
)

ADVERSARIAL_LATENCY = Histogram(
    "guardian_adversarial_latency_seconds",
    "Adversarial classify latency by source",
    ["source"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0),
    registry=REGISTRY,
)

ADVERSARIAL_ERRORS = Counter(
    "guardian_adversarial_errors_total",
    "Adversarial classify errors by reason",
    ["reason"],
    registry=REGISTRY,
)

ADVERSARIAL_CACHE_SIZE = Gauge(
    "guardian_adversarial_cache_size",
    "Current adversarial TTL cache size",
    registry=REGISTRY,
)
