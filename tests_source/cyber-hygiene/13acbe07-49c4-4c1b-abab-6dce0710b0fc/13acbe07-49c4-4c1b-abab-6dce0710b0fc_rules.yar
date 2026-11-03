/*
    SentinelOne defense-evasion detection scope
    MITRE ATT&CK: T1562.001
    Date: 2026-11-03

    Intentionally empty ruleset.

    The assessed implementation is a read-only compliance validator. It contains
    no embedded attack tool, malicious payload, script, or other static artifact
    with a defensible technique-specific YARA signature. Service queries, file
    version reads, registry reads, and product-name strings describe legitimate
    local inspection and would produce false positives if used as YARA rules.

    Use behavioral service-control, process-termination, file-change, and
    service-registry telemetry instead. This file is valid YARA source with no
    rules; it must not be interpreted as providing static detection coverage.
*/
