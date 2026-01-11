# F0RT1KA Defense Scoring Methodology

## Overview

This document defines a comprehensive, multi-factor scoring system for evaluating security defense effectiveness in F0RT1KA security tests. The scoring mechanism goes beyond simple detection counting to measure **defense depth and speed** - evaluating how early in the attack chain threats are stopped and how quickly defenses respond.

---

## Scoring Philosophy

The Defense Score reflects the quality of security posture by considering:

1. **Prevention over Detection** - Stopping threats before execution is valued more than post-execution detection
2. **Speed Matters** - Faster response times indicate better security automation
3. **Accuracy** - Correct threat severity assessment demonstrates understanding of risk
4. **Consistency** - Uniform protection across endpoints shows mature security controls

---

## Scoring Components

### Total Points Available: 100 points per event

Each correlated event (LimaCharlie event matched with Defender alert) is evaluated across four dimensions:

### 1. Detection Coverage (40 points)

**Purpose:** Reward comprehensive visibility into the attack

#### Base Detection (20 points)
- Event successfully matched between LimaCharlie and Defender: **20 points**
- Unmatched event: **0 points**

#### Multi-Evidence Detection (20 points)
Bonus points based on evidence diversity in Defender alert:

| Evidence Combination | Points |
|---------------------|--------|
| Multiple evidence types (3+) | +10 |
| Process + File evidence | +5 |
| Network evidence included | +5 |
| Single evidence type only | 0 |

**Rationale:** Multiple evidence types indicate defense-in-depth and comprehensive telemetry collection.

---

### 2. Prevention Quality (30 points)

**Purpose:** Measure effectiveness of blocking mechanisms

#### LimaCharlie Error Code Weights

Different error codes represent different stages of prevention:

| Error Code | Meaning | Base Points | Stage |
|-----------|---------|-------------|-------|
| **3** | Quarantined | 30 | Pre-execution blocking ⭐ Best |
| **1** | NF_denied | 25 | Kernel-level denial |
| **259** | exec_stop | 20 | Execution stopped (post-launch) |
| **0** | exec_error | 15 | Failed execution (partial) |
| **200** | Uploaded | 5 | Detection only (worst) |

#### Defender Status Modifiers

The Defender alert status applies a multiplier to the base points:

| Status | Multiplier | Effective Points Example (Error Code 3) |
|--------|-----------|----------------------------------------|
| **prevented** | 100% | 30 points |
| **blocked** | 80% | 24 points |
| **resolved** | 60% | 18 points |
| **inProgress** | 40% | 12 points |
| **new** | 20% | 6 points |

**Formula:** `Prevention Score = (LC_Error_Points × Defender_Status_Multiplier)`

**Rationale:** The combination of early blocking (LC error code) and proper remediation (Defender status) provides the complete prevention picture.

---

### 3. Response Speed (20 points)

**Purpose:** Measure how quickly the defense responded to the threat

Time difference between LimaCharlie event and Defender alert creation:

| Time Difference | Points | Assessment |
|----------------|--------|------------|
| **< 5 seconds** | 20 | Real-time protection |
| **5-30 seconds** | 18 | Near real-time |
| **30-60 seconds** | 15 | Fast response |
| **1-2 minutes** | 12 | Good response |
| **2-3 minutes** | 8 | Acceptable |
| **3-5 minutes** | 4 | Slow response |
| **> 5 minutes** | 0 | Delayed detection |

**Rationale:** Faster detection enables quicker incident response and reduces attacker dwell time.

---

### 4. Threat Severity Recognition (10 points)

**Purpose:** Assess accuracy of threat classification

Defender's severity assessment of the threat:

| Severity Level | Points | Meaning |
|---------------|--------|---------|
| **high** | 10 | Correct threat assessment ⭐ |
| **medium** | 7 | Reasonable assessment |
| **low** | 4 | Underestimated threat |
| **informational** | 1 | Missed severity |

**Rationale:** Accurate severity classification ensures appropriate prioritization and response urgency.

---

## Composite Score Calculation

### Per-Event Score

```
event_score = detection_coverage_score
            + prevention_quality_score
            + response_speed_score
            + severity_recognition_score
```

**Maximum per event:** 100 points

### Final Defense Score

```
Final Score = (Σ event_scores / (total_events × 100)) × 100
```

**Result:** Percentage score (0-100%)

---

## Penalty System

### Critical Failure Deductions

These penalties apply to the final score:

| Failure Type | Deduction | Reason |
|-------------|-----------|--------|
| Unmatched LC event | -5 points | Coverage gap |
| Late detection (>5 min) | -3 points | Slow response |
| Remediation status: "notRemediated" | -5 points | Incomplete response |
| Detection status: "notDetected" | -10 points | False positive indicator |

**Penalty Formula:** `Final Score = Composite Score - Σ penalties`

---

## Score Interpretation

| Score Range | Rating | Interpretation |
|------------|--------|----------------|
| **90-100** | ⭐⭐⭐⭐⭐ Excellent | Comprehensive pre-execution prevention with fast response |
| **75-89** | ⭐⭐⭐⭐ Strong | Effective early-stage blocking and good coverage |
| **60-74** | ⭐⭐⭐ Good | Solid detection with moderate prevention |
| **40-59** | ⭐⭐ Fair | Basic detection capabilities, needs improvement |
| **20-39** | ⭐ Weak | Limited and delayed detection, critical gaps |
| **0-19** | ❌ Critical | Inadequate protection, immediate action required |

---

## Advanced Scoring Features

### Kill Chain Stage Multipliers

Apply different weights based on MITRE ATT&CK stage:

| Attack Stage | Multiplier | Reasoning |
|-------------|-----------|-----------|
| Initial Access / Execution | **1.5×** | Critical to stop early |
| Persistence / Privilege Escalation | **1.3×** | Prevent foothold establishment |
| Defense Evasion | **1.2×** | Stop anti-detection techniques |
| Collection / Exfiltration | **1.0×** | Standard weight |
| Impact | **0.8×** | Too late in attack chain |

**Application:** `adjusted_event_score = event_score × kill_chain_multiplier`

### Behavioral Pattern Bonuses

Reward defense-in-depth strategies:

| Pattern | Bonus | Reason |
|---------|-------|--------|
| Multiple correlated alerts for same attack | +10 | Defense layering |
| Automated remediation triggered | +15 | Mature automation |
| Threat intel match | +5 | Enhanced detection |

### Confidence Adjustments

Modify final score based on overall pattern consistency:

| Condition | Adjustment | Reason |
|-----------|-----------|--------|
| High false positive rate | -10% | Noisy detection |
| Consistent prevention across all endpoints | +10% | Uniform protection |
| Mixed results on same endpoint | -5% | Inconsistent controls |

---

## Implementation Considerations

### Configurable Weights

Organizations can customize weights based on their security priorities:

```python
# Example configuration
SCORE_WEIGHTS = {
    'detection_coverage': 40,      # Default
    'prevention_quality': 30,      # Default
    'response_speed': 20,          # Default
    'severity_recognition': 10     # Default
}

# Security-first organization might prefer:
SCORE_WEIGHTS_PREVENTION_FOCUS = {
    'detection_coverage': 25,
    'prevention_quality': 50,      # Increased
    'response_speed': 15,
    'severity_recognition': 10
}

# Compliance-focused organization might prefer:
SCORE_WEIGHTS_COVERAGE_FOCUS = {
    'detection_coverage': 50,      # Increased
    'prevention_quality': 20,
    'response_speed': 20,
    'severity_recognition': 10
}
```

### Data Requirements

For full scoring implementation, the system needs:

- ✅ **Available Now:**
  - LimaCharlie error codes
  - Defender alert status
  - Defender severity levels
  - Timestamp correlation (for response speed)
  - Evidence data from alerts

- 🔄 **Future Enhancements:**
  - MITRE ATT&CK technique mapping (for kill chain multipliers)
  - Threat intelligence integration
  - Historical false positive rates
  - Automated remediation logs

---

## Scoring Example

### Sample Event Analysis

**LimaCharlie Event:**
- Hostname: `WORKSTATION-01`
- Timestamp: `2025-10-06 14:32:10`
- Error Code: `3 (Quarantined)`

**Defender Alert:**
- Timestamp: `2025-10-06 14:32:12`
- Status: `prevented`
- Severity: `high`
- Evidence: Process + File + Network (3 types)

**Score Calculation:**

1. **Detection Coverage:** 20 (base) + 10 (3+ evidence types) + 5 (network) = **35 points**
2. **Prevention Quality:** 30 (quarantined) × 1.0 (prevented) = **30 points**
3. **Response Speed:** 2 seconds difference = **20 points**
4. **Severity Recognition:** high severity = **10 points**

**Event Score:** 35 + 30 + 20 + 10 = **95 points** (95%)

### Poor Performance Example

**LimaCharlie Event:**
- Hostname: `WORKSTATION-02`
- Timestamp: `2025-10-06 15:45:30`
- Error Code: `200 (Uploaded)`

**Defender Alert:**
- Timestamp: `2025-10-06 15:51:45`
- Status: `new`
- Severity: `low`
- Evidence: File only (1 type)

**Score Calculation:**

1. **Detection Coverage:** 20 (base) + 0 (single evidence) = **20 points**
2. **Prevention Quality:** 5 (uploaded) × 0.2 (new status) = **1 point**
3. **Response Speed:** 6+ minutes = **0 points**
4. **Severity Recognition:** low severity = **4 points**

**Event Score:** 20 + 1 + 0 + 4 = **25 points** (25%)

**Penalties:** -3 (late detection) = **22 points final**

---

## Reporting Recommendations

### Score Display

The score should be prominently displayed in reports with context:

```markdown
## 🛡️ Defense Score: 87.5% (Strong)

**Interpretation:** Effective early-stage blocking with good coverage across endpoints.

### Score Breakdown:
- Detection Coverage: 92% (36.8/40 avg)
- Prevention Quality: 83% (24.9/30 avg)
- Response Speed: 85% (17.0/20 avg)
- Severity Recognition: 90% (9.0/10 avg)

### Key Findings:
✅ 95% of threats quarantined pre-execution
✅ Average response time: 8 seconds
⚠️ 2 unmatched events on WORKSTATION-03
⚠️ 1 late detection (7 minutes delay)
```

### Trend Analysis

Track scores over time to measure improvement:

```
Test Run History:
- 2025-10-01: 78.2% (Good)
- 2025-10-04: 82.5% (Strong)
- 2025-10-06: 87.5% (Strong) ↑ +5.0%

Trend: Improving ✅
```

---

## Future Enhancements

### Machine Learning Integration
- Anomaly detection for unusual score patterns
- Predictive scoring based on threat intelligence
- Adaptive weight adjustment based on environment

### Endpoint Risk Scoring
- Individual endpoint scores for targeted improvement
- Comparison across endpoint groups
- Identification of high-risk systems

### Compliance Mapping
- Map scores to compliance frameworks (NIST, CIS, etc.)
- Generate compliance gap reports
- Track remediation progress

---

## Conclusion

This multi-factor scoring methodology provides a comprehensive, nuanced view of security defense effectiveness. By considering detection coverage, prevention quality, response speed, and threat assessment accuracy, organizations can:

1. **Identify specific weaknesses** in their security posture
2. **Prioritize improvements** based on impact
3. **Track progress** over time with objective metrics
4. **Benchmark** against industry standards
5. **Justify investments** in security controls

The scoring system is designed to be flexible and configurable, allowing organizations to align it with their specific security priorities and risk tolerance.

---

**Document Version:** 1.0
**Last Updated:** 2025-10-06
**Author:** F0RT1KA Security Framework
