# F0RT1KA Defense Score Dashboard - Creation Guide

This guide provides step-by-step instructions for creating the Defense Score dashboard in Kibana using Lens visualizations.

## Overview

**Defense Score** = Percentage of test results with "protected" status

```
Defense Score = (protected results / total results) × 100%
```

## Prerequisites

- Kibana with access to `f0rtika-synthetic` or `f0rtika-results-*` data view
- Data view ID: `bdeea954-63a4-4f8a-9d0c-d547dbbafb35` (adjust if different)

## Dashboard Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│ [Org Filter Dropdown]                    [Time Picker: Last 30 days]│
├──────────────────────────────┬──────────────────────────────────────┤
│   GENERAL DEFENSE SCORE      │   DEFENSE SCORE BY ORGANIZATION      │
│        72.5%                 │   ████████████ sb: 78%               │
│      (big metric)            │   █████████    tpsgl: 65%            │
│                              │   ██████████   rga: 71%              │
├──────────────────────────────┴──────────────────────────────────────┤
│               GENERAL DEFENSE SCORE TREND (Line Chart)              │
│   100% ─┬────────────────────────────────────────────────────────── │
│    80% ─┼─────────╱╲────────╱╲──────────────────────────────────── │
│    60% ─┼────────╱──╲──────╱──╲─────────────────────────────────── │
│    40% ─┼───────╱────╲────╱────╲────────────────────────────────── │
│     0% ─┴────────────────────────────────────────────────────────── │
├──────────────────────────────┬──────────────────────────────────────┤
│  DEFENSE SCORE BY TEST       │  DEFENSE SCORE BY TEST (TREND)       │
│  ████████████ Process Inj    │  [Multi-line chart showing each test]│
│  █████████    Cred Dump      │                                      │
│  ███████████  Ransomware     │                                      │
├──────────────────────────────┼──────────────────────────────────────┤
│  DEFENSE SCORE BY TECHNIQUE  │  DEFENSE SCORE BY TECHNIQUE (TREND)  │
│  ████████████ T1055.001      │  [Multi-line chart showing each tech]│
│  █████████    T1003.001      │                                      │
│  ███████████  T1486          │                                      │
└──────────────────────────────┴──────────────────────────────────────┘
```

---

## Step 1: Create New Dashboard

1. Go to **Analytics** > **Dashboard**
2. Click **Create dashboard**
3. Click **Save** (top right)
4. Name: `F0RT1KA Defense Score`
5. Save

---

## Step 2: Add Organization Filter Control

1. Click **Controls** in the toolbar
2. Click **Add control**
3. Configure:
   - **Data view**: `f0rtika-synthetic` (or your data view)
   - **Field**: `routing.oid`
   - **Control type**: Options list
   - **Label**: Organization
4. Click **Save**

---

## Step 3: Create Visualizations

### Key Formula (Used in All Visualizations)

```
count(kql='f0rtika.is_protected: true') / count() * 100
```

This formula calculates the percentage of protected results.

---

### Visualization 1: General Defense Score (Metric)

1. Click **Create visualization**
2. Select **Lens**
3. Visualization type: **Metric**
4. Configure:
   - Drag **formula** to the metric area (or click "Add" under Primary metric)
   - Click the formula field and enter:
     ```
     count(kql='f0rtika.is_protected: true') / count() * 100
     ```
   - Label: `Defense Score`
   - Format: Number with suffix `%`
5. **Appearance** settings:
   - Title: `General Defense Score`
   - Subtitle: (leave empty or add "Overall Protection Rate")
6. Click **Save and return**

---

### Visualization 2: Defense Score by Test (Horizontal Bar)

1. Click **Create visualization**
2. Select **Lens**
3. Visualization type: **Bar horizontal**
4. Configure:
   - **Horizontal axis**: Formula
     ```
     count(kql='f0rtika.is_protected: true') / count() * 100
     ```
     - Label: `Defense Score %`
   - **Vertical axis**:
     - Field: `f0rtika.test_name`
     - Function: Top values (10-15)
     - Sort by: The formula metric (ascending to show worst first, or descending for best)
5. **Appearance**:
   - Title: `Defense Score by Test`
   - Show values on bars: Yes
6. Click **Save and return**

---

### Visualization 3: Defense Score by Technique (Horizontal Bar)

1. Click **Create visualization**
2. Select **Lens**
3. Visualization type: **Bar horizontal**
4. Configure:
   - **Horizontal axis**: Formula
     ```
     count(kql='f0rtika.is_protected: true') / count() * 100
     ```
     - Label: `Defense Score %`
   - **Vertical axis**:
     - Field: `f0rtika.techniques`
     - Function: Top values (15-20)
     - Sort by: The formula metric
5. **Appearance**:
   - Title: `Defense Score by Technique`
6. Click **Save and return**

---

### Visualization 4: Defense Score by Organization (Bar Chart)

1. Click **Create visualization**
2. Select **Lens**
3. Visualization type: **Bar vertical**
4. Configure:
   - **Vertical axis**: Formula
     ```
     count(kql='f0rtika.is_protected: true') / count() * 100
     ```
     - Label: `Defense Score %`
   - **Horizontal axis**:
     - Field: `routing.oid`
     - Function: Top values
5. **Appearance**:
   - Title: `Defense Score by Organization`
   - Colors: Use different color per organization if desired
6. **Important**: This visualization should NOT be filtered by the org dropdown (shows all orgs)
7. Click **Save and return**

---

### Visualization 5: General Defense Score Trend (Line Chart)

1. Click **Create visualization**
2. Select **Lens**
3. Visualization type: **Line**
4. Configure:
   - **Vertical axis**: Formula
     ```
     count(kql='f0rtika.is_protected: true') / count() * 100
     ```
     - Label: `Defense Score %`
   - **Horizontal axis**:
     - Field: `routing.event_time`
     - Function: Date histogram
     - Interval: Auto (adjusts to time range)
5. **Appearance**:
   - Title: `General Defense Score Trend`
   - Y-axis: 0 to 100 (fixed)
6. Click **Save and return**

---

### Visualization 6: Defense Score by Test Trend (Multi-Line)

1. Click **Create visualization**
2. Select **Lens**
3. Visualization type: **Line**
4. Configure:
   - **Vertical axis**: Formula
     ```
     count(kql='f0rtika.is_protected: true') / count() * 100
     ```
   - **Horizontal axis**:
     - Field: `routing.event_time`
     - Function: Date histogram
   - **Breakdown**:
     - Field: `f0rtika.test_name`
     - Function: Top values (5-10)
5. **Appearance**:
   - Title: `Defense Score by Test (Trend)`
   - Legend: Right or Bottom
6. Click **Save and return**

---

### Visualization 7: Defense Score by Technique Trend (Multi-Line)

1. Click **Create visualization**
2. Select **Lens**
3. Visualization type: **Line**
4. Configure:
   - **Vertical axis**: Formula
     ```
     count(kql='f0rtika.is_protected: true') / count() * 100
     ```
   - **Horizontal axis**:
     - Field: `routing.event_time`
     - Function: Date histogram
   - **Breakdown**:
     - Field: `f0rtika.techniques`
     - Function: Top values (5-10)
5. **Appearance**:
   - Title: `Defense Score by Technique (Trend)`
6. Click **Save and return**

---

### Visualization 8: Defense Score by Organization Trend (Multi-Line)

1. Click **Create visualization**
2. Select **Lens**
3. Visualization type: **Line**
4. Configure:
   - **Vertical axis**: Formula
     ```
     count(kql='f0rtika.is_protected: true') / count() * 100
     ```
   - **Horizontal axis**:
     - Field: `routing.event_time`
     - Function: Date histogram
   - **Breakdown**:
     - Field: `routing.oid`
     - Function: Top values
5. **Appearance**:
   - Title: `Defense Score by Organization (Trend)`
   - Line colors: Match org comparison bar chart
6. **Important**: This should NOT be filtered by org dropdown
7. Click **Save and return**

---

## Step 4: Arrange Dashboard Layout

1. Drag visualizations into the layout shown in the diagram above
2. Resize panels as needed
3. Group related visualizations:
   - Row 1: Org filter + General metric + Org comparison bar
   - Row 2: General trend (full width)
   - Row 3: By Test (bar + trend)
   - Row 4: By Technique (bar + trend)

---

## Step 5: Configure Filter Behavior

For visualizations 4, 8 (cross-org comparisons):
1. Click the panel menu (three dots)
2. Select **More** > **Ignore global filters** or exclude from org control

Alternatively, create two control groups:
- One for org-specific views (applied to viz 1, 2, 3, 5, 6, 7)
- Keep viz 4 and 8 unfiltered for comparison

---

## Step 6: Save Dashboard

1. Click **Save** (top right)
2. Ensure name is `F0RT1KA Defense Score`
3. Add optional description: "Security posture measurement showing percentage of tests that were blocked/protected"

---

## Troubleshooting

### Formula Not Working
- Ensure you're using **Lens** (not legacy visualizations)
- Check the KQL syntax: `f0rtika.is_protected: true` (no quotes around true)
- Verify the field exists in your data view

### No Data Showing
- Check time range includes your synthetic data
- Verify data view is correct
- Run in Discover: `f0rtika.is_protected: *` to confirm data exists

### Org Filter Not Working
- Ensure control is connected to same data view
- Check field name is exactly `routing.oid`

---

## Related Queries (ES|QL)

For experimentation in Discover:

```esql
FROM f0rtika-synthetic
| STATS protected = COUNT(*) WHERE f0rtika.is_protected == true,
        total = COUNT(*)
| EVAL defense_score = ROUND(protected * 100.0 / total, 1)
```

By organization:
```esql
FROM f0rtika-synthetic
| STATS protected = COUNT(*) WHERE f0rtika.is_protected == true,
        total = COUNT(*)
  BY routing.oid
| EVAL defense_score = ROUND(protected * 100.0 / total, 1)
| SORT defense_score DESC
```

By test:
```esql
FROM f0rtika-synthetic
| STATS protected = COUNT(*) WHERE f0rtika.is_protected == true,
        total = COUNT(*)
  BY f0rtika.test_name
| EVAL defense_score = ROUND(protected * 100.0 / total, 1)
| SORT defense_score ASC
```
