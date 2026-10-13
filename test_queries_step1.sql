USE shadow_ai_sentinel;

-- Q1. SELECT: see all categories
SELECT * FROM DetectionCategories;

-- Q2. INNER JOIN: active rules with their category name
SELECT r.rule_id, r.rule_name, c.category_name, r.is_active
FROM SecurityRules r
INNER JOIN DetectionCategories c ON r.category_id = c.category_id
WHERE r.is_active = 1
ORDER BY c.category_name;

-- Q3. COUNT: total scans
SELECT COUNT(*) AS total_scans FROM Scans;

-- Q4. WHERE + COUNT: high-risk scans
SELECT COUNT(*) AS high_risk_scans FROM Scans WHERE risk_level = 'High';

-- Q5. SUM: redacted scans (the comparison gives 1 or 0, SUM adds them up)
SELECT SUM(action_taken = 'Redacted') AS redacted_scans FROM Scans;

-- Q6. LEFT JOIN + GROUP BY: detections by category (shows 0 if none)
SELECT c.category_name,
       COALESCE(SUM(f.match_count), 0) AS total_detections
FROM DetectionCategories c
LEFT JOIN ScanFindings f ON c.category_id = f.category_id
GROUP BY c.category_id, c.category_name
ORDER BY total_detections DESC;

-- Q7. LEFT JOIN + IS NULL: scans that found nothing
SELECT s.scan_id, s.scan_time, s.risk_level
FROM Scans s
LEFT JOIN ScanFindings f ON s.scan_id = f.scan_id
WHERE f.finding_id IS NULL;

-- Q8. VIEW: scan summary
SELECT * FROM vw_scan_summary ORDER BY scan_time DESC;
