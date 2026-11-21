-- Attempts and approved spending by hour of day (the cardholder's local time).
SELECT
    hour,
    COUNT(*) AS attempts,
    SUM(approved) AS approved,
    ROUND(SUM(amount_cents * approved) / 100.0, 2) AS approved_volume
FROM transactions
GROUP BY hour
ORDER BY hour;
