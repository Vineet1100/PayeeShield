-- Approval rate per minute, and the running rate up to and including that minute.
WITH per_minute AS (
    SELECT
        CAST(at / 60 AS INTEGER) * 60 AS minute,
        COUNT(*) AS attempts,
        SUM(approved) AS approved
    FROM transactions
    GROUP BY minute
)
SELECT
    minute,
    attempts,
    approved,
    ROUND(100.0 * approved / attempts, 1) AS approval_rate_pct,
    ROUND(100.0 * SUM(approved) OVER w / SUM(attempts) OVER w, 1) AS running_rate_pct
FROM per_minute
WINDOW w AS (ORDER BY minute)
ORDER BY minute;
