-- Share of payment attempts approved, per channel.
SELECT
    channel,
    COUNT(*) AS attempts,
    SUM(approved) AS approved,
    ROUND(100.0 * SUM(approved) / COUNT(*), 1) AS approval_rate_pct
FROM transactions
GROUP BY channel
ORDER BY channel;
