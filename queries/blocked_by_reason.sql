-- Attempts stopped by a security control, grouped by why they were stopped.
SELECT
    reason,
    channel,
    COUNT(*) AS attempts
FROM transactions
WHERE security_block = 1
GROUP BY reason, channel
ORDER BY attempts DESC, reason;
