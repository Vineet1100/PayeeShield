# Roadmap

One improvement at a time, top of the list first. Finished items move to **Done** with the date.

## Up next

- [ ] **Store the ledger in SQLite.** Keep transactions and alerts in a SQLite database with parameterized queries only, and add a `queries/` folder of analytics SQL (approval rate by channel, blocked attempts by reason, hourly volume).
- [ ] **Model evaluation report.** Build a labelled synthetic test set (normal purchases plus injected fraud patterns) and compare the robust z-score, Local Outlier Factor and Isolation Forest on precision, recall and false-positive rate. Publish the table in the README.
- [ ] **Threshold A/B test.** Simulate two fraud-alert thresholds on the same traffic and compare fraud caught against good customers wrongly flagged, with a significance test on the difference.
- [ ] **Metrics page in the live demo.** Approval rate over time, blocked attempts by reason and alerts by severity, as charts on the bank page.
- [ ] **Explain each alert.** Show which features (amount, hour, channel) pushed a purchase over the line, so an analyst can see why it was flagged.
- [ ] **Impossible-travel rule.** Flag two in-store payments from merchants in different cities too close together in time to be real.
- [ ] **Merchant risk check.** Score merchants by their decline and alert history and flag purchases from new or high-risk merchants.
- [ ] **Signed webhooks for merchants.** Send payment results to merchants as webhooks signed with HMAC and a timestamp, with replay protection on the receiving side.
- [ ] **Key rotation.** Support several active keys per client with key ids, so keys can be rotated without downtime.
- [ ] **Data quality checks.** Validate the ledger (no negative amounts, no duplicate ids, timestamps in order) before analytics runs, and report anything that fails.
- [ ] **Type checking and coverage in CI.** Run mypy and fail the build if test coverage drops below the current level.
- [ ] **Docker setup.** A Dockerfile and docker-compose file that start the bank API, the demo and the MCP server with one command, running as a non-root user.
- [ ] **Accessibility pass on the live demo.** Keyboard navigation, focus states, screen reader labels and colour contrast to WCAG AA.
- [ ] **Disputes and chargebacks.** Let the cardholder dispute an approved payment and track it through to a decision.

## Done

- 2026-11-16: Fixed the dynamic CVV for pyotp 2.12.
- 2026-11-14: Hardened the live demo server and marked the demo as a prototype everywhere.
- 2026-11-13: Moved the live demo to Flask, hosted on Render.
- 2026-11-12: Added the secured bank API, MCP server, system design and security CI.
- 2026-11-02: Real Touch ID and laptop notifications in the browser demo.
- 2026-10-21: First version: biometric card simulator, dynamic CVV and fraud monitor.
