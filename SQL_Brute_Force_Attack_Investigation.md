## Scenario
A system administrator detected multiple failed login attempts across several user accounts and suspected a potential brute-force attack.

## Objective
Use SQL queries to analyze login activity and identify suspicious behavior that may indicate a security incident.

## Data Source
Login logs containing:
- username
- timestamp
- status (success/failed)
- IP address

## Investigation Queries

-- Identify failed login attempts per IP(ranked by volume)
SELECT ip_address, COUNT(*) AS failed_attempts
FROM login_logs
WHERE status = 'failed'
GROUP BY ip_address
ORDER BY failed_attempts DESC;

-- Detect possible brute-force attacks (more than 5 failed attempts)
SELECT username, COUNT(*) AS attempts
FROM login_logs
WHERE status = 'failed'
GROUP BY username
HAVING COUNT(*) > 5;

-- Identify suspicious IP addresses with multiple failed attempts
SELECT ip_address, COUNT(*) AS failed_attempts
FROM login_logs
WHERE status = 'failed'
GROUP BY ip_address
HAVING COUNT(*) > 10;

## Findings
- Multiple users experienced repeated failed login attempts
- Certain accounts exceeded normal login thresholds
- Specific IP addresses exhibited unusually high volumes of failed login attempts,indicating potential malicious activity

## Conclusion
This activity is consistent with brute-force or credential stuffing attacks targeting authentication systems. Immediate investigation and mitigation actions are recommended to prevent unauthorized access.

## Recommendations
- Enable account lockout after multiple failed attempts
- Implement multi-factor authentication (MFA)
- Block suspicious IP addresses
- Monitor activity using SIEM alerts
-  Implement IP rate limiting or geo-blocking to reduce repeated login attempts
