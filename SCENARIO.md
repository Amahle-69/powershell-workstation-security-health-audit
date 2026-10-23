
# PowerShell Workstation Security & Health Audit

## 1. Business Scenario

Mahlangu Business Solutions is a fictional company whose IT Support team is responsible for checking the basic security configuration and health of Windows workstations.

The team needs a repeatable way to collect selected system information, review security protection states, identify potential issues, and produce a report for further investigation.

This project simulates a read-only workstation audit on a Windows computer.

## 2. Business Problem

When employees report computer problems or an organisation performs routine workstation checks, technicians need evidence to help decide what to investigate.

Examples of checks include:

- Whether Microsoft Defender reports its protection features as enabled.
- Whether Windows Firewall profiles are enabled.
- Whether the system drive has sufficient free space.
- Which Windows version and build are running.
- Whether some checks cannot be completed because a command or data source is unavailable.

Performing these checks manually can be repetitive. A PowerShell script can collect the information consistently and place findings in a structured report.

## 3. Proposed Solution

Develop a PowerShell script that performs selected read-only workstation checks and generates a CSV report containing observed values, audit statuses, and recommended follow-up actions.

The script will distinguish between a finding, a successful check, and a check that could not be completed. Missing information will not automatically be treated as proof of a security problem.

## 4. Project Objectives

- Use Windows PowerShell 5.1-compatible scripting.
- Collect selected operating-system information.
- Inspect Microsoft Defender status where the necessary cmdlets are available.
- Inspect Windows Firewall profile states.
- Check system drive free space.
- Identify potential issues using clearly documented thresholds.
- Generate a CSV report with findings and recommendations.
- Handle unavailable commands and inaccessible data sources gracefully.
- Test the audit logic and edge cases.
- Document limitations and publish the project using Git and GitHub.

## 5. Fictional Workplace Scenarios

### Scenario A: Defender protection needs review

The audit cannot confirm that a required Defender protection feature is enabled.

The script should record that the check needs review and recommend investigating the relevant protection setting. It should not change security settings automatically.

### Scenario B: Firewall profile is disabled

One Windows Firewall profile is reported as disabled.

The script should record the observed profile state and recommend checking the device's approved security configuration.

### Scenario C: System drive is running low on space

The system drive has less free space than the configured threshold.

The script should flag the available space and recommend reviewing storage usage before taking cleanup action.

### Scenario D: A security check cannot be completed

A required command is unavailable or returns an error.

The report should state that the check could not be completed rather than incorrectly reporting that the workstation passed.

### Scenario E: No findings under the configured rules

The available data passes the checks implemented in the script.

The report should state that no findings were identified under those rules. It must not claim that the workstation is completely secure.

## 6. Planned Workflow

1. Collect operating-system information.
2. Inspect the available Defender status information.
3. Inspect Windows Firewall profiles.
4. Check system drive capacity and free space.
5. Apply the documented audit rules.
6. Record check results, findings, and recommendations.
7. Export the results to a CSV report.
8. Run automated tests and document limitations.

## 7. Technology Stack

- **Scripting language:** Windows PowerShell 5.1
- **Editor:** Visual Studio Code
- **Target environment:** Windows 11
- **Data interchange:** CSV where appropriate
- **Version control:** Git
- **Repository hosting:** GitHub

## 8. Safety and Privacy

This project is a read-only audit.

The script will not disable security protection, modify firewall rules, delete files, change system settings, or automatically remediate findings.

The public project will avoid including unnecessary identifying information such as the computer name, Windows username, IP addresses, or other personal system details.

## 9. Limitations

- Available commands and returned information may vary by Windows configuration.
- A missing or inaccessible status source does not prove that protection is disabled.
- Free-space thresholds are indicators for review, not proof of a disk fault.
- A successful audit does not guarantee that every possible security issue has been detected.
- The report provides observations and recommendations; it does not replace a comprehensive security assessment.

## 10. Expected Outcome

The completed project should demonstrate how PowerShell can collect selected workstation information, identify conditions that require attention, handle incomplete checks responsibly, and produce a structured audit report.

The project will include the audit script, automated tests, documentation, and sample audit results.
