# CyberShield — Serverless Security Log Analysis

CyberShield is an educational security-log analysis project built to demonstrate rule-based detection of suspicious authentication activity. The repository includes the original AWS serverless implementation and a browser-only demo that can be hosted as a static website.

> **Important:** The GitHub Pages demo runs entirely in the browser. It does not call AWS, does not require AWS credentials, and does not save findings to DynamoDB. The original AWS backend files are retained as project evidence and are separate from the static demo.

## Table of contents

- [Project overview](#project-overview)
- [Features](#features)
- [Detection rules](#detection-rules)
- [Architecture](#architecture)
- [Repository layout](#repository-layout)
- [Run the demo locally](#run-the-demo-locally)
- [Example input](#example-input)
- [Original AWS implementation](#original-aws-implementation)
- [Security and privacy](#security-and-privacy)
- [Limitations and future improvements](#limitations-and-future-improvements)
- [AWS cleanup checklist](#aws-cleanup-checklist)

## Project overview

Authentication logs can help identify patterns such as repeated failed logins and potentially suspicious sign-in activity. CyberShield demonstrates how simple, transparent rules can flag patterns for further review.

The project has two parts:

1. **Static browser demo:** an interactive `index.html` page that accepts a batch of sample log events and evaluates them locally.
2. **Original AWS serverless implementation:** Python Lambda code and supporting project documentation showing the intended AWS-based workflow.

This is a learning prototype, not a production security information and event management (SIEM) system.

## Features

- Load built-in sample events for a quick demonstration.
- Analyze a batch of authentication events in the browser.
- Display findings with rule identifiers, severity, and explanatory details.
- Export findings as CSV.
- Host the browser demo as a static site using GitHub Pages.
- Retain the AWS Lambda source and project report for technical review.

## Detection rules

The current browser demo implements these illustrative rules:

| Rule ID | Trigger | Severity |
|---|---|---|
| `AUTH-001` | Five or more `login_failed` events from the same IP address in the analyzed batch | High |
| `AUTH-002` | At least three failed logins and a `login_success` event from the same IP address in the analyzed batch | Medium |

These are simple batch-based indicators. They do not establish that an account was compromised, and they may produce false positives or miss activity outside the analyzed batch.

## Architecture

### Static demo

```text
User opens index.html
        |
        v
Browser loads sample or user-provided events
        |
        v
JavaScript evaluates local detection rules
        |
        v
Findings displayed in the dashboard
        |
        v
User may export findings as CSV
```

The static demo does not require an API endpoint or AWS service.

### Original AWS design

The original serverless workflow was designed around these components:

```text
Dashboard / client
       |
       v
Amazon API Gateway (POST /analyze)
       |
       v
AWS Lambda (CyberShieldAnalyzer)
       |
       +----> Amazon DynamoDB (CyberShieldFindings)
       |
       v
Response to client

Lambda logs and runtime errors ----> Amazon CloudWatch
```

The original project also used Amazon S3 for static website hosting. The AWS design and the browser-only demo are separate: publishing this static demo to GitHub Pages does not deploy or invoke the AWS backend.

## Repository layout

```text
CyberShield_AWS_Project/
├── index.html
├── index_aws_backup.html
├── indexold.html
├── README.md
├── .gitignore
├── samplejson.txt
├── lambda_function.py
├── backend/
│   └── lambda_function.py
└── report/
    └── CyberShield_Project_Flow_Report.docx
```

- `index.html` — current browser-only demo intended for GitHub Pages.
- `index_aws_backup.html` — retained copy of the earlier AWS-connected dashboard, if present.
- `indexold.html` — older dashboard version, if present.
- `lambda_function.py` and `backend/lambda_function.py` — Python backend source files; inspect them to confirm which version is authoritative before deployment.
- `samplejson.txt` — sample event data.
- `report/` — project report.

The list above describes the expected project files; optional legacy files may not exist in every checkout.

## Run the demo locally

### Option 1: Open the HTML file

Open `index.html` in a modern browser. Use the sample-data button and run the analysis.

### Option 2: Serve it locally

From the project directory, run:

```bash
python3 -m http.server 8000
```

Then open `http://localhost:8000` in your browser.

Stop the server with `Ctrl+C` when finished.

## Example input

A typical event batch may contain entries like:

```json
[
  {
    "timestamp": "2026-10-25T09:00:00Z",
    "event_type": "login_failed",
    "ip": "203.0.113.10",
    "username": "demo-user"
  },
  {
    "timestamp": "2026-10-25T09:01:00Z",
    "event_type": "login_success",
    "ip": "203.0.113.10",
    "username": "demo-user"
  }
]
```

Use the dashboard's built-in sample to see the exact input format supported by the current page. The IP address in this example belongs to a documentation range and is not intended to identify a real attacker.

## Original AWS implementation

The original AWS deployment used the following resources:

- **Amazon S3:** static dashboard hosting.
- **Amazon API Gateway:** HTTP API with a `POST /analyze` route.
- **AWS Lambda:** Python log-analysis handler.
- **Amazon DynamoDB:** storage for findings, according to the original design.
- **Amazon CloudWatch:** Lambda logs and troubleshooting.
- **AWS IAM:** execution role and permissions for the Lambda function.

A previously used deployment region was `us-east-1`. Actual resource names, table schemas, permissions, and current deployment status should be verified in the AWS console and source code before attempting a redeployment. Do not publish AWS access keys, credentials, session tokens, or sensitive log data.

## Security and privacy

- The browser demo analyzes data locally in the browser and does not need AWS credentials.
- Use synthetic or sanitized events in public demonstrations.
- Do not commit `.env` files, AWS credentials, private keys, or real security logs containing personal or confidential information.
- Review every file before publishing the repository, especially legacy HTML files that may contain old endpoints or configuration.
- Client-side rules can be inspected and modified by visitors; this is expected for a demonstration and is not a security boundary.
- A public GitHub Pages site is not suitable for processing confidential production logs.

## Limitations and future improvements

- Detection is rule-based and limited to the events in a single submitted batch.
- No persistent storage is used by the browser-only demo.
- There is no authentication, authorization, multi-user support, or production-grade audit trail in the static demo.
- Rules may generate false positives and do not replace investigation by a security analyst.

Possible improvements include configurable thresholds, time-window analysis, schema validation, unit tests, richer explanations, and a separately deployed backend with appropriate authentication, input validation, least-privilege IAM permissions, and monitoring.

## AWS cleanup checklist

If you previously deployed the AWS version and no longer need it, verify the resources in the AWS console before deleting them. Preserve screenshots or other project evidence first.

1. Confirm the account and region are correct.
2. Check API Gateway for the project API and delete it if no longer needed.
3. Check Lambda for `CyberShieldAnalyzer` and remove it if no longer needed.
4. Check DynamoDB for `CyberShieldFindings`; preserve any required evidence before deleting the table.
5. Check CloudWatch for `/aws/lambda/CyberShieldAnalyzer` and remove the log group if appropriate.
6. Empty and delete the project S3 bucket, if one exists and is no longer needed.
7. Review the Lambda execution role and project-specific IAM policies; remove them only after dependent resources are gone and you have confirmed they are not shared.
8. Check for related resources in other regions and review billing after usage data has updated.

Deleting resources is irreversible for some data. Verify each resource carefully and do not delete shared resources.
