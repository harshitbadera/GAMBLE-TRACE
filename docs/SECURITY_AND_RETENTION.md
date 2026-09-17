# Authentication, evidence security, and retention

Task 19 hardens the local GambleTrace deployment. These controls are intended
for a single trusted application deployment; Task 20 can add container and
deployment assets around them.

## Initial setup

Authentication is enabled by default. Before first startup, configure either:

1. `GAMBLETRACE_INITIAL_SETUP_TOKEN` and visit `/auth/setup` to create the
   first local administrator; or
2. both `GAMBLETRACE_ADMIN_USERNAME` and `GAMBLETRACE_ADMIN_PASSWORD` to
   bootstrap the first administrator automatically.

Use [.env.example](../.env.example) as a configuration reference. Do not
commit a real `.env` file or a real secret.

Production mode requires a dedicated secret key:

```powershell
$env:GAMBLETRACE_ENV = 'production'
$env:GAMBLETRACE_SECRET_KEY = 'generate-a-long-random-value'
$env:GAMBLETRACE_INITIAL_SETUP_TOKEN = 'one-time-setup-token'
python app.py
```

The application intentionally refuses production startup if
`GAMBLETRACE_SECRET_KEY` is missing.

## Controls included

- Local password-hash accounts with `ADMIN` and `ANALYST` roles.
- Session cookies configured as HTTP-only and SameSite=Lax; production cookies
  are Secure.
- Per-session CSRF tokens for state-changing browser and legacy API requests.
- Login throttling after repeated failed password attempts.
- Authentication enforced before case, evidence, export, and legacy API access.
- Standard security response headers, including a restrictive CSP, no-sniff,
  frame denial, referrer, and permissions policies.
- Optional trusted-proxy handling and forced HTTPS in production mode.

Create additional accounts from a protected terminal rather than a public web
administration endpoint:

```powershell
flask --app app create-user analyst_name --role ANALYST
```

## Evidence and export files

New case evidence, preserved seed sources, and generated export folders use
owner-restrictive POSIX permissions when the operating system supports them.
Windows permissions should be enforced with deployment-managed NTFS ACLs.

Evidence downloads remain case-scoped and path-validated. Generated evidence
ZIP packages independently hash-check every included evidence/source file;
mismatched files are reported and excluded.

## Retention cleanup

The cleanup command is conservative. It targets only generated case exports
and the temporary dashboard directory—never immutable evidence, preserved
source files, database rows, or observations.

Preview candidates first:

```powershell
flask --app app cleanup-generated-files
```

Apply the cleanup only after reviewing the preview:

```powershell
flask --app app cleanup-generated-files --apply
```

Default retention is 30 days for exports and 2 days for temporary files. Tune
`EXPORT_RETENTION_DAYS` and `TEMP_RETENTION_DAYS` in the application factory
or deployment configuration.
