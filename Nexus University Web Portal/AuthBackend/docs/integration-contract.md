# FYP Authentication + RBAC Integration Contract

This project owns the FIDO2/passwordless authentication backend. The RBAC module should integrate through the shared database fields and secure cookie claims listed here.

## Final Architecture

- Final system: one ASP.NET Core application.
- Development now: separate projects for FIDO2/authentication and RBAC/UI.
- Shared database: one schema containing users, roles, permissions, credentials, sessions, devices, and logs.
- Login state: ASP.NET cookie authentication with claims.

## Shared Role IDs

- `student`
- `lecturer`
- `admin`

## Shared Permission Names

- `read:dashboard`
- `read:profile`
- `manage:users`
- `manage:roles`
- `manage:devices`
- `manage:sessions`
- `read:logs`

## Cookie Claims After FIDO2 Login

- `sub`: user ID
- `email`: user email
- `name`: full name
- `role`: role ID
- `amr`: `fido2`
- `session_id`: database session ID

## Stable API Endpoints

- `POST /api/auth/register/options`
- `POST /api/auth/register/verify`
- `POST /api/auth/login/options`
- `POST /api/auth/login/verify`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `GET /api/devices`
- `POST /api/devices/register/options`
- `POST /api/devices/register/verify`
- `DELETE /api/devices/{deviceId}`
- `GET /api/security/logs`
- `GET /api/security/summary`
- `POST /api/admin/users`

## Ownership

Justin owns FIDO2 credential registration, authentication verification, signCount replay protection, authenticator/device registration, authentication sessions, and authentication audit logs.

RBAC partner owns role management, permission mapping, page/action authorization policy, and RBAC dashboard behavior.

Shared tables must keep `UserId` as the integration key. Do not store passwords or password hashes.
