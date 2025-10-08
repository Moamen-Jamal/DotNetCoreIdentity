## ASP.NET Core Identity (NET 8) – MVC + JWT Demo

### Overview
Custom MVC implementation of ASP.NET Core Identity on .NET 8 using JWT. Includes:
- User Registration and Login (JWT issuance)
- Email Confirmation (console-based demo sender)
- Roles and Claims (with seeding)
- Custom Authorization Policy (`permission=manage_users` → `CanManageUsers`)
- Email-based 2FA (one-time codes)
- Profile page (shows email, roles, claims, 2FA status)
- SQL Server persistence

### Requirements
- .NET 8 SDK
- SQL Server instance (configured in `appsettings.json`)

### Project Structure (highlights)
- `Program.cs`: DI and middleware (IdentityCore, JwtBearer, Authorization)
- `Data/ApplicationDbContext.cs`: Identity EF Core context
- `Data/IdentitySeeder.cs`: seeds roles and a demo admin user
- `Services/JwtTokenService.cs`: creates signed JWTs
- `Services/EmailSender.cs`: demo email sender (writes to console)
- `Authorization/*`: custom policy requirement/handler
- `Controllers/AccountController.cs`: Register, Login, 2FA, ConfirmEmail
- `Controllers/ProfileController.cs`: Profile (protected)
- `Controllers/AdminController.cs`: Minimal endpoints to add roles/claims
- `Views/*`: MVC views for account, profile, shared layout

### Configure SQL Server
Edit `DotNetCoreIdentity/DotNetCoreIdentity/appsettings.json`:
```
"ConnectionStrings": {
  "DefaultConnection": "Server=YOUR_SERVER;Database=aspnet-CoreIdentity;Trusted_Connection=True;MultipleActiveResultSets=true;TrustServerCertificate=True"
}
```
Note: `TrustServerCertificate=True` bypasses TLS trust errors for local dev. Use proper certs in production.

### JWT Settings
`appsettings.json` → `Jwt` section:
```
"Jwt": {
  "Issuer": "DotNetCoreIdentity",
  "Audience": "DotNetCoreIdentity",
  "Key": "DevSecretKey_ForJwt_Demo_ChangeInProduction_1234567890"
}
```
Change the `Key` for production.

### Database Migrations
- Create migration:
```
dotnet ef migrations add InitialSqlServer --project DotNetCoreIdentity/DotNetCoreIdentity --context DotNetCoreIdentity.Data.ApplicationDbContext --output-dir Data/Migrations
```
- Update database:
```
dotnet ef database update --project DotNetCoreIdentity/DotNetCoreIdentity --context DotNetCoreIdentity.Data.ApplicationDbContext
```

### Run
From the project directory:
```
dotnet run --project DotNetCoreIdentity/DotNetCoreIdentity
```
Browse to `https://localhost:xxxx/`.

### Usage Flow
1) Register: `/Account/Register`
   - A confirmation link is written to the console (via `EmailSender`).
   - Visit the link to confirm email.
2) Enable 2FA (optional): `/Profile` → Enable 2FA
3) Login: `/Account/Login`
   - If 2FA enabled, a one-time code is emailed (console); enter it at `/Account/Verify2FA`.
   - On success, a JWT is shown on the Token page.
4) Use JWT on protected endpoints: add header
```
Authorization: Bearer {token}
```
5) Profile page: `/Profile` (requires valid JWT)

### Roles, Claims, and Policy
- Seeded roles: `Admin`, `User`; demo admin user: `admin@demo.local` / `Admin#12345`
- The admin is given claim `permission=manage_users`.
- Policy `CanManageUsers` requires that claim.
- Admin endpoints (require policy):
  - POST `/Admin/AddRole` (form-data: `userEmail`, `role`)
  - POST `/Admin/AddClaim` (form-data: `userEmail`, `type`, `value`)

### Notes and Tips
- This app is stateless for auth; “logout” means discarding the JWT client-side.
- Replace `EmailSender` with a real provider (SMTP/SendGrid) for production.
- Keep the JWT secret out of source control; use `dotnet user-secrets` or environment variables.

### Troubleshooting
- TLS/certificate issues with SQL Server: use `TrustServerCertificate=True` for local dev, or install trusted certs.
- If auth fails on protected pages, ensure you’re sending the JWT token in the `Authorization` header.
- Verify email is confirmed before logging in (app requires confirmed email).


