using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Service;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDbContext<LoginDbContext>(o => o.UseSqlite(builder.Configuration.GetConnectionString("LoginDb") ?? "Data Source=kbaps.db"));
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(o =>
{
    o.Cookie.Name = "KBaps.Auth";
    o.Cookie.HttpOnly = true;
    o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    o.Cookie.SameSite = SameSiteMode.Strict;
    o.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    o.SlidingExpiration = true;
    o.Events.OnRedirectToLogin = c => { c.Response.StatusCode = StatusCodes.Status401Unauthorized; return Task.CompletedTask; };
    o.Events.OnRedirectToAccessDenied = c => { c.Response.StatusCode = StatusCodes.Status403Forbidden; return Task.CompletedTask; };
});
builder.Services.AddAuthorization();
var app = builder.Build();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

await using (var scope = app.Services.CreateAsyncScope())
{
    var db = scope.ServiceProvider.GetRequiredService<LoginDbContext>();
    await db.Database.EnsureCreatedAsync();
    // Bootstrap credentials are set in the deployment environment, never committed to source control.
    var adminName = Environment.GetEnvironmentVariable("KBAPS_ADMIN_USERNAME");
    var adminPassword = Environment.GetEnvironmentVariable("KBAPS_ADMIN_PASSWORD");
    if (!string.IsNullOrWhiteSpace(adminName) && !string.IsNullOrWhiteSpace(adminPassword) &&
        !await db.Users.AnyAsync(u => u.Role == AccountRoles.Admin))
    {
        db.Users.Add(new AccountUser { Username = adminName.Trim(), PasswordHash = BCrypt.Net.BCrypt.HashPassword(adminPassword), Role = AccountRoles.Admin, CreatedUtc = DateTime.UtcNow });
        await db.SaveChangesAsync();
    }
}

app.MapGet("/", () => Results.Ok(new { application = "Kvist & Bjælke ApS Login Platform", part = "1.1", status = "ready" }));
app.MapPost("/api/auth/login", async Task<IResult> (LoginRequest request, LoginDbContext db, HttpContext context) =>
{
    if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrEmpty(request.Password))
        return Results.BadRequest(new { message = "Username and password are required." });
    var account = await db.Users.SingleOrDefaultAsync(u => u.Username == request.Username.Trim());
    if (account is null || !BCrypt.Net.BCrypt.Verify(request.Password, account.PasswordHash))
        return Results.Json(new { message = "Invalid username or password." }, statusCode: StatusCodes.Status401Unauthorized);
    var claims = new[] { new Claim(ClaimTypes.NameIdentifier, account.Id.ToString()), new Claim(ClaimTypes.Name, account.Username), new Claim(ClaimTypes.Role, account.Role) };
    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
    return Results.Ok(new AccountResponse(account.Id, account.Username, account.Role, account.CreatedUtc));
}).AllowAnonymous();
app.MapPost("/api/auth/logout", async (HttpContext context) => { await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme); return Results.NoContent(); }).RequireAuthorization();
app.MapGet("/api/auth/me", (ClaimsPrincipal p) => Results.Ok(new { username = p.Identity?.Name, role = p.FindFirst(ClaimTypes.Role)?.Value })).RequireAuthorization();

var users = app.MapGroup("/api/users").RequireAuthorization();
users.MapGet("/", async (LoginDbContext db) => Results.Ok(await db.Users.OrderBy(u => u.Username).Select(u => new AccountResponse(u.Id, u.Username, u.Role, u.CreatedUtc)).ToListAsync()))
    .RequireAuthorization(p => p.RequireRole(AccountRoles.User, AccountRoles.Superuser, AccountRoles.Admin));
users.MapPost("/", async Task<IResult> (CreateAccountRequest request, ClaimsPrincipal actor, LoginDbContext db) =>
{
    var role = actor.FindFirst(ClaimTypes.Role)?.Value;
    if (!RoleRules.IsKnownRole(request.Role)) return Results.BadRequest(new { message = "Invalid role." });
    if (role == AccountRoles.Superuser && request.Role != AccountRoles.User) return Results.Forbid();
    if (role is not (AccountRoles.Superuser or AccountRoles.Admin)) return Results.Forbid();
    var name = request.Username?.Trim();
    if (string.IsNullOrWhiteSpace(name) || name.Length is < 3 or > 64) return Results.BadRequest(new { message = "Username must contain 3–64 characters." });
    if (string.IsNullOrWhiteSpace(request.Password) || request.Password.Length < 12) return Results.BadRequest(new { message = "Password must contain at least 12 characters." });
    if (await db.Users.AnyAsync(u => u.Username == name)) return Results.Conflict(new { message = "Username already exists." });
    var user = new AccountUser { Username = name, PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password), Role = request.Role, CreatedUtc = DateTime.UtcNow };
    db.Users.Add(user); await db.SaveChangesAsync();
    return Results.Created($"/api/users/{user.Id}", new AccountResponse(user.Id, user.Username, user.Role, user.CreatedUtc));
}).RequireAuthorization(p => p.RequireRole(AccountRoles.Superuser, AccountRoles.Admin));
users.MapPut("/{id:int}", async Task<IResult> (int id, UpdateAccountRequest request, ClaimsPrincipal actor, LoginDbContext db) =>
{
    var actorRole = actor.FindFirst(ClaimTypes.Role)?.Value;
    var user = await db.Users.FindAsync(id);
    if (user is null) return Results.NotFound();
    if (actorRole == AccountRoles.Superuser && user.Role != AccountRoles.User) return Results.Forbid();
    if (actorRole is not (AccountRoles.Superuser or AccountRoles.Admin)) return Results.Forbid();
    if (request.Username is not null)
    {
        var name = request.Username.Trim();
        if (name.Length is < 3 or > 64) return Results.BadRequest(new { message = "Username must contain 3–64 characters." });
        if (await db.Users.AnyAsync(u => u.Id != id && u.Username == name)) return Results.Conflict(new { message = "Username already exists." });
        user.Username = name;
    }
    if (request.Role is not null)
    {
        if (!RoleRules.IsKnownRole(request.Role)) return Results.BadRequest(new { message = "Invalid role." });
        if (actorRole == AccountRoles.Superuser && request.Role != AccountRoles.User) return Results.Forbid();
        user.Role = request.Role;
    }
    if (!string.IsNullOrEmpty(request.Password))
    {
        if (request.Password.Length < 12) return Results.BadRequest(new { message = "Password must contain at least 12 characters." });
        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);
    }
    await db.SaveChangesAsync();
    return Results.Ok(new AccountResponse(user.Id, user.Username, user.Role, user.CreatedUtc));
}).RequireAuthorization(p => p.RequireRole(AccountRoles.Superuser, AccountRoles.Admin));
users.MapDelete("/{id:int}", async Task<IResult> (int id, ClaimsPrincipal actor, LoginDbContext db) =>
{
    var actorRole = actor.FindFirst(ClaimTypes.Role)?.Value;
    var user = await db.Users.FindAsync(id);
    if (user is null) return Results.NotFound();
    if (actorRole == AccountRoles.Superuser && user.Role != AccountRoles.User) return Results.Forbid();
    if (actorRole is not (AccountRoles.Superuser or AccountRoles.Admin)) return Results.Forbid();
    if (user.Role == AccountRoles.Admin && await db.Users.CountAsync(u => u.Role == AccountRoles.Admin) <= 1)
        return Results.Conflict(new { message = "The last administrator cannot be deleted." });
    db.Users.Remove(user); await db.SaveChangesAsync(); return Results.NoContent();
}).RequireAuthorization(p => p.RequireRole(AccountRoles.Superuser, AccountRoles.Admin));
app.Run();
