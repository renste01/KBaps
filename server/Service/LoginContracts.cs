using Infra;

namespace Service;


public static class AccountRoles
{
    public const string User = "user"; public const string Superuser = "superuser"; public const string Admin = "admin";
}

public static class RoleRules
{
    public static bool IsKnownRole(string? role) => role is AccountRoles.User or AccountRoles.Superuser or AccountRoles.Admin;
}
public sealed record LoginRequest(string Username, string Password);
public sealed record CreateAccountRequest(string Username, string Password, string Role);
public sealed record UpdateAccountRequest(string? Username, string? Password, string? Role);
public sealed record AccountResponse(int Id, string Username, string Role, DateTime CreatedUtc);