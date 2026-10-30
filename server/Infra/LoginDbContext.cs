using Microsoft.EntityFrameworkCore;

namespace Infra;

public sealed class LoginDbContext(DbContextOptions<LoginDbContext> options) : DbContext(options)
{
    public DbSet<AccountUser> Users => Set<AccountUser>();
    protected override void OnModelCreating(ModelBuilder modelBuilder) => modelBuilder.Entity<AccountUser>(e => { e.HasKey(u => u.Id); e.Property(u => u.Username).HasMaxLength(64).IsRequired(); e.HasIndex(u => u.Username).IsUnique(); e.Property(u => u.PasswordHash).IsRequired(); e.Property(u => u.Role).HasMaxLength(16).IsRequired(); });
}
public sealed class AccountUser 
{ 
public int Id { get; set; } 
public required string Username { get; set; } 
public required string PasswordHash { get; set; } 
public required string Role { get; set; } 
public DateTime CreatedUtc { get; set; } 
}