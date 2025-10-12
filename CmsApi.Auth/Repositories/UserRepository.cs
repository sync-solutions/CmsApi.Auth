using Azure.Core;
using CmsApi.Auth.Data;
using CmsApi.Auth.DTOs;
using CmsApi.Auth.Models;
using Microsoft.EntityFrameworkCore;

namespace CmsApi.Auth.Repositories;

public class UserRepository(AuthDbContext dbContext)
{
    public async Task<User> Add(User user, string? hashedPassword, string provider)
    {
        var newUser = dbContext.Users.Add(user);
        await dbContext.SaveChangesAsync();
        return newUser.Entity;
    }
    public async Task<User?> GetById(int UserId)
    {
        return await dbContext.Users.FirstOrDefaultAsync(u => u.Id == UserId);
    }
    public async Task<User?> GetByEmailorMob(RegisterRequest request)
    {
        return await dbContext.Users
        .FirstOrDefaultAsync(u => u.Email == request.Email || u.MobileNumber == request.MobileNumber);
    }
    public async Task<User?> GetByEmailorUserName(string EmailOrUsername)
    {
        return await dbContext.Users
            .FirstOrDefaultAsync(u => u.Email == EmailOrUsername || u.Username == EmailOrUsername);
    }
    public Task<User?> GetByUserName(string username)
    {
        return dbContext.Users
                    .AsNoTracking()
                    .FirstOrDefaultAsync(u => u.Username == username);
    }
    public Task<User?> GetByEmail(string email)
    {
        return dbContext.Users
                    .AsNoTracking()
                    .FirstOrDefaultAsync(u => u.Email == email);
    }
    public async Task<string> UpdateResetPassToken(User user)
    {
        dbContext.Attach(user);
        user.ResetPassToken = Guid.NewGuid().ToString();
        user.ResetPassTokenExpiry = DateTime.Now.AddHours(1);
        dbContext.Entry(user).Property(u => u.ResetPassToken).IsModified = true;
        dbContext.Entry(user).Property(u => u.ResetPassTokenExpiry).IsModified = true;

        await dbContext.SaveChangesAsync();
        return user.ResetPassToken;
    }
    public async Task<User?> GetByValidResetToken(ResetPasswordRequest request)
    {
        return await dbContext.Users
            .FirstOrDefaultAsync(u => u.ResetPassToken == request.Token && u.ResetPassTokenExpiry > DateTime.Now);
    }
    public async Task<AuthResponse?> Update(UserEditRequest request)
    {
        var user = await dbContext.Users.FindAsync(request.Id);
        if (user == null) return null;

        dbContext.Users.Attach(user);

        if (!string.IsNullOrWhiteSpace(request.Name))
            dbContext.Entry(user).Property(u => u.Name).CurrentValue = request.Name;

        if (!string.IsNullOrWhiteSpace(request.Email))
            dbContext.Entry(user).Property(u => u.Email).CurrentValue = request.Email;

        if (!string.IsNullOrWhiteSpace(request.MobileNumber))
            dbContext.Entry(user).Property(u => u.MobileNumber).CurrentValue = request.MobileNumber;

        if (request.RoleId.HasValue)
            dbContext.Entry(user).Property(u => u.RoleId).CurrentValue = request.RoleId.Value;

        if (request.IsActive.HasValue)
            dbContext.Entry(user).Property(u => u.IsActive).CurrentValue = request.IsActive.Value;

        await dbContext.SaveChangesAsync();

        return new AuthResponse
        {
            UserId = user.Id,
            Username = user.Username,
            Email = user.Email,
            MobileNumber = user.MobileNumber,
            RoleId = user.RoleId,
            Success = true,
            Message = "User Update Successfully"
        };
    }
    public async Task<bool> SetPassword(int userId, string hashedPassword)
    {
        var user = new User { Id = userId };
        dbContext.Users.Attach(user);

        user.EncPassword = hashedPassword;
        dbContext.Entry(user).Property(u => u.EncPassword).IsModified = true;

        await dbContext.SaveChangesAsync();
        return true;
    }
    public async Task<bool> ResetPassword(User user)
    {
        dbContext.Users.Attach(user);

        dbContext.Entry(user).Property(u => u.EncPassword).IsModified = true;
        dbContext.Entry(user).Property(u => u.ResetPassToken).IsModified = true;
        dbContext.Entry(user).Property(u => u.ResetPassTokenExpiry).IsModified = true;

        await dbContext.SaveChangesAsync();
        return true;
    }

    public async Task<bool> DeleteAsync(int id)
    {
        var affected = await dbContext.Users
            .Where(u => u.Id == id)
            .ExecuteDeleteAsync();

        return affected > 0;
    }
    public async Task<bool> DeleteManyAsync(int[] ids)
    {
        var affected = await dbContext.Users
            .Where(u => ids.Contains(u.Id))
            .ExecuteDeleteAsync();

        return affected > 0;
    }
}
