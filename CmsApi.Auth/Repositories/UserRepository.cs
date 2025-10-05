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
    public async Task Update(User user)
    {
        dbContext.Users.Update(user);
        await dbContext.SaveChangesAsync();
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
    public async Task<AuthResponse?> Update(int userId, UserEditRequest request)
    {
        var user = await dbContext.Users.FindAsync(userId);
        if (user == null)
            return new AuthResponse { Success = false, Message = "User not found." };

        dbContext.Users.Attach(user);

        if (!string.IsNullOrWhiteSpace(request.Name))
        {
            user.Name = request.Name;
            dbContext.Entry(user).Property(u => u.Name).IsModified = true;
        }

        if (!string.IsNullOrWhiteSpace(request.MobileNumber))
        {
            user.MobileNumber = request.MobileNumber;
            dbContext.Entry(user).Property(u => u.MobileNumber).IsModified = true;
        }

        if (!string.IsNullOrWhiteSpace(request.Email))
        {
            user.Email = request.Email;
            dbContext.Entry(user).Property(u => u.Email).IsModified = true;
        }

        if (request.RoleId.HasValue)
        {
            user.RoleId = request.RoleId.Value;
            dbContext.Entry(user).Property(u => u.RoleId).IsModified = true;
        }

        if (request.IsActive.HasValue)
        {
            user.IsActive = request.IsActive.Value;
            dbContext.Entry(user).Property(u => u.IsActive).IsModified = true;
        }

        await dbContext.SaveChangesAsync();
        return new AuthResponse
        {
            UserId = user.Id,
            Username = user.Username,
            Email = user.Email,
            MobileNumber = user.MobileNumber,
            RoleId = user.RoleId,
            Success = true
        };
    }
}
