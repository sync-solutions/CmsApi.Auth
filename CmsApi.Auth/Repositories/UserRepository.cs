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
}
