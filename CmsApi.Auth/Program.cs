using CmsApi.Auth.Data;
using CmsApi.Auth.Helpers;
using CmsApi.Auth.Models;
using CmsApi.Auth.Repositories;
using CmsApi.Auth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using StackExchange.Redis;
using System.Net;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

var redisConfig = builder.Configuration.GetSection("Redis");

builder.Services.Configure<JwtSettings>(
    builder.Configuration.GetSection("Jwt"));

builder.Services.AddControllers();
builder.Services.AddDbContext<AuthDbContext>(opt =>
    opt.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddSingleton<IConnectionMultiplexer>(_ =>
{
    var options = new ConfigurationOptions
    {
        EndPoints = { { "redis-13781.c326.us-east-1-3.ec2.redns.redis-cloud.com", 13781 } },
        User = "default",
        Password = "htptVdgvbk3MiBIBf1VrYtf0ww9sNM9v"
    };
    return ConnectionMultiplexer.Connect(options);
});

builder.Services.AddScoped(sp =>
{
    var muxer = sp.GetRequiredService<IConnectionMultiplexer>();
    return muxer.GetDatabase();
});

builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IJwtService, JwtService>();
builder.Services.AddScoped<IEmailService, SmtpEmailService>();
builder.Services.AddScoped<SessionService>();
builder.Services.AddScoped<UserRepository>();
builder.Services.AddScoped<TokenRepository>();
builder.Services.AddScoped<ApikeyRepository>();
builder.Services.AddScoped<SessionRepository>();
builder.Services.AddScoped<SessionHelper>();
builder.Services.AddHttpContextAccessor();

var jwtSection = builder.Configuration.GetSection("Jwt");
var keyBytes = Encoding.UTF8.GetBytes(jwtSection["Key"]!);

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opts =>
    {
        opts.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            //ValidIssuer = jwtSection["Issuer"],
            ValidateAudience = false,
            //ValidAudiences = new[]
            //{
            //    jwtSection["Audience"],  // e.g. https://localhost:44323
            //    jwtSection["Issuer"]     // e.g. https://localhost:5195
            //},
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
            ValidateLifetime = true,
            NameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
            RoleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
        };
        opts.RequireHttpsMetadata = true;
        opts.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = ctx =>
            {
                Console.WriteLine("JWT auth failed: " + ctx.Exception.Message);
                return Task.CompletedTask;
            },
            OnTokenValidated = ctx =>
            {
                Console.WriteLine("JWT validated for: " + ctx.Principal.Identity?.Name);
                return Task.CompletedTask;
            },
            OnChallenge = async ctx =>
            {
                ctx.HandleResponse();

                ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                ctx.Response.ContentType = "application/json";

                var payload = new AuthResponse
                {
                    Success = false,
                    Message = "Unauthorized – invalid or missing token",
                    StatusCode = StatusCodes.Status401Unauthorized
                };

                await ctx.Response.WriteAsync(
                    JsonSerializer.Serialize(payload, new JsonSerializerOptions
                    {
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                    })
                );
            }
        };
    });

builder.Services.AddAuthorization();

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Auth API", Version = "v1" });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter ‘Bearer {token}’"
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id   = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();
var mux = app.Services.GetRequiredService<IConnectionMultiplexer>();
Console.WriteLine($"Redis connected at startup: {mux.IsConnected}");
app.UseExceptionHandler(errApp =>
{
    errApp.Run(async context =>
    {
        var ex = context.Features
                      .Get<IExceptionHandlerPathFeature>()?
                      .Error;
        var payload = new AuthResponse
        {
            Success = false,
            Message = ex?.Message ?? "Unexpected server error"
        };

        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        context.Response.ContentType = "application/json";
        await JsonSerializer.SerializeAsync(context.Response.Body, payload);
    });
});

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Auth API v1");
        c.RoutePrefix = string.Empty;
    });
}

app.UseHttpsRedirection();
app.UseRouting();
app.Use(async (context, next) =>
{
    var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
    await next();
});

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.Run();
