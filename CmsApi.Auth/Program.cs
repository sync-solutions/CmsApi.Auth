using CmsApi.Auth.Data;
using CmsApi.Auth.Helpers;
using CmsApi.Auth.Models;
using CmsApi.Auth.Repositories;
using CmsApi.Auth.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using StackExchange.Redis;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Configuration
var jwtSection = builder.Configuration.GetSection("Jwt");
var redisConfig = builder.Configuration.GetSection("Redis");
var keyBytes = Encoding.UTF8.GetBytes(jwtSection["Key"]!);

// Services
builder.Services.Configure<JwtSettings>(jwtSection);
builder.Services.AddControllers();
builder.Services.AddDbContext<AuthDbContext>(opt =>
    opt.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddSingleton<IConnectionMultiplexer>(_ =>
{
    var options = new ConfigurationOptions
    {
        EndPoints = { { redisConfig["Host"]!, int.Parse(redisConfig["Port"]!) } },
        User = redisConfig["User"],
        Password = redisConfig["Password"]
    };
    return ConnectionMultiplexer.Connect(options);
});

builder.Services.AddScoped(sp => sp.GetRequiredService<IConnectionMultiplexer>().GetDatabase());
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

// Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = "SmartScheme";
})
.AddPolicyScheme("SmartScheme", "JWT or Cookie", options =>
{
    options.ForwardDefaultSelector = context =>
    {
        return context.Request.Headers.ContainsKey("Authorization")
            ? JwtBearerDefaults.AuthenticationScheme
            : CookieAuthenticationDefaults.AuthenticationScheme;
    };
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
.AddGoogle(GoogleDefaults.AuthenticationScheme, options =>
{
    options.ClientId = builder.Configuration["Authentication:Google:ClientId"];
    options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"];
    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.CallbackPath = "/signin-google";
    options.Scope.Add("openid");
    options.Scope.Add("email");
    options.Scope.Add("profile");
    options.Scope.Add("https://www.googleapis.com/auth/user.phonenumbers.read");
    options.ClaimActions.MapJsonKey("email", "email");
    options.ClaimActions.MapJsonKey("name", "name");
    options.ClaimActions.MapJsonKey("phonenumber", "phoneNumber");
    options.Events.OnCreatingTicket = async ctx =>
    {
        var identity = (ClaimsIdentity)ctx.Principal.Identity!;
        var userJson = ctx.User;

        if (userJson.TryGetProperty("email", out var emailElement) && emailElement.ValueKind == JsonValueKind.String)
            identity.AddClaim(new Claim(ClaimTypes.Email, emailElement.GetString()!));

        if (userJson.TryGetProperty("name", out var nameElement) && nameElement.ValueKind == JsonValueKind.String)
            identity.AddClaim(new Claim(ClaimTypes.Name, nameElement.GetString()!));

        if (userJson.TryGetProperty("phoneNumber", out var phoneElement) && phoneElement.ValueKind == JsonValueKind.String)
            identity.AddClaim(new Claim("phonenumber", phoneElement.GetString()!));

        await ctx.HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            ctx.Principal,
            ctx.Properties);
    };
})
.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, opts =>
{
    opts.RequireHttpsMetadata = true;
    opts.SaveToken = true;

    opts.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = jwtSection["Issuer"],
        ValidateAudience = true,
        ValidAudience = jwtSection["Audience"],
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromMinutes(2),
        NameClaimType = ClaimTypes.NameIdentifier,
        RoleClaimType = ClaimTypes.Role
    };

    opts.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = ctx =>
        {
            Console.WriteLine($"JWT authentication failed: {ctx.Exception.Message}");
            return Task.CompletedTask;
        },
        OnTokenValidated = ctx =>
        {
            Console.WriteLine($"JWT validated for user: {ctx.Principal.Identity?.Name}");
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

            await ctx.Response.WriteAsync(JsonSerializer.Serialize(payload, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            }));
        }
    };
});

builder.Services.AddAuthorization();

// Swagger
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

// Redis connectivity check
var mux = app.Services.GetRequiredService<IConnectionMultiplexer>();
Console.WriteLine($"Redis connected at startup: {mux.IsConnected}");

// Global exception handler
app.UseExceptionHandler(errApp =>
{
    errApp.Run(async context =>
    {
        var ex = context.Features.Get<IExceptionHandlerPathFeature>()?.Error;
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

// Middleware
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
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();
