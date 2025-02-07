using Emerald.Api.Configuration;
using Emerald.Api.Data;
using Emerald.Api.Endpoints;
using Emerald.Api.Extensions;
using Emerald.Api.Interfaces;
using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApi((options =>
{
    options.AddDocumentTransformer<BearerSecuritySchemeTransformer>();
}));

builder.Services.AddProblemDetails();

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("SqliteConnection")));

builder.Services.AddIdentityConfig(builder.Configuration);
builder.Services.Configure<AppSettings>(builder.Configuration.GetSection(nameof(AppSettings)));
builder.Services.AddTransient<IEmailSender, FakeEmailSender>();

var app = builder.Build();

app.MapOpenApi();
app.MapScalarApiReference(option =>
{
    option
        .WithTitle("Auth API")
        .WithTheme(ScalarTheme.BluePlanet)
        .WithDownloadButton(true)
        .WithDefaultHttpClient(ScalarTarget.CSharp, ScalarClient.HttpClient);
});

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

// Map endpoint groups
app.MapAuthEndpoints();
app.MapUserEndpoints();
app.MapEmailEndpoints();

// Common endpoints
app.MapGet("/auth/check", () =>
    Results.Ok(new { Success = true, Message = "API is running" }));

app.MapGet("/auth/token-validation", () =>
    Results.Ok(new { Success = true, Message = "Token is valid" }))
    .RequireAuthorization();

app.Run();
