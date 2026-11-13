using Microsoft.EntityFrameworkCore;
using VulnerableShop;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddHttpClient();
builder.Services.AddDbContext<ShopDb>(options => options.UseSqlite("Data Source=shop.db"));
builder.Services.AddScoped<VulnerableShop.Vulnerable.IProductSearch, VulnerableShop.Vulnerable.SqlProductSearch>();
builder.Services.AddScoped<VulnerableShop.Fixed.IProductSearch, VulnerableShop.Fixed.SqlProductSearch>();

var app = builder.Build();
app.MapControllers();
app.Run();
