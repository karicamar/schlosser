namespace Schlosser.Tests;

public class SqlInjectionTests
{
    private const string Db = """
        public class User { public int Id { get; set; } public string Name { get; set; } = ""; }
        public class AppDb : Microsoft.EntityFrameworkCore.DbContext
        {
            public Microsoft.EntityFrameworkCore.DbSet<User> Users => Set<User>();
        }
        """;

    [Fact]
    public Task Concatenated_action_parameter_in_command_text()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using Microsoft.Data.Sqlite;

            public class UsersController : ControllerBase
            {
                public IActionResult Search(string name)
                {
                    using var connection = new SqliteConnection("Data Source=app.db");
                    var command = connection.CreateCommand();
                    command.CommandText = {|SL001:"SELECT * FROM Users WHERE Name = '" + name + "'"|};
                    return Ok(command.ExecuteScalar());
                }
            }
            """);
    }

    [Fact]
    public Task Parameterized_command_is_fine()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using Microsoft.Data.Sqlite;

            public class UsersController : ControllerBase
            {
                public IActionResult Search(string name)
                {
                    using var connection = new SqliteConnection("Data Source=app.db");
                    var command = connection.CreateCommand();
                    command.CommandText = "SELECT * FROM Users WHERE Name = @name";
                    command.Parameters.AddWithValue("@name", name);
                    return Ok(command.ExecuteScalar());
                }
            }
            """);
    }

    [Fact]
    public Task Numbers_dates_and_guids_cannot_carry_sql()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using Microsoft.Data.Sqlite;

            public enum Status { Open, Closed }

            public class OrdersController : ControllerBase
            {
                public IActionResult Get(int id, Guid tenant, DateTime since, Status status, bool archived, long? page)
                {
                    using var connection = new SqliteConnection("Data Source=app.db");
                    var command = connection.CreateCommand();
                    command.CommandText = $"SELECT * FROM Orders WHERE Id = {id} AND Tenant = '{tenant}' AND Created > '{since:O}' " +
                                          $"AND Status = {(int)status} AND Archived = {(archived ? 1 : 0)} LIMIT {page ?? 1}";
                    return Ok(command.ExecuteScalar());
                }
            }
            """);
    }

    [Fact]
    public Task Parsing_to_a_number_removes_the_taint()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using Microsoft.Data.Sqlite;

            public class OrdersController : ControllerBase
            {
                public IActionResult Get(string id)
                {
                    var number = int.Parse(id);
                    using var connection = new SqliteConnection("Data Source=app.db");
                    var command = new SqliteCommand("SELECT * FROM Orders WHERE Id = " + number, connection);
                    return Ok(command.ExecuteScalar());
                }
            }
            """);
    }

    [Fact]
    public Task Taint_survives_locals_string_methods_and_format()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using Microsoft.Data.Sqlite;

            public class UsersController : ControllerBase
            {
                public IActionResult Search(string name)
                {
                    var trimmed = name.Trim().ToLowerInvariant();
                    var filter = string.Format("Name = '{0}'", trimmed);
                    var sql = "SELECT * FROM Users WHERE " + filter;
                    using var connection = new SqliteConnection("Data Source=app.db");
                    var command = new SqliteCommand({|SL001:sql|}, connection);
                    return Ok(command.ExecuteScalar());
                }
            }
            """);
    }

    [Fact]
    public Task StringBuilder_and_compound_assignment()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using System.Text;
            using Microsoft.Data.Sqlite;

            public class UsersController : ControllerBase
            {
                public IActionResult Search(string name, string city)
                {
                    var builder = new StringBuilder("SELECT * FROM Users WHERE 1 = 1");
                    if (name != null) builder.Append(" AND Name = '").Append(name).Append("'");
                    var sql = "SELECT * FROM Users WHERE 1 = 1";
                    sql += " AND City = '" + city + "'";
                    using var connection = new SqliteConnection("Data Source=app.db");
                    var first = new SqliteCommand({|SL001:builder.ToString()|}, connection);
                    var second = new SqliteCommand({|SL001:sql|}, connection);
                    return Ok();
                }
            }
            """);
    }

    [Fact]
    public Task Request_properties_are_sources()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using Microsoft.Data.Sqlite;

            public class UsersController : ControllerBase
            {
                public IActionResult FromQuery()
                {
                    string name = Request.Query["name"]!;
                    var agent = Request.Headers["User-Agent"].ToString();
                    Request.Cookies.TryGetValue("tenant", out var tenant);
                    using var connection = new SqliteConnection("Data Source=app.db");
                    var a = new SqliteCommand({|SL001:"SELECT 1 FROM Users WHERE Name = '" + name + "'"|}, connection);
                    var b = new SqliteCommand({|SL001:$"INSERT INTO Visits (Agent) VALUES ('{agent}')"|}, connection);
                    var c = new SqliteCommand({|SL001:"SELECT 1 FROM Tenants WHERE Id = '" + tenant + "'"|}, connection);
                    return Ok();
                }
            }
            """);
    }

    [Fact]
    public Task Model_properties_are_tainted()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using Microsoft.Data.Sqlite;

            public class LoginRequest { public string Username { get; set; } = ""; public int Age { get; set; } }

            [ApiController]
            public class AuthController : ControllerBase
            {
                [HttpPost]
                public IActionResult Login([FromBody] LoginRequest request)
                {
                    using var connection = new SqliteConnection("Data Source=app.db");
                    var byName = new SqliteCommand({|SL001:"SELECT * FROM Users WHERE Name = '" + request.Username + "'"|}, connection);
                    var byAge = new SqliteCommand("SELECT * FROM Users WHERE Age = " + request.Age, connection);
                    return Ok();
                }
            }
            """);
    }

    [Fact]
    public Task Ef_core_raw_sql()
    {
        return Verify.Analyzer<InjectionAnalyzer>(Db + """

            public class UsersController : ControllerBase
            {
                private readonly AppDb _db;
                public UsersController(AppDb db) => _db = db;

                public IActionResult Search(string name)
                {
                    var bad = Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.FromSqlRaw(_db.Users, {|SL001:$"SELECT * FROM Users WHERE Name = '{name}'"|}).ToList();
                    var alsoBad = Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions.ExecuteSqlRaw(_db.Database, {|SL001:"DELETE FROM Users WHERE Name = '" + name + "'"|});
                    // parameters of FromSqlRaw and interpolated SQL are sent as parameters
                    var good = Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.FromSqlRaw(_db.Users, "SELECT * FROM Users WHERE Name = {0}", name).ToList();
                    var alsoGood = Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.FromSqlInterpolated(_db.Users, $"SELECT * FROM Users WHERE Name = {name}").ToList();
                    var linq = _db.Users.Where(u => u.Name == name).ToList();
                    return Ok();
                }
            }
            """);
    }

    [Fact]
    public Task Dapper()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using Dapper;
            using Microsoft.Data.Sqlite;

            public class UsersController : ControllerBase
            {
                public IActionResult Search(string name, string sort)
                {
                    using var connection = new SqliteConnection("Data Source=app.db");
                    var bad = connection.Query<string>({|SL001:"SELECT Name FROM Users WHERE Name LIKE '%" + name + "%'"|});
                    var good = connection.Query<string>("SELECT Name FROM Users WHERE Name LIKE @pattern", new { pattern = "%" + name + "%" });
                    // ORDER BY cannot be a parameter: an allow-list is the fix
                    var column = sort == "city" ? "City" : "Name";
                    var sorted = connection.Query<string>($"SELECT Name FROM Users ORDER BY {column}");
                    return Ok();
                }
            }
            """);
    }

    [Fact]
    public Task Follows_the_value_through_an_interface_into_the_repository()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using Microsoft.Data.Sqlite;

            public interface IUserRepository { object? Find(string name); }

            public class UsersController : ControllerBase
            {
                private readonly IUserRepository _users;
                public UsersController(IUserRepository users) => _users = users;

                public IActionResult Search(string name) => Ok(_users.Find(name.Trim()));
            }

            public class SqlUserRepository : IUserRepository
            {
                public object? Find(string name) => Run("SELECT * FROM Users WHERE Name = '" + name + "'");

                private static object? Run(string sql)
                {
                    using var connection = new SqliteConnection("Data Source=app.db");
                    var command = new SqliteCommand({|SL001:sql|}, connection);
                    return command.ExecuteScalar();
                }
            }
            """);
    }

    [Fact]
    public async Task The_message_names_the_source_and_the_call_path()
    {
        var diagnostics = await Verify.Diagnostics<InjectionAnalyzer>("""
            using Microsoft.Data.Sqlite;

            public class UsersController : ControllerBase
            {
                private readonly UserService _service = new();
                public IActionResult Search(string name) => Ok(_service.Find(name));
            }

            public class UserService
            {
                private readonly UserRepository _repository = new();
                public object? Find(string name) => _repository.ByName(name);
            }

            public class UserRepository
            {
                public object? ByName(string name)
                {
                    using var connection = new SqliteConnection("Data Source=app.db");
                    var command = new SqliteCommand("SELECT * FROM Users WHERE Name = '" + name + "'", connection);
                    return command.ExecuteScalar();
                }
            }
            """);

        var diagnostic = Assert.Single(diagnostics);
        Assert.Equal("SL001", diagnostic.Id);
        Assert.Equal(
            "SQL injection: parameter 'name' of UsersController.Search flows into new SqliteCommand " +
            "(call path: UsersController.Search → UserService.Find → UserRepository.ByName). " +
            "Pass the value as a parameter instead of building the SQL text.",
            diagnostic.GetMessage());
        Assert.Single(diagnostic.AdditionalLocations); // the call in the controller
    }

    [Fact]
    public Task Without_a_request_path_built_sql_is_only_a_note()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using Microsoft.Data.Sqlite;

            public class ReportJob
            {
                private const string Table = "Orders";
                private static readonly string Schema = "dbo";

                public object? Count(string customer, int year)
                {
                    using var connection = new SqliteConnection("Data Source=app.db");
                    var constant = new SqliteCommand("SELECT COUNT(*) FROM " + Table + " WHERE Year = " + year, connection);
                    var schema = new SqliteCommand($"SELECT COUNT(*) FROM {Schema}.{Table}", connection);
                    var built = new SqliteCommand({|SL002:"SELECT COUNT(*) FROM Orders WHERE Customer = '" + customer + "'"|}, connection);
                    return built.ExecuteScalar();
                }
            }
            """);
    }

    [Fact]
    public Task A_wrapper_that_passes_sql_through_is_not_reported_itself()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using Microsoft.Data.Sqlite;

            public class Database
            {
                public object? Scalar(string sql)
                {
                    using var connection = new SqliteConnection("Data Source=app.db");
                    return new SqliteCommand(sql, connection).ExecuteScalar();
                }

                public object? CountUsers() => Scalar("SELECT COUNT(*) FROM Users");
            }
            """);
    }

    [Fact]
    public Task Minimal_api_lambda_parameters_are_sources_but_services_are_not()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using Dapper;
            using Microsoft.Data.Sqlite;

            public class ProductService { public string TableName { get; set; } = "Products"; }
            public record SearchRequest(string Term);

            public static class Endpoints
            {
                public static void Map(WebApplication app)
                {
                    app.MapGet("/products", (string term, SqliteConnection connection) =>
                        connection.Query<string>({|SL001:"SELECT Name FROM Products WHERE Name LIKE '" + term + "%'"|}));

                    app.MapPost("/products/search", (SearchRequest request, SqliteConnection connection) =>
                        connection.Query<string>({|SL001:$"SELECT Name FROM Products WHERE Name = '{request.Term}'"|}));

                    app.MapGet("/products/count", (ProductService service, SqliteConnection connection) =>
                        connection.Query<int>({|SL002:"SELECT COUNT(*) FROM " + service.TableName|}));
                }
            }
            """);
    }

    [Fact]
    public Task Minimal_api_method_group_handler()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using Dapper;
            using Microsoft.Data.Sqlite;

            public static class Endpoints
            {
                public static void Map(WebApplication app) => app.MapGet("/products", Search);

                private static IEnumerable<string> Search(string term, SqliteConnection connection) =>
                    connection.Query<string>({|SL001:"SELECT Name FROM Products WHERE Name LIKE '" + term + "%'"|});
            }
            """);
    }

    [Fact]
    public Task Razor_page_bound_property_and_handler_parameter()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using Dapper;
            using Microsoft.AspNetCore.Mvc.RazorPages;
            using Microsoft.Data.Sqlite;

            public class SearchModel : PageModel
            {
                [BindProperty(SupportsGet = true)]
                public string Term { get; set; } = "";

                public string Title { get; set; } = "Search";

                public void OnGet(string category)
                {
                    using var connection = new SqliteConnection("Data Source=app.db");
                    connection.Query<string>({|SL001:"SELECT Name FROM Products WHERE Name = '" + Term + "'"|});
                    connection.Query<string>({|SL001:"SELECT Name FROM Products WHERE Category = '" + category + "'"|});
                }
            }
            """);
    }

    [Fact]
    public Task Services_injected_into_actions_are_not_sources()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using Dapper;
            using Microsoft.Data.Sqlite;

            public interface ITenantProvider { string Table { get; } }

            public class ReportsController : ControllerBase
            {
                public IActionResult Count([FromServices] ITenantProvider tenants, CancellationToken cancellationToken)
                {
                    using var connection = new SqliteConnection("Data Source=app.db");
                    return Ok(connection.Query<int>({|SL002:"SELECT COUNT(*) FROM " + tenants.Table|}));
                }

                [NonAction]
                public IEnumerable<string> Helper(string table)
                {
                    using var connection = new SqliteConnection("Data Source=app.db");
                    return connection.Query<string>({|SL002:"SELECT Name FROM " + table|});
                }
            }
            """);
    }
}
