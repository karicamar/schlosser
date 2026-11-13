namespace Schlosser.Tests;

public class MassAssignmentTests
{
    private const string Model = """
        using Microsoft.EntityFrameworkCore;

        public class User
        {
            public int Id { get; set; }
            public string Name { get; set; } = "";
            public string Email { get; set; } = "";
            public bool IsAdmin { get; set; }
            public decimal Balance { get; set; }
        }

        public class Note { public int Id { get; set; } public string Text { get; set; } = ""; }

        public class AppDb : DbContext
        {
            public DbSet<User> Users { get; set; } = null!;
            public DbSet<Note> Notes => Set<Note>();
        }

        public class UpdateProfileRequest { public string Name { get; set; } = ""; public string Email { get; set; } = ""; }

        """;

    [Fact]
    public Task Entity_as_action_parameter()
    {
        return Verify.Analyzer<MassAssignmentAnalyzer>(Model + """
            [ApiController]
            public class UsersController : ControllerBase
            {
                [HttpPut("{id}")]
                public IActionResult Update(int id, [FromBody] User {|SL011:user|}) => Ok();

                [HttpPost]
                public IActionResult Create(User {|SL011:user|}, [FromServices] AppDb db) => Ok();

                [HttpPut("profile")]
                public IActionResult UpdateProfile(UpdateProfileRequest request) => Ok();

                [HttpPost("notes")]
                public IActionResult AddNote([Bind("Text")] Note note) => Ok();
            }
            """);
    }

    [Fact]
    public Task Entity_in_minimal_api_and_razor_page()
    {
        return Verify.Analyzer<MassAssignmentAnalyzer>(Model + """
            public class EditModel : Microsoft.AspNetCore.Mvc.RazorPages.PageModel
            {
                public void OnPost(Note {|SL011:note|}) { }
            }

            public static class Endpoints
            {
                public static void Map(WebApplication app)
                {
                    app.MapPost("/users", (User {|SL011:user|}, AppDb db) => Results.Ok());
                    app.MapPut("/profile", (UpdateProfileRequest request, AppDb db) => Results.Ok());
                }
            }
            """);
    }

    [Fact]
    public async Task The_message_names_the_dangerous_properties()
    {
        var diagnostics = await Verify.Diagnostics<MassAssignmentAnalyzer>(Model + """
            public class UsersController : ControllerBase
            {
                public IActionResult Update(User user) => Ok();
            }
            """);

        Assert.Equal(
            "Mass assignment: 'UsersController.Update' binds the request directly to the database entity 'User'. " +
            "The client can set every property, including 'IsAdmin', 'Balance'. Bind a request model with only the allowed fields.",
            Assert.Single(diagnostics).GetMessage());
    }

    [Fact]
    public Task Classes_that_are_not_entities_are_fine()
    {
        return Verify.Analyzer<MassAssignmentAnalyzer>("""
            public class Order { public int Id { get; set; } public bool Paid { get; set; } }

            public class OrdersController : ControllerBase
            {
                public IActionResult Create(Order order) => Ok();
            }
            """);
    }
}
