using Dapper;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace VulnerableShop.Fixed;

public interface IProductSearch
{
    IEnumerable<Product> ByName(string term);
}

[ApiController, Route("fixed/products")]
public class ProductsController(IProductSearch search, ShopDb db) : ControllerBase
{
    [HttpGet("search")]
    public IActionResult Search(string term) => Ok(search.ByName(term.Trim()));

    // Every hole of an interpolated SQL string becomes a parameter
    [HttpGet("category")]
    public IActionResult ByCategory(string category) =>
        Ok(db.Products.FromSqlInterpolated($"SELECT * FROM Products WHERE Category = {category}").ToList());

    // ORDER BY cannot be a parameter: choose from an allow-list
    [HttpGet("sorted")]
    public IActionResult Sorted(string column)
    {
        var orderBy = column switch
        {
            "price" => "Price",
            "category" => "Category",
            _ => "Name",
        };
        return Ok(db.Database.GetDbConnection().Query<Product>("SELECT * FROM Products ORDER BY " + orderBy));
    }
}

public class SqlProductSearch(ShopDb db) : IProductSearch
{
    public IEnumerable<Product> ByName(string term) =>
        db.Database.GetDbConnection().Query<Product>("SELECT * FROM Products WHERE Name LIKE @pattern", new { pattern = "%" + term + "%" });
}
