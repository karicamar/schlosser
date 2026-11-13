using Dapper;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace VulnerableShop.Vulnerable;

public interface IProductSearch
{
    IEnumerable<Product> ByName(string term);
}

[ApiController, Route("vulnerable/products")]
public class ProductsController(IProductSearch search, ShopDb db) : ControllerBase
{
    // The controller looks harmless: the SQL is two calls away, behind an interface
    [HttpGet("search")]
    public IActionResult Search(string term) => Ok(search.ByName(term.Trim()));

    [HttpGet("category")]
    public IActionResult ByCategory(string category) =>
        Ok(db.Products.FromSqlRaw($"SELECT * FROM Products WHERE Category = '{category}'").ToList());

    [HttpGet("sorted")]
    public IActionResult Sorted(string column) =>
        Ok(db.Database.GetDbConnection().Query<Product>("SELECT * FROM Products ORDER BY " + column));
}

public class SqlProductSearch(ShopDb db) : IProductSearch
{
    public IEnumerable<Product> ByName(string term) => Run("SELECT * FROM Products WHERE Name LIKE '%" + term + "%'");

    private IEnumerable<Product> Run(string sql) => db.Database.GetDbConnection().Query<Product>(sql);
}
