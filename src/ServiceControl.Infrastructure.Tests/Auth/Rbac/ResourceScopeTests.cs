namespace ServiceControl.Infrastructure.Tests.Auth.Rbac;

using NUnit.Framework;
using ServiceControl.Infrastructure.Auth.Rbac;

[TestFixture]
public class ResourceScopeTests
{
    [TestCase("acme.sales", new[] { "acme.sales.*" }, new string[0], ExpectedResult = false)]
    [TestCase("acme.sales.orders", new[] { "acme.sales.*" }, new string[0], ExpectedResult = true)]
    [TestCase("acme.sales.orders", new[] { "*" }, new[] { "acme.sales.*" }, ExpectedResult = false)]
    [TestCase("acme.logistics", new[] { "*" }, new[] { "acme.secret.*" }, ExpectedResult = true)]
    [TestCase("acme.sales", new[] { "acme.sales" }, new string[0], ExpectedResult = true)]
    public bool Permits(string resource, string[] allow, string[] deny)
        => new ResourceScope(allow, deny).Permits(resource);

    [Test]
    public void Permits_typed_QueueResource_delegates_to_name()
    {
        // Verify the typed overload delegates to the string overload without changing semantics.
        var scope = new ResourceScope(["acme.sales.*"], []);
        Assert.That(scope.Permits(new QueueResource("acme.sales.orders")), Is.True);
        Assert.That(scope.Permits(new QueueResource("acme.finance.ap")), Is.False);
    }
}
