#nullable enable
namespace ServiceControl.Infrastructure.Tests.Auth.Rbac;

using System;
using System.Collections.Generic;
using NUnit.Framework;
using ServiceControl.Infrastructure.Auth.Rbac;

/// <summary>
/// Unit tests for <see cref="RbacPolicyToCasbinCompiler"/>.
/// Verifies that an <see cref="RbacPolicy"/> is correctly compiled to Casbin policy lines
/// that the S4 variant feeds into a <c>TextAdapter</c> at startup.
/// </summary>
[TestFixture]
public class RbacPolicyToCasbinCompilerTests
{
    /// <summary>
    /// A policy with one role, one allow permission (unrestricted), and one scoped deny
    /// must produce the expected p-lines and g-lines.
    /// </summary>
    [Test]
    public void Compiles_one_role_with_allow_and_scoped_deny_to_expected_lines()
    {
        var policy = new RbacPolicy(
            SchemaVersion: 1,
            Roles: new Dictionary<string, RbacRole>
            {
                ["sc-operator"] = new RbacRole(
                    Name: "sc-operator",
                    Bindings: ["role:sc-operator"],
                    Permissions:
                    [
                        // unrestricted allow — perm applies to every resource
                        new PermissionGrant("messages:retry", Scope: null),
                        // scoped allow + deny — allow Sales.*, deny Sales.Secret.*
                        new PermissionGrant("messages:view", Scope: new ResourceScopeSpec(
                            Allow: ["Sales.*"],
                            Deny: ["Sales.Secret.*"]))
                    ])
            });

        var lines = RbacPolicyToCasbinCompiler.Compile(policy);

        // Unrestricted allow: resource pattern is "*"
        Assert.That(lines, Has.Member("p, role:sc-operator, messages:retry, *, allow"),
            "Unrestricted permission must produce an allow line with wildcard resource");

        // Scoped allow: one line per allow pattern
        Assert.That(lines, Has.Member("p, role:sc-operator, messages:view, Sales.*, allow"),
            "Scoped allow must produce an allow line for each allow pattern");

        // Scoped deny: one line per deny pattern
        Assert.That(lines, Has.Member("p, role:sc-operator, messages:view, Sales.Secret.*, deny"),
            "Scoped deny must produce a deny line for each deny pattern");

        // Role binding: g, <binding>, role:<rolename> — the binding IS already "role:sc-operator"
        // so we expect: g, role:sc-operator, role:sc-operator
        Assert.That(lines, Has.Member("g, role:sc-operator, role:sc-operator"),
            "Each role binding must produce a g-line mapping the binding to the role's policy subject");
    }

    /// <summary>
    /// The wildcard role (<c>*</c>) must produce an unrestricted allow line for every resource.
    /// </summary>
    [Test]
    public void Wildcard_permission_compiles_to_allow_star_for_every_resource()
    {
        var policy = new RbacPolicy(
            SchemaVersion: 1,
            Roles: new Dictionary<string, RbacRole>
            {
                ["sc-admin"] = new RbacRole(
                    Name: "sc-admin",
                    Bindings: ["role:sc-admin"],
                    Permissions:
                    [
                        new PermissionGrant("*", Scope: null)
                    ])
            });

        var lines = RbacPolicyToCasbinCompiler.Compile(policy);

        // Wildcard "*" permission with no scope → p, role:sc-admin, *, *, allow
        Assert.That(lines, Has.Member("p, role:sc-admin, *, *, allow"),
            "Wildcard '*' permission must produce an allow line with wildcard permission and resource");
    }

    /// <summary>
    /// Multiple bindings on one role must each produce a g-line.
    /// </summary>
    [Test]
    public void Multiple_bindings_each_produce_a_g_line()
    {
        var policy = new RbacPolicy(
            SchemaVersion: 1,
            Roles: new Dictionary<string, RbacRole>
            {
                ["sc-viewer"] = new RbacRole(
                    Name: "sc-viewer",
                    Bindings: ["role:sc-viewer", "group:/viewers"],
                    Permissions:
                    [
                        new PermissionGrant("messages:view", Scope: null)
                    ])
            });

        var lines = RbacPolicyToCasbinCompiler.Compile(policy);

        Assert.That(lines, Has.Member("g, role:sc-viewer, role:sc-viewer"),
            "First binding must have a g-line");

        Assert.That(lines, Has.Member("g, group:/viewers, role:sc-viewer"),
            "Second binding must also have a g-line");
    }
}
