#nullable enable
namespace ServiceControl.UnitTests.Infrastructure.Auth.S3;

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using NUnit.Framework;
using ServiceControl.Infrastructure.Auth.Rbac;
using ServiceControl.Infrastructure.WebApi.Auth;
using ServiceControl.MessageFailures;
using ServiceControl.Contracts.Operations;

/// <summary>
/// Unit tests for the S3 resource-based authorization handler.
/// TDD: these tests should fail before the implementation is in place.
/// </summary>
[TestFixture]
public class PermissionRequirementTests
{
    const string OperatorPolicyYaml = """
        schemaVersion: 1
        roles:
          sc-operator:
            bindings: [ "role:sc-operator" ]
            permissions:
              - "messages:retry"
              - "messages:view"
        """;

    const string ScopedPolicyYaml = """
        schemaVersion: 1
        roles:
          sales-operator:
            bindings: [ "role:sales-operator" ]
            permissions:
              - permission: "messages:retry"
                scope: { allow: ["acme.sales.*"], deny: [] }
        """;

    const string ViewerPolicyYaml = """
        schemaVersion: 1
        roles:
          sc-viewer:
            bindings: [ "role:sc-viewer" ]
            permissions:
              - "messages:view"
        """;

    // Helper: build a FailedMessage with a given queue address
    static FailedMessage BuildFailedMessage(string queueAddress) => new()
    {
        Id = "FailedMessages/1",
        UniqueMessageId = "msg-1",
        Status = FailedMessageStatus.Unresolved,
        ProcessingAttempts =
        [
            new FailedMessage.ProcessingAttempt
            {
                AttemptedAt = DateTime.UtcNow,
                FailureDetails = new FailureDetails
                {
                    AddressOfFailingEndpoint = queueAddress
                }
            }
        ]
    };

    static ClaimsPrincipal PrincipalWithRole(string role)
    {
        var identity = new ClaimsIdentity("Bearer");
        identity.AddClaim(new Claim("role", role));
        return new ClaimsPrincipal(identity);
    }

    // --- PermissionRequirement tests ---

    [Test]
    public void PermissionRequirement_exposes_permission_string()
    {
        var req = new PermissionRequirement("messages:retry");
        Assert.That(req.Permission, Is.EqualTo("messages:retry"));
    }

    [Test]
    public void PermissionRequirement_implements_IAuthorizationRequirement()
    {
        var req = new PermissionRequirement("messages:retry");
        Assert.That(req, Is.InstanceOf<IAuthorizationRequirement>());
    }

    // --- FailedMessageAuthorizationHandler tests ---

    [Test]
    public async Task Handler_succeeds_when_user_is_in_scope()
    {
        var evaluator = new PermissionEvaluator(() => RbacPolicyLoader.Parse(OperatorPolicyYaml));
        var auditLog = new FakeAuditLog();
        var handler = new FailedMessageAuthorizationHandler(evaluator, auditLog);

        var user = PrincipalWithRole("sc-operator");
        var message = BuildFailedMessage("acme.sales.orders");
        var requirement = new PermissionRequirement("messages:retry");

        var context = new AuthorizationHandlerContext(
            [requirement],
            user,
            message);

        await handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.True, "Should succeed for operator with messages:retry");
    }

    [Test]
    public async Task Handler_fails_when_user_lacks_permission()
    {
        var evaluator = new PermissionEvaluator(() => RbacPolicyLoader.Parse(ViewerPolicyYaml));
        var auditLog = new FakeAuditLog();
        var handler = new FailedMessageAuthorizationHandler(evaluator, auditLog);

        var user = PrincipalWithRole("sc-viewer");
        var message = BuildFailedMessage("acme.sales.orders");
        var requirement = new PermissionRequirement("messages:retry");

        var context = new AuthorizationHandlerContext(
            [requirement],
            user,
            message);

        await handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False, "Viewer lacks messages:retry");
    }

    [Test]
    public async Task Handler_fails_when_user_has_permission_but_resource_out_of_scope()
    {
        var evaluator = new PermissionEvaluator(() => RbacPolicyLoader.Parse(ScopedPolicyYaml));
        var auditLog = new FakeAuditLog();
        var handler = new FailedMessageAuthorizationHandler(evaluator, auditLog);

        var user = PrincipalWithRole("sales-operator");
        // Out of scope: sales-operator can only retry acme.sales.*
        var message = BuildFailedMessage("acme.finance.ap");
        var requirement = new PermissionRequirement("messages:retry");

        var context = new AuthorizationHandlerContext(
            [requirement],
            user,
            message);

        await handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False, "sales-operator must not retry acme.finance.ap");
    }

    [Test]
    public async Task Handler_succeeds_when_user_has_permission_and_resource_in_scope()
    {
        var evaluator = new PermissionEvaluator(() => RbacPolicyLoader.Parse(ScopedPolicyYaml));
        var auditLog = new FakeAuditLog();
        var handler = new FailedMessageAuthorizationHandler(evaluator, auditLog);

        var user = PrincipalWithRole("sales-operator");
        var message = BuildFailedMessage("acme.sales.orders");
        var requirement = new PermissionRequirement("messages:retry");

        var context = new AuthorizationHandlerContext(
            [requirement],
            user,
            message);

        await handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.True, "sales-operator should retry acme.sales.orders");
    }

    [Test]
    public async Task Handler_logs_allow_decision()
    {
        var evaluator = new PermissionEvaluator(() => RbacPolicyLoader.Parse(OperatorPolicyYaml));
        var auditLog = new FakeAuditLog();
        var handler = new FailedMessageAuthorizationHandler(evaluator, auditLog);

        var user = PrincipalWithRole("sc-operator");
        var message = BuildFailedMessage("acme.sales.orders");
        var requirement = new PermissionRequirement("messages:retry");

        var context = new AuthorizationHandlerContext([requirement], user, message);
        await handler.HandleAsync(context);

        Assert.That(auditLog.Decisions, Has.Count.EqualTo(1));
        Assert.That(auditLog.Decisions[0].Allowed, Is.True);
        Assert.That(auditLog.Decisions[0].Permission, Is.EqualTo("messages:retry"));
        Assert.That(auditLog.Decisions[0].Resource, Is.EqualTo("acme.sales.orders"));
    }

    [Test]
    public async Task Handler_logs_deny_decision_when_out_of_scope()
    {
        var evaluator = new PermissionEvaluator(() => RbacPolicyLoader.Parse(ScopedPolicyYaml));
        var auditLog = new FakeAuditLog();
        var handler = new FailedMessageAuthorizationHandler(evaluator, auditLog);

        var user = PrincipalWithRole("sales-operator");
        var message = BuildFailedMessage("acme.finance.ap");
        var requirement = new PermissionRequirement("messages:retry");

        var context = new AuthorizationHandlerContext([requirement], user, message);
        await handler.HandleAsync(context);

        Assert.That(auditLog.Decisions, Has.Count.EqualTo(1));
        Assert.That(auditLog.Decisions[0].Allowed, Is.False);
        Assert.That(auditLog.Decisions[0].Permission, Is.EqualTo("messages:retry"));
    }

    [Test]
    public async Task Handler_logs_deny_decision_when_missing_permission()
    {
        var evaluator = new PermissionEvaluator(() => RbacPolicyLoader.Parse(ViewerPolicyYaml));
        var auditLog = new FakeAuditLog();
        var handler = new FailedMessageAuthorizationHandler(evaluator, auditLog);

        var user = PrincipalWithRole("sc-viewer");
        var message = BuildFailedMessage("acme.sales.orders");
        var requirement = new PermissionRequirement("messages:retry");

        var context = new AuthorizationHandlerContext([requirement], user, message);
        await handler.HandleAsync(context);

        Assert.That(auditLog.Decisions, Has.Count.EqualTo(1));
        Assert.That(auditLog.Decisions[0].Allowed, Is.False);
        Assert.That(auditLog.Decisions[0].Permission, Is.EqualTo("messages:retry"));
    }

    // --- Fake helpers ---

    sealed class FakeAuditLog : IAuthorizationAuditLog
    {
        public List<DecisionRecord> Decisions { get; } = [];

        public void Decision(string subject, string permission, string? resource, bool allowed, string reason)
        {
            Decisions.Add(new DecisionRecord(subject, permission, resource, allowed, reason));
        }

        public record DecisionRecord(string Subject, string Permission, string? Resource, bool Allowed, string Reason);
    }
}
