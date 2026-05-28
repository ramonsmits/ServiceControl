namespace ServiceControl.Infrastructure.Tests.Auth.Rbac;

using System;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using ServiceControl.AcceptanceTesting.Auth;
using ServiceControl.Infrastructure.Auth.Rbac;

[TestFixture]
public class AuthorizationAuditLogTests
{
    [Test]
    public void Decision_allow_emits_one_log_entry_on_the_audit_category()
    {
        var provider = new RecordingLoggerProvider();
        var factory = LoggerFactory.Create(b => b.AddProvider(provider));
        var auditLog = new AuthorizationAuditLog(factory);

        auditLog.Decision("alice-sub-001", "Alice Smith", "messages:retry", "acme.sales", allowed: true, reason: "role:sc-operator matched");

        var entries = provider.EntriesFor("ServiceControl.Audit");
        Assert.That(entries, Has.Count.EqualTo(1));
        Assert.That(entries[0].Message, Does.Contain("alice-sub-001"));
        Assert.That(entries[0].Message, Does.Contain("Alice Smith"));
        Assert.That(entries[0].Message, Does.Contain("messages:retry"));
        Assert.That(entries[0].Message, Does.Contain("allow"));
        Assert.That(entries[0].Level, Is.EqualTo(LogLevel.Information));
    }

    [Test]
    public void Decision_deny_emits_one_log_entry_on_the_audit_category()
    {
        var provider = new RecordingLoggerProvider();
        var factory = LoggerFactory.Create(b => b.AddProvider(provider));
        var auditLog = new AuthorizationAuditLog(factory);

        auditLog.Decision("bob-sub-002", "Bob Jones", "messages:retry", null, allowed: false, reason: "no matching role");

        var entries = provider.EntriesFor("ServiceControl.Audit");
        Assert.That(entries, Has.Count.EqualTo(1));
        Assert.That(entries[0].Message, Does.Contain("bob-sub-002"));
        Assert.That(entries[0].Message, Does.Contain("Bob Jones"));
        Assert.That(entries[0].Message, Does.Contain("messages:retry"));
        Assert.That(entries[0].Message, Does.Contain("deny"));
        Assert.That(entries[0].Level, Is.EqualTo(LogLevel.Information));
    }

    [Test]
    public void Decision_does_not_appear_in_other_categories()
    {
        var provider = new RecordingLoggerProvider();
        var factory = LoggerFactory.Create(b => b.AddProvider(provider));
        var auditLog = new AuthorizationAuditLog(factory);

        auditLog.Decision("carol-sub-003", "Carol White", "endpoints:view", null, allowed: true, reason: "role:sc-viewer matched");

        var otherEntries = provider.EntriesFor("ServiceControl.SomeOtherCategory");
        Assert.That(otherEntries, Is.Empty);
    }

    [Test]
    public void Multiple_decisions_accumulate_in_order()
    {
        var provider = new RecordingLoggerProvider();
        var factory = LoggerFactory.Create(b => b.AddProvider(provider));
        var auditLog = new AuthorizationAuditLog(factory);

        auditLog.Decision("alice-sub-001", "alice", "messages:view", null, allowed: true, "role matched");
        auditLog.Decision("alice-sub-001", "alice", "messages:retry", "acme.finance", allowed: false, "out of scope");

        var entries = provider.EntriesFor("ServiceControl.Audit");
        Assert.That(entries, Has.Count.EqualTo(2));
        Assert.That(entries[0].Message, Does.Contain("allow"));
        Assert.That(entries[1].Message, Does.Contain("deny"));
    }

    [Test]
    public void Decision_throws_when_subjectId_is_null()
    {
        var provider = new RecordingLoggerProvider();
        var factory = LoggerFactory.Create(b => b.AddProvider(provider));
        var auditLog = new AuthorizationAuditLog(factory);

        Assert.That(
            () => auditLog.Decision(null!, "Alice Smith", "messages:retry", null, allowed: true, reason: "test"),
            Throws.InstanceOf<ArgumentException>());
    }

    [Test]
    public void Decision_throws_when_subjectId_is_empty()
    {
        var provider = new RecordingLoggerProvider();
        var factory = LoggerFactory.Create(b => b.AddProvider(provider));
        var auditLog = new AuthorizationAuditLog(factory);

        Assert.That(
            () => auditLog.Decision("", "Alice Smith", "messages:retry", null, allowed: true, reason: "test"),
            Throws.InstanceOf<ArgumentException>());
    }

    [Test]
    public void Decision_throws_when_subjectName_is_null()
    {
        var provider = new RecordingLoggerProvider();
        var factory = LoggerFactory.Create(b => b.AddProvider(provider));
        var auditLog = new AuthorizationAuditLog(factory);

        Assert.That(
            () => auditLog.Decision("alice-sub-001", null!, "messages:retry", null, allowed: true, reason: "test"),
            Throws.InstanceOf<ArgumentException>());
    }

    [Test]
    public void Decision_throws_when_subjectName_is_empty()
    {
        var provider = new RecordingLoggerProvider();
        var factory = LoggerFactory.Create(b => b.AddProvider(provider));
        var auditLog = new AuthorizationAuditLog(factory);

        Assert.That(
            () => auditLog.Decision("alice-sub-001", "", "messages:retry", null, allowed: true, reason: "test"),
            Throws.InstanceOf<ArgumentException>());
    }
}
