namespace ServiceControl.AcceptanceTests.Security.Authorization
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Text.Json;
    using System.Threading.Tasks;
    using AcceptanceTesting;
    using AcceptanceTesting.Auth;
    using AcceptanceTesting.OpenIdConnect;
    using Contracts.Operations;
    using MessageFailures;
    using Microsoft.Extensions.DependencyInjection;
    using NServiceBus.AcceptanceTesting;
    using NUnit.Framework;
    using ServiceControl.Operations;
    using ServiceControl.Persistence;

    /// <summary>
    /// Acceptance tests for the R1 scope filter on list endpoints.
    /// A scoped user sees only messages from queues matching their scope; an unrestricted
    /// user sees all messages. Applied to:
    ///   GET api/errors
    ///   GET api/endpoints/{name}/errors
    /// </summary>
    class When_listing_errors_with_scoped_permissions : AcceptanceTest
    {
        const string TestAudience = "api://test-audience";
        const string TestClientId = "test-client-id";
        const string TestApiScopes = "api://test-audience/.default";

        const string SalesQueueAddress = "Sales.OrderHandler@localhost";
        const string FinanceQueueAddress = "Finance.Payments@localhost";

        OpenIdConnectTestConfiguration configuration;
        MockOidcServer mockOidcServer;

        [SetUp]
        public void ConfigureAuth()
        {
            mockOidcServer = new MockOidcServer(audience: TestAudience);
            mockOidcServer.Start();

            configuration = new OpenIdConnectTestConfiguration(ServiceControlInstanceType.Primary)
                .WithConfigurationValidationDisabled()
                .WithAuthenticationEnabled()
                .WithAuthority(mockOidcServer.Authority)
                .WithAudience(TestAudience)
                .WithServicePulseClientId(TestClientId)
                .WithServicePulseApiScopes(TestApiScopes)
                .WithRequireHttpsMetadata(false);
        }

        [TearDown]
        public void CleanupAuth()
        {
            configuration?.Dispose();
            mockOidcServer?.Dispose();
        }

        // -----------------------------------------------------------------------
        // R1: unrestricted viewer sees all messages
        // -----------------------------------------------------------------------

        [Test]
        public async Task Unrestricted_viewer_sees_all_messages()
        {
            var salesId = Guid.NewGuid().ToString("N");
            var financeId = Guid.NewGuid().ToString("N");
            string responseBody = null;

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    await StoreFailedMessage(salesId, SalesQueueAddress);
                    await StoreFailedMessage(financeId, FinanceQueueAddress);

                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-all", ["sc-viewer"]);
                    var response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/errors", token);

                    Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
                    responseBody = await response.Content.ReadAsStringAsync();
                    return true;
                })
                .Run();

            // sc-viewer has unrestricted messages:view → both messages returned
            using var doc = JsonDocument.Parse(responseBody!);
            var ids = doc.RootElement.EnumerateArray()
                .Select(e => e.TryGetProperty("id", out var idProp) ? idProp.GetString() : null)
                .ToList();

            Assert.That(ids, Has.Some.Contains(salesId),
                "Unrestricted viewer should see the Sales message");
            Assert.That(ids, Has.Some.Contains(financeId),
                "Unrestricted viewer should see the Finance message");
        }

        // -----------------------------------------------------------------------
        // R1: paging totals must reflect only in-scope messages (Fix 1 correctness)
        // -----------------------------------------------------------------------

        [Test]
        public async Task Scoped_viewer_paging_total_count_reflects_only_in_scope_messages()
        {
            // Critical regression test for Fix 1: the scope filter must be applied BEFORE
            // .Paging()/.Statistics() so that Total-Count / total headers reflect only messages
            // the caller is allowed to see — not the full DB count minus filtered rows.
            var salesId = Guid.NewGuid().ToString("N");
            var financeId = Guid.NewGuid().ToString("N");
            HttpResponseMessage response = null;

            using var scopedConfig = new ScopedViewerRbacConfiguration();

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    await StoreFailedMessage(salesId, SalesQueueAddress);
                    await StoreFailedMessage(financeId, FinanceQueueAddress);

                    var token = mockOidcServer.GenerateTokenWithRealmRoles("sales-viewer-paging", ["sales-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/errors?page=1&per_page=50", token);

                    Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
                    return true;
                })
                .Run();

            // Total-Count must be 1 (only the Sales message), not 2 (both messages minus filter).
            // Before Fix 1, paging was applied AFTER scope filter so the header showed count=2
            // but the body had 1 row, causing the client to believe there was a second page.
            var totalCount = response.Headers.TryGetValues("Total-Count", out var values)
                ? values.FirstOrDefault()
                : null;

            Assert.That(totalCount, Is.Not.Null, "Total-Count header must be present");
            Assert.That(int.Parse(totalCount!), Is.EqualTo(1),
                "Total-Count must equal the number of in-scope messages (1), not the total DB count (2). " +
                "Failure here means the scope filter is applied post-paging, not pre-paging.");
        }

        // -----------------------------------------------------------------------
        // R1: scoped viewer sees only in-scope messages
        // -----------------------------------------------------------------------

        [Test]
        public async Task Scoped_viewer_sees_only_in_scope_messages()
        {
            var salesId = Guid.NewGuid().ToString("N");
            var financeId = Guid.NewGuid().ToString("N");
            string responseBody = null;

            using var scopedConfig = new ScopedViewerRbacConfiguration();

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    await StoreFailedMessage(salesId, SalesQueueAddress);
                    await StoreFailedMessage(financeId, FinanceQueueAddress);

                    var token = mockOidcServer.GenerateTokenWithRealmRoles("sales-viewer", ["sales-viewer"]);
                    var response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/errors", token);

                    Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
                    responseBody = await response.Content.ReadAsStringAsync();
                    return true;
                })
                .Run();

            // sales-viewer has messages:view scoped to Sales.* → only Sales message returned
            using var doc = JsonDocument.Parse(responseBody!);
            var ids = doc.RootElement.EnumerateArray()
                .Select(e => e.TryGetProperty("id", out var idProp) ? idProp.GetString() : null)
                .ToList();

            Assert.That(ids, Has.Some.Contains(salesId),
                "Scoped viewer should see the in-scope Sales message");
            Assert.That(ids.Any(id => id?.Contains(financeId) == true), Is.False,
                "Scoped viewer must NOT see the out-of-scope Finance message");
        }

        // -----------------------------------------------------------------------
        // R1: scoped viewer on ErrorsByEndpointName sees only in-scope messages
        // -----------------------------------------------------------------------

        [Test]
        public async Task Scoped_viewer_errors_by_endpoint_sees_only_in_scope_messages()
        {
            var salesId = Guid.NewGuid().ToString("N");
            var financeId = Guid.NewGuid().ToString("N");
            string salesBody = null;
            string financeBody = null;

            using var scopedConfig = new ScopedViewerRbacConfiguration();

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    await StoreFailedMessage(salesId, SalesQueueAddress);
                    await StoreFailedMessage(financeId, FinanceQueueAddress);

                    var token = mockOidcServer.GenerateTokenWithRealmRoles("sales-viewer-ep", ["sales-viewer"]);

                    // Sales endpoint — has messages in scope for sales-viewer
                    var salesResponse = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/endpoints/Sales.OrderHandler/errors", token);
                    Assert.That(salesResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
                    salesBody = await salesResponse.Content.ReadAsStringAsync();

                    // Finance endpoint — has messages out of scope for sales-viewer
                    var financeResponse = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/endpoints/Finance.Payments/errors", token);
                    Assert.That(financeResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
                    financeBody = await financeResponse.Content.ReadAsStringAsync();

                    return true;
                })
                .Run();

            using var salesDoc = JsonDocument.Parse(salesBody!);
            var salesIds = salesDoc.RootElement.EnumerateArray()
                .Select(e => e.TryGetProperty("id", out var idProp) ? idProp.GetString() : null)
                .ToList();

            Assert.That(salesIds, Has.Some.Contains(salesId),
                "Scoped viewer should see the in-scope Sales message when querying Sales endpoint");

            using var financeDoc = JsonDocument.Parse(financeBody!);
            var financeIds = financeDoc.RootElement.EnumerateArray()
                .Select(e => e.TryGetProperty("id", out var idProp) ? idProp.GetString() : null)
                .ToList();

            Assert.That(financeIds.Any(id => id?.Contains(financeId) == true), Is.False,
                "Scoped viewer must NOT see out-of-scope Finance message when querying Finance endpoint");
        }

        // -----------------------------------------------------------------------
        // R1: ErrorLastBy returns 403 for out-of-scope message
        // -----------------------------------------------------------------------

        [Test]
        public async Task GetErrorLastBy_scoped_viewer_out_of_scope_receives_403()
        {
            var messageId = Guid.NewGuid().ToString("N");
            HttpResponseMessage response = null;

            using var scopedConfig = new ScopedViewerRbacConfiguration();

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    await StoreFailedMessage(messageId, FinanceQueueAddress);

                    var token = mockOidcServer.GenerateTokenWithRealmRoles("sales-viewer-last", ["sales-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, $"/api/errors/last/{messageId}", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "Scoped viewer should receive 403 for GetErrorLastBy on out-of-scope message");
        }

        [Test]
        public async Task GetErrorLastBy_scoped_viewer_in_scope_receives_200()
        {
            var messageId = Guid.NewGuid().ToString("N");
            HttpResponseMessage response = null;

            using var scopedConfig = new ScopedViewerRbacConfiguration();

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    await StoreFailedMessage(messageId, SalesQueueAddress);

                    var token = mockOidcServer.GenerateTokenWithRealmRoles("sales-viewer-last-ok", ["sales-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, $"/api/errors/last/{messageId}", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "Scoped viewer should receive 200 for GetErrorLastBy on in-scope message");
        }

        // -----------------------------------------------------------------------
        // Helpers
        // -----------------------------------------------------------------------

        Task StoreFailedMessage(string messageId, string queueAddress)
        {
            var dataStore = Services.GetRequiredService<IErrorMessageDataStore>();
            return dataStore.StoreFailedMessagesForTestsOnly(BuildFailedMessage(messageId, queueAddress));
        }

        static FailedMessage BuildFailedMessage(string uniqueMessageId, string queueAddress) =>
            new()
            {
                Id = $"FailedMessages/{uniqueMessageId}",
                UniqueMessageId = uniqueMessageId,
                Status = FailedMessageStatus.Unresolved,
                ProcessingAttempts =
                [
                    new FailedMessage.ProcessingAttempt
                    {
                        AttemptedAt = DateTime.UtcNow,
                        MessageId = uniqueMessageId,
                        FailureDetails = new FailureDetails
                        {
                            AddressOfFailingEndpoint = queueAddress,
                            TimeOfFailure = DateTime.UtcNow
                        },
                        Headers = new Dictionary<string, string>
                        {
                            ["NServiceBus.MessageId"] = uniqueMessageId,
                            ["NServiceBus.FailedQ"] = queueAddress
                        },
                        MessageMetadata = new Dictionary<string, object>
                        {
                            ["MessageId"] = uniqueMessageId,
                            ["MessageType"] = "TestMessage",
                            ["IsSystemMessage"] = false,
                            ["TimeSent"] = DateTime.UtcNow,
                            ["ReceivingEndpoint"] = new EndpointDetails
                            {
                                Name = queueAddress.Split('@')[0],
                                Host = "localhost",
                                HostId = Guid.Empty
                            },
                            ["SendingEndpoint"] = new EndpointDetails
                            {
                                Name = queueAddress.Split('@')[0],
                                Host = "localhost",
                                HostId = Guid.Empty
                            }
                        }
                    }
                ]
            };

        /// <summary>
        /// RBAC config with a "sales-viewer" role scoped to Sales.* queues only.
        /// </summary>
        sealed class ScopedViewerRbacConfiguration : IDisposable
        {
            readonly string tempYamlPath;
            bool disposed;

            public ScopedViewerRbacConfiguration()
            {
                const string scopedYaml = """
                    schemaVersion: 1
                    roles:
                      sc-admin:
                        bindings: [ "role:sc-admin" ]
                        permissions: [ "*" ]
                      sc-operator:
                        bindings: [ "role:sc-operator" ]
                        permissions:
                          - "messages:view"
                          - "messages:retry"
                      sc-viewer:
                        bindings: [ "role:sc-viewer" ]
                        permissions:
                          - "messages:view"
                      sales-viewer:
                        bindings: [ "role:sales-viewer" ]
                        permissions:
                          - permission: "messages:view"
                            scope: { allow: ["Sales.*"] }
                    """;

                tempYamlPath = Path.Combine(Path.GetTempPath(), $"rbac-test-{Guid.NewGuid():N}.yaml");
                File.WriteAllText(tempYamlPath, scopedYaml);
                Environment.SetEnvironmentVariable("SERVICECONTROL_AUTHENTICATION_RBACPOLICYFILE", tempYamlPath);
            }

            public void Dispose()
            {
                if (!disposed)
                {
                    Environment.SetEnvironmentVariable("SERVICECONTROL_AUTHENTICATION_RBACPOLICYFILE", null);
                    if (File.Exists(tempYamlPath))
                    {
                        File.Delete(tempYamlPath);
                    }
                    disposed = true;
                }
            }
        }

        class Context : ScenarioContext;
    }
}
