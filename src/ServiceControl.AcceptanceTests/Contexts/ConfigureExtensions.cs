namespace ServiceBus.Management.AcceptanceTests.Contexts
{
    using System.Collections.Generic;
    using System.IO;
    using System.Reflection;
    using NServiceBus;
    using NServiceBus.AcceptanceTesting;
    using NUnit.Framework;
    using TransportIntegration;

    public static class ConfigureExtensions
    {
        public static string GetOrNull(this IDictionary<string, string> dictionary, string key)
        {
            if (!dictionary.ContainsKey(key))
            {
                return null;
            }

            return dictionary[key];
        }

        public static void DefineTransport(this BusConfiguration config, ITransportIntegration transport)
        {
            var transportDefinitionType = transport.Type;
            var connectionString = transport.ConnectionString;

            if (connectionString == null)
            {
                config.UseTransport(transportDefinitionType);
                return;
            }

            config.UseTransport(transportDefinitionType).ConnectionString(connectionString);
        }

        public static EndpointConfigurationBuilder WithHeartbeats(this EndpointConfigurationBuilder builder)
        {
            var heartbeatsAssembly = Assembly.LoadFile(
                Path.Combine(
                    TestContext.CurrentContext.TestDirectory,
                    "ServiceControl.Plugin.Nsb5.Heartbeat.dll"));

            return builder.IncludeAssembly(heartbeatsAssembly);
        }

        public static EndpointConfigurationBuilder WithSagaAudit(this EndpointConfigurationBuilder builder)
        {
            var sagaAuditAssembly = Assembly.LoadFile(
                Path.Combine(
                    TestContext.CurrentContext.TestDirectory,
                    "ServiceControl.Plugin.Nsb5.SagaAudit.dll"));

            return builder.IncludeAssembly(sagaAuditAssembly);
        }
    }
}