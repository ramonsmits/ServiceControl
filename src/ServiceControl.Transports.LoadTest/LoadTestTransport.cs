using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Threading.Tasks;
using NServiceBus;
using NServiceBus.Performance.TimeToBeReceived;
using NServiceBus.Routing;
using NServiceBus.Settings;
using NServiceBus.Transport;


class Options
{
    public int Rate { get; set; } = int.Parse(ConfigurationManager.AppSettings["RateLimit"]);
}

public class LoadTestTransport :
    TransportDefinition
{
    internal static Options Options = new Options();
    public override bool RequiresConnectionString => true;
    public override string ExampleConnectionStringForErrorMessage { get; } = string.Empty;

    public override TransportInfrastructure Initialize(SettingsHolder settings, string connectionString)
    {
        return new LoadTestTransportInfrastructure();
    }
}

public class LoadTestTransportInfrastructure :
    TransportInfrastructure
{
    public override TransportReceiveInfrastructure ConfigureReceiveInfrastructure() =>
        new TransportReceiveInfrastructure(
            messagePumpFactory: () => new MessagePump(),
            queueCreatorFactory: () => new QueueCreator(),
            preStartupCheck: () => Task.FromResult(StartupCheckResult.Success));

    public override TransportSendInfrastructure ConfigureSendInfrastructure() =>
        new TransportSendInfrastructure(
            dispatcherFactory: () => new Dispatcher(),
            preStartupCheck: () => Task.FromResult(StartupCheckResult.Success));

    public override TransportSubscriptionInfrastructure ConfigureSubscriptionInfrastructure() => throw new NotImplementedException();

    public override EndpointInstance BindToLocalEndpoint(EndpointInstance instance) => instance;

    public override string ToTransportAddress(LogicalAddress logicalAddress)
    {
        var endpointInstance = logicalAddress.EndpointInstance;
        var discriminator = endpointInstance.Discriminator ?? "";
        var qualifier = logicalAddress.Qualifier ?? "";
        return Path.Combine(endpointInstance.Endpoint, discriminator, qualifier);
    }

    public override IEnumerable<Type> DeliveryConstraints
    {
        get
        {
            yield return typeof(DiscardIfNotReceivedBefore);
        }
    }

    public override TransportTransactionMode TransactionMode => TransportTransactionMode.None;

    public override OutboundRoutingPolicy OutboundRoutingPolicy => new OutboundRoutingPolicy(sends: OutboundRoutingType.Unicast, publishes: OutboundRoutingType.Unicast, replies: OutboundRoutingType.Unicast);
}