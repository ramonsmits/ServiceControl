namespace ServiceControl.Transports.LoadTest
{
    using System;
    using NServiceBus;
    using NServiceBus.Raw;

    public class LoadTestTransportCustomization : TransportCustomization
    {
        public override void CustomizeSendOnlyEndpoint(EndpointConfiguration endpointConfiguration, TransportSettings transportSettings)
        {
            CustomizeEndpoint(endpointConfiguration);
        }

        public override void CustomizeServiceControlEndpoint(EndpointConfiguration endpointConfiguration, TransportSettings transportSettings)
        {
            CustomizeEndpoint(endpointConfiguration);
        }

        public override void CustomizeRawSendOnlyEndpoint(RawEndpointConfiguration endpointConfiguration, TransportSettings transportSettings)
        {
            CustomizeRawEndpoint(endpointConfiguration);
        }

        public override void CustomizeForErrorIngestion(RawEndpointConfiguration endpointConfiguration, TransportSettings transportSettings)
        {
            CustomizeRawEndpoint(endpointConfiguration);
        }

        public override void CustomizeForAuditIngestion(RawEndpointConfiguration endpointConfiguration, TransportSettings transportSettings)
        {
            CustomizeRawEndpoint(endpointConfiguration);
        }

        public override void CustomizeForMonitoringIngestion(EndpointConfiguration endpointConfiguration, TransportSettings transportSettings)
        {
            CustomizeEndpoint(endpointConfiguration);
        }

        public override void CustomizeForReturnToSenderIngestion(RawEndpointConfiguration endpointConfiguration, TransportSettings transportSettings)
        {
            CustomizeRawEndpoint(endpointConfiguration);
        }

        public override IProvideQueueLength CreateQueueLengthProvider()
        {
            return new QueueLengthProvider();
        }

        static void CustomizeEndpoint(EndpointConfiguration endpointConfig, TransportTransactionMode transportTransactionMode = TransportTransactionMode.None)
        {
            var transport = endpointConfig.UseTransport<LoadTestTransport>();
            //transport.StorageDirectory(Environment.ExpandEnvironmentVariables(transportSettings.ConnectionString));
            transport.Transactions(transportTransactionMode);
        }

        static void CustomizeRawEndpoint(RawEndpointConfiguration endpointConfig, TransportTransactionMode transportTransactionMode = TransportTransactionMode.None)
        {
            var transport = endpointConfig.UseTransport<LoadTestTransport>();
            //transport.StorageDirectory(Environment.ExpandEnvironmentVariables(transportSettings.ConnectionString));
            transport.Transactions(transportTransactionMode);
        }
    }
}