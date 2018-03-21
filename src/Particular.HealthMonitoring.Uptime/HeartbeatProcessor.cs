namespace Particular.HealthMonitoring.Uptime
{
    using System.Threading.Tasks;
    using Particular.Operations.Heartbeats.Api;

    class HeartbeatProcessor : IProcessHeartbeats
    {
        EndpointInstanceMonitoring monitoring;
        EventInfrastructure eventInfrastructure;

        public HeartbeatProcessor(EndpointInstanceMonitoring monitoring, EventInfrastructure eventInfrastructure)
        {
            this.monitoring = monitoring;
            this.eventInfrastructure = eventInfrastructure;
        }

        public Task Handle(RegisterEndpointStartup endpointStartup)
        {
            var @event = monitoring.StartTrackingEndpoint(endpointStartup.Endpoint, endpointStartup.Host, endpointStartup.HostId);
            return eventInfrastructure.Publish(@event);
        }

        public Task Handle(EndpointHeartbeat heartbeat)
        {
            monitoring.RecordHeartbeat(heartbeat.EndpointName, heartbeat.Host, heartbeat.HostId, heartbeat.ExecutedAt);
            return Task.FromResult(0);
        }
    }
}