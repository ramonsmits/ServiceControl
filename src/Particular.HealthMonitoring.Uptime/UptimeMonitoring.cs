namespace Particular.HealthMonitoring.Uptime
{
    using System.Threading.Tasks;
    using ServiceControl.Api;

    public class UptimeMonitoring : IComponent
    {
        public async Task<ComponentOutput> Initialize(ComponentInput input)
        {
            var monitoring = new EndpointInstanceMonitoring();

            var persister = new EndpointUptimeInformationPersister(input.DocumentStore);
            var events = await persister.Load().ConfigureAwait(false);
            monitoring.Initialize(events);


            var statsViewModel = new StatisticsViewModel(input.DomainEvents);
            var endpointsViewModel = new EndpointsViewModel();

            var eventInfrastructure = new EventInfrastructure(input.DomainEvents, persister, statsViewModel, endpointsViewModel);


            var apiModule = new UptimeApiModule(monitoring, persister, statsViewModel, endpointsViewModel);
            var failureDetector = new HeartbeatFailureDetector(monitoring, eventInfrastructure);
            var heartbeatProcessor = new HeartbeatProcessor(monitoring, eventInfrastructure);
            var endpointDetector = new EndpointDetectingProcessor(monitoring, eventInfrastructure);

            return new Output(endpointDetector, endpointDetector, heartbeatProcessor, apiModule, failureDetector);
        }

        public Task TearDown()
        {
            return Task.FromResult(0);
        }
    }
}