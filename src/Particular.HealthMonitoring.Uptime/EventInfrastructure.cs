namespace Particular.HealthMonitoring.Uptime
{
    using System.Threading.Tasks;
    using Particular.HealthMonitoring.Uptime.Api;
    using ServiceControl.Infrastructure.DomainEvents;

    class EventInfrastructure
    {
        StatisticsViewModel statsViewModel;
        EndpointsViewModel endpoinsViewModel;
        IDomainEvents domainEvents;
        IPersistEndpointUptimeInformation persister;

        public EventInfrastructure(IDomainEvents domainEvents, IPersistEndpointUptimeInformation persister, 
            StatisticsViewModel statsViewModel, EndpointsViewModel endpoinsViewModel)
        {
            this.domainEvents = domainEvents;
            this.persister = persister;
            this.statsViewModel = statsViewModel;
            this.endpoinsViewModel = endpoinsViewModel;
        }
        
        public Task Publish(params IHeartbeatEvent[] events)
        {
            foreach (var @event in events)
            {
                statsViewModel.Handle(@event);
                endpoinsViewModel.Handle(@event);
                domainEvents.Raise(@event);
            }

            return persister.Store(events);
        }
    }
}