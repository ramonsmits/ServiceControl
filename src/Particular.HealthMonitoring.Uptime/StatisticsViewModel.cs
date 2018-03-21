namespace Particular.HealthMonitoring.Uptime
{
    using System;
    using System.Linq;
    using System.Collections.Concurrent;
    using Particular.HealthMonitoring.Uptime.Api;
    using ServiceControl.Infrastructure.DomainEvents;

    class StatisticsViewModel : BaseViewModel
    {
        ConcurrentDictionary<Guid, bool> statistics = new ConcurrentDictionary<Guid, bool>();
        IDomainEvents domainEvents;

        public StatisticsViewModel(IDomainEvents domainEvents)
        {
            this.domainEvents = domainEvents;
        }

        public bool Handle(IDomainEvent @event)
        {
            return TryHandle<HeartbeatingEndpointDetected>(@event, Handle)
                   || TryHandle<EndpointHeartbeatRestored>(@event, Handle)
                   || TryHandle<EndpointFailedToHeartbeat>(@event, Handle);
        }

        void Handle(HeartbeatingEndpointDetected domainEvent)
        {
            statistics.AddOrUpdate(domainEvent.EndpointInstanceId, true, (_, __) => true);
            RaiseChangedEvent();
        }


        void Handle(EndpointHeartbeatRestored domainEvent)
        {
            statistics.AddOrUpdate(domainEvent.EndpointInstanceId, true, (_, __) => true);
            RaiseChangedEvent();
        }

        void Handle(EndpointFailedToHeartbeat domainEvent)
        {
            statistics.AddOrUpdate(domainEvent.EndpointInstanceId, false, (_, __) => true);
            RaiseChangedEvent();
        }

        void RaiseChangedEvent()
        {
            domainEvents.Raise(new HeartbeatsUpdated
            {
                Active = statistics.Values.Count(v => v),
                Failing = statistics.Values.Count(v => !v),
                RaisedAt = DateTime.UtcNow
            });
        }

        public EndpointMonitoringStats GetStats()
        {
            return new EndpointMonitoringStats
            {
                Active = statistics.Values.Count(v => v),
                Failing = statistics.Values.Count(v => !v),
            };
        }
    }
}