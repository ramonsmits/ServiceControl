namespace Particular.HealthMonitoring.Uptime
{
    using System;
    using System.Linq;
    using System.Collections.Concurrent;
    using Particular.HealthMonitoring.Uptime.Api;
    using ServiceControl.Infrastructure.DomainEvents;

    class StatisticsViewModel
    {
        ConcurrentDictionary<Guid, bool> statistics = new ConcurrentDictionary<Guid, bool>();

        IDomainEvents domainEvents;

        public StatisticsViewModel(IDomainEvents domainEvents)
        {
            this.domainEvents = domainEvents;
        }

        public bool Handle(IHeartbeatEvent @event)
        {
            return @event.TryApply<HeartbeatingEndpointDetected>(Handle)
                   || @event.TryApply<EndpointHeartbeatRestored>(Handle)
                   || @event.TryApply<EndpointFailedToHeartbeat>(Handle);
        }

        IDomainEvent Handle(HeartbeatingEndpointDetected domainEvent)
        {
            statistics.AddOrUpdate(domainEvent.EndpointInstanceId, true, (_, __) => true);
            RaiseChangedEvent();
            return domainEvent;
        }


        IDomainEvent Handle(EndpointHeartbeatRestored domainEvent)
        {
            statistics.AddOrUpdate(domainEvent.EndpointInstanceId, true, (_, __) => true);
            RaiseChangedEvent();
            return domainEvent;
        }

        IDomainEvent Handle(EndpointFailedToHeartbeat domainEvent)
        {
            statistics.AddOrUpdate(domainEvent.EndpointInstanceId, false, (_, __) => true);
            RaiseChangedEvent();
            return domainEvent;
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

    }
}