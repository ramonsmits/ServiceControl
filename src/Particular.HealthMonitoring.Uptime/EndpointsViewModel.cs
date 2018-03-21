namespace Particular.HealthMonitoring.Uptime
{
    using System;
    using System.Collections.Concurrent;
    using System.Linq;
    using Particular.HealthMonitoring.Uptime.Api;
    using ServiceControl.Infrastructure.DomainEvents;

    class EndpointsViewModel : BaseViewModel
    {
        ConcurrentDictionary<Guid, EndpointsView> cache = new ConcurrentDictionary<Guid, EndpointsView>();

        public bool Handle(IDomainEvent @event)
        {
            return TryHandle<HeartbeatingEndpointDetected>(@event, Handle)
                   || TryHandle<EndpointHeartbeatRestored>(@event, Handle)
                   || TryHandle<EndpointFailedToHeartbeat>(@event, Handle)
                   || TryHandle<MonitoringDisabledForEndpoint>(@event, Handle)
                   || TryHandle<MonitoringEnabledForEndpoint>(@event, Handle);
        }

        void Handle(HeartbeatingEndpointDetected domainEvent)
        {
            var newValue = NewViewValue(domainEvent, Status.Beating, domainEvent.DetectedAt);
            cache.AddOrUpdate(domainEvent.EndpointInstanceId, newValue, (_, __) => newValue);
        }

        void Handle(EndpointHeartbeatRestored domainEvent)
        {
            var newValue = NewViewValue(domainEvent, Status.Beating, domainEvent.RestoredAt);
            cache.AddOrUpdate(domainEvent.EndpointInstanceId, newValue, (_, __) => newValue);
        }

        void Handle(EndpointFailedToHeartbeat domainEvent)
        {
            var newValue = NewViewValue(domainEvent, Status.Dead, domainEvent.LastReceivedAt);
            cache.AddOrUpdate(domainEvent.EndpointInstanceId, newValue, (_, __) => newValue);
        }

        void Handle(MonitoringEnabledForEndpoint domainEvent)
        {
            var newValue = new EndpointsView
            {
                Id = domainEvent.EndpointInstanceId,
                Name = domainEvent.Endpoint.Name,
                HostDisplayName = domainEvent.Endpoint.Host,
                Monitored = true,
                MonitorHeartbeat = true,
                HeartbeatInformation = new HeartbeatInformation
                {
                    ReportedStatus = Status.Dead,
                    LastReportAt = DateTime.MinValue
                }
            };

            cache.AddOrUpdate(domainEvent.EndpointInstanceId, newValue, (_, old) => new EndpointsView
            {
                Id = old.Id,
                Name = old.Name,
                HostDisplayName = old.HostDisplayName,
                Monitored = true,
                MonitorHeartbeat = true,
                HeartbeatInformation = old.HeartbeatInformation
            });
        }

        void Handle(MonitoringDisabledForEndpoint domainEvent)
        {
            var newValue = new EndpointsView
            {
                Id = domainEvent.EndpointInstanceId,
                Name = domainEvent.Endpoint.Name,
                HostDisplayName = domainEvent.Endpoint.Host,
                Monitored = false,
                MonitorHeartbeat = false,
                HeartbeatInformation = new HeartbeatInformation
                {
                    ReportedStatus = Status.Dead,
                    LastReportAt = DateTime.MinValue
                }
            };

            cache.AddOrUpdate(domainEvent.EndpointInstanceId, newValue, (_, old) => new EndpointsView
            {
                Id = old.Id,
                Name = old.Name,
                HostDisplayName = old.HostDisplayName,
                Monitored = false,
                MonitorHeartbeat = false,
                HeartbeatInformation = old.HeartbeatInformation
            });
        }

        static EndpointsView NewViewValue(IHeartbeatEvent domainEvent, Status status, DateTime lastReportAt)
        {
            return new EndpointsView
            {
                Id = domainEvent.EndpointInstanceId,
                Name = domainEvent.Endpoint.Name,
                HostDisplayName = domainEvent.Endpoint.Host,
                Monitored = true,
                MonitorHeartbeat = true,
                HeartbeatInformation = new HeartbeatInformation
                {
                    ReportedStatus = status,
                    LastReportAt = lastReportAt
                }
            };
        }

        public EndpointsView[] GetEndpoints()
        {
            return cache.Values.ToArray();
        }
    }
}