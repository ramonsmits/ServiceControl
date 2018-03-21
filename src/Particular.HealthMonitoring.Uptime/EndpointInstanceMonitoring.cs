namespace Particular.HealthMonitoring.Uptime
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Linq;
    using Particular.HealthMonitoring.Uptime.Api;

    class EndpointInstanceMonitoring
    {
        ConcurrentDictionary<Guid, EndpointInstanceMonitor> endpoints = new ConcurrentDictionary<Guid, EndpointInstanceMonitor>();
        ConcurrentDictionary<EndpointInstanceId, HeartbeatMonitor> heartbeats = new ConcurrentDictionary<EndpointInstanceId, HeartbeatMonitor>();

        public void Initialize(IEnumerable<IHeartbeatEvent> events)
        {
            foreach (var @event in events)
            {
                var monitor = GetOrCreateMonitor(@event.Endpoint.Name, @event.Endpoint.Host, @event.Endpoint.HostId);
                monitor.TryApply(@event);
            }
        }

        public void RecordHeartbeat(string name, string host, Guid hostId, DateTime timestamp)
        {
            var endpointInstanceId = new EndpointInstanceId(name, host, hostId);

            var heartbeatMonitor = heartbeats.GetOrAdd(endpointInstanceId, id => new HeartbeatMonitor());
            heartbeatMonitor.MarkAlive(timestamp);
        }

        public IHeartbeatEvent StartTrackingEndpoint(string name, string host, Guid hostId)
        {
            var monitor = GetOrCreateMonitor(name, host, hostId);
            return monitor.StartTrackingEndpoint();
        }

        public IHeartbeatEvent[] CheckEndpoints(DateTime threshold, DateTime currentTime)
        {
            return heartbeats
                .Select(entry => CheckEndpoint(threshold, currentTime, entry))
                .Where(update => update != null)
                .ToArray();
        }

        IHeartbeatEvent CheckEndpoint(DateTime threshold, DateTime currentTime, KeyValuePair<EndpointInstanceId, HeartbeatMonitor> entry)
        {
            var instanceId = entry.Key;
            var monitor = GetOrCreateMonitor(instanceId.LogicalName, instanceId.HostName, instanceId.HostGuid);
            var newState = entry.Value.MarkDeadIfOlderThan(threshold);
            return monitor.UpdateStatus(newState.Status, newState.Timestamp, currentTime);
        }

        EndpointInstanceMonitor GetOrCreateMonitor(string name, string host, Guid hostId)
        {
            var endpointInstanceId = new EndpointInstanceId(name, host, hostId);

            return endpoints.GetOrAdd(endpointInstanceId.UniqueId, id => new EndpointInstanceMonitor(endpointInstanceId));
        }

        public IHeartbeatEvent EnableMonitoring(Guid id)
        {
            EndpointInstanceMonitor monitor;
            return !endpoints.TryGetValue(id, out monitor) ? null : monitor.EnableMonitoring();
        }

        public IHeartbeatEvent DisableMonitoring(Guid id)
        {
            EndpointInstanceMonitor monitor;
            return !endpoints.TryGetValue(id, out monitor) ? null : monitor.DisableMonitoring();
        }
    }
}