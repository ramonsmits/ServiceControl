namespace Particular.HealthMonitoring.Uptime
{
    using System;
    using Particular.HealthMonitoring.Uptime.Api;
    using ServiceControl.Contracts.Operations;

    class EndpointInstanceMonitor
    {
        EndpointInstanceId id;
        HeartbeatStatus status;
        bool monitored;

        public EndpointInstanceMonitor(EndpointInstanceId endpointInstanceId)
        {
            id = endpointInstanceId;
        }

        public bool TryApply(IHeartbeatEvent @event)
        {
            return @event.TryApply<MonitoringEnabledForEndpoint>(Apply)
                   || @event.TryApply<MonitoringDisabledForEndpoint>(Apply)
                   || @event.TryApply<HeartbeatingEndpointDetected>(Apply)
                   || @event.TryApply<EndpointHeartbeatRestored>(Apply)
                   || @event.TryApply<EndpointFailedToHeartbeat>(Apply);
        }

        public IHeartbeatEvent EnableMonitoring()
        {
            return Apply(new MonitoringEnabledForEndpoint
            {
                EndpointInstanceId = id.UniqueId,
                Endpoint = Convert(id)
            });
        }

        public IHeartbeatEvent DisableMonitoring()
        {
            return Apply(new MonitoringDisabledForEndpoint
            {
                EndpointInstanceId = id.UniqueId,
                Endpoint = Convert(id)
            });
        }

        public IHeartbeatEvent StartTrackingEndpoint()
        {
            return Apply(new EndpointDetected
            {
                EndpointInstanceId = id.UniqueId,
                Endpoint = Convert(id)
            });
        }

        public IHeartbeatEvent UpdateStatus(HeartbeatStatus newStatus, DateTime? latestTimestamp, DateTime currentTime)
        {
            if (newStatus == status)
            {
                return null;
            }

            if (newStatus == HeartbeatStatus.Alive)
            {
                if (status == HeartbeatStatus.Unknown)
                {
                    // NOTE: If an endpoint starts randomly sending heartbeats we monitor it by default
                    // NOTE: This means we'll start monitoring endpoints sending heartbeats after a restart
                    return Apply(new HeartbeatingEndpointDetected
                    {
                        EndpointInstanceId = id.UniqueId,
                        Endpoint = Convert(id),
                        DetectedAt = latestTimestamp ?? DateTime.UtcNow
                    });
                }

                if (status == HeartbeatStatus.Dead && monitored)
                {
                    return Apply(new EndpointHeartbeatRestored
                    {
                        EndpointInstanceId = id.UniqueId,
                        Endpoint = Convert(id),
                        RestoredAt = latestTimestamp ?? DateTime.UtcNow
                    });
                }
            }
            else if (newStatus == HeartbeatStatus.Dead && monitored)
            {
                return Apply(new EndpointFailedToHeartbeat
                {
                    EndpointInstanceId = id.UniqueId,
                    Endpoint = Convert(id),
                    DetectedAt = currentTime,
                    LastReceivedAt = latestTimestamp ?? DateTime.MinValue
                });
            }

            return null;
        }

        IHeartbeatEvent Apply(EndpointDetected @event)
        {
            return @event;
        }

        IHeartbeatEvent Apply(HeartbeatingEndpointDetected @event)
        {
            monitored = true;
            status = HeartbeatStatus.Alive;
            return @event;
        }

        IHeartbeatEvent Apply(EndpointHeartbeatRestored @event)
        {
            monitored = true;
            status = HeartbeatStatus.Alive;
            return @event;
        }

        IHeartbeatEvent Apply(EndpointFailedToHeartbeat @event)
        {
            monitored = true;
            status = HeartbeatStatus.Dead;
            return @event;
        }

        IHeartbeatEvent Apply(MonitoringEnabledForEndpoint @event)
        {
            monitored = true;
            return @event;
        }

        IHeartbeatEvent Apply(MonitoringDisabledForEndpoint @event)
        {
            monitored = false;
            return @event;
        }

        static EndpointDetails Convert(EndpointInstanceId endpointInstanceId)
        {
            return new EndpointDetails
            {
                Host = endpointInstanceId.HostName,
                HostId = endpointInstanceId.HostGuid,
                Name = endpointInstanceId.LogicalName
            };
        }
    }
}