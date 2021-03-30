using System;
using System.Threading.Tasks;
using ServiceControl.Transports;

class QueueLengthProvider : IProvideQueueLength
{
    public void Initialize(string connectionString, Action<QueueLengthEntry[], EndpointToQueueMapping> store)
    {
    }

    public void TrackEndpointInputQueue(EndpointToQueueMapping queueToTrack)
    {
    }

    public Task Start()
    {
        return Task.CompletedTask;
    }

    public Task Stop()
    {
        return Task.CompletedTask;
    }
}