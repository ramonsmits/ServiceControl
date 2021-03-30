using System.Threading.Tasks;
using NServiceBus.Transport;

class QueueCreator :
    ICreateQueues
{
    public Task CreateQueueIfNecessary(QueueBindings queueBindings, string identity) => Task.CompletedTask;
}