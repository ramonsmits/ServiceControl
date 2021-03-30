// unset

using System.Threading.Tasks;
using NServiceBus.Extensibility;
using NServiceBus.Transport;

class Dispatcher :
    IDispatchMessages
{
    public Task Dispatch(TransportOperations outgoingMessages, TransportTransaction transaction, ContextBag context) => Task.CompletedTask;
}