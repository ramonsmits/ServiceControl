using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NServiceBus;
using NServiceBus.Extensibility;
using NServiceBus.Logging;
using NServiceBus.Transport;

class MessagePump :
    IPushMessages
{
    static ILog log = LogManager.GetLogger<MessagePump>();
    RateGate rateGate = new RateGate(LoadTestTransport.Options.Rate, TimeSpan.FromSeconds(1));

    CancellationToken cancellationToken;
    CancellationTokenSource cancellationTokenSource;
    SemaphoreSlim concurrencyLimiter;
    Task messagePumpTask;
    Func<ErrorContext, Task<ErrorHandleResult>> onError;
    Func<MessageContext, Task> pipeline;
    ConcurrentDictionary<Task, Task> runningReceiveTasks;

    bool dummy;
    bool isError;

    public Task Init(Func<MessageContext, Task> onMessage, Func<ErrorContext, Task<ErrorHandleResult>> onError, CriticalError criticalError, PushSettings settings)
    {
        switch (settings.InputQueue)
        {
            case "audit":
                break;
            case "error":
                isError = true;
                break;
            default:
                dummy = true;
                break;
        }

        this.onError = onError;
        pipeline = onMessage;
        return Task.CompletedTask;
    }

    public void Start(PushRuntimeSettings limitations)
    {
        runningReceiveTasks = new ConcurrentDictionary<Task, Task>();
        concurrencyLimiter = new SemaphoreSlim(limitations.MaxConcurrency);
        cancellationTokenSource = new CancellationTokenSource();

        cancellationToken = cancellationTokenSource.Token;

        if (dummy)
        {
            return;
        }

        messagePumpTask = Task.Factory
            .StartNew(
                function: ProcessMessages,
                cancellationToken: CancellationToken.None,
                creationOptions: TaskCreationOptions.LongRunning,
                scheduler: TaskScheduler.Default)
            .Unwrap();
    }

    public async Task Stop()
    {
        cancellationTokenSource.Cancel();

        var timeoutTask = Task.Delay(TimeSpan.FromSeconds(30), cancellationTokenSource.Token);
        var allTasks = runningReceiveTasks.Values.Concat(new[]
        {
            messagePumpTask
        });
        var finishedTask = await Task.WhenAny(Task.WhenAll(allTasks), timeoutTask)
            .ConfigureAwait(false);

        if (finishedTask.Equals(timeoutTask))
        {
            log.Error("The message pump failed to stop with in the time allowed(30s)");
        }

        concurrencyLimiter.Dispose();
        runningReceiveTasks.Clear();
    }

    [DebuggerNonUserCode]
    async Task ProcessMessages()
    {
        try
        {
            await InnerProcessMessages()
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // For graceful shutdown purposes
        }
        catch (Exception ex)
        {
            log.Error("File Message pump failed", ex);
        }

        if (!cancellationToken.IsCancellationRequested)
        {
            await ProcessMessages()
                .ConfigureAwait(false);
        }
    }

    async Task InnerProcessMessages()
    {
        while (!cancellationTokenSource.IsCancellationRequested)
        {
            await rateGate.WaitAsync(cancellationToken)
                .ConfigureAwait(false);
            await concurrencyLimiter.WaitAsync(cancellationToken)
                .ConfigureAwait(false);

            var task = Task.Run(async () =>
            {
                try
                {
                    var msg = FakeMessageGenerator.Create(isError: isError);
                    var transactionDummy = new TransportTransaction();
                    await HandleMessageWithRetries(msg.id, msg.headers, msg.body, transactionDummy, 1)
                        .ConfigureAwait(false);
                }
                finally
                {
                    concurrencyLimiter.Release();
                }
            }, cancellationToken);

            task.ContinueWith(t =>
                    {
                        runningReceiveTasks.TryRemove(t, out var toBeRemoved);
                    },
                    TaskContinuationOptions.ExecuteSynchronously)
                .Ignore();

            runningReceiveTasks.AddOrUpdate(task, task, (k, v) => task)
                .Ignore();
        }
    }

    async Task<bool> HandleMessageWithRetries(string messageId, Dictionary<string, string> headers, byte[] body, TransportTransaction transportTransaction, int processingAttempt)
    {
        try
        {
            var receiveCancellationTokenSource = new CancellationTokenSource();
            var pushContext = new MessageContext(
                messageId: messageId,
                headers: new Dictionary<string, string>(headers),
                body: body,
                transportTransaction: transportTransaction,
                receiveCancellationTokenSource: receiveCancellationTokenSource,
                context: new ContextBag());

            await pipeline(pushContext)
                .ConfigureAwait(false);

            return !receiveCancellationTokenSource.IsCancellationRequested;
        }
        catch (Exception e)
        {
            var errorContext = new ErrorContext(e, headers, messageId, body, transportTransaction, processingAttempt);
            var errorHandlingResult = await onError(errorContext)
                .ConfigureAwait(false);

            if (errorHandlingResult == ErrorHandleResult.RetryRequired)
            {
                return await HandleMessageWithRetries(messageId, headers, body, transportTransaction, ++processingAttempt)
                    .ConfigureAwait(false);
            }

            return true;
        }
    }
}