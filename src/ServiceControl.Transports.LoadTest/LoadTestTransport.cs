// unset

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NServiceBus;
using NServiceBus.Extensibility;
using NServiceBus.Logging;
using NServiceBus.Performance.TimeToBeReceived;
using NServiceBus.Routing;
using NServiceBus.Settings;
using NServiceBus.Transport;

/// <summary>
/// A transport optimized for development and learning use. DO NOT use in production.
/// </summary>
public class LoadTestTransport : TransportDefinition
{
    /// <summary>
    /// Used by implementations to control if a connection string is necessary.
    /// </summary>
    public override bool RequiresConnectionString => false;

    /// <summary>
    /// Gets an example connection string to use when reporting the lack of a configured connection string to the user.
    /// </summary>
    public override string ExampleConnectionStringForErrorMessage { get; } = "";

    /// <summary>
    /// Initializes all the factories and supported features for the transport. This method is called right before all features
    /// are activated and the settings will be locked down. This means you can use the SettingsHolder both for providing
    /// default capabilities as well as for initializing the transport's configuration based on those settings (the user cannot
    /// provide information anymore at this stage).
    /// </summary>
    /// <param name="settings">An instance of the current settings.</param>
    /// <param name="connectionString">The connection string.</param>
    /// <returns>The supported factories.</returns>
    public override TransportInfrastructure Initialize(SettingsHolder settings, string connectionString)
    {
        //Guard.AgainstNull(nameof(settings), settings);
        return new FileTransportInfrastructure();
    }
}

public static class BaseDirectoryBuilder
{
    public static string BuildBasePath(string address)
    {
        var temp = Environment.ExpandEnvironmentVariables("%temp%");
        var fullPath = Path.Combine(temp, "FileTransport", address);
        _ = Directory.CreateDirectory(fullPath);
        return fullPath;
    }
}

class DirectoryBasedTransaction :
    IDisposable
{
    string basePath;
    bool committed;
    string transactionDir;

    public DirectoryBasedTransaction(string basePath)
    {
        this.basePath = basePath;
        var transactionId = Guid.NewGuid().ToString();

        transactionDir = Path.Combine(basePath, ".pending", transactionId);
    }

    public string FileToProcess { get; private set; }

    public void BeginTransaction(string incomingFilePath)
    {
        Directory.CreateDirectory(transactionDir);
        FileToProcess = Path.Combine(transactionDir, Path.GetFileName(incomingFilePath));
        File.Move(incomingFilePath, FileToProcess);
    }

    public void Commit() => committed = true;

    public void Dispose()
    {
        if (!committed)
        {
            // rollback by moving the file back to the main dir
            File.Move(FileToProcess, Path.Combine(basePath, Path.GetFileName(FileToProcess)));
        }

        Directory.Delete(transactionDir, true);
    }
}

class Dispatcher :
    IDispatchMessages
{
    public Task Dispatch(TransportOperations outgoingMessages, TransportTransaction transaction, ContextBag context)
    {
        foreach (var operation in outgoingMessages.UnicastTransportOperations)
        {
            var basePath = BaseDirectoryBuilder.BuildBasePath(operation.Destination);
            var nativeMessageId = Guid.NewGuid().ToString();
            var bodyPath = Path.Combine(basePath, ".bodies", $"{nativeMessageId}.xml");

            var dir = Path.GetDirectoryName(bodyPath);
            if (!Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }
            File.WriteAllBytes(bodyPath, operation.Message.Body);

            var messageContents = new List<string>
            {
                bodyPath,
                HeaderSerializer.Serialize(operation.Message.Headers)
            };

            var messagePath = Path.Combine(basePath, $"{nativeMessageId}.txt");

            // write to temp file first so an atomic move can be done
            // this avoids the file being locked when the receiver tries to process it
            var tempFile = Path.GetTempFileName();
            File.WriteAllLines(tempFile, messageContents);
            File.Move(tempFile, messagePath);
        }

        return Task.CompletedTask;
    }
}

public class FileTransport :
    TransportDefinition
{
    public override bool RequiresConnectionString => false;

    public override TransportInfrastructure Initialize(SettingsHolder settings, string connectionString)
    {
        return new FileTransportInfrastructure();
    }

    public override string ExampleConnectionStringForErrorMessage { get; } = "";
}

public class FileTransportInfrastructure :
    TransportInfrastructure
{
    public override TransportReceiveInfrastructure ConfigureReceiveInfrastructure()
    {
        return new TransportReceiveInfrastructure(
            messagePumpFactory: () => new FileTransportMessagePump(),
            queueCreatorFactory: () => new FileTransportQueueCreator(),
            preStartupCheck: () => Task.FromResult(StartupCheckResult.Success));
    }

    public override TransportSendInfrastructure ConfigureSendInfrastructure()
    {
        return new TransportSendInfrastructure(
            dispatcherFactory: () => new Dispatcher(),
            preStartupCheck: () => Task.FromResult(StartupCheckResult.Success));
    }

    public override TransportSubscriptionInfrastructure ConfigureSubscriptionInfrastructure()
    {
        throw new NotImplementedException();
    }

    public override EndpointInstance BindToLocalEndpoint(EndpointInstance instance)
    {
        return instance;
    }

    public override string ToTransportAddress(LogicalAddress logicalAddress)
    {
        var endpointInstance = logicalAddress.EndpointInstance;
        var discriminator = endpointInstance.Discriminator ?? "";
        var qualifier = logicalAddress.Qualifier ?? "";
        return Path.Combine(endpointInstance.Endpoint, discriminator, qualifier);
    }

    public override IEnumerable<Type> DeliveryConstraints
    {
        get
        {
            yield return typeof(DiscardIfNotReceivedBefore);
        }
    }

    public override TransportTransactionMode TransactionMode => TransportTransactionMode.None;

    public override OutboundRoutingPolicy OutboundRoutingPolicy => new OutboundRoutingPolicy(sends: OutboundRoutingType.Unicast, publishes: OutboundRoutingType.Unicast, replies: OutboundRoutingType.Unicast);
}

class FileTransportMessagePump :
    IPushMessages
{
    static ILog log = LogManager.GetLogger<FileTransportMessagePump>();

    CancellationToken cancellationToken;
    CancellationTokenSource cancellationTokenSource;
    SemaphoreSlim concurrencyLimiter;
    Task messagePumpTask;
    Func<ErrorContext, Task<ErrorHandleResult>> onError;
    string path;
    Func<MessageContext, Task> pipeline;
    bool purgeOnStartup;
    ConcurrentDictionary<Task, Task> runningReceiveTasks;

    public Task Init(Func<MessageContext, Task> onMessage, Func<ErrorContext, Task<ErrorHandleResult>> onError, CriticalError criticalError, PushSettings settings)
    {
        this.onError = onError;
        pipeline = onMessage;
        path = BaseDirectoryBuilder.BuildBasePath(settings.InputQueue);
        purgeOnStartup = settings.PurgeOnStartup;
        return Task.CompletedTask;
    }

    public void Start(PushRuntimeSettings limitations)
    {
        runningReceiveTasks = new ConcurrentDictionary<Task, Task>();
        concurrencyLimiter = new SemaphoreSlim(limitations.MaxConcurrency);
        cancellationTokenSource = new CancellationTokenSource();

        cancellationToken = cancellationTokenSource.Token;

        if (purgeOnStartup)
        {
            Directory.Delete(path, true);
            Directory.CreateDirectory(path);
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
            var filesFound = false;

            foreach (var filePath in Directory.EnumerateFiles(path, "*.*"))
            {
                filesFound = true;
                await ProcessFile(filePath)
                    .ConfigureAwait(false);
            }

            if (!filesFound)
            {
                await Task.Delay(10, cancellationToken)
                    .ConfigureAwait(false);
            }
        }
    }

    async Task ProcessFile(string filePath)
    {
        var nativeMessageId = Path.GetFileNameWithoutExtension(filePath);

        await concurrencyLimiter.WaitAsync(cancellationToken)
            .ConfigureAwait(false);

        var task = Task.Run(async () =>
        {
            try
            {
                await ProcessFileWithTransaction(filePath, nativeMessageId)
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

    async Task ProcessFileWithTransaction(string filePath, string messageId)
    {
        using (var transaction = new DirectoryBasedTransaction(path))
        {
            transaction.BeginTransaction(filePath);

            var message = File.ReadAllLines(transaction.FileToProcess);
            var bodyPath = message.First();
            var json = string.Join("", message.Skip(1));
            var headers = HeaderSerializer.DeSerialize(json);

            if (headers.TryGetValue(Headers.TimeToBeReceived, out var ttbrString))
            {
                var ttbr = TimeSpan.Parse(ttbrString);
                // file.move preserves create time
                var sentTime = File.GetCreationTimeUtc(transaction.FileToProcess);

                if (sentTime + ttbr < DateTime.UtcNow)
                {
                    return;
                }
            }

            var body = File.ReadAllBytes(bodyPath);
            var transportTransaction = new TransportTransaction();
            transportTransaction.Set(transaction);

            var shouldCommit = await HandleMessageWithRetries(messageId, headers, body, transportTransaction, 1)
                .ConfigureAwait(false);

            if (shouldCommit)
            {
                transaction.Commit();
            }
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


class FileTransportQueueCreator :
    ICreateQueues
{
    public Task CreateQueueIfNecessary(QueueBindings queueBindings, string identity)
    {
        foreach (var address in queueBindings.SendingAddresses)
        {
            CreateQueueDirectory(address);
        }

        foreach (var address in queueBindings.ReceivingAddresses)
        {
            CreateQueueDirectory(address);
        }

        return Task.CompletedTask;
    }

    static void CreateQueueDirectory(string address)
    {
        var fullPath = BaseDirectoryBuilder.BuildBasePath(address);
        var committedPath = Path.Combine(fullPath, ".committed");
        Directory.CreateDirectory(committedPath);
        var bodiesPath = Path.Combine(fullPath, ".bodies");
        Directory.CreateDirectory(bodiesPath);
    }
}

static class HeaderSerializer
{
    public static string Serialize(Dictionary<string, string> instance)
    {
        var serializer = BuildSerializer();
        using (var stream = new MemoryStream())
        {
            serializer.WriteObject(stream, instance);
            return Encoding.UTF8.GetString(stream.ToArray());
        }
    }

    public static Dictionary<string, string> DeSerialize(string json)
    {
        var serializer = BuildSerializer();
        using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(json)))
        {
            return (Dictionary<string, string>)serializer.ReadObject(stream);
        }
    }

    static DataContractJsonSerializer BuildSerializer()
    {
        var settings = new DataContractJsonSerializerSettings
        {
            UseSimpleDictionaryFormat = true,
        };
        return new DataContractJsonSerializer(typeof(Dictionary<string, string>), settings);
    }
}

public static class TaskEx
{
    // Used to explicitly suppress the compiler warning about
    // using the returned value from async operations
    public static void Ignore(this Task task)
    {
    }
}