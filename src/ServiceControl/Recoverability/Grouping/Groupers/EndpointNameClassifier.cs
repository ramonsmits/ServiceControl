namespace ServiceControl.Recoverability
{
    public class EndpointNameClassifier : IFailureClassifier
    {
        public const string Id = "Endpoint Name";
        public string Name => Id;

        public string ClassifyFailure(ClassifiableMessageDetails failureDetails)
        {
            if (failureDetails.ProcessingAttempt == null)
            {
                return null;
            }

            var instanceId = EndpointInstanceId.From(failureDetails.ProcessingAttempt.Headers);
            return instanceId.EndpointName;
        }
    }
}