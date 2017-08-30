namespace ServiceControl.UnitTests
{
    using System;
    using System.IO;
    using System.Runtime.CompilerServices;
    using NUnit.Framework;

    // NOTE: This class is included to fix the "current directory" for Approval Tests
    [SetUpFixture]
    public class SetUpFixture
    {
        [OneTimeSetUp]
        public void SetUp()
        {
            FixCurrentDirectory();
        }

        void FixCurrentDirectory([CallerFilePath] string callerFilePath = "")
        {
            Environment.CurrentDirectory = Directory.GetParent(callerFilePath).FullName;
        }
    }
}