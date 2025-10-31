﻿namespace KSeF.Client.Core.Infrastructure.Rest
{
    /// <summary>
    /// Adresy endpointów API KSeF.
    /// </summary>
    public static class Routes
    {
        /// <summary>
        /// Adresy endpointów dotyczących danych testowych.
        /// </summary>
        public static class TestData
        {
            private const string Prefix = "testdata";

            public const string CreateSubject = Prefix + "/subject";
            public const string RemoveSubject = Prefix + "/subject/remove";

            public const string CreatePerson = Prefix + "/person";
            public const string RemovePerson = Prefix + "/person/remove";

            public const string GrantPerms = Prefix + "/permissions";
            public const string RevokePerms = Prefix + "/permissions/revoke";

            public const string EnableAttach = Prefix + "/attachment";
            public const string DisableAttach = Prefix + "/attachment/revoke";

            public const string ChangeSessionLimitsInCurrentContext = Prefix + "/limits/context/session";
            public const string RestoreDefaultSessionLimitsInCurrentContext = Prefix + "/limits/context/session";
            
            public const string ChangeCertificatesLimitInCurrentSubject = Prefix + "/limits/subject/certificate";
            public const string RestoreDefaultCertificatesLimitInCurrentSubject = Prefix + "/limits/subject/certificate";

            public const string RateLimits = Prefix + "/rate-limits";
        }

        /// <summary>
        /// Adresy endpointów dotyczących limitów żądań wysyłanych do API.
        /// </summary>
        public static class Limits
        {
            private const string Prefix = "limits";
            public const string CurrentContext = Prefix + "/context";
            public const string CurrentSubject = Prefix + "/subject";

            public const string RateLimits = "rate-limits";
            
        }
    }
}