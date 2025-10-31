using KSeF.Client.Core.Models.Sessions.ActiveSessions;
using System;

namespace KSeF.Client.Core.Models
{
    public class AuthStatus
    {
        public DateTime StartDate { get; set; }
        public AuthenticationMethodEnum AuthenticationMethod { get; set; }
        public StatusInfo Status { get; set; }
    }
}