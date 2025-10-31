﻿using System;

namespace KSeF.Client.Core.Models.TestData
{
    /// <summary>Żądanie utworzenia osoby fizycznej w środowisku testowym.</summary>
    public sealed class PersonCreateRequest
    {
        public string Nip { get; set; }
        public string Pesel { get; set; }
        /// <summary>Czy osoba jest komornikiem/bailiff.</summary>
        public bool IsBailiff { get; set; }
        public string Description { get; set; }
        public string CreatedDate { get; private set; } = null;
        public void SetCreatedDate(DateTime createdDate)
        {
            CreatedDate = createdDate.ToString("yyyy-MM-ddTHH:mm:ssZ");
        }
    }
}
