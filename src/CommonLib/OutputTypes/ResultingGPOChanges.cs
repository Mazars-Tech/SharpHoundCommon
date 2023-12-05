﻿using System;
using System.Collections.Generic;

namespace SharpHoundCommonLib.OutputTypes
{
    public class ResultingGPOChanges
    {
        public GPOChanges Enforced;
        public GPOChanges Unenforced;
        public TypedPrincipal[] LocalAdmins { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] RemoteDesktopUsers { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] DcomUsers { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] PSRemoteUsers { get; set; } = Array.Empty<TypedPrincipal>();
        public bool BlockInheritance;
        public TypedPrincipal[] AffectedComputers { get; set; } = Array.Empty<TypedPrincipal>();
    }

    public class GPOChanges
    {
        public Dictionary<string, int> PasswordPolicies = new();
        public Dictionary<string, int> LockoutPolicies = new();
        public Dictionary<string, bool> SMBSigning = new();
        public Dictionary<string, bool> LDAPSigning = new();
        public Dictionary<string, object> LMAuthenticationLevel = new();
        public Dictionary<string, int> MSCache = new();
    }
}