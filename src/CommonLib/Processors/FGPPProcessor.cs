using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.LDAPQueries;
using System.DirectoryServices.Protocols;

namespace SharpHoundCommonLib.Processors
{
    public class FGPPProcessor
    {

        private readonly ILDAPUtils _utils;
        private readonly ILogger _log;

        public FGPPProcessor(ILDAPUtils utils, ILogger log = null)
        {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("FGPPProc");
        }

        internal bool IsMemberOf(string userDN, string groupDN)
        {
            bool isMember = false;

            var options = new LDAPQueryOptions
            {
                Filter = new LDAPFilter().CheckIsMemberOf(userDN, groupDN).GetFilter(),
                Scope = SearchScope.Subtree
            };

            var rawMembers = _utils.QueryLDAP(options).ToArray();

            if (rawMembers.Count() != 0)
                isMember = true;

            return isMember;
        }

        internal string AffectedLevel(ISearchResultEntry fgpp, string distinguishedname)
        {
            if (!fgpp.PropertyNames().Contains(LDAPProperties.PSOAppliesTo))
                return null;

            string[] affectedObjects = fgpp.GetArrayProperty(LDAPProperties.PSOAppliesTo);
            distinguishedname = distinguishedname.ToUpper();

            foreach (string affectedObject in affectedObjects)
            {
                string affectedObjectUpper = affectedObject.ToUpper();
                if (affectedObjectUpper == distinguishedname)
                    return "User";

                else if (IsMemberOf(distinguishedname, affectedObjectUpper))
                    return "Group";
            }

            return null;

        }

        internal int[] ReverseId(string idChunk)
        {
            List<int> idValues = new();
            for (int i = 0; i < idChunk.Length; i += 2)
                idValues.Add(Convert.ToInt32(string.Concat(idChunk[i], idChunk[i + 1]), 16));

            int[] idValuesRev = idValues.ToArray();
            Array.Reverse(idValuesRev);

            return idValuesRev;
        }

        internal Dictionary<string, string> AddFGPP(ISearchResultEntry fgpp, string affectedLevel)
        {
            Dictionary<string, string> finalFGPP = new();

            foreach (string name in fgpp.PropertyNames())
            {
                string cleanName = name.Replace('-', '_');
                try
                {
                    // Add if values are numbers
                    long value = Int64.Parse(fgpp.GetProperty(name));
                    // Not set values have negative values
                    if (value >= 0)
                        finalFGPP.Add(cleanName, String.Join(";", fgpp.GetArrayProperty(name)));
                }
                catch (Exception e)
                {
                    // Add if values are strings
                    finalFGPP.Add(cleanName, String.Join(";", fgpp.GetArrayProperty(name)));
                }
            }

            finalFGPP.Add("affectedLevel", affectedLevel);

            return finalFGPP;
        }

        public Dictionary<string, string> GetFGPP(string id, string distinguishedname)
        {
            Dictionary<string, string> finalFGPP = new();
            string[] attributes = {LDAPProperties.Name, LDAPProperties.LockoutThreshold, LDAPProperties.PSOAppliesTo, LDAPProperties.MinimumPasswordLength,
                                 LDAPProperties.PasswordHistoryLength, LDAPProperties.LockoutObservationWindow, LDAPProperties.LockoutDuration,
                                 LDAPProperties.PasswordSettingPrecedence, LDAPProperties.PasswordComplexity, LDAPProperties.Description,
                                 LDAPProperties.PasswordReversibleEncryption, LDAPProperties.MinimumPasswordAge, LDAPProperties.MaximumPasswordAge};

            var options = new LDAPQueryOptions
            {
                Filter = new LDAPFilter().AddPasswordSettings().GetFilter(),
                Scope = SearchScope.Subtree,
                Properties = attributes,
                DomainName = Helpers.DistinguishedNameToDomain(distinguishedname)
            };

            var rawFGPPs = _utils.QueryLDAP(options).ToArray();

            finalFGPP.Add("id", id);
            foreach (var rawFGPP in rawFGPPs)
            {
                string affectedLevel = AffectedLevel(rawFGPP, distinguishedname);
                // if the user is affected by the FGPP
                if (affectedLevel is not null)
                {
                    // multiple FGPP for the same user : precedences
                    if (finalFGPP.Count > 1)
                    {
                        // if the current FGPP is applied at the User level and the stored one at the Group level => priority to the current one
                        if (affectedLevel == "User" && finalFGPP["affectedLevel"] == "Group")
                        {
                            finalFGPP = AddFGPP(rawFGPP, affectedLevel);
                        }
                        // if the current FGPP is applied at the Group level and the stored one at the User level => priority to the stored one
                        else if (affectedLevel == "Group" && finalFGPP["affectedLevel"] == "User")
                        {
                            ;
                        }
                        // if the current FGPP and the stored one are applied at the same level => choose with precedence parameter
                        else if (affectedLevel == finalFGPP["affectedLevel"])
                        {
                            // the current fgpp has priority
                            if (Int32.Parse(finalFGPP[LDAPProperties.PasswordSettingPrecedence.Replace('-', '_')]) > Int32.Parse(rawFGPP.GetProperty(LDAPProperties.PasswordSettingPrecedence)))
                            {
                                finalFGPP = AddFGPP(rawFGPP, affectedLevel);
                            }
                            // the stored fgpp has priority
                            else if (Int32.Parse(finalFGPP[LDAPProperties.PasswordSettingPrecedence.Replace('-', '_')]) < Int32.Parse(rawFGPP.GetProperty(LDAPProperties.PasswordSettingPrecedence)))
                            {
                                ;
                            }
                            // the precedences are equal
                            else if (Int32.Parse(finalFGPP[LDAPProperties.PasswordSettingPrecedence.Replace('-', '_')]) == Int32.Parse(rawFGPP.GetProperty(LDAPProperties.PasswordSettingPrecedence)))
                            {
                                int partQty = id.Split('-').Length;
                                for (int part = 0; part < partQty; part++)
                                {
                                    int[] currentGUIDChunkedRev = ReverseId(id.Split('-')[part]);
                                    int[] storedGUIDChunkedRev = ReverseId(finalFGPP["id"].Split('-')[part]);

                                    for (int i = 0; i < currentGUIDChunkedRev.Length; i++)
                                    {
                                        // the stored fgpp has priority
                                        if (currentGUIDChunkedRev[i] > storedGUIDChunkedRev[i])
                                        {
                                            break;
                                        }
                                        // the current fgpp has priority
                                        else if (currentGUIDChunkedRev[i] < storedGUIDChunkedRev[i])
                                        {
                                            finalFGPP = AddFGPP(rawFGPP, affectedLevel);
                                            break;
                                        }
                                    }
                                }

                            }
                        }
                    }
                    // first FGPP for the user
                    else
                        finalFGPP = AddFGPP(rawFGPP, affectedLevel);
                }
            }
            if(finalFGPP.Count == 1)
                return null;
            return finalFGPP;
        }
    }
}