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

        internal string AffectedLevel(ISearchResultEntry fgpp, string distinguishedname)
        {
            if (!fgpp.PropertyNames().Contains("msds-psoappliesto"))
                return null;

            string[] affectedObjects = fgpp.GetArrayProperty("msds-psoappliesto");
            distinguishedname = distinguishedname.ToUpper();

            foreach (string affectedObject in affectedObjects)
            {
                string affectedObjectUpper = affectedObject.ToUpper();
                if (affectedObjectUpper == distinguishedname)
                    return "User";

                else if (distinguishedname.Contains(affectedObjectUpper))
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

            foreach (var name in fgpp.PropertyNames())
            {
                try
                {
                    long value = Int64.Parse(fgpp.GetProperty(name));
                    if (value >= 0)
                        finalFGPP.Add(name, String.Join(";", fgpp.GetArrayProperty(name)));
                }
                catch (Exception e)
                {
                    finalFGPP.Add(name, String.Join(";", fgpp.GetArrayProperty(name)));
                }
            }

            finalFGPP.Add("affectedLevel", affectedLevel);

            return finalFGPP;
        }

        public Dictionary<string, string> GetFGPP(string id, string distinguishedname)
        {
            Dictionary<string, string> finalFGPP = new();
            string[] attributes = {"name", "msds-lockoutthreshold", "msds-psoappliesto", "msds-minimumpasswordlength",
                                 "msds-passwordhistorylength", "msds-lockoutobservationwindow", "msds-lockoutduration",
                                 "msds-passwordsettingsprecedence", "msds-passwordcomplexityenabled", "Description",
                                 "msds-passwordreversibleencryptionenabled", "msds-minimumpasswordage", "msds-maximumpasswordage"};

            var options = new LDAPQueryOptions
            {
                Filter = new LDAPFilter().AddPasswordSettings().GetFilter(),
                Scope = SearchScope.Subtree,
                Properties = attributes,
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
                            if (Int32.Parse(finalFGPP["msds-passwordsettingsprecedence"]) > Int32.Parse(rawFGPP.GetProperty("msds-passwordsettingsprecedence")))
                            {
                                finalFGPP = AddFGPP(rawFGPP, affectedLevel);
                            }
                            // the stored fgpp has priority
                            else if (Int32.Parse(finalFGPP["msds-passwordsettingsprecedence"]) < Int32.Parse(rawFGPP.GetProperty("msds-passwordsettingsprecedence")))
                            {
                                ;
                            }
                            // the precedences are equal
                            else if (Int32.Parse(finalFGPP["msds-passwordsettingsprecedence"]) == Int32.Parse(rawFGPP.GetProperty("msds-passwordsettingsprecedence")))
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
            return finalFGPP;
        }
    }
}