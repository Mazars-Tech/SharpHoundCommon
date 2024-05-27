using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading.Tasks;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using System.DirectoryServices;
using System.IO;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;
using SharpHoundCommonLib.LDAPQueries;

namespace SharpHoundCommonLib.Processors
{
    public class LDAPPropertyProcessor
    {
        private static readonly string[] ReservedAttributes =
        {
            "pwdlastset", "lastlogon", "lastlogontimestamp", "objectsid",
            "sidhistory", "useraccountcontrol", "operatingsystem",
            "operatingsystemservicepack", "serviceprincipalname", "displayname", "mail", "title",
            "homedirectory", "description", "admincount", "userpassword", "gpcfilesyspath", "objectclass",
            "msds-behavior-version", "objectguid", "name", "gpoptions", "msds-allowedtodelegateto",
            "msDS-allowedtoactonbehalfofotheridentity", "displayname",
            "sidhistory", "samaccountname", "samaccounttype", "objectsid", "objectguid", "objectclass",
            "samaccountname", "msds-groupmsamembership",
            "distinguishedname", "memberof", "logonhours", "ntsecuritydescriptor", "dsasignature", "repluptodatevector",
            "member", "whenCreated"
        };

        private readonly ILDAPUtils _utils;

        public LDAPPropertyProcessor(ILDAPUtils utils)
        {
            _utils = utils;
        }

        private static Dictionary<string, object> GetCommonProps(ISearchResultEntry entry)
        {
            return new Dictionary<string, object>
            {
                {
                    "description", entry.GetProperty(LDAPProperties.Description)
                },
                {
                    "whencreated", Helpers.ConvertTimestampToUnixEpoch(entry.GetProperty(LDAPProperties.WhenCreated))
                }
            };
        }

        /// <summary>
        ///     Reads specific LDAP properties related to Domains
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static Dictionary<string, object> ReadDomainProperties(ISearchResultEntry entry)
        {
            var props = GetCommonProps(entry);

            if (!int.TryParse(entry.GetProperty(LDAPProperties.DomainFunctionalLevel), out var level)) level = -1;

            props.Add("functionallevel", FunctionalLevelToString(level));

            return props;
        }

        /// <summary>
        ///     Converts a numeric representation of a functional level to its appropriate functional level string
        /// </summary>
        /// <param name="level"></param>
        /// <returns></returns>
        public static string FunctionalLevelToString(int level)
        {
            var functionalLevel = level switch
            {
                0 => "2000 Mixed/Native",
                1 => "2003 Interim",
                2 => "2003",
                3 => "2008",
                4 => "2008 R2",
                5 => "2012",
                6 => "2012 R2",
                7 => "2016",
                _ => "Unknown"
            };

            return functionalLevel;
        }

        /// <summary>
        ///     Reads specific LDAP properties related to GPOs
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static Dictionary<string, object> ReadGPOProperties(ISearchResultEntry entry)
        {
            var props = GetCommonProps(entry);
            props.Add("gpcpath", entry.GetProperty(LDAPProperties.GPCFileSYSPath)?.ToUpper());
            return props;
        }

        /// <summary>
        ///     Reads specific LDAP properties related to OUs
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static Dictionary<string, object> ReadOUProperties(ISearchResultEntry entry)
        {
            var props = GetCommonProps(entry);
            return props;
        }

        /// <summary>
        ///     Reads specific LDAP properties related to Groups
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static Dictionary<string, object> ReadGroupProperties(ISearchResultEntry entry)
        {
            var props = GetCommonProps(entry);

            var ac = entry.GetProperty(LDAPProperties.AdminCount);
            if (ac != null)
            {
                var a = int.Parse(ac);
                props.Add("admincount", a != 0);
            }
            else
            {
                props.Add("admincount", false);
            }

            return props;
        }

        /// <summary>
        /// Reads specific LDAP properties related to containers
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static Dictionary<string, object> ReadContainerProperties(ISearchResultEntry entry)
        {
            var props = GetCommonProps(entry);
            return props;
        }

        /// <summary>
        ///     Reads specific LDAP properties related to Users
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public async Task<UserProperties> ReadUserProperties(ISearchResultEntry entry)
        {
            var userProps = new UserProperties();
            var props = GetCommonProps(entry);

            var uac = entry.GetProperty(LDAPProperties.UserAccountControl);
            bool enabled, trustedToAuth, sensitive, dontReqPreAuth, passwdNotReq, unconstrained, pwdNeverExpires;
            if (int.TryParse(uac, out var flag))
            {
                var flags = (UacFlags) flag;
                enabled = (flags & UacFlags.AccountDisable) == 0;
                trustedToAuth = (flags & UacFlags.TrustedToAuthForDelegation) != 0;
                sensitive = (flags & UacFlags.NotDelegated) != 0;
                dontReqPreAuth = (flags & UacFlags.DontReqPreauth) != 0;
                passwdNotReq = (flags & UacFlags.PasswordNotRequired) != 0;
                unconstrained = (flags & UacFlags.TrustedForDelegation) != 0;
                pwdNeverExpires = (flags & UacFlags.DontExpirePassword) != 0;
            }
            else
            {
                trustedToAuth = false;
                enabled = true;
                sensitive = false;
                dontReqPreAuth = false;
                passwdNotReq = false;
                unconstrained = false;
                pwdNeverExpires = false;
            }

            props.Add("sensitive", sensitive);
            props.Add("dontreqpreauth", dontReqPreAuth);
            props.Add("passwordnotreqd", passwdNotReq);
            props.Add("unconstraineddelegation", unconstrained);
            props.Add("pwdneverexpires", pwdNeverExpires);
            props.Add("enabled", enabled);
            props.Add("trustedtoauth", trustedToAuth);
            var domain = Helpers.DistinguishedNameToDomain(entry.DistinguishedName);

            var comps = new List<TypedPrincipal>();
            if (trustedToAuth)
            {
                var delegates = entry.GetArrayProperty(LDAPProperties.AllowedToDelegateTo);
                props.Add("allowedtodelegate", delegates);

                foreach (var d in delegates)
                {
                    if (d == null)
                        continue;

                    var resolvedHost = await _utils.ResolveHostToSid(d, domain);
                    if (resolvedHost != null && (resolvedHost.Contains(".") || resolvedHost.Contains("S-1")))
                        comps.Add(new TypedPrincipal
                        {
                            ObjectIdentifier = resolvedHost,
                            ObjectType = Label.Computer
                        });
                }
            }

            userProps.AllowedToDelegate = comps.Distinct().ToArray();

            props.Add("lastlogon", Helpers.ConvertFileTimeToUnixEpoch(entry.GetProperty(LDAPProperties.LastLogon)));
            props.Add("lastlogontimestamp",
                Helpers.ConvertFileTimeToUnixEpoch(entry.GetProperty(LDAPProperties.LastLogonTimestamp)));
            props.Add("pwdlastset", Helpers.ConvertFileTimeToUnixEpoch(entry.GetProperty(LDAPProperties.PasswordLastSet)));
            var spn = entry.GetArrayProperty(LDAPProperties.ServicePrincipalNames);
            props.Add("serviceprincipalnames", spn);
            props.Add("hasspn", spn.Length > 0);
            props.Add("displayname", entry.GetProperty(LDAPProperties.DisplayName));
            props.Add("email", entry.GetProperty(LDAPProperties.Email));
            props.Add("title", entry.GetProperty(LDAPProperties.Title));
            props.Add("homedirectory", entry.GetProperty(LDAPProperties.HomeDirectory));
            props.Add("userpassword", entry.GetProperty(LDAPProperties.UserPassword));
            props.Add("unixpassword", entry.GetProperty(LDAPProperties.UnixUserPassword));
            props.Add("unicodepassword", entry.GetProperty(LDAPProperties.UnicodePassword));
            props.Add("sfupassword", entry.GetProperty(LDAPProperties.MsSFU30Password));
            props.Add("logonscript", entry.GetProperty(LDAPProperties.ScriptPath));

            var ac = entry.GetProperty(LDAPProperties.AdminCount);
            if (ac != null)
            {
                if (int.TryParse(ac, out var parsed))
                    props.Add("admincount", parsed != 0);
                else
                    props.Add("admincount", false);
            }
            else
            {
                props.Add("admincount", false);
            }

            var sh = entry.GetByteArrayProperty(LDAPProperties.SIDHistory);
            var sidHistoryList = new List<string>();
            var sidHistoryPrincipals = new List<TypedPrincipal>();
            foreach (var sid in sh)
            {
                string sSid;
                try
                {
                    sSid = new SecurityIdentifier(sid, 0).Value;
                }
                catch
                {
                    continue;
                }

                sidHistoryList.Add(sSid);

                var res = _utils.ResolveIDAndType(sSid, domain);

                sidHistoryPrincipals.Add(res);
            }

            userProps.SidHistory = sidHistoryPrincipals.Distinct().ToArray();

            props.Add("sidhistory", sidHistoryList.ToArray());

            userProps.Props = props;

            return userProps;
        }

        /// <summary>
        ///     Reads specific LDAP properties related to Computers
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public async Task<ComputerProperties> ReadComputerProperties(ISearchResultEntry entry)
        {
            var compProps = new ComputerProperties();
            var props = GetCommonProps(entry);

            var uac = entry.GetProperty(LDAPProperties.UserAccountControl);
            bool enabled, unconstrained, trustedToAuth, serverTrustAccount, trustedForDelegation, partialSecretsAccount, workstationTrustAccount;
            if (int.TryParse(uac, out var flag))
            {
                var uACFlags = (UacFlags)flag;
                enabled = (uACFlags & UacFlags.AccountDisable) == 0;
                unconstrained = (uACFlags & UacFlags.TrustedForDelegation) == UacFlags.TrustedForDelegation;
                trustedToAuth = (uACFlags & UacFlags.TrustedToAuthForDelegation) != 0;
                serverTrustAccount = (uACFlags & UacFlags.ServerTrustAccount) != 0;
                trustedForDelegation = (uACFlags & UacFlags.TrustedForDelegation) != 0;
                partialSecretsAccount = (uACFlags & UacFlags.PartialSecretsAccount) != 0;
                workstationTrustAccount = (uACFlags & UacFlags.WorkstationTrustAccount) != 0;
            }
            else
            {
                unconstrained = false;
                enabled = true;
                trustedToAuth = false;
                serverTrustAccount = false;
                trustedForDelegation = false;
                partialSecretsAccount = false;
                workstationTrustAccount = false;
            }

            var domain = Helpers.DistinguishedNameToDomain(entry.DistinguishedName);

            var comps = new List<TypedPrincipal>();
            if (trustedToAuth)
            {
                var delegates = entry.GetArrayProperty(LDAPProperties.AllowedToDelegateTo);
                props.Add("allowedtodelegate", delegates);

                foreach (var d in delegates)
                {
                    var hname = d.Contains("/") ? d.Split('/')[1] : d;
                    hname = hname.Split(':')[0];
                    var resolvedHost = await _utils.ResolveHostToSid(hname, domain);
                    if (resolvedHost != null && (resolvedHost.Contains(".") || resolvedHost.Contains("S-1")))
                        comps.Add(new TypedPrincipal
                        {
                            ObjectIdentifier = resolvedHost,
                            ObjectType = Label.Computer
                        });
                }
            }

            compProps.AllowedToDelegate = comps.Distinct().ToArray();

            var allowedToActPrincipals = new List<TypedPrincipal>();
            var rawAllowedToAct = entry.GetByteProperty(LDAPProperties.AllowedToActOnBehalfOfOtherIdentity);
            if (rawAllowedToAct != null)
            {
                var sd = _utils.MakeSecurityDescriptor();
                sd.SetSecurityDescriptorBinaryForm(rawAllowedToAct, AccessControlSections.Access);
                foreach (var rule in sd.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    var res = _utils.ResolveIDAndType(rule.IdentityReference(), domain);
                    allowedToActPrincipals.Add(res);
                }
            }

            compProps.AllowedToAct = allowedToActPrincipals.ToArray();

            props.Add("enabled", enabled);
            props.Add("unconstraineddelegation", unconstrained);
            props.Add("trustedtoauth", trustedToAuth);
            props.Add("servertrustaccount", serverTrustAccount);
            props.Add("trustedfordelegation", trustedForDelegation);
            props.Add("partialsecretaccount", partialSecretsAccount);
            props.Add("workstationtrustaccount", workstationTrustAccount);
            props.Add("lastlogon", Helpers.ConvertFileTimeToUnixEpoch(entry.GetProperty(LDAPProperties.LastLogon)));
            props.Add("lastlogontimestamp",
                Helpers.ConvertFileTimeToUnixEpoch(entry.GetProperty(LDAPProperties.LastLogonTimestamp)));
            props.Add("pwdlastset", Helpers.ConvertFileTimeToUnixEpoch(entry.GetProperty(LDAPProperties.PasswordLastSet)));
            props.Add("serviceprincipalnames", entry.GetArrayProperty(LDAPProperties.ServicePrincipalNames));
            var os = entry.GetProperty(LDAPProperties.OperatingSystem);
            var sp = entry.GetProperty(LDAPProperties.ServicePack);

            if (sp != null) os = $"{os} {sp}";

            props.Add("operatingsystem", os);

            var sh = entry.GetByteArrayProperty(LDAPProperties.SIDHistory);
            var sidHistoryList = new List<string>();
            var sidHistoryPrincipals = new List<TypedPrincipal>();
            foreach (var sid in sh)
            {
                string sSid;
                try
                {
                    sSid = new SecurityIdentifier(sid, 0).Value;
                }
                catch
                {
                    continue;
                }

                sidHistoryList.Add(sSid);

                var res = _utils.ResolveIDAndType(sSid, domain);

                sidHistoryPrincipals.Add(res);
            }

            compProps.SidHistory = sidHistoryPrincipals.ToArray();

            props.Add("sidhistory", sidHistoryList.ToArray());

            compProps.Props = props;

            return compProps;
        }

        /// <summary>
        ///     Reads shadow credentials
        /// </summary>
        /// <param name="distinguishedname"></param>
        /// <returns></returns>
        public Dictionary<string, object> GetShadowCredentials()
        {
            Dictionary<string, object> shadowCredentials = new();

            // set options of the query for the msds-keycredentiallink
            string[] attributes = { LDAPProperties.KeyCredentialLink };
            var options = new LDAPQueryOptions
            {
                Filter = new LDAPFilter().AddKeyCredentialLink().GetFilter(),
                Scope = SearchScope.Subtree,
                Properties = attributes
            };
            // query LDAP for the msds-keycredentiallink
            var rawKCLs = _utils.QueryLDAP(options).ToArray();

            // parse results
            foreach (var rawKCL in rawKCLs)
            {
                string kcl = rawKCL.GetProperty(LDAPProperties.KeyCredentialLink.ToLower());
                string[] kclParts = kcl.Split(':');
                if (kclParts.Length != 4)
                    continue;
                int kclSize = Int32.Parse(kclParts[1]);
                byte[] kclBytes = Helpers.StringToByteArray(kclParts[2]);
                Stream kclStream = new MemoryStream(kclBytes);
                if (kclSize == kclBytes.Length * 2)
                {
                    long fileTime = 0;
                    long epochTime = 0;
                    var reader = new BinaryReader(kclStream);
                    // read BLOB version
                    int version = BitConverter.ToInt32(reader.ReadBytes(4), 0);

                    // read BLOB entries
                    byte[] rawDataLength = reader.ReadBytes(2);
                    while (rawDataLength != null && rawDataLength.Length > 0)
                    {
                        // read entry length
                        int dataLength = BitConverter.ToInt16(rawDataLength, 0);

                        // read entry type
                        int dataType = reader.ReadByte();

                        // read entry value
                        switch (dataType)
                        {
                            // DeviceId
                            case 6:
                                shadowCredentials["deviceid"] = BitConverter.ToString(reader.ReadBytes(dataLength));
                                break;
                            // KeyApproximateLastLogonTimeStamp
                            case 8:
                                fileTime = BitConverter.ToInt64(reader.ReadBytes(dataLength), 0);
                                // conversion to Unix epoch time
                                epochTime = Helpers.ConvertFileTimeToUnixEpoch(fileTime.ToString());
                                shadowCredentials["keyapproximatelastlogontimestamp"] = epochTime;
                                break;
                            // KeyCreationTimeStamp
                            case 9:
                                fileTime = BitConverter.ToInt64(reader.ReadBytes(dataLength), 0);
                                // conversion to Unix epoch time
                                epochTime = Helpers.ConvertFileTimeToUnixEpoch(fileTime.ToString());
                                shadowCredentials["keycreationtimestamp"] = epochTime;
                                break;
                            default:
                                reader.ReadBytes(dataLength);
                                break;
                        }

                        rawDataLength = reader.ReadBytes(2);

                    }
                }
            }
            return shadowCredentials;
        }

        /// <summary>
        ///     Reads DC state through the configuration naming context
        /// </summary>
        /// <param name="distinguishedname"></param>
        /// <returns></returns>
        public string GetDCState(string distinguishedname)
        {
            DirectoryEntry rootDSE = new DirectoryEntry("LDAP://RootDSE");
            string configurationContext = rootDSE.Properties[LDAPProperties.ConfigurationNamingContext][0].ToString().ToUpper();

            string states = "unsecure";
            Dictionary<string, string> NTDSSettings = new();

            // set options of the query for the server references
            string[] attributes = { LDAPProperties.DistinguishedName, LDAPProperties.ServerReference };
            var options = new LDAPQueryOptions
            {
                Filter = new LDAPFilter().AddServerReferences().GetFilter(),
                Scope = SearchScope.Subtree,
                Properties = attributes,
                AdsPath = configurationContext
            };
            // query LDAP for the server references
            var rawServerReferences = _utils.QueryLDAP(options).ToArray();

            // set options of the query for the NTDS settings
            attributes = new string[] { LDAPProperties.DistinguishedName, LDAPProperties.ObjectClass };
            options = new LDAPQueryOptions
            {
                Filter = new LDAPFilter().AddNTDSSettings().GetFilter(),
                Scope = SearchScope.Subtree,
                Properties = attributes,
                AdsPath = configurationContext
            };
            // query LDAP for the NTDS settings
            var rawNTDSSettings = _utils.QueryLDAP(options).ToArray();

            foreach (var rawNTDSSetting in rawNTDSSettings)
            {
                foreach (string objectclass in rawNTDSSetting.GetArrayProperty(LDAPProperties.ObjectClass))
                {
                    if (objectclass.Contains("nTDSDSA"))
                    {
                        NTDSSettings.Add(rawNTDSSetting.GetProperty(LDAPProperties.DistinguishedName), objectclass);
                    }
                }
            }

            foreach (var rawServerReference in rawServerReferences)
            {
                foreach (string reference in rawServerReference.GetArrayProperty(LDAPProperties.ServerReference))
                {
                    if (reference.ToUpper() == distinguishedname)
                    {
                        states = "unsecure";
                        foreach (KeyValuePair<string, string> NTDSSetting in NTDSSettings)
                        {
                            if (NTDSSetting.Key.Contains(rawServerReference.GetProperty(LDAPProperties.DistinguishedName)))
                            {
                                states = "secure";
                            }
                        }
                    }
                }
            }

            return states;
        }

        /// <summary>
        ///     Reads Display Specifiers to find scripts
        /// </summary>
        /// <param name="distinguishedname"></param>
        /// <returns></returns>
        public List<string> GetDisplaySpecifierScripts(string distinguishedname)
        {
            DirectoryEntry rootDSE = new DirectoryEntry("LDAP://RootDSE");
            string configurationContext = rootDSE.Properties[LDAPProperties.ConfigurationNamingContext][0].ToString().ToUpper();
            string domainname = Helpers.DistinguishedNameToDomain(distinguishedname);

            List<string> scripts = new();

            // set display specifiers LDAP query parameters
            var options = new LDAPQueryOptions
            {
                Filter = new LDAPFilter().AddDisplaySpecifiers().GetFilter(),
                Scope = SearchScope.Subtree,
                DomainName = domainname,
                AdsPath = "CN=DisplaySpecifiers," + configurationContext
            };

            // query LDAP
            var rawProps = _utils.QueryLDAP(options).ToArray();
            foreach (var rawProp in rawProps)
            {
                foreach (string name in rawProp.PropertyNames())
                {
                    string[] props = rawProp.GetArrayProperty(name);
                    foreach (string prop in props)
                    {
                        try
                        {
                            string script = prop.Split(',')[2].Trim();
                            if (script.StartsWith("\\\\") && !script.StartsWith("\\\\" + domainname + "\\SYSVOL"))
                                scripts.Add(script);
                        }
                        catch (Exception e)
                        {
                            ; // this prop is not a script
                        }
                    }
                }
            }

            return new List<string>()
            {
                domainname + "/" + String.Join("/", scripts)
            };
        }

        /// <summary>
        ///     Reads DNS LDAP properties
        /// </summary>
        /// <param name="distinguishedname"></param>
        /// <returns></returns>
        public List<string> GetDNSProperties(string distinguishedname)
        {
            List<string> dNSProps = new();

            // set LDAP query parameters
            string[] attributes = { LDAPProperties.DNSProperty, LDAPProperties.Name };
            var options = new LDAPQueryOptions
            {
                Filter = new LDAPFilter().AddDNSProperty().GetFilter(),
                Scope = SearchScope.Subtree,
                Properties = attributes,
                DomainName = Helpers.DistinguishedNameToDomain(distinguishedname),
                AdsPath = "DC=DOMAINDNSZONES," + distinguishedname
            };

            // query LDAP
            var rawDNSProps = _utils.QueryLDAP(options).ToArray();

            // parse LDAP query's result
            for (int i = 0; i < rawDNSProps.Length; i++)
            {
                byte[][] allDNSPropss = rawDNSProps[i].GetByteArrayProperty(LDAPProperties.DNSProperty);
                string name = rawDNSProps[i].GetProperty(LDAPProperties.Name);
                for (int j = 0; j < allDNSPropss.Length; j++)
                {
                    int propertyId = BitConverter.ToInt32(allDNSPropss[j], 16);
                    switch (propertyId)
                    {
                        case 2:
                            int allowUpdateValue = BitConverter.ToInt32(allDNSPropss[j], 20);
                            if (allowUpdateValue == 0 || allowUpdateValue == 1 || allowUpdateValue == 2)
                            {
                                dNSProps.Add(name + "/allowUpdate/" + allowUpdateValue.ToString());
                            }
                            break;
                    }
                }
            }
            return dNSProps;
        }

        /// <summary>
        ///     Attempts to parse all LDAP attributes outside of the ones already collected and converts them to a human readable
        ///     format using a best guess
        /// </summary>
        /// <param name="entry"></param>
        public Dictionary<string, object> ParseAllProperties(ISearchResultEntry entry)
        {
            var flag = IsTextUnicodeFlags.IS_TEXT_UNICODE_STATISTICS;
            var props = new Dictionary<string, object>();

            foreach (var property in entry.PropertyNames())
            {
                if (ReservedAttributes.Contains(property))
                    continue;

                var collCount = entry.PropCount(property);
                if (collCount == 0)
                    continue;

                if (collCount == 1)
                {
                    var testBytes = entry.GetByteProperty(property);

                    if (testBytes == null || testBytes.Length == 0 ||
                        !IsTextUnicode(testBytes, testBytes.Length, ref flag)) continue;

                    var testString = entry.GetProperty(property);

                    if (!string.IsNullOrEmpty(testString))
                        if (property == "badpasswordtime")
                            props.Add(property, Helpers.ConvertFileTimeToUnixEpoch(testString));
                        else
                            props.Add(property, BestGuessConvert(testString));
                }
                else
                {
                    var arrBytes = entry.GetByteArrayProperty(property);
                    if (arrBytes.Length == 0 || !IsTextUnicode(arrBytes[0], arrBytes[0].Length, ref flag))
                        continue;

                    var arr = entry.GetArrayProperty(property);
                    if (arr.Length > 0) props.Add(property, arr.Select(BestGuessConvert).ToArray());
                }
            }

            return props;
        }

        /// <summary>
        ///     Does a best guess conversion of the property to a type useable by the UI
        /// </summary>
        /// <param name="property"></param>
        /// <returns></returns>
        private static object BestGuessConvert(string property)
        {
            //Parse boolean values
            if (bool.TryParse(property, out var boolResult)) return boolResult;

            //A string ending with 0Z is likely a timestamp
            if (property.EndsWith("0Z")) return Helpers.ConvertTimestampToUnixEpoch(property);

            //This string corresponds to the max int, and is usually set in accountexpires
            if (property == "9223372036854775807") return -1;

            return property;
        }

        [DllImport("Advapi32", SetLastError = false)]
        private static extern bool IsTextUnicode(byte[] buf, int len, ref IsTextUnicodeFlags opt);

        [Flags]
        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        [SuppressMessage("ReSharper", "InconsistentNaming")]
        private enum IsTextUnicodeFlags
        {
            IS_TEXT_UNICODE_ASCII16 = 0x0001,
            IS_TEXT_UNICODE_REVERSE_ASCII16 = 0x0010,

            IS_TEXT_UNICODE_STATISTICS = 0x0002,
            IS_TEXT_UNICODE_REVERSE_STATISTICS = 0x0020,

            IS_TEXT_UNICODE_CONTROLS = 0x0004,
            IS_TEXT_UNICODE_REVERSE_CONTROLS = 0x0040,

            IS_TEXT_UNICODE_SIGNATURE = 0x0008,
            IS_TEXT_UNICODE_REVERSE_SIGNATURE = 0x0080,

            IS_TEXT_UNICODE_ILLEGAL_CHARS = 0x0100,
            IS_TEXT_UNICODE_ODD_LENGTH = 0x0200,
            IS_TEXT_UNICODE_DBCS_LEADBYTE = 0x0400,
            IS_TEXT_UNICODE_NULL_BYTES = 0x1000,

            IS_TEXT_UNICODE_UNICODE_MASK = 0x000F,
            IS_TEXT_UNICODE_REVERSE_MASK = 0x00F0,
            IS_TEXT_UNICODE_NOT_UNICODE_MASK = 0x0F00,
            IS_TEXT_UNICODE_NOT_ASCII_MASK = 0xF000
        }
    }


    public class UserProperties
    {
        public Dictionary<string, object> Props { get; set; }
        public TypedPrincipal[] AllowedToDelegate { get; set; }
        public TypedPrincipal[] SidHistory { get; set; }
    }

    public class ComputerProperties
    {
        public Dictionary<string, object> Props { get; set; }
        public TypedPrincipal[] AllowedToDelegate { get; set; }
        public TypedPrincipal[] AllowedToAct { get; set; }
        public TypedPrincipal[] SidHistory { get; set; }
    }
}