﻿using System.Collections.Generic;
using System.Linq;

namespace SharpHoundCommonLib.LDAPQueries
{
    /// <summary>
    ///     A class used to more easily build LDAP filters based on the common filters used by SharpHound
    /// </summary>
    public class LDAPFilter
    {
        private readonly List<string> _filterParts = new();
        private readonly List<string> _mandatory = new();

        /// <summary>
        ///     Pre-filters conditions passed into filters. Will fix filters that are missing parentheses naively
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        private static string[] CheckConditions(IEnumerable<string> conditions)
        {
            return conditions.Select(FixFilter).ToArray();
        }

        private static string FixFilter(string filter)
        {
            if (!filter.StartsWith("(")) filter = $"({filter}";

            if (!filter.EndsWith(")")) filter = $"{filter})";

            return filter;
        }

        /// <summary>
        ///     Takes a base filter and appends any number of LDAP conditionals in a LDAP "And" statement.
        ///     Returns the base filter if no extra conditions are specified
        /// </summary>
        /// <param name="baseFilter"></param>
        /// <param name="conditions"></param>
        /// <returns></returns>
        private static string BuildString(string baseFilter, params string[] conditions)
        {
            if (conditions.Length == 0) return baseFilter;

            return $"(&{baseFilter}{string.Join("", CheckConditions(conditions))})";
        }

        /// <summary>
        ///     Add a wildcard filter will match all object types
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LDAPFilter AddAllObjects(params string[] conditions)
        {
            _filterParts.Add(BuildString("(objectclass=*)", conditions));

            return this;
        }

        /// <summary>
        ///     Add a filter that will match User objects
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LDAPFilter AddUsers(params string[] conditions)
        {
            _filterParts.Add(BuildString("(samaccounttype=805306368)", conditions));

            return this;
        }

        /// <summary>
        ///     Add a filter that will match Group objects
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LDAPFilter AddGroups(params string[] conditions)
        {
            _filterParts.Add(BuildString(
                "(|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913))",
                conditions));

            return this;
        }

        /// <summary>
        ///     Add a filter that will include any object with a primary group
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LDAPFilter AddPrimaryGroups(params string[] conditions)
        {
            _filterParts.Add(BuildString("(primarygroupid=*)", conditions));

            return this;
        }

        /// <summary>
        ///     Add a filter that will include GPO objects
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LDAPFilter AddGPOs(params string[] conditions)
        {
            _filterParts.Add(BuildString("(&(objectcategory=groupPolicyContainer)(flags=*))", conditions));

            return this;
        }

        /// <summary>
        ///     Add a filter that will include OU objects
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LDAPFilter AddOUs(params string[] conditions)
        {
            _filterParts.Add(BuildString("(objectcategory=organizationalUnit)", conditions));

            return this;
        }

        /// <summary>
        ///     Add a filter that will include Domain objects
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LDAPFilter AddDomains(params string[] conditions)
        {
            _filterParts.Add(BuildString("(objectclass=domain)", conditions));

            return this;
        }

        /// <summary>
        ///     Add a filter that will include Container objects
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LDAPFilter AddContainers(params string[] conditions)
        {
            _filterParts.Add(BuildString("(objectClass=container)", conditions));

            return this;
        }

        /// <summary>
        ///     Add a filter that will include Configuration objects
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LDAPFilter AddConfiguration(params string[] conditions)
        {
            _filterParts.Add(BuildString("(objectClass=configuration)", conditions));

            return this;
        }

        /// <summary>
        ///     Add a filter that will include Computer objects
        ///
        ///     Note that gMSAs and sMSAs have this samaccounttype as well
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LDAPFilter AddComputers(params string[] conditions)
        {
            _filterParts.Add(BuildString("(samaccounttype=805306369)", conditions));
            return this;
        }

        /// <summary>
        ///     Add a filter that will include PKI Certificate templates
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LDAPFilter AddCertificateTemplates(params string[] conditions)
        {
            _filterParts.Add(BuildString("(objectclass=pKICertificateTemplate)", conditions));
            return this;
        }

        /// <summary>
        ///     Add a filter that will include Certificate Authorities
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LDAPFilter AddCertificateAuthorities(params string[] conditions)
        {
            _filterParts.Add(BuildString("(|(objectClass=certificationAuthority)(objectClass=pkiEnrollmentService))",
                conditions));
            return this;
        }

        /// <summary>
        ///     Add a filter that will include Enterprise Certificate Authorities
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LDAPFilter AddEnterpriseCertificationAuthorities(params string[] conditions)
        {
            _filterParts.Add(BuildString("(objectCategory=pKIEnrollmentService)", conditions));
            return this;
        }

        /// <summary>
        ///     Add a filter that will include schema items
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LDAPFilter AddSchemaID(params string[] conditions)
        {
            _filterParts.Add(BuildString("(schemaidguid=*)", conditions));
            return this;
        }

        /// <summary>
        ///     Add a filter that will include Computer objects but exclude gMSA and sMSA objects
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LDAPFilter AddComputersNoMSAs(params string[] conditions)
        {
            _filterParts.Add(BuildString("(&(samaccounttype=805306369)(!(objectclass=msDS-GroupManagedServiceAccount))(!(objectclass=msDS-ManagedServiceAccount)))", conditions));
            return this;
        }

        /// <summary>
        ///     Add a filter that will include Password Settings Objects
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LDAPFilter AddPasswordSettings(params string[] conditions)
        {
            _filterParts.Add(BuildString("(objectclass=msDS-PasswordSettings)", conditions));
            return this;
        }

        /// <summary>
        ///     Add a filter that will include msDS-KeyCredentialLink
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LDAPFilter AddKeyCredentialLink(params string[] conditions)
        {
            _filterParts.Add(BuildString("(msDS-KeyCredentialLink=*)", conditions));
            return this;
        }

        /// <summary>
        ///     Add a filter that will include Display Specifiers
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LDAPFilter AddDisplaySpecifiers(params string[] conditions)
        {
            _filterParts.Add(BuildString("(objectClass=displaySpecifier)", conditions));
            return this;
        }

        /// <summary>
        ///     Add a filter that will include server references
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LDAPFilter AddServerReferences(params string[] conditions)
        {
            _filterParts.Add(BuildString("(objectClass=server)", conditions));
            return this;
        }

        /// <summary>
        ///     Add a filter that will include NTDS Settings
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LDAPFilter AddNTDSSettings(params string[] conditions)
        {
            _filterParts.Add(BuildString("(CN=NTDS Settings)", conditions));
            return this;
        }

        /// <summary>
        ///     Add a filter that will include DNSProperty
        /// </summary>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LDAPFilter AddDNSProperty(params string[] conditions)
        {
            _filterParts.Add(BuildString("(objectclass=dnsZone)", conditions));
            return this;
        }

        /// <summary>
        ///     Adds a generic user specified filter
        /// </summary>
        /// <param name="filter">LDAP Filter to add to query</param>
        /// <param name="enforce">If true, filter will be AND otherwise OR</param>
        /// <returns></returns>
        public LDAPFilter AddFilter(string filter, bool enforce)
        {
            if (enforce)
                _mandatory.Add(FixFilter(filter));
            else
                _filterParts.Add(FixFilter(filter));

            return this;
        }

        /// <summary>
        ///     Checks if a user is member of a group
        /// </summary>
        /// <param name="user"></param>
        /// <param name="group"></param>
        /// <param name="conditions"></param>
        /// <returns></returns>
        public LDAPFilter CheckIsMemberOf(string user, string group, params string[] conditions)
        {
            _filterParts.Add(BuildString("(&(objectClass=user)(memberof=" + group + ")(distinguishedname=" + user + "))", conditions));
            return this;
        }

        /// <summary>
        ///     Combines all the specified parts of the LDAP filter and merges them into a single string
        /// </summary>
        /// <returns></returns>
        public string GetFilter()
        {

            var filterPartList = _filterParts.ToArray().Distinct();
            var mandatoryList = _mandatory.ToArray().Distinct();

            var filterPartsExceptMandatory = filterPartList.Except(mandatoryList).ToList();

            var filterPartsDistinct = string.Join("", filterPartsExceptMandatory);
            var mandatoryDistinct = string.Join("", mandatoryList);

            if (filterPartsExceptMandatory.Count == 1)
                filterPartsDistinct = filterPartsExceptMandatory[0];
            else if (filterPartsExceptMandatory.Count > 1)
                filterPartsDistinct = $"(|{filterPartsDistinct})";

            filterPartsDistinct = _mandatory.Count > 0 ? $"(&{filterPartsDistinct}{mandatoryDistinct})" : filterPartsDistinct;

            return filterPartsDistinct;
        }

        public IEnumerable<string> GetFilterList()
        {
            return _filterParts;
        }
    }
}