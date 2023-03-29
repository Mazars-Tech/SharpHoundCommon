using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class ComposedProcessors
    {
        private readonly ACLProcessor _aclProcessor;
        private readonly ComputerAvailability _computerAvailability;
        private readonly ComputerSessionProcessor _computerSessionProcessor;
        private readonly ContainerProcessor _containerProcessor;
        private readonly DomainTrustProcessor _domainTrustProcessor;
        private readonly GroupProcessor _groupProcessor;
        private readonly LDAPPropertyProcessor _ldapPropertyProcessor;
        private readonly LocalGroupProcessor _localGroupProcessor;
        private readonly ILogger _log;
        private readonly SPNProcessors _spnProcessor;
        private readonly UserRightsAssignmentProcessor _userRightsAssignmentProcessor;
        private readonly ILDAPUtils _utils;
        private readonly ResolvedCollectionMethod _collectionMethods;
        private readonly int _passwordResetWindows;
        private readonly bool _allowRegistrySessions;
        
        public ComposedProcessors(ResolvedCollectionMethod collectionMethods, ILDAPUtils utils, ILogger log = null, int passwordResetWindow = 60, int maxSearchQueries = 15, bool allowRegistrySessions = true)
        {
            _collectionMethods = collectionMethods;
            _utils = utils ?? new LDAPUtils(maxSearchQueries);
            _passwordResetWindows = passwordResetWindow;
            _allowRegistrySessions = allowRegistrySessions;
            _log = log ?? Logging.LogProvider.CreateLogger("ComposedProcessor");
        }

        public async Task<Computer> ProcessComputerObject(ISearchResultEntry searchResultEntry,
            ResolvedSearchResult resolvedSearchResult)
        {
            var ret = new Computer();
            
            ret.Properties.Add("domain", resolvedSearchResult.Domain);
            ret.Properties.Add("name", resolvedSearchResult.DisplayName);
            ret.Properties.Add("distinguishedname", searchResultEntry.DistinguishedName.ToUpper());
            ret.Properties.Add("domainsid", resolvedSearchResult.DomainSid);
            
            //Process the LAPSExpirationTime entry into a haslaps property
            var hasLaps = searchResultEntry.GetProperty(LDAPProperties.LAPSExpirationTime) != null;
            ret.Properties.Add("haslaps", hasLaps);

            if ((_collectionMethods & ResolvedCollectionMethod.ObjectProps) != 0)
            {
                var props = await _ldapPropertyProcessor.ReadComputerProperties(searchResultEntry);
                ret.ConsumeComputerProps(props);
            }

            if ((_collectionMethods & ResolvedCollectionMethod.Group) != 0)
            {
                ret.PrimaryGroupSID = GroupProcessor.GetPrimaryGroupInfo(searchResultEntry, resolvedSearchResult);
            }

            if ((_collectionMethods & ResolvedCollectionMethod.ACL) != 0)
            {
                ret.Aces = _aclProcessor.ProcessACL(searchResultEntry, resolvedSearchResult).ToArray();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(searchResultEntry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
            }

            if (_collectionMethods.IsComputerCollectionSet())
            {
                var computerStatus = await _computerAvailability.IsComputerAvailable(searchResultEntry, resolvedSearchResult);

                if (!computerStatus.Connectable)
                {
                    _log.LogDebug("Computer {DisplayName} is unavailable due to: {Status}", resolvedSearchResult.DisplayName, computerStatus.Error);
                    ret.Status = computerStatus;
                    return ret;
                }
            }

            if ((_collectionMethods & ResolvedCollectionMethod.Session) != 0)
            {
                ret.Sessions = await _computerSessionProcessor.ReadUserSessions(searchResultEntry, resolvedSearchResult);;
            }

            if ((_collectionMethods & ResolvedCollectionMethod.LoggedOn) != 0)
            {
                ret.PrivilegedSessions = _computerSessionProcessor.ReadUserSessionsPrivileged(searchResultEntry, resolvedSearchResult);

                if (_allowRegistrySessions)
                {
                    ret.RegistrySessions = await _computerSessionProcessor.ReadUserSessionsRegistry(searchResultEntry, resolvedSearchResult);
                }
            }

            if (_collectionMethods.IsLocalGroupCollectionSet())
            {
                ret.LocalGroups = _localGroupProcessor.GetLocalGroups(resolvedSearchResult).ToArray();
            }
        }
    }
}