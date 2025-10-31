using KSeF.Client.Core.Models;
using KSeF.Client.Core.Models.Permissions;
using KSeF.Client.Core.Models.Permissions.Identifiers;
using KSeF.Client.Core.Models.Permissions.Person;
using KSeF.Client.Core.Models.Token;
using KSeF.Client.Tests.Utils;

namespace KSeF.Client.Tests.Features
{
    [Collection("CredentialsGrantScenario")]
    [Trait("Category", "Features")]
    [Trait("Features", "credentials_grant.feature")]
    public class CredentialsGrantTests : KsefIntegrationTestBase
    {
        [Theory]
        [InlineData("90091309123", new[] { PersonPermissionType.InvoiceWrite })]
        [InlineData("90091309123", new[] { PersonPermissionType.InvoiceRead, PersonPermissionType.InvoiceWrite })]
        [InlineData("90091309123", new[] { PersonPermissionType.CredentialsManage })]
        [InlineData("90091309123", new[] { PersonPermissionType.CredentialsRead })]
        [InlineData("90091309123", new[] { PersonPermissionType.Introspection })]
        [InlineData("90091309123", new[] { PersonPermissionType.SubunitManage })]

        [InlineData("6651887777", new[] { PersonPermissionType.InvoiceWrite })]
        [InlineData("6651887777", new[] { PersonPermissionType.InvoiceRead })]
        [InlineData("6651887777", new[] { PersonPermissionType.CredentialsManage })]
        [InlineData("6651887777", new[] { PersonPermissionType.CredentialsRead })]
        [InlineData("6651887777", new[] { PersonPermissionType.Introspection })]
        [InlineData("6651887777", new[] { PersonPermissionType.InvoiceWrite, PersonPermissionType.InvoiceRead })]
        [Trait("Scenario", "Nadanie uprawnienia wystawianie faktur")]
        public async Task GivenOwnerIsAuthenticated_WhenGrantInvoiceIssuingPermissionToEntity_ThenPermissionIsConfirmed(string identyficator, PersonPermissionType[] permissions)
        {
            string ownerNIP = MiscellaneousUtils.GetRandomNip();

            await TestGrantPermissions(identyficator, permissions, ownerNIP);
        }

        [Theory]
        [InlineData("90091309123", new[] { PersonPermissionType.InvoiceWrite })]
        [InlineData("90091309123", new[] { PersonPermissionType.InvoiceRead, PersonPermissionType.InvoiceWrite })]
        [InlineData("90091309123", new[] { PersonPermissionType.CredentialsManage })]
        [InlineData("90091309123", new[] { PersonPermissionType.CredentialsRead })]
        [InlineData("90091309123", new[] { PersonPermissionType.Introspection })]
        [InlineData("90091309123", new[] { PersonPermissionType.SubunitManage })]

        [InlineData("6651887777", new[] { PersonPermissionType.InvoiceWrite })]
        [InlineData("6651887777", new[] { PersonPermissionType.InvoiceRead })]
        [InlineData("6651887777", new[] { PersonPermissionType.CredentialsManage })]
        [InlineData("6651887777", new[] { PersonPermissionType.CredentialsRead })]
        [InlineData("6651887777", new[] { PersonPermissionType.Introspection })]
        [InlineData("6651887777", new[] { PersonPermissionType.InvoiceWrite, PersonPermissionType.InvoiceRead })]
        [Trait("Scenario", "Nadanie uprawnień przez osobę z uprawnieniem do zarządzania uprawnieniami")]
        public async Task GivenDelegatedByOwnerIsAuthenticated_WhenGrantInvoiceIssuingPermissionToEntity_ThenPermissionIsConfirmed(string identyficator, PersonPermissionType[] permissions)
        {
            string ownerNIP = MiscellaneousUtils.GetRandomNip();
            string authToken = (await AuthenticationUtils.AuthenticateAsync(KsefClient, SignatureService, ownerNIP)).AccessToken.Token;

            string nipWhichWillDelegatePermissions = MiscellaneousUtils.GetRandomNip();

            GrantPermissionsPersonSubjectIdentifier subjectIdentifier = new GrantPermissionsPersonSubjectIdentifier { Type = GrantPermissionsPersonSubjectIdentifierType.Nip, Value = nipWhichWillDelegatePermissions };

            PersonPermissionType[] managePermission = new[] { PersonPermissionType.CredentialsManage };

            OperationResponse operationResponse = await PermissionsUtils.GrantPersonPermissionsAsync(KsefClient, authToken, subjectIdentifier, permissions);

            await Task.Delay(1000);
            //tests
            await TestGrantPermissions(identyficator, permissions, nipWhichWillDelegatePermissions);

            //revoke permissions to delegate
            IReadOnlyList<PersonPermission> grantedPermissions = await PermissionsUtils.SearchPersonPermissionsAsync(KsefClient, authToken, PersonPermissionState.Active);
            Assert.True(grantedPermissions.Any());

            foreach (PersonPermission item in grantedPermissions)
            {
                OperationResponse revokeSuccessful = await PermissionsUtils.RevokePersonPermissionAsync(KsefClient, authToken, item.Id);
                Assert.NotNull(revokeSuccessful);
                await Task.Delay(3000);
            }

            IReadOnlyList<PersonPermission> activePermissionsAfterRevoke = await PermissionsUtils.SearchPersonPermissionsAsync(KsefClient, authToken, PersonPermissionState.Active);
            Assert.Empty(activePermissionsAfterRevoke);
        }


        private async Task TestGrantPermissions(string identifier, PersonPermissionType[] permissions, string nip)
        {
            string authToken = (await AuthenticationUtils.AuthenticateAsync(KsefClient, SignatureService, nip)).AccessToken.Token;

            bool isNIP = identifier.Length == 10;

            GrantPermissionsPersonSubjectIdentifier subjectIdentifier = new GrantPermissionsPersonSubjectIdentifier { Type = isNIP ? GrantPermissionsPersonSubjectIdentifierType.Nip : GrantPermissionsPersonSubjectIdentifierType.Pesel, Value = identifier };

            OperationResponse grantPermissionsResponse = await PermissionsUtils.GrantPersonPermissionsAsync(KsefClient,
                    authToken,
                    subjectIdentifier,
                    permissions, "CredentialsGrantTests");

            PermissionsOperationStatusResponse grantPermissionsActionStatus = await PermissionsUtils.GetPermissionsOperationStatusAsync(KsefClient, grantPermissionsResponse.ReferenceNumber, authToken);

            await Task.Delay(3000);
            IReadOnlyList<PersonPermission> grantedPermissions = await PermissionsUtils.SearchPersonPermissionsAsync(KsefClient, authToken, PersonPermissionState.Active);
            Assert.True(grantedPermissions.Count == permissions.Length);

            //uwierzytelnienie w kontekście w którym otrzymano uprawnienia
            Core.Models.Authorization.AuthenticationOperationStatusResponse authContext = await AuthenticationUtils.AuthenticateAsync(KsefClient, SignatureService, identifier, nip);
            Assert.NotNull(authContext);
            PersonToken personToken = TokenService.MapFromJwt(authContext.AccessToken.Token);
            Assert.True(personToken.Permissions.Length == permissions.Length);

            foreach (PersonPermission item in grantedPermissions)
            {
                OperationResponse revokeSuccessful = await PermissionsUtils.RevokePersonPermissionAsync(KsefClient, authToken, item.Id);
                Assert.NotNull(revokeSuccessful);
                await Task.Delay(3000);
            }

            IReadOnlyList<PersonPermission> activePermissionsAfterRevoke = await PermissionsUtils.SearchPersonPermissionsAsync(KsefClient, authToken, PersonPermissionState.Active);
            Assert.Empty(activePermissionsAfterRevoke);
        }
    }
}