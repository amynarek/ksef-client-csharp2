using KSeF.Client.Api.Builders.Certificates;
using KSeF.Client.Api.Builders.PersonPermissions;
using KSeF.Client.Api.Builders.X509Certificates;
using KSeF.Client.Core.Exceptions;
using KSeF.Client.Core.Models;
using KSeF.Client.Core.Models.Authorization;
using KSeF.Client.Core.Models.Certificates;
using KSeF.Client.Core.Models.Permissions;
using KSeF.Client.Core.Models.Permissions.Identifiers;
using KSeF.Client.Core.Models.Permissions.Person;
using KSeF.Client.Tests.Utils;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace KSeF.Client.Tests.Core.E2E.Certificates;

[Collection("CertificateScenarioE2ECollection")]
public class CertificatesE2ETests : TestBase
{
    private const string TestCertificateName = "E2E Test Cert";
    private const int CertificateValidityDays = 1;
    private const int StatusCompletedCode = 200;
    private readonly CertificatesScenarioE2EFixture TestFixture;

    private const string GivenName = "Jan";
    private const string Surname = "Kowalski";
    private const string SerialNumberPrefix = "TEST";
    private const string CommonName = "Jan Kowalski";

    private const string OrganizationName = "Spółka Testowa sp. z o.o.";
    private const string OrganizationCommonName = "Spółka Testowa";

    public CertificatesE2ETests()
    {
        TestFixture = new CertificatesScenarioE2EFixture();
    }

    /// <summary>
    /// Logowanie jako właściciel,
    /// nadanie uprawnień CredentialManage dla podmiotu trzeciego.
    /// podmiot delegowany przeprowadza podstawowe operacje 
    /// Właściciel odwołuje uprawnienia dla podmiotu trzeciego.
    /// </summary>
    [Fact]
    public async Task GivenGrantedCredentialManagePermission_WhenThirdPartyCreatesAndRevokesCertificate_ThenCertificateLifecycleCompletesSuccessfully()
    {
        //przygotuj nip właściciela oraz nip pośrednika
        string ownerNip = MiscellaneousUtils.GetRandomNip();
        string delegateNip = MiscellaneousUtils.GetRandomNip();

        //zaloguj jako właściciel 
        AuthenticationOperationStatusResponse ownerAuthProcessResponse = await AuthenticationUtils.AuthenticateAsync(KsefClient, SignatureService, ownerNip);
        string ownerAccessToken = ownerAuthProcessResponse.AccessToken.Token;

        #region nadanie uprawnień CredentialsManage

        GrantPermissionsPersonRequest request = GrantPersonPermissionsRequestBuilder
        .Create()
        .WithSubject(new GrantPermissionsPersonSubjectIdentifier { Type = GrantPermissionsPersonSubjectIdentifierType.Nip, Value = delegateNip })
        .WithPermissions(PersonPermissionType.CredentialsManage)
        .WithDescription("Access for quarterly review")
        .Build();

        OperationResponse operationResult = await KsefClient.GrantsPermissionPersonAsync(request, ownerAccessToken);
        Assert.NotNull(operationResult);

        // Poll status operacji nadania uprawnień do momentu zakończenia (200)
        PermissionsOperationStatusResponse operationStatus =
            await AsyncPollingUtils.PollAsync(
                async () => await KsefClient.OperationsStatusAsync(operationResult.ReferenceNumber, ownerAccessToken, CancellationToken),
                result => result.Status.Code == 200,
                delay: TimeSpan.FromMilliseconds(SleepTime),
                maxAttempts: 30,
                cancellationToken: CancellationToken);

        Assert.NotNull(operationStatus);
        Assert.Equal(200, operationStatus.Status.Code);

        #endregion nadanie uprawnień CredentialsManage

        #region zaloguj jako podmiot trzeci w kontekście właściciela

        AuthenticationOperationStatusResponse delegateAuthOperationStatusResponse =
            await AuthenticationUtils.AuthenticateAsync(KsefClient, SignatureService, delegateNip, ownerNip);
        string delegateAccessToken = delegateAuthOperationStatusResponse.AccessToken.Token;

        #endregion

        //Przeprowadź podstawowe operacje.
        #region Pobierz limity certyfikatów
        // Act
        CertificateLimitResponse certificateLimitsResponse = await GetCertificateLimitsAsync(delegateAccessToken);
        TestFixture.Limits = certificateLimitsResponse;

        // Assert
        Assert.NotNull(TestFixture.Limits);
        Assert.True(TestFixture.Limits.CanRequest);
        #endregion

        #region Pobierz informacje o zarejestrowanych certyfikatach
        // Act
        CertificateEnrollmentsInfoResponse certificateEnrollmentsInfoResponse = await GetCertificateEnrollmentDataAsync(delegateAccessToken);
        TestFixture.EnrollmentInfo = certificateEnrollmentsInfoResponse;

        // Assert
        Assert.NotNull(TestFixture.EnrollmentInfo);
        Assert.NotEmpty(TestFixture.EnrollmentInfo.SerialNumber);
        #endregion

        #region Wyślij zgłoszenie nowe
        // Arrange
        (string csr, string key) = CryptographyService.GenerateCsrWithRsa(TestFixture.EnrollmentInfo, RSASignaturePadding.Pkcs1);
        SendCertificateEnrollmentRequest sendCertificateEnrollmentRequest = SendCertificateEnrollmentRequestBuilder
            .Create()
            .WithCertificateName(TestCertificateName)
            .WithCertificateType(CertificateType.Authentication)
            .WithCsr(csr)
            .WithValidFrom(DateTimeOffset.UtcNow.AddDays(CertificateValidityDays))
            .Build();

        // Act
        CertificateEnrollmentResponse certificateEnrollmentResponse = await SendCertificateEnrollmentAsync(csr, sendCertificateEnrollmentRequest, delegateAccessToken);
        TestFixture.EnrollmentReference = certificateEnrollmentResponse.ReferenceNumber;

        // Assert
        Assert.NotNull(TestFixture.EnrollmentReference);
        Assert.False(string.IsNullOrWhiteSpace(TestFixture.EnrollmentReference));
        #endregion

        #region Sprawdź status rejestracji
        // Act: czekaj aż status będzie 200
        CertificateEnrollmentStatusResponse certificateEnrollmentStatusResponse =
            await AsyncPollingUtils.PollAsync(
                async () => await GetCertificateEnrollmentStatusAsync(delegateAccessToken),
                result => result.Status.Code == StatusCompletedCode,
                delay: TimeSpan.FromSeconds(5),
                maxAttempts: 10,
                cancellationToken: CancellationToken);

        TestFixture.EnrollmentStatus = certificateEnrollmentStatusResponse;

        // Assert
        Assert.Equal(StatusCompletedCode, TestFixture.EnrollmentStatus.Status.Code);
        #endregion

        #region Pobierz zarejestrowany certyfikat
        // Arrange
        TestFixture.SerialNumbers = new List<string> { TestFixture.EnrollmentStatus.CertificateSerialNumber };
        CertificateListRequest certificateListRequest = new CertificateListRequest { CertificateSerialNumbers = TestFixture.SerialNumbers };

        // Act
        CertificateListResponse certificateListResponse = await GetCertificateListAsync(certificateListRequest, delegateAccessToken);
        TestFixture.RetrievedCertificates = certificateListResponse;

        // Assert
        Assert.NotNull(TestFixture.RetrievedCertificates);
        Assert.Single(TestFixture.RetrievedCertificates.Certificates);
        #endregion

        #region Cofnij certyfikat
        // Arrange
        string certificateSerialNumber = TestFixture.RetrievedCertificates.Certificates.ToList().First().CertificateSerialNumber;
        CertificateRevokeRequest certificateRevokeRequest = RevokeCertificateRequestBuilder
            .Create()
            .WithRevocationReason(CertificateRevocationReason.KeyCompromise)
            .Build();

        // Act && Assert
        Exception exception = await Record.ExceptionAsync(async () =>
            await RevokeCertificateAsync(certificateRevokeRequest, certificateSerialNumber, delegateAccessToken)
        );
        Assert.Null(exception);
        #endregion

        #region Pobierz listę metadanych zarejestrowanych certyfikatów
        CertificateMetadataListResponse certificateMetadataListResponse = await GetCertificateMetadataListAsync(delegateAccessToken);
        TestFixture.MetadataList = certificateMetadataListResponse;

        // Assert
        Assert.NotNull(TestFixture.MetadataList);
        Assert.Contains(TestFixture.MetadataList.Certificates.ToList(), m => TestFixture.SerialNumbers.Contains(m.CertificateSerialNumber));
        #endregion

        #region odwołaj uprawnienia

        PagedPermissionsResponse<PersonPermission> permissions =
            await KsefClient
            .SearchGrantedPersonPermissionsAsync(
                new PersonPermissionsQueryRequest { },
                delegateAccessToken,
                pageOffset: 0,
                pageSize: 10,
                CancellationToken);

        Assert.NotEmpty(permissions.Permissions);

        OperationResponse operationResponse = await KsefClient.RevokeCommonPermissionAsync(permissions.Permissions.First().Id, ownerAccessToken, CancellationToken);

        // Poll status operacji cofnięcia uprawnień do 200
        PermissionsOperationStatusResponse revokeOpStatus = await AsyncPollingUtils.PollAsync(
            async () => await KsefClient.OperationsStatusAsync(operationResponse.ReferenceNumber, ownerAccessToken, CancellationToken),
            result => result.Status.Code == 200,
            delay: TimeSpan.FromMilliseconds(SleepTime),
            maxAttempts: 30,
            cancellationToken: CancellationToken);

        Assert.Equal(200, revokeOpStatus.Status.Code);

        // Poll aż lista uprawnień delegata będzie pusta
        permissions = await AsyncPollingUtils.PollAsync(
            async () => await KsefClient
                .SearchGrantedPersonPermissionsAsync(
                    new PersonPermissionsQueryRequest { },
                    delegateAccessToken,
                    pageOffset: 0,
                    pageSize: 10,
                    CancellationToken),
            result => result.Permissions is { Count: 0 },
            delay: TimeSpan.FromMilliseconds(SleepTime),
            maxAttempts: 15,
            cancellationToken: CancellationToken);

        Assert.Empty(permissions.Permissions);
        #endregion zdejmij uprawnienia
    }

    /// <summary>
    /// Sprawdzenie tworzenia osobistego certyfikatu samopodpisanego do podpisu XAdES.
    /// </summary>
    /// <param name="encryptionMethodEnum"></param>
    [Theory]
    [InlineData(EncryptionMethodEnum.Rsa)]
    [InlineData(EncryptionMethodEnum.ECDsa)]
    public void SelfSignedCertificateForSignatureBuilder_Create_ShouldReturnObject(EncryptionMethodEnum encryptionMethodEnum)
    {
        // Arrange
        EncryptionMethodEnum encryptionType = encryptionMethodEnum;
        string serialNumber = MiscellaneousUtils.GetRandomNip();

        // Act
        X509Certificate2 certificate = SelfSignedCertificateForSignatureBuilder
                    .Create()
                    .WithGivenName(GivenName)
                    .WithSurname(Surname)
                    .WithSerialNumber($"{SerialNumberPrefix}-{serialNumber}")
                    .WithCommonName(CommonName)
                    .AndEncryptionType(encryptionType)
                    .Build();

        // Assert
        Assert.NotNull(certificate);
        Assert.True(certificate.HasPrivateKey);
        if (encryptionType == EncryptionMethodEnum.ECDsa)
        {
            Assert.IsAssignableFrom<ECDsa>(certificate.GetECDsaPrivateKey());
        }
        else
        {
            Assert.IsAssignableFrom<RSA>(certificate.GetRSAPrivateKey());
        }
    }

    /// <summary>
    /// Sprawdzenie tworzenia firmowego certyfikatu (company seal) samopodpisanego do podpisu XAdES.
    /// </summary>
    /// <param name="encryptionMethodEnum"></param>
    [Theory]
    [InlineData(EncryptionMethodEnum.Rsa)]
    [InlineData(EncryptionMethodEnum.ECDsa)]
    public void SelfSignedCompanySealForSignatureBuilder_Create_ShouldReturnObject(EncryptionMethodEnum encryptionMethodEnum)
    {
        // Arrange
        string organizationIdentifier = MiscellaneousUtils.GetRandomNip();
        string serialNumber = MiscellaneousUtils.GetRandomNip();

        EncryptionMethodEnum encryptionType = encryptionMethodEnum;

        // Act
        X509Certificate2 certificate = SelfSignedCertificateForSealBuilder
                    .Create()
                    .WithOrganizationName(OrganizationName)
                    .WithOrganizationIdentifier(organizationIdentifier)
                    .WithCommonName(OrganizationCommonName)
                    .Build();

        // Assert
        Assert.NotNull(certificate);
        Assert.True(certificate.HasPrivateKey);
    }

    [Fact]
    public async Task CertificatesLimits_WhenExtended_ShouldThrowException()
    {
        // Arrange
        // uwierzytelnienie
        string ownerNip = MiscellaneousUtils.GetRandomNip();
        AuthenticationOperationStatusResponse authenticationOperationStatusResponse =
            await AuthenticationUtils.AuthenticateAsync(KsefClient, SignatureService, ownerNip);

        // pobieranie limitów
        CertificateLimitResponse certsLimits = await KsefClient.GetCertificateLimitsAsync(authenticationOperationStatusResponse.AccessToken.Token, CancellationToken);
        Assert.NotNull(certsLimits);
        Assert.True(certsLimits.Certificate.Remaining > 0);
        Assert.True(certsLimits.Certificate.Limit > 0);

        // Act - generowanie certyfikatów do wyczerpania limitu
        int certificateMaxLimit = certsLimits.Certificate.Limit;
        int currentIteration = 0;
        List<CertificateEnrollmentStatusResponse> certificates = new List<CertificateEnrollmentStatusResponse>();
        try
        {
            do
            {
                CertificateEnrollmentsInfoResponse enrollmentInfo = await KsefClient.GetCertificateEnrollmentDataAsync(authenticationOperationStatusResponse.AccessToken.Token, CancellationToken);
                (string csr, string key) = CryptographyService.GenerateCsrWithRsa(enrollmentInfo, RSASignaturePadding.Pkcs1);
                
                SendCertificateEnrollmentRequest sendCertificateEnrollmentRequest = SendCertificateEnrollmentRequestBuilder
                    .Create()
                    .WithCertificateName($"{TestCertificateName} {currentIteration + 1}")
                    .WithCertificateType(CertificateType.Authentication)
                    .WithCsr(csr)
                    .WithValidFrom(DateTimeOffset.UtcNow.AddDays(CertificateValidityDays))
                    .Build();
                CertificateEnrollmentResponse certificateEnrollmentResponse = await KsefClient
                    .SendCertificateEnrollmentAsync(sendCertificateEnrollmentRequest, authenticationOperationStatusResponse.AccessToken.Token, CancellationToken);

                CertificateEnrollmentStatusResponse certificate =
                    await AsyncPollingUtils.PollAsync(
                    action: async () => await KsefClient.GetCertificateEnrollmentStatusAsync(
                            certificateEnrollmentResponse.ReferenceNumber,
                            authenticationOperationStatusResponse.AccessToken.Token,
                            CancellationToken)
                    ,
                    condition:  certificate => certificate is not null &&
                                !string.IsNullOrWhiteSpace(certificate.CertificateSerialNumber),
                    delay: TimeSpan.FromSeconds(2),
                    maxAttempts: 10,
                    cancellationToken: CancellationToken);


                certificates.Add(certificate);
                Assert.NotNull(certificateEnrollmentResponse);
                Assert.False(string.IsNullOrWhiteSpace(certificateEnrollmentResponse.ReferenceNumber));

                // sprawdź limity ponownie
                certsLimits = await KsefClient.GetCertificateLimitsAsync(authenticationOperationStatusResponse.AccessToken.Token, CancellationToken);
                Assert.NotNull(certsLimits);
                Assert.True(certsLimits.Certificate.Remaining >= 0);
                Assert.True(certsLimits.Certificate.Limit > 0);
            }
            while (certsLimits.Certificate.Remaining > 0);

            // Assert - żądanie wystawienia certyfikatu przekraczające limit powinno zakończyć się wyjątkiem
            KsefApiException ksefApiException = await Assert.ThrowsAsync<KsefApiException>(async () =>
            {
                CertificateEnrollmentsInfoResponse enrollmentInfo = await KsefClient.GetCertificateEnrollmentDataAsync(authenticationOperationStatusResponse.AccessToken.Token, CancellationToken);
                (string csr, string key) = CryptographyService.GenerateCsrWithRsa(enrollmentInfo, RSASignaturePadding.Pkcs1);
                
                SendCertificateEnrollmentRequest sendCertificateEnrollmentRequest = SendCertificateEnrollmentRequestBuilder
                    .Create()
                    .WithCertificateName($"Test certificate")
                    .WithCertificateType(CertificateType.Authentication)
                    .WithCsr(csr)
                    .WithValidFrom(DateTimeOffset.UtcNow.AddDays(CertificateValidityDays))
                    .Build();
                CertificateEnrollmentResponse certificateEnrollmentResponse = await KsefClient
                    .SendCertificateEnrollmentAsync(sendCertificateEnrollmentRequest, authenticationOperationStatusResponse.AccessToken.Token, CancellationToken);
            });

            string expectedExceptionMessage = "25007: Osiągnięto limit dopuszczalnej liczby posiadanych certyfikatów.";
            Assert.NotNull(ksefApiException);
            Assert.Equal(expectedExceptionMessage, ksefApiException.Message);
        }
        finally
        {
            // czyszczenie - odwołanie wystawionych certyfikatów
            foreach (CertificateEnrollmentStatusResponse certificate in certificates)
            {
                await KsefClient.RevokeCertificateAsync(
                    RevokeCertificateRequestBuilder
                        .Create()
                        .WithRevocationReason(CertificateRevocationReason.Superseded)
                        .Build(),
                    certificate.CertificateSerialNumber,
                    authenticationOperationStatusResponse.AccessToken.Token,
                    CancellationToken);
            }
            await Task.Delay(SleepTime);

            // sprawdzenie limitów po odwołaniu certyfikatów - powinny wrócić do wartości początkowej
            certsLimits = await KsefClient.GetCertificateLimitsAsync(authenticationOperationStatusResponse.AccessToken.Token, CancellationToken);
            Assert.NotNull(certsLimits);
            Assert.True(certsLimits.Certificate.Remaining > 0);
            Assert.True(certsLimits.Certificate.Limit > 0);
        }
    }

    /// <summary>
    /// Pobiera limity certyfikatów dla uwierzytelnionego użytkownika.
    /// </summary>
    /// <returns>Informacje o liczbie wystawionych wniosków oraz certyfikatów.</returns>
    private async Task<CertificateLimitResponse> GetCertificateLimitsAsync(string accessToken)
    {
        CertificateLimitResponse certificateLimitResponse = await KsefClient
            .GetCertificateLimitsAsync(accessToken, CancellationToken);

        return certificateLimitResponse;
    }

    /// <summary>
    /// Pobiera dane niezbędne do wygenerowania CSR.
    /// </summary>
    /// <returns>Dane niezbędne do wygenerowania CSR.</returns>
    private async Task<CertificateEnrollmentsInfoResponse> GetCertificateEnrollmentDataAsync(string accessToken)
    {
        CertificateEnrollmentsInfoResponse certificateEnrollmentsInfoResponse =
            await KsefClient.GetCertificateEnrollmentDataAsync(accessToken, CancellationToken);

        return certificateEnrollmentsInfoResponse;
    }

    /// <summary>
    /// Wysyła żądanie wystawienia certyfikatu.
    /// </summary>
    /// <param name="csr"></param>
    /// <param name="sendCertificateEnrollmentRequest"></param>
    /// <returns>Zwraca numer referencyjny oraz datę i godzinę operacji.</returns>
    private async Task<CertificateEnrollmentResponse> SendCertificateEnrollmentAsync(string csr, SendCertificateEnrollmentRequest sendCertificateEnrollmentRequest, string accessToken)
    {
        CertificateEnrollmentResponse certificateEnrollmentResponse = await KsefClient
            .SendCertificateEnrollmentAsync(sendCertificateEnrollmentRequest, accessToken, CancellationToken);

        return certificateEnrollmentResponse;
    }

    /// <summary>
    /// Pobiera status wystawienia certyfikatu (pojedyncze wywołanie).
    /// </summary>
    private async Task<CertificateEnrollmentStatusResponse> GetCertificateEnrollmentStatusAsync(string accessToken)
    {
        CertificateEnrollmentStatusResponse certificateEnrollmentStatusResponse = await KsefClient
            .GetCertificateEnrollmentStatusAsync(TestFixture.EnrollmentReference, accessToken, CancellationToken);

        return certificateEnrollmentStatusResponse;
    }

    /// <summary>
    /// Pobiera wystawione certyfikaty na podstawie podanych numerów seryjnych.
    /// </summary>
    /// <param name="certificateListRequest"></param>
    /// <returns>Listę wystawionych certyfikatów.</returns>
    private async Task<CertificateListResponse> GetCertificateListAsync(CertificateListRequest certificateListRequest, string accessToken)
    {
        CertificateListResponse certificateListResponse = await KsefClient
            .GetCertificateListAsync(certificateListRequest, accessToken, CancellationToken);

        return certificateListResponse;
    }

    /// <summary>
    /// Odwołuje certyfikat na podstawie podanego numeru seryjnego.
    /// </summary>
    /// <param name="certificateRevokeRequest"></param>
    /// <param name="certificateSerialNumber"></param>
    /// <param name="accessToken"></param>
    private async Task RevokeCertificateAsync(CertificateRevokeRequest certificateRevokeRequest, string certificateSerialNumber, string accessToken)
    {
        await KsefClient
            .RevokeCertificateAsync(certificateRevokeRequest, certificateSerialNumber, accessToken, CancellationToken);
    }

    /// <summary>
    /// Pobiera metadane wystawionych certyfikatów.
    /// </summary>
    /// <param name="accessToken"></param>
    /// <returns>Listę metadanych wystawionych certyfikatów.</returns>
    private async Task<CertificateMetadataListResponse> GetCertificateMetadataListAsync(string accessToken, CertificateMetadataListRequest? requestPayload = null, int pageSize = 10, int pageOffset = 0)
    {
        CertificateMetadataListResponse certificateMetadataListResponse = await KsefClient
            .GetCertificateMetadataListAsync(accessToken, requestPayload, pageSize, pageOffset, CancellationToken);

        return certificateMetadataListResponse;
    }
}