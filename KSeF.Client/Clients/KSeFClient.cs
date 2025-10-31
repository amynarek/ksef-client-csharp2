using KSeF.Client.Core.Models.Authorization;
using KSeF.Client.Core.Models.Certificates;
using KSeF.Client.Core.Models.Invoices;
using KSeF.Client.Core.Models.Peppol;
using KSeF.Client.Core.Models.Permissions;
using KSeF.Client.Core.Models.Permissions.Entity;
using KSeF.Client.Core.Models.Permissions.EUEntity;
using KSeF.Client.Core.Models.Permissions.EuEntityRepresentative;
using KSeF.Client.Core.Models.Permissions.IndirectEntity;
using KSeF.Client.Core.Models.Permissions.Person;
using KSeF.Client.Core.Models.Sessions;
using KSeF.Client.Core.Models.Sessions.ActiveSessions;
using KSeF.Client.Core.Models.Sessions.BatchSession;
using KSeF.Client.Core.Models.Sessions.OnlineSession;
using KSeF.Client.Core.Models;
using System.Text;
using System.Text.RegularExpressions;
using KSeF.Client.Http;
using KSeF.Client.Core.Interfaces.Clients;
using KSeF.Client.Core.Models.Permissions.Authorizations;
using KSeF.Client.Core.Interfaces.Rest;
using KSeF.Client.Core.Models.Permissions.SubUnit;

namespace KSeF.Client.Clients;

/// <inheritdoc />
public class KSeFClient(IRestClient restClient) : IKSeFClient
{
    private readonly IRestClient restClient = restClient;

    /// <inheritdoc />
    public async Task<AuthenticationListResponse> GetActiveSessions(string accessToken, int? pageSize, string continuationToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        StringBuilder urlBuilder = new StringBuilder();

        urlBuilder.Append("/api/v2/auth/sessions");

        if (pageSize.HasValue)
        {
            urlBuilder.Append($"?pageSize={pageSize.Value}");
        }

        string url = urlBuilder.ToString();

        return await restClient.SendAsync<AuthenticationListResponse, object>(HttpMethod.Get,
                                                                            url,
                                                                            default,
                                                                            accessToken,
                                                                            RestClient.DefaultContentType,
                                                                            cancellationToken,
                                                                         !string.IsNullOrEmpty(continuationToken) ?
                                                                          new Dictionary<string, string> { { "x-continuation-token", Regex.Unescape(continuationToken) } }
                                                                              : null).ConfigureAwait(false);

    }

    /// <inheritdoc />
    public async Task RevokeCurrentSessionAsync(string token, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        await restClient.SendAsync(HttpMethod.Delete,
                                   "/api/v2/auth/sessions/current",
                                   token,
                                   RestClient.DefaultContentType,
                                   cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task RevokeSessionAsync(string sessionReferenceNumber, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionReferenceNumber);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        await restClient.SendAsync(HttpMethod.Delete,
                                   $"/api/v2/auth/sessions/{Uri.EscapeDataString(sessionReferenceNumber)}",
                                   accessToken,
                                   RestClient.DefaultContentType,
                                   cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<AuthenticationChallengeResponse> GetAuthChallengeAsync(CancellationToken cancellationToken = default)
    {
        return await restClient.SendAsync<AuthenticationChallengeResponse, string>(HttpMethod.Post,
                                                                                       "/api/v2/auth/challenge",
                                                                                       default,
                                                                                       default,
                                                                                       RestClient.DefaultContentType,
                                                                                       cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<SignatureResponse> SubmitXadesAuthRequestAsync(string signedXML, bool verifyCertificateChain = false, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(signedXML);

        string url = $"/api/v2/auth/xades-signature?verifyCertificateChain={verifyCertificateChain.ToString().ToLower()}";

        return await restClient.SendAsync<SignatureResponse, string>(HttpMethod.Post,
                                                                     url,
                                                                     signedXML,
                                                                     default,
                                                                     RestClient.XmlContentType,
                                                                     cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<SignatureResponse> SubmitKsefTokenAuthRequestAsync(AuthenticationKsefTokenRequest requestPayload, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestPayload);

        return await restClient.SendAsync<SignatureResponse, AuthenticationKsefTokenRequest>(HttpMethod.Post,
                                                                     "/api/v2/auth/ksef-token",
                                                                     requestPayload,
                                                                     default,
                                                                     RestClient.DefaultContentType,
                                                                     cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<AuthStatus> GetAuthStatusAsync(string authOperationReferenceNumber, string authenticationToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticationToken);

        return await restClient.SendAsync<AuthStatus, string>(HttpMethod.Get,
                                                                   $"/api/v2/auth/{Uri.EscapeDataString(authOperationReferenceNumber)}",
                                                                   default,
                                                                   authenticationToken,
                                                                   RestClient.DefaultContentType,
                                                                   cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<AuthenticationOperationStatusResponse> GetAccessTokenAsync(string authenticationToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticationToken);

        return await restClient.SendAsync<AuthenticationOperationStatusResponse, string>(HttpMethod.Post,
                                                                               $"/api/v2/auth/token/redeem",
                                                                               default,
                                                                               authenticationToken,
                                                                               RestClient.DefaultContentType,
                                                                               cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<RefreshTokenResponse> RefreshAccessTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(refreshToken);

        return await restClient.SendAsync<RefreshTokenResponse, string>(HttpMethod.Post,
                                                                        $"/api/v2/auth/token/refresh",
                                                                        default,
                                                                        refreshToken,
                                                                        RestClient.DefaultContentType,
                                                                        cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<OpenOnlineSessionResponse> OpenOnlineSessionAsync(OpenOnlineSessionRequest requestPayload, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestPayload);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        return await restClient.SendAsync<OpenOnlineSessionResponse, OpenOnlineSessionRequest>(HttpMethod.Post,
                                                                                               "/api/v2/sessions/online",
                                                                                               requestPayload,
                                                                                               accessToken,
                                                                                               RestClient.DefaultContentType,
                                                                                               cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<SendInvoiceResponse> SendOnlineSessionInvoiceAsync(SendInvoiceRequest requestPayload, string sessionReferenceNumber, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestPayload);
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionReferenceNumber);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        return await restClient.SendAsync<SendInvoiceResponse, SendInvoiceRequest>(HttpMethod.Post,
                                                                                    $"/api/v2/sessions/online/{Uri.EscapeDataString(sessionReferenceNumber)}/invoices",
                                                                                    requestPayload,
                                                                                    accessToken,
                                                                                    RestClient.DefaultContentType,
                                                                                    cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task CloseOnlineSessionAsync(string sessionReferenceNumber, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionReferenceNumber);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        await restClient.SendAsync(HttpMethod.Post,
                                   $"/api/v2/sessions/online/{sessionReferenceNumber}/close",
                                   accessToken,
                                   RestClient.DefaultContentType,
                                   cancellationToken);
    }

    /// <inheritdoc />
    public async Task<OpenBatchSessionResponse> OpenBatchSessionAsync(OpenBatchSessionRequest requestPayload, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestPayload);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        return await restClient.SendAsync<OpenBatchSessionResponse, OpenBatchSessionRequest>(HttpMethod.Post, "/api/v2/sessions/batch", requestPayload, accessToken, RestClient.DefaultContentType, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task CloseBatchSessionAsync(string batchSessionReferenceNumber, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(batchSessionReferenceNumber);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        await restClient.SendAsync<object>(HttpMethod.Post,
                                           $"/api/v2/sessions/batch/{Uri.EscapeDataString(batchSessionReferenceNumber)}/close",
                                           default, accessToken, RestClient.DefaultContentType, cancellationToken).ConfigureAwait(false);
    }
    /// <inheritdoc />
    public async Task<SessionsListResponse> GetSessionsAsync(SessionType sessionType, string accessToken, int? pageSize, string continuationToken, SessionsFilter sessionsFilter = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        StringBuilder urlBuilder = new StringBuilder();

        urlBuilder.Append($"/api/v2/sessions?sessionType={sessionType}");

        if (pageSize.HasValue)
        {
            urlBuilder.Append($"&pageSize={pageSize.Value}");
        }

        if (sessionsFilter != null)
        {
            if (!string.IsNullOrEmpty(sessionsFilter.ReferenceNumber))
            {
                urlBuilder.Append($"&referenceNumber={Uri.EscapeDataString(sessionsFilter.ReferenceNumber)}");
            }
            if (sessionsFilter.DateCreatedFrom.HasValue)
            {
                urlBuilder.Append($"&dateCreatedFrom={Uri.EscapeDataString(sessionsFilter.DateCreatedFrom.Value.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ"))}");
            }
            if (sessionsFilter.DateCreatedTo.HasValue)
            {
                urlBuilder.Append($"&dateCreatedTo={Uri.EscapeDataString(sessionsFilter.DateCreatedTo.Value.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ"))}");
            }
            if (sessionsFilter.DateClosedFrom.HasValue)
            {
                urlBuilder.Append($"&dateClosedFrom={Uri.EscapeDataString(sessionsFilter.DateClosedFrom.Value.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ"))}");
            }
            if (sessionsFilter.DateClosedTo.HasValue)
            {
                urlBuilder.Append($"&dateClosedTo={Uri.EscapeDataString(sessionsFilter.DateClosedTo.Value.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ"))}");
            }
            if (sessionsFilter.DateModifiedFrom.HasValue)
            {
                urlBuilder.Append($"&dateModifiedFrom={Uri.EscapeDataString(sessionsFilter.DateModifiedFrom.Value.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ"))}");
            }
            if (sessionsFilter.DateModifiedTo.HasValue)
            {
                urlBuilder.Append($"&dateModifiedTo={Uri.EscapeDataString(sessionsFilter.DateModifiedTo.Value.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ"))}");
            }
            if (sessionsFilter.Statuses != null && sessionsFilter.Statuses.Any())
            {
                urlBuilder.Append($"&statuses={Uri.EscapeDataString(string.Join(",", sessionsFilter.Statuses))}");
            }
        }

        string url = urlBuilder.ToString();

        return await restClient.SendAsync<SessionsListResponse, object>(HttpMethod.Get,
                                                                            url,
                                                                            default,
                                                                            accessToken,
                                                                            RestClient.DefaultContentType,
                                                                            cancellationToken,
                                                                            !string.IsNullOrEmpty(continuationToken) ?
                                                                             new Dictionary<string, string> { { "x-continuation-token", Regex.Unescape(continuationToken) } }
                                                                              : null).ConfigureAwait(false);

    }

    /// <inheritdoc />
    public async Task<SessionStatusResponse> GetSessionStatusAsync(string sessionReferenceNumber, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionReferenceNumber);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        return await restClient.SendAsync<SessionStatusResponse, object>(HttpMethod.Get,
                                                                              $"/api/v2/sessions/{Uri.EscapeDataString(sessionReferenceNumber)}",
                                                                              default,
                                                                              accessToken,
                                                                              RestClient.DefaultContentType,
                                                                              cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<SessionInvoicesResponse> GetSessionInvoicesAsync(string sessionReferenceNumber, string accessToken, int? pageSize = null, string continuationToken = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionReferenceNumber);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        StringBuilder urlBuilder = new StringBuilder();

        urlBuilder.Append("/api/v2/sessions/");
        urlBuilder.Append(Uri.EscapeDataString(sessionReferenceNumber));
        urlBuilder.Append("/invoices");

        if (pageSize.HasValue)
        {
            urlBuilder.Append($"?pageSize={pageSize.Value}");
        }

        string url = urlBuilder.ToString();


        return await restClient.SendAsync<SessionInvoicesResponse, object>(HttpMethod.Get,
                                                                                       url,
                                                                                       default,
                                                                                       accessToken,
                                                                                       RestClient.DefaultContentType,
                                                                                       cancellationToken,
                                                                                       !string.IsNullOrEmpty(continuationToken) ?
                                                                                        new Dictionary<string, string> { { "x-continuation-token", Regex.Unescape(continuationToken) } }
                                                                                        : null).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<SessionInvoice> GetSessionInvoiceAsync(string sessionReferenceNumber, string invoiceReferenceNumber, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionReferenceNumber);
        ArgumentException.ThrowIfNullOrWhiteSpace(invoiceReferenceNumber);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        StringBuilder urlBuilder = new StringBuilder();
        urlBuilder.Append("/api/v2/sessions/");
        urlBuilder.Append(Uri.EscapeDataString(sessionReferenceNumber));
        urlBuilder.Append("/invoices/");
        urlBuilder.Append(Uri.EscapeDataString(invoiceReferenceNumber));

        string url = urlBuilder.ToString();

        return await restClient.SendAsync<SessionInvoice, object>(HttpMethod.Get, url, default, accessToken, RestClient.DefaultContentType, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<SessionInvoicesResponse> GetSessionFailedInvoicesAsync(string sessionReferenceNumber, string accessToken, int? pageSize, string continuationToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionReferenceNumber);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        StringBuilder urlBuilder = new StringBuilder();

        urlBuilder.Append("/api/v2/sessions/");
        urlBuilder.Append(Uri.EscapeDataString(sessionReferenceNumber));
        urlBuilder.Append("/invoices/failed");

        if (pageSize.HasValue)
        {
            urlBuilder.Append($"?pageSize={pageSize.Value}");
        }

        string url = urlBuilder.ToString();

        return await restClient.SendAsync<SessionInvoicesResponse, object>(HttpMethod.Get,
                                                                            url,
                                                                            default,
                                                                            accessToken,
                                                                            RestClient.DefaultContentType,
                                                                            cancellationToken,
                                                                            !string.IsNullOrEmpty(continuationToken) ?
                                                                             new Dictionary<string, string> { { "x-continuation-token", Regex.Unescape(continuationToken) } }
                                                                              : null).ConfigureAwait(false);

    }

    /// <inheritdoc />
    public async Task<string> GetSessionInvoiceUpoByKsefNumberAsync(string sessionReferenceNumber, string ksefNumber, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionReferenceNumber);
        ArgumentException.ThrowIfNullOrWhiteSpace(ksefNumber);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        StringBuilder urlBuilder = new StringBuilder();

        urlBuilder.Append("/api/v2/sessions/");
        urlBuilder.Append(Uri.EscapeDataString(sessionReferenceNumber));
        urlBuilder.Append("/invoices/ksef/");
        urlBuilder.Append(Uri.EscapeDataString(ksefNumber));
        urlBuilder.Append("/upo");

        string url = urlBuilder.ToString();

        return await restClient.SendAsync<string, object>(HttpMethod.Get, url, default, accessToken, RestClient.DefaultContentType, cancellationToken).ConfigureAwait(false);

    }

    /// <inheritdoc />
    public async Task<string> GetSessionInvoiceUpoByReferenceNumberAsync(string sessionReferenceNumber, string invoiceReferenceNumber, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionReferenceNumber);
        ArgumentException.ThrowIfNullOrWhiteSpace(invoiceReferenceNumber);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        StringBuilder urlBuilder = new StringBuilder();

        urlBuilder.Append("/api/v2/sessions/");
        urlBuilder.Append(Uri.EscapeDataString(sessionReferenceNumber));
        urlBuilder.Append("/invoices/");
        urlBuilder.Append(Uri.EscapeDataString(invoiceReferenceNumber));
        urlBuilder.Append("/upo");

        string url = urlBuilder.ToString();

        return await restClient.SendAsync<string, object>(HttpMethod.Get, url, default, accessToken, RestClient.DefaultContentType, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<string> GetSessionUpoAsync(string sessionReferenceNumber, string upoReferenceNumber, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionReferenceNumber);
        ArgumentException.ThrowIfNullOrWhiteSpace(upoReferenceNumber);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        StringBuilder urlBuilder = new StringBuilder();
        urlBuilder.Append("/api/v2/sessions/");
        urlBuilder.Append(Uri.EscapeDataString(sessionReferenceNumber));
        urlBuilder.Append("/upo/");
        urlBuilder.Append(Uri.EscapeDataString(upoReferenceNumber));

        string url = urlBuilder.ToString();

        return await restClient.SendAsync<string, object>(HttpMethod.Get, url, default, accessToken, RestClient.DefaultContentType, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<string> GetInvoiceAsync(string ksefNumber, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ksefNumber);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        StringBuilder urlBuilder = new StringBuilder();
        urlBuilder.Append("/api/v2/invoices/ksef/");
        urlBuilder.Append(Uri.EscapeDataString(ksefNumber));

        string url = urlBuilder.ToString();

        return await restClient.SendAsync<string, object>(HttpMethod.Get, url, default, accessToken, RestClient.XmlContentType, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<PagedInvoiceResponse> QueryInvoiceMetadataAsync(InvoiceQueryFilters requestPayload, string accessToken, int? pageOffset = null, int? pageSize = null, SortOrder sortOrder = SortOrder.Asc, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestPayload);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        StringBuilder urlBuilder = new StringBuilder($"/api/v2/invoices/query/metadata?sortOrder={sortOrder}");

        Pagination(pageOffset, pageSize, urlBuilder, true);

        return await restClient.SendAsync<PagedInvoiceResponse, InvoiceQueryFilters>(HttpMethod.Post,
                                                                    urlBuilder.ToString(),
                                                                    requestPayload,
                                                                    accessToken,
                                                                    RestClient.DefaultContentType,
                                                                    cancellationToken)
                                                                    .ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<PermissionsOperationStatusResponse> OperationsStatusAsync(string operationReferenceNumber, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operationReferenceNumber);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        StringBuilder urlBuilder = new StringBuilder();

        urlBuilder.Append("/api/v2/permissions/operations/");
        urlBuilder.Append(Uri.EscapeDataString(operationReferenceNumber));

        return await restClient.SendAsync<PermissionsOperationStatusResponse, string>(HttpMethod.Get,
                                                                                      urlBuilder.ToString(),
                                                                                      default,
                                                                                      accessToken,
                                                                                      RestClient.DefaultContentType,
                                                                                      cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<OperationResponse> RevokeCommonPermissionAsync(string permissionId, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(permissionId);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        return await restClient.SendAsync<OperationResponse, string>(HttpMethod.Delete,
                                                             $"/api/v2/permissions/common/grants/{Uri.EscapeDataString(permissionId)}",
                                                             default,
                                                             accessToken,
                                                             RestClient.DefaultContentType,
                                                             cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<OperationResponse> RevokeAuthorizationsPermissionAsync(string permissionId, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(permissionId);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        return await restClient.SendAsync<OperationResponse, string>(HttpMethod.Delete,
                                                             $"/api/v2/permissions/authorizations/grants/{Uri.EscapeDataString(permissionId)}",
                                                             default,
                                                             accessToken,
                                                             RestClient.DefaultContentType,
                                                             cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<PermissionsAttachmentAllowedResponse> GetAttachmentPermissionStatusAsync(string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        return await restClient.SendAsync<PermissionsAttachmentAllowedResponse, string>(HttpMethod.Get,
                                                             "/api/v2/permissions/attachments/status",
                                                             default,
                                                             accessToken,
                                                             RestClient.DefaultContentType,
                                                             cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<PagedPermissionsResponse<PersonalPermission>> SearchGrantedPersonalPermissionsAsync(
        PersonalPermissionsQueryRequest requestPayload,
              string accessToken,
              int? pageOffset = null,
              int? pageSize = null,
              CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestPayload);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        StringBuilder urlBuilder = new StringBuilder("/api/v2/permissions/query/personal/grants");

        Pagination(pageOffset, pageSize, urlBuilder);

        return await restClient.SendAsync<PagedPermissionsResponse<PersonalPermission>, PersonalPermissionsQueryRequest>(
            HttpMethod.Post,
            urlBuilder.ToString(),
            requestPayload,
            accessToken,
            RestClient.DefaultContentType,
            cancellationToken
        ).ConfigureAwait(false);
    }
    /// <inheritdoc />
    public async Task<PagedPermissionsResponse<PersonPermission>> SearchGrantedPersonPermissionsAsync(
              PersonPermissionsQueryRequest requestPayload,
              string accessToken,
              int? pageOffset = null,
              int? pageSize = null,
              CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestPayload);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        StringBuilder urlBuilder = new StringBuilder("/api/v2/permissions/query/persons/grants");

        Pagination(pageOffset, pageSize, urlBuilder);

        return await restClient.SendAsync<PagedPermissionsResponse<PersonPermission>, PersonPermissionsQueryRequest>(
            HttpMethod.Post,
            urlBuilder.ToString(),
            requestPayload,
            accessToken,
            RestClient.DefaultContentType,
            cancellationToken
        ).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<PagedPermissionsResponse<SubunitPermission>> SearchSubunitAdminPermissionsAsync(
               SubunitPermissionsQueryRequest request,
               string accessToken,
               int? pageOffset = null,
               int? pageSize = null,
               CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        StringBuilder urlBuilder = new StringBuilder("/api/v2/permissions/query/subunits/grants");

        Pagination(pageOffset, pageSize, urlBuilder);

        return await restClient.SendAsync<PagedPermissionsResponse<SubunitPermission>, SubunitPermissionsQueryRequest>(
            HttpMethod.Post,
            urlBuilder.ToString(),
            request,
            accessToken,
            RestClient.DefaultContentType,
            cancellationToken
        ).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<PagedRolesResponse<EntityRole>> SearchEntityInvoiceRolesAsync(
             string accessToken,
             int? pageOffset = null,
             int? pageSize = null,
             CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        StringBuilder urlBuilder = new StringBuilder("/api/v2/permissions/query/entities/roles");

        Pagination(pageOffset, pageSize, urlBuilder);

        return await restClient.SendAsync<PagedRolesResponse<EntityRole>, object>(
            HttpMethod.Get,
            urlBuilder.ToString(),
            default,
            accessToken,
            RestClient.DefaultContentType,
            cancellationToken
        ).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<PagedRolesResponse<SubordinateEntityRole>> SearchSubordinateEntityInvoiceRolesAsync(
           SubordinateEntityRolesQueryRequest request,
           string accessToken,
           int? pageOffset,
           int? pageSize,
           CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        StringBuilder urlBuilder = new StringBuilder("/api/v2/permissions/query/subordinate-entities/roles");

        Pagination(pageOffset, pageSize, urlBuilder);

        return await restClient.SendAsync<PagedRolesResponse<SubordinateEntityRole>, SubordinateEntityRolesQueryRequest>(
            HttpMethod.Post,
            urlBuilder.ToString(),
            request,
            accessToken,
            RestClient.DefaultContentType,
            cancellationToken
        ).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<PagedAuthorizationsResponse<AuthorizationGrant>> SearchEntityAuthorizationGrantsAsync(
                   EntityAuthorizationsQueryRequest requestPayload,
                   string accessToken,
                   int? pageOffset,
                   int? pageSize,
                   CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestPayload);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        StringBuilder urlBuilder = new StringBuilder("/api/v2/permissions/query/authorizations/grants");

        Pagination(pageOffset, pageSize, urlBuilder);

        return await restClient.SendAsync<PagedAuthorizationsResponse<AuthorizationGrant>, EntityAuthorizationsQueryRequest>(
            HttpMethod.Post,
            urlBuilder.ToString(),
            requestPayload,
            accessToken,
            RestClient.DefaultContentType,
            cancellationToken
        ).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<PagedPermissionsResponse<EuEntityPermission>> SearchGrantedEuEntityPermissionsAsync(
           EuEntityPermissionsQueryRequest request,
           string accessToken,
           int? pageOffset = null,
           int? pageSize = null,
           CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        StringBuilder urlBuilder = new StringBuilder("/api/v2/permissions/query/eu-entities/grants");

        Pagination(pageOffset, pageSize, urlBuilder);

        return await restClient.SendAsync<PagedPermissionsResponse<EuEntityPermission>, EuEntityPermissionsQueryRequest>(
            HttpMethod.Post,
            urlBuilder.ToString(),
            request,
            accessToken,
            RestClient.DefaultContentType,
            cancellationToken
        ).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<OperationResponse> GrantsPermissionPersonAsync(GrantPermissionsPersonRequest requestPayload, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestPayload);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        return await restClient.SendAsync<OperationResponse, GrantPermissionsPersonRequest>(HttpMethod.Post,
                                                                                      "/api/v2/permissions/persons/grants",
                                                                                      requestPayload,
                                                                                      accessToken,
                                                                                      RestClient.DefaultContentType,
                                                                                      cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<OperationResponse> GrantsPermissionEntityAsync(GrantPermissionsEntityRequest requestPayload, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestPayload);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        return await restClient.SendAsync<OperationResponse,
            GrantPermissionsEntityRequest>(HttpMethod.Post,
                                           "/api/v2/permissions/entities/grants",
                                           requestPayload,
                                           accessToken,
                                           RestClient.DefaultContentType,
                                           cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<OperationResponse> GrantsAuthorizationPermissionAsync(GrantPermissionsAuthorizationRequest requestPayload, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestPayload);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        return await restClient.SendAsync<OperationResponse, GrantPermissionsAuthorizationRequest>(HttpMethod.Post,
                                 "/api/v2/permissions/authorizations/grants",
                                 requestPayload,
                                 accessToken,
                                 RestClient.DefaultContentType,
                                 cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<OperationResponse> GrantsPermissionIndirectEntityAsync(
        GrantPermissionsIndirectEntityRequest requestPayload, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestPayload);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        return await restClient.SendAsync<OperationResponse, GrantPermissionsIndirectEntityRequest>(HttpMethod.Post,
                                                                                       "/api/v2/permissions/indirect/grants",
                                                                                       requestPayload,
                                                                                       accessToken,
                                                                                       RestClient.DefaultContentType,
                                                                                       cancellationToken).ConfigureAwait(false);
    }


    /// <inheritdoc />
    public async Task<OperationResponse> GrantsPermissionSubUnitAsync(
        GrantPermissionsSubunitRequest requestPayload, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestPayload);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        return await restClient.SendAsync<OperationResponse,
            GrantPermissionsSubunitRequest>(HttpMethod.Post,
                                                                                 "/api/v2/permissions/subunits/grants",
                                                                                 requestPayload,
                                                                                 accessToken,
                                                                                 RestClient.DefaultContentType,
                                                                                 cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<OperationResponse> GrantsPermissionEUEntityAsync(
       GrantPermissionsEuEntityRequest requestPayload, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestPayload);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        return await restClient.SendAsync<OperationResponse, GrantPermissionsEuEntityRequest>(
            HttpMethod.Post, "/api/v2/permissions/eu-entities/administration/grants", requestPayload, accessToken, RestClient.DefaultContentType, cancellationToken
        ).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<OperationResponse> GrantsPermissionEUEntityRepresentativeAsync(
        GrantPermissionsEuEntityRepresentativeRequest requestPayload, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestPayload);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        return await restClient.SendAsync<OperationResponse, GrantPermissionsEuEntityRepresentativeRequest>(
            HttpMethod.Post, "/api/v2/permissions/eu-entities/grants", requestPayload, accessToken, RestClient.DefaultContentType, cancellationToken
        ).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<CertificateLimitResponse> GetCertificateLimitsAsync(string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        return await restClient.SendAsync<CertificateLimitResponse, object>(HttpMethod.Get, "/api/v2/certificates/limits", default, accessToken, RestClient.DefaultContentType, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<CertificateEnrollmentsInfoResponse> GetCertificateEnrollmentDataAsync(string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        return await restClient.SendAsync<CertificateEnrollmentsInfoResponse, object>(HttpMethod.Get,
                                                                                      "/api/v2/certificates/enrollments/data",
                                                                                      default,
                                                                                      accessToken,
                                                                                      RestClient.DefaultContentType,
                                                                                      cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<CertificateEnrollmentResponse> SendCertificateEnrollmentAsync(SendCertificateEnrollmentRequest requestPayload, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestPayload);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        return await restClient.SendAsync<CertificateEnrollmentResponse, SendCertificateEnrollmentRequest>(HttpMethod.Post,
                                                                                                           "/api/v2/certificates/enrollments",
                                                                                                           requestPayload,
                                                                                                           accessToken,
                                                                                                           RestClient.DefaultContentType,
                                                                                                           cancellationToken)
                                                                                                         .ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<CertificateEnrollmentStatusResponse> GetCertificateEnrollmentStatusAsync(string enrollmentReferenceNumber, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(enrollmentReferenceNumber);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        return await restClient.SendAsync<CertificateEnrollmentStatusResponse, string>(HttpMethod.Get,
                                                                                       $"/api/v2/certificates/enrollments/{Uri.EscapeDataString(enrollmentReferenceNumber)}",
                                                                                       default, accessToken,
                                                                                       RestClient.DefaultContentType,
                                                                                       cancellationToken).ConfigureAwait(false);

    }

    /// <inheritdoc />
    public async Task<CertificateListResponse> GetCertificateListAsync(CertificateListRequest requestPayload, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestPayload);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        return await restClient.SendAsync<CertificateListResponse, CertificateListRequest>(HttpMethod.Post,
                                                                                           $"/api/v2/certificates/retrieve",
                                                                                           requestPayload, accessToken,
                                                                                           RestClient.DefaultContentType,
                                                                                           cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task RevokeCertificateAsync(CertificateRevokeRequest requestPayload, string serialNumber, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestPayload);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);
        ArgumentException.ThrowIfNullOrWhiteSpace(serialNumber);

        await restClient.SendAsync(HttpMethod.Post,
                                   $"/api/v2/certificates/{Uri.EscapeDataString(serialNumber)}/revoke",
                                   requestPayload,
                                   accessToken,
                                   RestClient.DefaultContentType,
                                   cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<CertificateMetadataListResponse> GetCertificateMetadataListAsync(
       string accessToken,
       CertificateMetadataListRequest requestPayload = null,
       int? pageSize = null,
       int? pageOffset = null,
       CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        StringBuilder urlBuilder = new StringBuilder("/api/v2/certificates/query");

        Pagination(pageOffset, pageSize, urlBuilder);

        return await restClient.SendAsync<CertificateMetadataListResponse, CertificateMetadataListRequest>(
            HttpMethod.Post,
            urlBuilder.ToString(),
            requestPayload,
            accessToken,
            RestClient.DefaultContentType,
            cancellationToken
        ).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<KsefTokenResponse> GenerateKsefTokenAsync(KsefTokenRequest requestPayload, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestPayload);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        return await restClient.SendAsync<KsefTokenResponse, KsefTokenRequest>(HttpMethod.Post,
                                                                               "/api/v2/tokens",
                                                                               requestPayload,
                                                                               accessToken,
                                                                               RestClient.DefaultContentType,
                                                                               cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<QueryKsefTokensResponse> QueryKsefTokensAsync(
    string accessToken,
    ICollection<AuthenticationKsefTokenStatus> statuses = null,
    string authorIdentifier = null,
    Core.Models.Token.TokenContextIdentifierType? authorIdentifierType = null,
    string description = null,
    string continuationToken = null,
    int? pageSize = 10,
    CancellationToken cancellationToken = default)
    {
        StringBuilder urlBuilder = new StringBuilder("/api/v2/tokens?");

        if (statuses != null && statuses.Any())
        {
            foreach (AuthenticationKsefTokenStatus s in statuses)
            {
                urlBuilder.Append($"status={Uri.EscapeDataString(s.ToString())}&");
            }
        }

        if (!string.IsNullOrWhiteSpace(authorIdentifier))
        {
            urlBuilder.Append($"authorIdentifier={Uri.EscapeDataString(authorIdentifier)}&");
        }

        if (authorIdentifierType.HasValue)
        {
            urlBuilder.Append($"authorIdentifierType={authorIdentifierType.Value}&");
        }

        if (!string.IsNullOrWhiteSpace(description))
        {
            urlBuilder.Append($"description={Uri.EscapeDataString(description)}&");
        }

        Pagination(null, pageSize, urlBuilder);

        return await restClient.SendAsync<QueryKsefTokensResponse, string>(
            HttpMethod.Get,
            urlBuilder.ToString().TrimEnd('&'),
            default,
            accessToken,
            RestClient.DefaultContentType,
            cancellationToken,
            !string.IsNullOrWhiteSpace(continuationToken)
                            ? new Dictionary<string, string> { { "x-continuation-token", Regex.Unescape(continuationToken) } }
                            : null
                    ).ConfigureAwait(false);
    }



    /// <inheritdoc />
    public async Task<AuthenticationKsefToken> GetKsefTokenAsync(string tokenReferenceNumber, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenReferenceNumber);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        return await restClient.SendAsync<AuthenticationKsefToken, string>(HttpMethod.Get,
                                                                            $"/api/v2/tokens/{Uri.EscapeDataString(tokenReferenceNumber)}",
                                                                            default,
                                                                            accessToken,
                                                                            RestClient.DefaultContentType,
                                                                            cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task RevokeKsefTokenAsync(string tokenReferenceNumber, string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenReferenceNumber);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        await restClient.SendAsync(HttpMethod.Delete,
                                   $"/api/v2/tokens/{Uri.EscapeDataString(tokenReferenceNumber)}",
                                   accessToken,
                                   RestClient.DefaultContentType,
                                   cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<QueryPeppolProvidersResponse> QueryPeppolProvidersAsync(
     string accessToken,
     int? pageOffset = null,
     int? pageSize = null,
     CancellationToken cancellationToken = default)
    {
        StringBuilder urlBuilder = new StringBuilder("/api/v2/peppol/query?");

        if (pageOffset.HasValue)
            urlBuilder.Append($"pageOffset={pageOffset.Value}&");

        if (pageSize.HasValue)
            urlBuilder.Append($"pageSize={pageSize.Value}&");

        string url = urlBuilder.ToString().TrimEnd('&').TrimEnd('?');

        return await restClient.SendAsync<QueryPeppolProvidersResponse, string>(
            HttpMethod.Get,
            url,
            default,
            accessToken,
            RestClient.DefaultContentType,
            cancellationToken
        ).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task SendBatchPartsAsync(OpenBatchSessionResponse openBatchSessionResponse, ICollection<BatchPartSendingInfo> parts, CancellationToken cancellationToken = default)
    {
        if (parts == null || parts.Count == 0)
            throw new ArgumentException("Brak plików do wysłania.", nameof(parts));

        await SendPackagePartsAsync(
            openBatchSessionResponse.PartUploadRequests,
            parts,
            (info) => new ByteArrayContent(info.Data),
            cancellationToken
        ).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task SendBatchPartsWithStreamAsync(OpenBatchSessionResponse openBatchSessionResponse, ICollection<BatchPartStreamSendingInfo> parts, CancellationToken cancellationToken = default)
    {
        if (parts == null || parts.Count == 0)
            throw new ArgumentException("Brak plików do wysłania.", nameof(parts));

        await SendPackagePartsAsync(
            openBatchSessionResponse.PartUploadRequests,
            parts,
            (info) => new StreamContent(info.DataStream),
            cancellationToken
        ).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<OperationResponse> ExportInvoicesAsync(
    InvoiceExportRequest requestPayload,
    string accessToken,
    CancellationToken cancellationToken = default,
    bool includeMetadata = true)
    {
        ArgumentNullException.ThrowIfNull(requestPayload);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        StringBuilder urlBuilder = new StringBuilder("/api/v2/invoices/exports");

        Dictionary<string, string> headers = null;
        if (includeMetadata)
        {
            headers = new Dictionary<string, string>
            {
                ["x-ksef-feature"] = "include-metadata"
            };
        }

        return await restClient.SendAsync<OperationResponse, InvoiceExportRequest>(
            HttpMethod.Post,
            urlBuilder.ToString(),
            requestPayload,
            accessToken,
            RestClient.DefaultContentType,
            cancellationToken,
            headers
        ).ConfigureAwait(false);
    }
    /// <inheritdoc />
    public async Task<InvoiceExportStatusResponse> GetInvoiceExportStatusAsync(
    string referenceNumber,
    string accessToken,
    CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(referenceNumber);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);

        string url = $"/api/v2/invoices/exports/{Uri.EscapeDataString(referenceNumber)}";

        return await restClient.SendAsync<InvoiceExportStatusResponse, object>(
            HttpMethod.Get,
            url,
            default,
            accessToken,
            RestClient.DefaultContentType,
            cancellationToken
        ).ConfigureAwait(false);
    }
    /// <inheritdoc />
    public async Task<string> GetUpoAsync(Uri uri, CancellationToken cancellationToken = default)
    {
        return await restClient.SendAsync<string, object>(
            method: HttpMethod.Get,
            url: uri.ToString(),
            requestBody: null,
            token: null,
            contentType: default,
            cancellationToken: cancellationToken
        ).ConfigureAwait(false);
    }

    private async Task SendPackagePartsAsync<TInfo>(
        ICollection<PackagePartSignatureInitResponseType> parts,
        ICollection<TInfo> batchPartSendingInfos,
        Func<TInfo, HttpContent> contentFactory,
        CancellationToken cancellationToken = default)
        where TInfo : class
    {
        if (parts == null)
            throw new InvalidOperationException("Brak informacji o częściach paczki do wysłania.");

        List<string> errors = new List<string>();

        foreach (PackagePartSignatureInitResponseType part in parts)
        {
            TInfo fileInfo = batchPartSendingInfos.FirstOrDefault(x =>
                (int)x.GetType().GetProperty("OrdinalNumber")!.GetValue(x)! == part.OrdinalNumber);

            if (fileInfo == null)
            {
                errors.Add($"Brak danych dla części paczki {part.OrdinalNumber}.");
                continue;
            }

            using HttpContent content = contentFactory(fileInfo);

            if (string.IsNullOrWhiteSpace(part.Method))
            {
                errors.Add($"Brak metody HTTP dla części paczki {part.OrdinalNumber}.");
                continue;
            }

            try
            {
                await restClient.SendAsync(
                    new HttpMethod(part.Method.ToUpperInvariant()),
                    part.Url.ToString(),
                    content,
                    part.Headers,
                    cancellationToken
                ).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                errors.Add($"Błąd wysyłki części paczki {part.OrdinalNumber}: {ex.Message}");
            }
        }

        if (errors.Count > 0)
        {
            throw new AggregateException(
                "Wystąpiły błędy podczas wysyłania części paczki.",
                errors.Select(e => new Exception(e))
            );
        }
    }

    private static void Pagination(int? pageOffset, int? pageSize, StringBuilder urlBuilder,bool hasQuery = false)
    {
        if (pageSize.HasValue && pageSize > 0)
        {
            urlBuilder.Append(hasQuery ? "&" : "?");
            urlBuilder.Append("pageSize=").Append(Uri.EscapeDataString(pageSize.ToString()));
            hasQuery = true;
        }
        if (pageOffset.HasValue && pageOffset > 0)
        {
            urlBuilder.Append(hasQuery ? "&" : "?");
            urlBuilder.Append("pageOffset=").Append(Uri.EscapeDataString(pageOffset.ToString()));
            hasQuery = true;
        }
    }
}