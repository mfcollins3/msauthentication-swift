// Copyright 2024 Michael F. Collins, III
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to eal in the Software without restriction including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shell be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

import Foundation
import MSAL

public struct AuthenticationError: Error {
    public enum ErrorType {
        /// The operation requires interaction with the user.
        ///
        /// This error can happen for a number of reasons. For example, when
        /// attempting to use the acquireTokenSilent function to acquire a valid
        /// access token using an account that previously logged in on the device,
        /// the authorization service may determine that the access token cannot
        /// be released and that the user must re-authenticate with the Microsoft
        /// identity service.
        case interactionRequired
        
        /// internalError indicates an unrecoverable error occurred within the MSAL
        /// client or on the server.
        ///
        /// Generally, internalError errors cannot be recovered at runtime. The
        /// error should be logged and reported. The specific internal failure is
        /// described by the attched AuthenticationInternalError value.
        case internalError(InternalErrorType)
        
        /// The request was not fully completed and some scopes were not granted
        /// access to.
        ///
        /// This error can be caused by a user declining consent on certain scopes.
        case serverDeclinedScopes(granted: [String]?, declined: [String]?)
        
        ///The server returned a server error.
        case serverError
        
        /// The requested resource is protected by an Intime Conditional Access
        /// policy.
        ///
        /// The calling application should integrate the Intune SDK and call the
        /// remediateComplianceForIdentity:silent: API.
        case serverProtectionPoliciesRequired
        
        /// The user cancelled the web authentication session by tapping the
        /// "Done" or "Cancel" button in the web browser.
        case userCanceled
        
        /// Workplace hoin is required to proceed.
        case workplaceJoinRequired
    }
    
    /// InternalErrorType is used to report internal errors from the
    /// Microsoft Authentication library or reported by the server.
    ///
    /// The internal errors are unrecoverable errors. They are returned for logging
    /// and debugging purposes.
    public enum InternalErrorType {
        /// MSAL requires a non-nill account for the acquire token silent call.
        case accountRequired
        
        /// Multiple accounts were found in cache.
        ///
        /// Use the getAccounts: API which supports multiple accounts.
        case ambiguousAccount
        
        /// The user or application failed to authenticate in the interactive flow.
        ///
        /// The attached values contain more detailed information about the error.
        case authorizationFailed(error: String?, description: String?)
        
        /// MSAL tried to open a URL from an extension, which is not allowed.
        case attemptToOpenURLFromExtension
        
        /// Failed to read the broker application token.
        case brokerApplicationTokenReadFailed
        
        /// Failed to write the broker application token.
        case brokerApplicationTokenWriteFailed
        
        /// MSAL cannot read broker resume state.
        ///
        /// The state is probably corrupted.
        case brokerBadResumeStateFound
        
        /// Corrupted broker response.
        case brokerCorruptedResponse
        
        /// Failed to create broker key.
        case brokerKeyFailedToCreate
        
        /// Could not read the broker key.
        ///
        /// The broker's key might have been wiped from the keychain.
        case brokerKeyNotFound
        
        /// MSAL cannot read broker resume state.
        ///
        /// The saved resume state is for a different redirect URI. The application
        /// should check its registered schema.
        case brokerMismatchedResumeState
        
        /// MSAL cannot read broker resume state.
        ///
        /// The application might have removed the state, or UserDefaults is
        /// corrupted.
        case brokerNoResumeStateFound
        
        /// The broker is either not found on the device or is not available for
        /// this configuration.
        case brokerNotAvailable
        
        /// Decryption of the broker response failed.
        case brokerResponseDecryptionFailed
        
        /// Unexpected broker response hash.
        case brokerResponseHashMismatch
        
        /// Invalid broker response.
        case brokerResponseHashMissing
        
        /// The user returned manually to the application without completing
        /// authentication inside the broker.
        case brokerResponseNotReceived
        
        /// The broker returned an unreadable result.
        case brokerUnknown
        
        /// The device is not PSSO registered.
        case deviceNotPSSORegistered
        
        /// The passed in authority URL does not pass validation.
        ///
        /// If you are trying to use B2C, you must disable authority validation
        /// by setting validateAuthority of MSPublicClientApplication to false.
        case failedAuthorityValidation
        
        /// An interactive authentication session is already running with the web
        /// browser visible.
        ///
        /// This error occurs when an authentication session is being requested,
        /// but another request is currently running.
        case interactiveSessionAlreadyRunning
        
        /// Client authentication filed.
        ///
        /// invalidClient typically occurs if the client id or client secret are
        /// not valid. To fix, the application administrator needs to update the
        /// values.
        case invalidClient
        
        /// The provided grant is invalid or has expired.
        ///
        /// This might be recoverable by re-attempting to authorize the
        /// application.
        case invalidGrant
        
        /// A required parameter was not provided, or a passed in parameter was
        /// invalid.
        ///
        /// The attached value contains a description of the problem parameter.
        case invalidParameter(String)
        
        /// A protocol error occurred, such as a missing required parameter.
        case invalidRequest
        
        /// A response was returned in a network call, but the response body was
        /// invalid.
        case invalidResponse
        
        /// An invalid scope parameeter was specified.
        case invalidScope
        
        /// The state returned by the server does not match the state that was
        /// sent to the server at the beginning of the authorization attempt.
        case invalidState
        
        /// JIT - Compliance Check - Could not create compliance check web view
        /// controller.
        case jitComplianceCheckCreateController
        
        /// JIT - Compliance Check - Invalid linkPayload from SSO configuration.
        case jitComplianceCheckInvalidLinkPayload
        
        /// JIT - Compliance Check = Device not compliant
        case jitComplianceCheckResultNotCompliant
        
        /// JIT - Compliance Check - CP timeout
        case jitComplianceCheckResultTimeout
        
        /// JIT - Compliance Check - Result unknown
        case jitComplianceCheckResultUnknown
        
        /// JIT - Link - Invalid LinkTokenConfig
        case jitInvalidLinkTokenConfig
        
        /// JIT - Link - Error while acquiring intune token.
        case jitLinkAcquireTokenError
        
        /// JIT - Link - LinkConfig not found.
        case jitLinkConfigNotFound
        
        /// JIT - Link - Error during linking.
        case jitLinkError
        
        /// JIT - Link - Error while waiting for server confirmation.
        case jitLinkServerConfirmationError
        
        /// JIT - Link - Timeout while waiting for server confirmation.
        case jitLinkServerConfirmationTimeout
        
        /// JIT - Link - Token acquired for wrong tenant.
        case jitLinkTokenAcquiredWrongTenant
        
        /// JIT - Retry JIT process (WPJ or Link)
        case jitRetryRequired
        
        /// JIT - Troubleshooting - Acquire token error.
        case jitTroubleshootingAcquireToken
        
        /// JIT - Troubleshooting - Could not create web view controller.
        case jitTroubleshootingCreateController
        
        /// JIT - Troubleshooting flow needed.
        case jitTroubleshootingRequired
        
        /// JIT - Troubleshooting - Result unknown.
        case jitTroubleshootingResultUnknown
        
        /// JIT - Unexpected status received from webCP troubleshooting flow.
        case jitUnknownStatusWebCP
        
        /// JIT - WPJ - AccountIdentifier is nil.
        case jitWPJAccountIdentifierNil
        
        /// JIT - WPJ - Failed to acquire broken token.
        case jitWPJAcquireTokenError
        
        /// JIT - WPJ - Device registration failed.
        case jitWPJDeviceRegistrationFailed
        
        case mismatchedUser
        
        /// MSAL could not find the current view controller in the view controller
        /// hierarchy to display the web browser on top of.
        case noViewController
        
        ///The server tried to redirect to a non-HTTPS URL.
        case nonHTTPSRedirect
        
        /// In PSSO, keyId stored in passkey provider storage does not match the
        /// NGC key.
        ///
        /// This needs to be configured and retried.
        case pssoKeyIDMismatch
        
        /// The required MSAL URL scheme is not registered in the application's
        /// Info.plist.
        ///
        /// The scheme should be "msauth.$(PRODUCT_BUNDLE_IDENTIFIER)" and should
        /// be registered in the CFBundleURLTypes - CFBundleURLSchemes key in the
        /// Info.plist file.
        case redirectSchemeNotRegistered
        
        /// The authentication request was cancelled programmatically.
        case sessionCanceled
        
        /// MSAL tried to show UI in the extension, which is not allowed.
        case uiNotSupportedInExtension
        
        /// The client application is not permitted to  request an authorization
        /// code.
        ///
        /// This error occurs when the client application is not registered with
        /// Azure Entra ID or is not added to the user's Azure Entra ID tenant.
        ///
        /// The application can handle this error by prompting the user with
        /// instructions on how to install the application and add it to Microsoft
        /// Entra ID.
        case unauthorizedClient
        
        /// An unexpected error occurred within the MSAL client.
        case unexpected
        
        /// The server returned an expected HTTP response.
        ///
        /// This code is returned if for 5xx server responses when something has
        /// gone wrong on the server but the server could not be more specific on
        /// what the problem is.
        case unhandledResponse
    }
    
    public let errorType: ErrorType
    public let oauthError: String?
    public let oauthSubError: String?
    public let errorDescription: String?
    public let httpHeaders: [String: Any]?
    public let correlationID: String?
    public let httpResponseCode: Int?
    public let displayableUserID: String?
    public let invalidResult: String?
    public let brokerVersion: String?
    public let homeAccountID: String?
    
    public var localizedDescription: String {
        errorDescription ?? "A description is not available for this error"
    }
    
    init(errorType: ErrorType, userInfo: [String: Any]) {
        self.errorType = errorType
        self.oauthError = userInfo[MSALOAuthErrorKey] as? String
        self.oauthSubError = userInfo[MSALOAuthSubErrorKey] as? String
        self.errorDescription = userInfo[MSALErrorDescriptionKey] as? String
        self.httpHeaders = userInfo[MSALHTTPHeadersKey] as? [String: Any]
        self.correlationID = userInfo[MSALCorrelationIDKey] as? String
        self.httpResponseCode = userInfo[MSALHTTPResponseCodeKey] as? Int
        self.displayableUserID = userInfo[MSALDisplayableUserIdKey] as? String
        self.invalidResult = userInfo[MSALInvalidResultKey] as? String
        self.brokerVersion = userInfo[MSALBrokerVersionKey] as? String
        self.homeAccountID = userInfo[MSALHomeAccountIdKey] as? String
    }
    
    static func from(_ error: Error) -> Error {
        let nserror = error as NSError
        guard nserror.domain == MSALErrorDomain else {
            return error
        }
        
        switch nserror.code {
        case MSALError.internal.rawValue:
            return makeInternalError(from: nserror)
            
        case MSALError.workplaceJoinRequired.rawValue:
            return AuthenticationError(
                errorType: .workplaceJoinRequired,
                userInfo: nserror.userInfo
            )
            
        case MSALError.interactionRequired.rawValue:
            return AuthenticationError(
                errorType: .interactionRequired,
                userInfo: nserror.userInfo
            )
            
        case MSALError.serverDeclinedScopes.rawValue:
            let grantedScopes =
                nserror.userInfo[MSALGrantedScopesKey] as? [String]
            let declinedScopes = 
                nserror.userInfo[MSALDeclinedScopesKey] as? [String]
            return AuthenticationError(
                errorType: .serverDeclinedScopes(
                    granted: grantedScopes,
                    declined: declinedScopes
                ),
                userInfo: nserror.userInfo
            )
            
        case MSALError.serverProtectionPoliciesRequired.rawValue:
            return AuthenticationError(
                errorType: .serverProtectionPoliciesRequired,
                userInfo: nserror.userInfo
            )
            
        case MSALError.userCanceled.rawValue:
            return AuthenticationError(
                errorType: .userCanceled,
                userInfo: nserror.userInfo
            )
            
        case MSALError.serverError.rawValue:
            return AuthenticationError(
                errorType: .serverError,
                userInfo: nserror.userInfo
            )
            
        default:
            return error
        }
    }
    
    private static func makeInternalError(
        from nserror: NSError
    ) -> Error {
        guard let code = nserror.userInfo[MSALInternalErrorCodeKey] as? Int else {
            return nserror
        }
        
        switch code {
        case MSALInternalError.internalErrorInvalidParameter.rawValue:
            let description = nserror.userInfo[MSALErrorDescriptionKey] as? String
            return AuthenticationError(
                errorType: .internalError(.invalidParameter(description!)),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorRedirectSchemeNotRegistered.rawValue:
            return AuthenticationError(
                errorType: .internalError(.redirectSchemeNotRegistered),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorInvalidRequest.rawValue:
            return AuthenticationError(
                errorType: .internalError(.invalidRequest),
                userInfo: nserror.userInfo
            )

        case MSALInternalError.internalErrorInvalidClient.rawValue:
            return AuthenticationError(
                errorType: .internalError(.invalidClient),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorInvalidGrant.rawValue:
            return AuthenticationError(
                errorType: .internalError(.invalidGrant),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorInvalidScope.rawValue:
            return AuthenticationError(
                errorType: .internalError(.invalidScope),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorUnauthorizedClient.rawValue:
            return AuthenticationError(
                errorType: .internalError(.unauthorizedClient),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorUnhandledResponse.rawValue:
            return AuthenticationError(
                errorType: .internalError(.unhandledResponse),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorUnexpected.rawValue:
            return AuthenticationError(
                errorType: .internalError(.unexpected),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorFailedAuthorityValidation.rawValue:
            return AuthenticationError(
                errorType: .internalError(.failedAuthorityValidation),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorMismatchedUser.rawValue:
            return AuthenticationError(
                errorType: .internalError(.mismatchedUser),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorAmbiguousAccount.rawValue:
            return AuthenticationError(
                errorType: .internalError(.ambiguousAccount),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorAuthorizationFailed.rawValue:
            let error = nserror.userInfo[MSALOAuthErrorKey] as? String
            let description = nserror.userInfo[MSALErrorDescriptionKey] as? String
            return AuthenticationError(
                errorType: .internalError(
                    .authorizationFailed(
                        error: error,
                        description: description
                    )
                ),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorAccountRequired.rawValue:
            return AuthenticationError(
                errorType: .internalError(.accountRequired),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorSessionCanceled.rawValue:
            return AuthenticationError(
                errorType: .internalError(.sessionCanceled),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorInteractiveSessionAlreadyRunning.rawValue:
            return AuthenticationError(
                errorType: .internalError(.interactiveSessionAlreadyRunning),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorNoViewController.rawValue:
            return AuthenticationError(
                errorType: .internalError(.noViewController),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorAttemptToOpenURLFromExtension.rawValue:
            return AuthenticationError(
                errorType: .internalError(.attemptToOpenURLFromExtension),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorUINotSupportedInExtension.rawValue:
            return AuthenticationError(
                errorType: .internalError(.uiNotSupportedInExtension),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorInvalidState.rawValue:
            return AuthenticationError(
                errorType: .internalError(.invalidState),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorInvalidResponse.rawValue:
            return AuthenticationError(
                errorType: .internalError(.invalidResponse),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorNonHttpsRedirect.rawValue:
            return AuthenticationError(
                errorType: .internalError(.nonHTTPSRedirect),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorBrokerResponseNotReceived.rawValue:
            return AuthenticationError(
                errorType: .internalError(.brokerResponseNotReceived),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorBrokerNoResumeStateFound.rawValue:
            return AuthenticationError(
                errorType: .internalError(.brokerNoResumeStateFound),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorBrokerBadResumeStateFound.rawValue:
            return AuthenticationError(
                errorType: .internalError(.brokerBadResumeStateFound),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorBrokerMismatchedResumeState.rawValue:
            return AuthenticationError(
                errorType: .internalError(.brokerMismatchedResumeState),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorBrokerResponseHashMissing.rawValue:
            return AuthenticationError(
                errorType: .internalError(.brokerResponseHashMissing),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorBrokerCorruptedResponse.rawValue:
            return AuthenticationError(
                errorType: .internalError(.brokerCorruptedResponse),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorBrokerResponseDecryptionFailed.rawValue:
            return AuthenticationError(
                errorType: .internalError(.brokerResponseDecryptionFailed),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorBrokerResponseHashMismatch.rawValue:
            return AuthenticationError(
                errorType: .internalError(.brokerResponseHashMismatch),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorBrokerKeyFailedToCreate.rawValue:
            return AuthenticationError(
                errorType: .internalError(.brokerKeyFailedToCreate),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorBrokerKeyNotFound.rawValue:
            return AuthenticationError(
                errorType: .internalError(.brokerKeyNotFound),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorBrokerUnknown.rawValue:
            return AuthenticationError(
                errorType: .internalError(.brokerUnknown),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorBrokerApplicationTokenWriteFailed.rawValue:
            return AuthenticationError(
                errorType: .internalError(.brokerApplicationTokenWriteFailed),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorBrokerApplicationTokenReadFailed.rawValue:
            return AuthenticationError(
                errorType: .internalError(.brokerApplicationTokenReadFailed),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalBrokerNotAvailable.rawValue:
            return AuthenticationError(
                errorType: .internalError(.brokerNotAvailable),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorJITLinkServerConfirmationError.rawValue:
            return AuthenticationError(
                errorType: .internalError(.jitLinkServerConfirmationError),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorJITLinkAcquireTokenError.rawValue:
            return AuthenticationError(
                errorType: .internalError(.jitLinkAcquireTokenError),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorJITLinkTokenAcquiredWrongTenant.rawValue:
            return AuthenticationError(
                errorType: .internalError(.jitLinkTokenAcquiredWrongTenant),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorJITLinkError.rawValue:
            return AuthenticationError(
                errorType: .internalError(.jitLinkError),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorJITComplianceCheckResultNotCompliant.rawValue:
            return AuthenticationError(
                errorType: .internalError(
                    .jitComplianceCheckResultNotCompliant
                ),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorJITComplianceCheckResultTimeout.rawValue:
            return AuthenticationError(
                errorType: .internalError(.jitComplianceCheckResultTimeout),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorJITComplianceCheckResultUnknown.rawValue:
            return AuthenticationError(
                errorType: .internalError(.jitComplianceCheckResultUnknown),
                userInfo: nserror.userInfo
            )
                
        case MSALInternalError.errorJITComplianceCheckInvalidLinkPayload.rawValue:
            return AuthenticationError(
                errorType: .internalError(
                    .jitComplianceCheckInvalidLinkPayload
                ),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.errorJITComplianceCheckCreateController.rawValue:
            return AuthenticationError(
                errorType: .internalError(.jitComplianceCheckCreateController),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.errorJITLinkConfigNotFound.rawValue:
            return AuthenticationError(
                errorType: .internalError(.jitLinkConfigNotFound),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.errorJITInvalidLinkTokenConfig.rawValue:
            return AuthenticationError(
                errorType: .internalError(.jitInvalidLinkTokenConfig),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.errorJITWPJDeviceRegistrationFailed.rawValue:
            return AuthenticationError(
                errorType: .internalError(.jitWPJDeviceRegistrationFailed),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.errorJITWPJAccountIdentifierNil.rawValue:
            return AuthenticationError(
                errorType: .internalError(.jitWPJAccountIdentifierNil),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.errorJITWPJAcquireTokenError.rawValue:
            return AuthenticationError(
                errorType: .internalError(.jitWPJAcquireTokenError),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.errorJITRetryRequired.rawValue:
            return AuthenticationError(
                errorType: .internalError(.jitRetryRequired),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.errorJITUnknownStatusWebCP.rawValue:
            return AuthenticationError(
                errorType: .internalError(.jitUnknownStatusWebCP),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.errorJITTroubleshootingCreateController.rawValue:
            return AuthenticationError(
                errorType: .internalError(.jitTroubleshootingCreateController),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.errorJITTroubleshootingAcquireToken.rawValue:
            return AuthenticationError(
                errorType: .internalError(.jitTroubleshootingAcquireToken),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.internalErrorJITLinkServerConfirmationTimeout.rawValue:
            return AuthenticationError(
                errorType: .internalError(.jitLinkServerConfirmationTimeout),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.errorJITTroubleshootingRequired.rawValue:
            return AuthenticationError(
                errorType: .internalError(.jitTroubleshootingRequired),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.errorJITTroubleshootingResultUnknown.rawValue:
            return AuthenticationError(
                errorType: .internalError(.jitTroubleshootingResultUnknown),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.errorDeviceNotPSSORegistered.rawValue:
            return AuthenticationError(
                errorType: .internalError(.deviceNotPSSORegistered),
                userInfo: nserror.userInfo
            )
            
        case MSALInternalError.errorPSSOKeyIdMismatch.rawValue:
            return AuthenticationError(
                errorType: .internalError(.pssoKeyIDMismatch),
                userInfo: nserror.userInfo
            )
            
        default:
            return nserror
        }
    }
}
