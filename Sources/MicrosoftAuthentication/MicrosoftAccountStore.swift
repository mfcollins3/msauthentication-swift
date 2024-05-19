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

import MSAL
import SwiftUI

@Observable public final class MicrosoftAccountStore {
    public var accessToken: String?
    public var account: MSALAccount?
    public var authorizationHeader: String?
    public var claims: [String: Any]?
    public var expiresOn: Date?
    public var idToken: String?
    public var identifier: String?
    public var isLoggedIn: Bool = false
    
    private let clientApplication: MSALPublicClientApplication

    public init(
        clientID: String,
        redirectURI: String? = nil,
        authority: MSALAuthority? = nil
    ) throws {
        let configuration = MSALPublicClientApplicationConfig(
            clientId: clientID,
            redirectUri: redirectURI,
            authority: authority
        )
        do {
            self.clientApplication = try .init(configuration: configuration)
        } catch {
            throw AuthenticationError.from(error)
        }
    }
    
    @MainActor public func acquireToken(
        for account: MSALAccount? = nil,
        viewController: UIViewController,
        scopes: [String] = []
    ) async throws {
        let webviewParameters = MSALWebviewParameters(
            authPresentationViewController: viewController
        )
        let parameters = MSALInteractiveTokenParameters(
            scopes: scopes,
            webviewParameters: webviewParameters
        )
        parameters.account = account
        do {
            let result = try await clientApplication.acquireToken(
                with: parameters
            )
            self.account = result.account
            self.accessToken = result.accessToken
            self.authorizationHeader = result.authorizationHeader
            self.idToken = result.idToken
            self.claims = result.tenantProfile.claims
            self.identifier = result.tenantProfile.identifier
            self.expiresOn = result.expiresOn
            self.isLoggedIn = true
        } catch {
            throw AuthenticationError.from(error)
        }
    }
    
    @MainActor public func acquireTokenSilently(
        for accountIdentifier: String,
        scopes: [String] = []
    ) async throws {
        let account: MSALAccount
        do {
            account = try clientApplication.account(forIdentifier: accountIdentifier)
        } catch {
            throw AuthenticationError.from(error)
        }
        
        try await acquireTokenSilently(for: account, scopes: scopes)
    }
    
    @MainActor public func acquireTokenSilently(
        for account: MSALAccount,
        scopes: [String] = []
    ) async throws {
        let silentParameters = MSALSilentTokenParameters(
            scopes: scopes,
            account: account
        )
        do {
            let result = try await clientApplication.acquireTokenSilent(
                with: silentParameters
            )
            self.account = result.account
            self.accessToken = result.accessToken
            self.authorizationHeader = result.authorizationHeader
            self.idToken = result.idToken
            self.claims = result.tenantProfile.claims
            self.identifier = result.tenantProfile.identifier
            self.expiresOn = result.expiresOn
            self.isLoggedIn = true
        } catch {
            throw AuthenticationError.from(error)
        }
    }
    
    @MainActor public func tryAcquireTokenSilently(
        for accountIdentifier: String,
        viewController: UIViewController,
        scopes: [String] = []
    ) async throws {
        let account: MSALAccount
        do {
            account = try clientApplication.account(forIdentifier: accountIdentifier)
        } catch {
            throw AuthenticationError.from(error)
        }

        try await tryAcquireTokenSilently(
            for: account,
            viewController: viewController,
            scopes: scopes
        )
    }
    
    @MainActor public func tryAcquireTokenSilently(
        for account: MSALAccount,
        viewController: UIViewController,
        scopes: [String] = []
    ) async throws {
        do {
            try await acquireTokenSilently(for: account, scopes: scopes)
        } catch let error as AuthenticationError {
            switch error.errorType {
            case .interactionRequired:
                try await acquireToken(
                    for: account,
                    viewController: viewController,
                    scopes: scopes
                )
                
            default:
                throw error
            }
        } catch {
            throw error
        }
    }
}
