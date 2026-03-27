/**
 * SCITT (Supply Chain Integrity, Transparency, and Trust) verification support.
 *
 * <p>This package provides cryptographic verification of agent registrations using
 * SCITT artifacts delivered via HTTP headers, eliminating the need for live
 * Transparency Log queries during connection establishment.</p>
 *
 * <h2>Key Components</h2>
 * <ul>
 *   <li>{@link com.godaddy.ans.sdk.transparency.scitt.ScittReceipt} - COSE_Sign1 receipt with Merkle proof</li>
 *   <li>{@link com.godaddy.ans.sdk.transparency.scitt.StatusToken} - Time-bounded status assertion</li>
 *   <li>{@link com.godaddy.ans.sdk.transparency.scitt.ScittVerifier} - Receipt and token verification</li>
 *   <li>{@link com.godaddy.ans.sdk.transparency.TransparencyClient} - Public key fetching via getRootKeyAsync()</li>
 * </ul>
 *
 * <h2>Verification Flow</h2>
 * <ol>
 *   <li>Extract SCITT headers from HTTP response</li>
 *   <li>Parse receipt (COSE_Sign1) and verify TL signature</li>
 *   <li>Verify Merkle inclusion proof in receipt</li>
 *   <li>Parse status token (COSE_Sign1) and verify RA signature</li>
 *   <li>Check token expiry with clock skew tolerance</li>
 *   <li>Extract expected certificate fingerprints</li>
 *   <li>Compare actual certificate against expectations</li>
 * </ol>
 *
 * <h2>Security Considerations</h2>
 * <ul>
 *   <li>Only ES256 (ECDSA P-256) signatures are accepted</li>
 *   <li>Key pinning prevents first-use attacks</li>
 *   <li>Constant-time comparison for fingerprints</li>
 *   <li>Trusted RA registry prevents rogue TL acceptance</li>
 * </ul>
 *
 * @see com.godaddy.ans.sdk.transparency.scitt.ScittVerifier
 * @see com.godaddy.ans.sdk.transparency.scitt.StatusToken
 */
package com.godaddy.ans.sdk.transparency.scitt;
