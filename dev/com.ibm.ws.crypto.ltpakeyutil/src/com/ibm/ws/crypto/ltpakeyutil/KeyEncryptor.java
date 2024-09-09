/*******************************************************************************
 * Copyright (c) 1997, 2011 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.crypto.ltpakeyutil;

import java.security.MessageDigest;

/**
 * A package local class for performing encryption and decryption of keys based
 * on admin's password
 */
public class KeyEncryptor {

	private static final String MESSAGE_DIGEST_ALGORITHM = "SHA256";
//    private static final String DES_ECB_CIPHER = "DESede/ECB/PKCS5Padding";
//	private static final String AES_GMC_CIPHER = "AES/GCM/PKCS5Padding";
	private static final String AES_CBC_CIPHER = "AES/CBC/NoPadding";

	private final byte[] aesKey;

	/**
	 * A KeyEncryptor constructor.
	 *
	 * @param password The key password
	 */
	public KeyEncryptor(byte[] password) throws Exception {
		MessageDigest md = MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM);
		byte[] digest = md.digest(password);
		aesKey = new byte[32];
		System.out.println("DEBUG UTLE: digest length " + digest.length);
		System.out.println("DEBUG UTLE: digest length " + digest);
		System.arraycopy(digest, 0, aesKey, 0, digest.length);
		System.out.println("DEBUG UTLE: aesKey " + aesKey.toString());
//		aesKey[20] = (byte) 0x00;
//		aesKey[21] = (byte) 0x00;
//		aesKey[22] = (byte) 0x00;
//		aesKey[23] = (byte) 0x00;
	}

	/**
	 * Decrypt the key.
	 *
	 * @param encryptedKey The encrypted key
	 * @return The decrypted key
	 */
	public byte[] decrypt(byte[] encryptedKey) throws Exception {
		System.out.println("DEBUG UTLE: decrypt() encryptedKey length:  " + encryptedKey.length);
		byte[] result = LTPACrypto.decrypt(encryptedKey, aesKey, AES_CBC_CIPHER);
		System.out.println("DEBUG UTLE: decrypt() aesKey " + aesKey.toString());
		System.out.println("DEBUG UTLE: decrypt() " + result.toString());
		System.out.println("DEBUG UTLE: decrypt() length: " + result.length);

		return result;
	}

	public byte[] encrypt(byte[] key) throws Exception {
		System.out.println("DEBUG UTLE: encrypt() key length:  " + key.length);
		byte[] result = LTPACrypto.encrypt(key, aesKey, AES_CBC_CIPHER);
		System.out.println("DEBUG UTLE: encrypt() aesKey " + aesKey.toString());
		System.out.println("DEBUG UTLE: encrypt() " + result.toString());
		System.out.println("DEBUG UTLE: encrypt() result length: " + result.length);
		return result;
	}
}
