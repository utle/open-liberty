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

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

final class LTPADigSignature {

	static byte[][] testRawPubKey = null;
	static byte[][] testRawPrivKey = null;
	static MessageDigest md1 = null;
	static private Object lockObj1 = new Object();
	static long created = 0;
	static long cacheHits = 0;
	static KeyPair keyPair = null;
	static PrivateKey privateKey = null;
	static PublicKey publicKey = null;

	static {
		try {
			if (LTPAKeyUtil.isFIPSEnabled() && LTPAKeyUtil.isIBMJCEPlusFIPSAvailable()) {
				md1 = MessageDigest.getInstance(LTPAKeyUtil.MESSAGE_DIGEST_ALGORITHM_SHA256,
						LTPAKeyUtil.IBMJCE_PLUS_FIPS_NAME);
			} else if (LTPAKeyUtil.isIBMJCEAvailable()) {
				md1 = MessageDigest.getInstance(LTPAKeyUtil.MESSAGE_DIGEST_ALGORITHM_SHA, LTPAKeyUtil.IBMJCE_NAME);
			} else {
				md1 = MessageDigest.getInstance(LTPAKeyUtil.MESSAGE_DIGEST_ALGORITHM_SHA256);
			}

		} catch (NoSuchAlgorithmException e) {
			// instrumented ffdc
		} catch (NoSuchProviderException e) {
			// instrumented ffdc;
		}
	}

	public LTPADigSignature() {
		super();
	}

	static KeyPair generateRSAKeys(byte[][] rsaPubKey, byte[][] rsaPrivKey) {

		if (true) { // TODO
			keyPair = LTPACrypto.rsaKeyPair(256, true, true);
			privateKey = keyPair.getPrivate();
			publicKey = keyPair.getPublic();
		} else {
			byte[][] rsaKey = LTPACrypto.rsaKey(128, true, true); // 64 is 512, 128 is 1024

			rsaPrivKey[0] = rsaKey[0];
			rsaPrivKey[2] = rsaKey[2];
			rsaPrivKey[4] = rsaKey[3];
			rsaPrivKey[3] = rsaKey[4];
			rsaPrivKey[5] = rsaKey[5];
			rsaPrivKey[6] = rsaKey[6];
			rsaPrivKey[7] = rsaKey[7];

			rsaPubKey[0] = rsaKey[0];
			rsaPubKey[1] = rsaKey[2];
		}
		return keyPair;
	}

	static boolean verify(byte[] mesg, byte[] signature, LTPAPublicKey pubKey) throws Exception {
		byte[][] rsaPubKey = pubKey.getRawKey();
		byte[] data;
		synchronized (lockObj1) {
			data = md1.digest(mesg);
		}
		return LTPACrypto.verifyISO9796(rsaPubKey, data, 0, data.length, signature, 0, signature.length,
				pubKey.getPublicKey());
	}

	static LTPAKeyPair generateLTPAKeyPair() {
		LTPAPublicKey pubKey = null;
		LTPAPrivateKey privKey = null;
		byte[][] rsaPubKey = new byte[2][];
		byte[][] rsaPrivKey = new byte[8][];
		keyPair = generateRSAKeys(rsaPubKey, rsaPrivKey);
		if (true) {
			privateKey = keyPair.getPrivate();
			publicKey = keyPair.getPublic();
			pubKey = new LTPAPublicKey(keyPair.getPublic().getEncoded(), publicKey);
			privKey = new LTPAPrivateKey(keyPair.getPrivate().getEncoded(), privateKey);
		} else {
			pubKey = new LTPAPublicKey(rsaPubKey);
			privKey = new LTPAPrivateKey(rsaPrivKey);
		}
		return new LTPAKeyPair(pubKey, privKey);
	}

	static PublicKey getPublicKey() {
		return publicKey;
	}

	static PrivateKey getPrivateKey() {
		return privateKey;
	}

}
