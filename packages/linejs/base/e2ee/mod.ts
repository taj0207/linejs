import { sharedKey } from "curve25519-js";
import crypto from "node:crypto";
import { Buffer } from "node:buffer";
import type { Location, Message } from "@evex/linejs-types";
import nacl from "tweetnacl";
import { InternalError } from "../core/utils/error.ts";
import * as LINETypes from "@evex/linejs-types";
import type { BaseClient } from "../core/mod.ts";
import { ContentType } from "../thrift/readwrite/struct.ts";
import CryptoJS from "crypto-js";
import type { LooseType } from "@evex/loose-types";

interface GroupKey {
	privKey: string;
	keyId: number;
}

export class E2EE {
	readonly client: BaseClient;
	constructor(client: BaseClient) {
		this.client = client;
	}
	public async getE2EESelfKeyData(mid: string): Promise<LooseType> {
		try {
			const keyData = JSON.parse(
				await this.client.storage.get("e2eeKeys:" + mid) as string,
			);
			if (keyData && keyData.privKey && keyData.pubKey) return keyData;
		} catch (_e) {
			/* Do Nothing */
		}
		const keys = await this.client.talk.getE2EEPublicKeys();
		for (let i = 0; i < keys.length; i++) {
			const key = keys[i];
			const keyId = key.keyId ?? (key as unknown as { "2"?: string })[2];
			const _keyData = await this.getE2EESelfKeyDataByKeyId(keyId);
			if (_keyData) {
				await this.saveE2EESelfKeyData(_keyData);
				return _keyData;
			}
		}
		throw new InternalError(
			"NoE2EEKey",
			"E2EE Key has not been saved, try register `saveE2EESelfKeyDataByKeyId` or use E2EE Login",
		);
	}
	public async getE2EESelfKeyDataByKeyId(
		keyId: string | number,
	): Promise<LooseType> {
		try {
			return JSON.parse(
				await this.client.storage.get("e2eeKeys:" + keyId) as string,
			);
		} catch (_e) {
			/* Do Nothing */
		}
	}
	public async saveE2EESelfKeyDataByKeyId(
		keyId: string | number,
		value: LooseType,
	) {
		await this.client.storage.set(
			"e2eeKeys:" + keyId,
			JSON.stringify(value),
		);
	}
	public async saveE2EESelfKeyData(value: LooseType) {
		await this.client.storage.set(
			"e2eeKeys:" + this.client.profile?.mid,
			JSON.stringify(value),
		);
	}
	public async getE2EELocalPublicKey(
		mid: string,
		keyId?: string | number | undefined,
	): Promise<Buffer | GroupKey> {
		const toType = this.client.getToType(mid);

		if (toType === LINETypes.enums.MIDType.USER) {
			let key: string | undefined = undefined;
			if (keyId !== undefined) {
				key = (await this.client.storage.get(
					`e2eePublicKeys:${keyId}`,
				)) as string;
			}
			let receiverKeyData: LINETypes.E2EENegotiationResult;
			if (!key) {
				receiverKeyData = await this.client.talk.negotiateE2EEPublicKey(
					{ mid },
				);
				const specVersion = receiverKeyData.specVersion;
				if (specVersion === -1) {
					throw new InternalError("Not support E2EE", `${mid}`);
				}
				const publicKey = receiverKeyData.publicKey;
				const receiverKeyId = publicKey.keyId;
				if (receiverKeyId == keyId) {
					key = Buffer.from(publicKey.keyData).toString("base64");
					await this.client.storage.set(
						`e2eePublicKeys:${keyId}`,
						key,
					);
				} else {
					throw new InternalError(
						"No E2EEKey",
						`E2EE key id ${keyId} not found on ${mid}, key id should be ${receiverKeyId}`,
					);
				}
			}
			return Buffer.from(key, "base64");
		} else {
			let key: string | undefined;
			key = (await this.client.storage.get(
				`e2eeGroupKeys:${mid}`,
			)) as string;
			if (keyId && key) {
				const keyData = JSON.parse(key);
				if (keyId !== keyData["keyId"]) {
					this.e2eeLog("getE2EELocalPublicKeykeyIdMismatch", mid);
					key = undefined;
				} else {
					return keyData;
				}
			} else {
				key = undefined;
			}
			if (!key) {
				let e2eeGroupSharedKey:
					| LINETypes.Pb1_U3
					| undefined;
				try {
					e2eeGroupSharedKey = await this.client.talk
						.getLastE2EEGroupSharedKey({
							keyVersion: 2,
							chatMid: mid,
						});
				} catch (error) {
					if (
						error instanceof InternalError &&
						error.data.code == "NOT_FOUND"
					) {
						// No group key on server — register a fresh one.
						this.e2eeLog("getE2EELocalPublicKeyGroupKeyNotFound", { mid });
						await this.tryRegisterE2EEGroupKey(mid);
						const cached = await this.client.storage.get(
							`e2eeGroupKeys:${mid}`,
						);
						if (!cached) {
							throw new InternalError(
								"NoE2EEKey",
								`E2EE group key cache missing after registration for ${mid}`,
							);
						}
						return JSON.parse(cached as string);
					} else {
						throw error;
					}
				}
				const groupKeyId = e2eeGroupSharedKey.groupKeyId;
				const creator = e2eeGroupSharedKey.creator;
				const creatorKeyId = e2eeGroupSharedKey.creatorKeyId;
				const receiverKeyId = e2eeGroupSharedKey.receiverKeyId;
				const encryptedSharedKey = Buffer.from(
					e2eeGroupSharedKey.encryptedSharedKey,
				);

				this.e2eeLog("getE2EEGroupSharedKeyResponse", {
					mid,
					groupKeyId,
					creator,
					creatorKeyId,
					receiverKeyId,
					encryptedSharedKeyLen: encryptedSharedKey.length,
				});
				console.log(`[e2ee-diag] groupKey server response: mid=${mid} groupKeyId=${groupKeyId} creator=${creator} creatorKeyId=${creatorKeyId} receiverKeyId=${receiverKeyId} encLen=${encryptedSharedKey.length}`);

				// If the group shared key was encrypted for an old key we
				// no longer have (e.g. after QR secondary-device login),
				// re-register the group key using current keys.
				// tryRegisterE2EEGroupKey caches the plaintext directly,
				// so we can return it without needing to decrypt.
				let selfKeyForGroup = await this.getE2EESelfKeyDataByKeyId(
					receiverKeyId,
				);
				if (!selfKeyForGroup && this.client.profile?.mid) {
					// receiverKeyId not found locally. Check if it's the same
					// key material under a different keyId (server reassigned
					// keyId) vs a genuinely different keypair (QR re-login).
					const selfByMid = await this.getE2EESelfKeyData(
						this.client.profile.mid,
					);
					if (selfByMid) {
						try {
							const nego = await this.client.talk.negotiateE2EEPublicKey(
								{ mid: this.client.profile.mid },
							);
							const serverPubKey = Buffer.from(nego.publicKey.keyData).toString("base64");
							const serverKeyId = nego.publicKey.keyId;
							const localPubKey = selfByMid.pubKey;
							const pubMatch = localPubKey === serverPubKey;
							console.log(`[e2ee-diag] alias check: receiverKeyId=${receiverKeyId} serverKeyId=${serverKeyId} localKeyId=${selfByMid.keyId} pubMatch=${pubMatch}`);
							if (pubMatch && serverKeyId === receiverKeyId) {
								// Same key material, server just uses a different keyId
								// than what we stored locally. Safe to alias.
								const aliased = { ...selfByMid, keyId: String(receiverKeyId) };
								await this.saveE2EESelfKeyDataByKeyId(receiverKeyId, aliased);
								selfKeyForGroup = aliased;
								console.log(`[e2ee-diag] alias created: e2eeKeys:${receiverKeyId} (local was ${selfByMid.keyId})`);
							}
							// else: pubKey mismatch or receiverKeyId != server current
							// → fall through to re-registration
						} catch (negoErr) {
							console.log(`[e2ee-diag] negotiateE2EEPublicKey failed during alias check: ${String(negoErr)}`);
							// Network error → fall through to re-registration
						}
					}
				}
				if (!selfKeyForGroup) {
					// Group key is encrypted for a key we can't use.
					// Re-register with current keys.
					this.e2eeLog(
						"getE2EELocalPublicKeyReceiverKeyMismatch",
						{ receiverKeyId, mid },
					);
					console.log(`[e2ee-diag] no valid self key for receiverKeyId=${receiverKeyId}, re-registering group key for ${mid}`);
					await this.tryRegisterE2EEGroupKey(mid);
					const cached = await this.client.storage.get(
						`e2eeGroupKeys:${mid}`,
					);
					if (!cached) {
						throw new InternalError(
							"NoE2EEKey",
							`E2EE group key cache missing after re-registration for ${mid}`,
						);
					}
					return JSON.parse(cached as string);
				}

				// Normal path — we have the right self key, decrypt the
				// server-provided group shared key.
				const selfKey = Buffer.from(
					selfKeyForGroup["privKey"],
					"base64",
				);
				const creatorKey = await this.getE2EELocalPublicKey(
					creator,
					creatorKeyId,
				);

				const aesKey = this.generateSharedSecret(
					selfKey,
					creatorKey as Buffer,
				);
				const aes_key = this.getSHA256Sum(Buffer.from(aesKey), "Key");
				const aes_iv = this.xor(
					this.getSHA256Sum(Buffer.from(aesKey), "IV"),
				);

				this.e2eeLog("getE2EELocalPublicKeyAESInfo", {
					aes_key,
					aes_iv,
					encryptedSharedKey,
				});

				let data: { privKey: string; keyId: number };
				try {
					const decipher = crypto.createDecipheriv(
						"aes-256-cbc",
						aes_key,
						aes_iv,
					);
					const plainText = Buffer.concat([
						decipher.update(encryptedSharedKey),
						decipher.final(),
					]);
					this.e2eeLog(
						"getE2EELocalPublicKeyDecryptedLength",
						plainText.length,
					);
					const decrypted = plainText.toString("base64");
					this.e2eeLog("getE2EELocalPublicKeyDecrypted", decrypted);
					data = {
						privKey: decrypted,
						keyId: groupKeyId,
					};
				} catch (decryptErr) {
					// Decryption failed — server's group key is encrypted with
					// bad/outdated key material. Re-register to fix it.
					this.e2eeLog("getE2EELocalPublicKeyDecryptFailed", {
						error: String(decryptErr), mid, groupKeyId, creator, creatorKeyId, receiverKeyId,
					});
					await this.tryRegisterE2EEGroupKey(mid);
					const cached = await this.client.storage.get(
						`e2eeGroupKeys:${mid}`,
					);
					if (!cached) {
						throw new InternalError(
							"NoE2EEKey",
							`E2EE group key cache missing after decrypt-failure re-registration for ${mid}`,
						);
					}
					return JSON.parse(cached as string);
				}
				key = JSON.stringify(data);
				await this.client.storage.set(`e2eeGroupKeys:${mid}`, key);
				return data;
			}
			return JSON.parse(key);
		}
	}
	public async tryRegisterE2EEGroupKey(
		chatMid: string,
	): Promise<LINETypes.Pb1_U3> {
		const e2eePublicKeys = await this.client.talk.getLastE2EEPublicKeys({
			chatMid,
		});
		const members: string[] = [];
		const keyIds: number[] = [];
		const encryptedSharedKeys: Buffer[] = [];
		const selfKeyId = e2eePublicKeys[this.client.profile!.mid].keyId;
		let selfKeyData = await this.getE2EESelfKeyDataByKeyId(selfKeyId);
		if (!selfKeyData && this.client.profile?.mid) {
			// Server keyId differs from local. Try finding key by mid.
			const selfByMid = await this.getE2EESelfKeyData(this.client.profile.mid);
			if (selfByMid) {
				console.log(`[e2ee-diag] tryRegisterE2EEGroupKey: e2eeKeys:${selfKeyId} not found, found by mid (local keyId=${selfByMid.keyId}). Creating alias.`);
				const aliased = { ...selfByMid, keyId: String(selfKeyId) };
				await this.saveE2EESelfKeyDataByKeyId(selfKeyId, aliased);
				selfKeyData = aliased;
			}
		}
		if (!selfKeyData) {
			throw new InternalError(
				"NoE2EEKey",
				"E2EE Key has not been saved, try register `saveE2EESelfKeyDataByKeyId` or use E2EE Login",
			);
		}
		const selfKey = Buffer.from(selfKeyData.privKey, "base64");
		const private_key = crypto.randomBytes(32);
		for (const mid in e2eePublicKeys) {
			if (Object.prototype.hasOwnProperty.call(e2eePublicKeys, mid)) {
				const key = e2eePublicKeys[mid];
				members.push(mid);
				const { keyId, keyData } = key;
				keyIds.push(keyId);

				const aesKey = this.generateSharedSecret(
					selfKey,
					Buffer.from(keyData),
				);
				const aes_key = this.getSHA256Sum(Buffer.from(aesKey), "Key");
				const aes_iv = this.xor(
					this.getSHA256Sum(Buffer.from(aesKey), "IV"),
				);
				const cipher = crypto.createCipheriv(
					"aes-256-cbc",
					aes_key,
					aes_iv,
				);
				const encryptedSharedKey = Buffer.concat([
					cipher.update(private_key),
					cipher.final(),
				]);
				encryptedSharedKeys.push(encryptedSharedKey);
			}
		}
		const response = await this.client.talk.registerE2EEGroupKey({
			keyVersion: 1,
			chatMid,
			keyIds,
			members,
			encryptedSharedKeys,
		});
		// Cache the plaintext group key immediately.
		// We generated private_key ourselves, so we know the plaintext —
		// no need to decrypt the server response (which may not include
		// a valid encryptedSharedKey for us).
		const groupKeyData = {
			privKey: private_key.toString("base64"),
			keyId: response.groupKeyId,
		};
		await this.client.storage.set(
			`e2eeGroupKeys:${chatMid}`,
			JSON.stringify(groupKeyData),
		);
		this.e2eeLog("tryRegisterE2EEGroupKeyCached", {
			chatMid,
			groupKeyId: response.groupKeyId,
		});
		return response;
	}
	public generateSharedSecret(
		privateKey: Buffer,
		publicKey: Buffer,
	): Uint8Array {
		this.e2eeLog("generateSharedSecretKeyInfo", {
			privateKey: privateKey.length,
			publicKey: publicKey.length,
		});
		return sharedKey(
			Uint8Array.from(privateKey),
			Uint8Array.from(publicKey),
		);
	}

	public xor(buf: Buffer): Buffer {
		const bufLength = Math.floor(buf.length / 2);
		const buf2 = Buffer.alloc(bufLength);
		for (let i = 0; i < bufLength; i++) {
			buf2[i] = buf[i] ^ buf[bufLength + i];
		}
		return buf2;
	}

	public getSHA256Sum(...args: (string | Buffer)[]): Buffer {
		const hash = crypto.createHash("sha256");
		for (let arg of args) {
			if (typeof arg === "string") {
				arg = Buffer.from(arg);
			}
			hash.update(arg);
		}
		return hash.digest();
	}

	public encryptAESECB(aesKey: Buffer, plainData: Buffer): Buffer {
		const cipher = crypto.createCipheriv(
			"aes-256-ecb",
			aesKey,
			new Uint8Array(0),
		);
		cipher.setAutoPadding(false);
		return Buffer.concat([cipher.update(plainData), cipher.final()]);
	}

	public async decodeE2EEKeyV1(
		data: LooseType,
		secret: Buffer,
	): Promise<
		| { keyId: LooseType; privKey: Buffer; pubKey: Buffer; e2eeVersion: LooseType }
		| undefined
	> {
		console.log(`[e2ee-qr] decodeE2EEKeyV1 RAW e2eeInfo: keyId=${data.keyId} e2eeVersion=${data.e2eeVersion} hasEncryptedKeyChain=${!!data.encryptedKeyChain} publicKey=${data.publicKey?.slice(0, 30)}... allFields=${JSON.stringify(Object.keys(data))}`);
		if (data.encryptedKeyChain) {
			const encryptedKeyChain = Buffer.from(
				data.encryptedKeyChain,
				"base64",
			);
			const keyId = data.keyId;
			const publicKey = Buffer.from(data.publicKey, "base64");
			const e2eeVersion = data.e2eeVersion;
			console.log(`[e2ee-qr] decodeE2EEKeyV1: keyId=${keyId} e2eeVersion=${e2eeVersion} phonePubKeyLen=${publicKey.length} encKeychainLen=${encryptedKeyChain.length} secretLen=${secret.length}`);
			const keychainResult = this.decryptKeyChain(
				publicKey,
				secret,
				encryptedKeyChain,
				keyId,
			);
			const [privKey, pubKey] = keychainResult.matched;

			this.e2eeLog("decodeE2EEKeyV1E2EEKeyInfo", {
				e2eeKey: {
					keyId,
					privKey,
					pubKey,
					e2eeVersion,
				},
			});
			console.log(`[e2ee-diag] QR login received key: keyId=${keyId} privKey=${privKey.toString("base64")} pubKey=${pubKey.toString("base64")} e2eeVersion=${e2eeVersion}`);

			// Save ALL keys from the keychain (not just the matched one).
			// Historical messages may be encrypted with older keyIds — we need
			// all of them in storage for getChatHistory E2EE decrypt to work.
			console.log(`[e2ee-qr] saving ${keychainResult.allEntries.length} keys from keychain`);
			for (const entry of keychainResult.allEntries) {
				const entryJson = JSON.stringify({
					keyId: entry.keyId,
					privKey: entry.privKey.toString("base64"),
					pubKey: entry.pubKey.toString("base64"),
					e2eeVersion,
				});
				await this.client.storage.set("e2eeKeys:" + entry.keyId, entryJson);
				console.log(`[e2ee-qr] saved e2eeKeys:${entry.keyId}`);
			}

			// Also update the mid-based cache with the current (matched) key
			// so getE2EESelfKeyData doesn't return stale data.
			const keyJson = JSON.stringify({
				keyId,
				privKey: privKey.toString("base64"),
				pubKey: pubKey.toString("base64"),
				e2eeVersion,
			});
			if (this.client.profile?.mid) {
				await this.client.storage.set("e2eeKeys:" + this.client.profile.mid, keyJson);
				console.log(`[e2ee-diag] QR login also updated e2eeKeys:${this.client.profile.mid}`);
			}
			const savedBack = await this.client.storage.get("e2eeKeys:" + keyId);
			console.log(`[e2ee-diag] QR login saved to DB: e2eeKeys:${keyId} verified=${savedBack === keyJson}`);
			// Immediately verify against server
			try {
				const nego = await this.client.talk.negotiateE2EEPublicKey(
					{ mid: this.client.profile?.mid || "" },
				);
				const serverPubKey = Buffer.from(nego.publicKey.keyData).toString("base64");
				const serverKeyId = nego.publicKey.keyId;
				const localPubKey = pubKey.toString("base64");
				const pubMatch = localPubKey === serverPubKey;
				console.log(`[e2ee-qr] POST-LOGIN SERVER CHECK: localKeyId=${keyId} serverKeyId=${serverKeyId} pubMatch=${pubMatch}`);
				if (!pubMatch) {
					console.log(`[e2ee-qr] MISMATCH! local=${localPubKey.slice(0, 30)}... server=${serverPubKey.slice(0, 30)}...`);
					console.log(`[e2ee-qr] server specVersion=${nego.specVersion} server keyData full=${serverPubKey}`);
				} else {
					console.log(`[e2ee-qr] OK: keychain pubKey matches server`);
				}
			} catch (negoErr) {
				console.log(`[e2ee-qr] POST-LOGIN SERVER CHECK failed: ${String(negoErr)}`);
			}
			return {
				keyId,
				privKey,
				pubKey,
				e2eeVersion,
			};
		}
	}
	public decryptKeyChain(
		publicKey: Buffer,
		privateKey: Buffer,
		encryptedKeyChain: Buffer,
		targetKeyId: number | string,
	): { matched: [Buffer, Buffer]; allEntries: Array<{ keyId: number; privKey: Buffer; pubKey: Buffer }> } {
		console.log(`[e2ee-qr] decryptKeyChain INPUT: phonePubKey=${publicKey.toString("base64").slice(0, 20)}... botSecretKey=${privateKey.toString("base64").slice(0, 20)}... encKeychainLen=${encryptedKeyChain.length} targetKeyId=${targetKeyId}`);
		this.e2eeLog("decryptKeyChainKeyInfo", {
			decryptKeyChain: {
				publicKey: publicKey.toString("base64"),
				privateKey: privateKey.toString("base64"),
				encryptedKeyChain: encryptedKeyChain.toString("base64"),
			},
		});
		const sharedSecret = this.generateSharedSecret(privateKey, publicKey);
		console.log(`[e2ee-qr] decryptKeyChain ECDH sharedSecret=${Buffer.from(sharedSecret).toString("base64").slice(0, 20)}...`);
		const aesKey = this.getSHA256Sum(Buffer.from(sharedSecret), "Key");
		const aesIv = this.xor(
			this.getSHA256Sum(Buffer.from(sharedSecret), "IV"),
		);
		const decipher = crypto.createDecipheriv("aes-256-cbc", aesKey, aesIv);
		decipher.setAutoPadding(false);
		const keychainData = Buffer.concat([
			decipher.update(encryptedKeyChain),
			decipher.final(),
		]);
		console.log(`[e2ee-qr] decryptKeyChain CBC decrypted: len=${keychainData.length} hex=${keychainData.toString("hex").slice(0, 80)}...`);
		this.e2eeLog("decryptKeyChainBinKeyInfo", {
			binkey: keychainData.toString("hex"),
		});
		const thriftParsed = this.client.thrift.readThriftStruct(keychainData);
		console.log(`[e2ee-qr] decryptKeyChain thrift keys: ${JSON.stringify(Object.keys(thriftParsed))}`);
		const keyEntries = thriftParsed[1];
		const entryKeys = Object.keys(keyEntries ?? {});
		console.log(`[e2ee-qr] decryptKeyChain thrift[1] entry count: ${entryKeys.length} keys: ${JSON.stringify(entryKeys)}`);

		// Parse ALL entries and find the one matching targetKeyId
		const targetKeyIdNum = Number(targetKeyId);
		let matchedIdx: string | null = null;
		const allEntries: Array<{ keyId: number; privKey: Buffer; pubKey: Buffer }> = [];

		for (const idx of entryKeys) {
			const entry = keyEntries[idx];
			const entryFieldKeys = Object.keys(entry ?? {});
			// field 1 = version (number), field 2 = keyId (number), field 4 = pubKey (buffer), field 5 = privKey (buffer)
			const entryKeyId = entry[2];
			const entryPub = (entry[4] && typeof entry[4] !== "number") ? Buffer.from(entry[4]).toString("base64") : String(entry[4]);
			console.log(`[e2ee-qr] decryptKeyChain entry[${idx}]: fields=${JSON.stringify(entryFieldKeys)} keyId=${entryKeyId} pubKey=${typeof entry[4] !== "number" ? entryPub.slice(0, 30) + "..." : "N/A"}`);

			if (entry[4] && entry[5]) {
				// field 4 = pubKey, field 5 = privKey (same order as matched return)
				allEntries.push({
					keyId: Number(entryKeyId),
					privKey: Buffer.from(entry[5]),
					pubKey: Buffer.from(entry[4]),
				});
			} else {
				console.error(`[e2ee-qr] decryptKeyChain entry[${idx}] keyId=${entryKeyId} SKIPPED: missing pubKey(field4) or privKey(field5)`);
			}

			if (Number(entryKeyId) === targetKeyIdNum) {
				matchedIdx = idx;
				console.log(`[e2ee-qr] decryptKeyChain entry[${idx}] MATCHED targetKeyId=${targetKeyId}`);
			}
		}

		if (!matchedIdx) {
			console.log(`[e2ee-qr] decryptKeyChain WARNING: no entry matched targetKeyId=${targetKeyId}, falling back to entry[0]`);
			matchedIdx = "0";
		}

		const chosenEntry = keyEntries[matchedIdx];
		if (!chosenEntry || !chosenEntry[4] || !chosenEntry[5]) {
			console.log(`[e2ee-qr] decryptKeyChain FATAL: chosen entry[${matchedIdx}] missing pubKey(field4) or privKey(field5): ${JSON.stringify(Object.keys(chosenEntry ?? {}))}`);
			throw new Error(`decryptKeyChain: entry[${matchedIdx}] missing key fields`);
		}
		const publicKeyBytes = Buffer.from(chosenEntry[4]);
		const privateKeyBytes = Buffer.from(chosenEntry[5]);
		console.log(`[e2ee-qr] decryptKeyChain RESULT from entry[${matchedIdx}]: keyId=${chosenEntry[2]} privKey=${privateKeyBytes.toString("base64")} pubKey=${publicKeyBytes.toString("base64")} privLen=${privateKeyBytes.length} pubLen=${publicKeyBytes.length}`);
		console.log(`[e2ee-qr] decryptKeyChain returning ${allEntries.length} total entries`);
		return { matched: [privateKeyBytes, publicKeyBytes], allEntries };
	}

	public encryptDeviceSecret(
		publicKey: Buffer,
		privateKey: Buffer,
		encryptedKeyChain: Buffer,
	): Buffer {
		const sharedSecret = this.generateSharedSecret(privateKey, publicKey);
		const aesKey = this.getSHA256Sum(Buffer.from(sharedSecret), "Key");
		encryptedKeyChain = this.xor(this.getSHA256Sum(encryptedKeyChain));
		const cipher = crypto.createCipheriv(
			"aes-256-ecb",
			aesKey,
			new Uint8Array(0),
		);
		cipher.setAutoPadding(false);
		const keychainData = Buffer.concat([
			cipher.update(encryptedKeyChain),
			cipher.final(),
		]);
		return keychainData;
	}

	public generateAAD(
		a: string,
		b: string,
		c: number,
		d: number,
		e = 2,
		f = 0,
	): Buffer {
		let aad = Buffer.alloc(0);
		aad = Buffer.concat([aad, Buffer.from(a)]);
		aad = Buffer.concat([aad, Buffer.from(b)]);
		aad = Buffer.concat([aad, this.getIntBytes(c)]);
		aad = Buffer.concat([aad, this.getIntBytes(d)]);
		aad = Buffer.concat([aad, this.getIntBytes(e)]);
		aad = Buffer.concat([aad, this.getIntBytes(f)]);
		return aad;
	}
	public getIntBytes(i: number): Uint8Array {
		const j = 4;
		let res: Uint8Array;

		if (j ** 2 === 16) {
			const buffer = new ArrayBuffer(4);
			const view = new DataView(buffer);
			view.setInt32(0, i);
			res = new Uint8Array(buffer);
		} else {
			const buffer = new ArrayBuffer(8);
			const view = new DataView(buffer);
			view.setBigInt64(0, BigInt(i));
			res = new Uint8Array(buffer);
		}
		return res;
	}

	public async encryptE2EEMessage(
		to: string,
		data: string | Location | Record<string, LooseType>,
		contentType: LINETypes.ContentType = 0,
		specVersion = 2,
	): Promise<Buffer[]> {
		contentType = ContentType(contentType) ?? 0;
		const _from = this.client.profile?.mid as string;
		const selfKeyData = await this.getE2EESelfKeyData(_from);

		if (
			to.length === 0 ||
			![0, 1, 2].includes(this.client.getToType(to) ?? -1)
		) {
			throw new InternalError("Invalid mid", to);
		}

		const senderKeyId = selfKeyData.keyId;
		let receiverKeyId, keyData;

		if (this.client.getToType(to) === LINETypes.enums.MIDType.USER) {
			const privateKey = Buffer.from(selfKeyData.privKey, "base64");
			const receiverKeyData = await this.client.talk
				.negotiateE2EEPublicKey({
					mid: to,
				});
			specVersion = receiverKeyData.specVersion;

			if (specVersion === -1) {
				throw new InternalError("Not support E2EE", `${to}`);
			}

			const publicKey = receiverKeyData.publicKey;
			receiverKeyId = publicKey.keyId;
			const receiverKeyDataBuffer = Buffer.from(publicKey.keyData);
			keyData = this.generateSharedSecret(
				privateKey,
				receiverKeyDataBuffer,
			);
		} else {
			const groupK =
				(await this.getE2EELocalPublicKey(to, undefined)) as GroupKey;
			const privK = Buffer.from(groupK.privKey, "base64");
			const pubK = Buffer.from(selfKeyData.pubKey, "base64");
			receiverKeyId = groupK.keyId;
			console.log(`[e2ee-diag] GROUP ENCRYPT: selfPubKey keyId=${selfKeyData.keyId} pub=${selfKeyData.pubKey} groupKeyId=${groupK.keyId}`);
			keyData = this.generateSharedSecret(privK, pubK);
		}
		if (
			contentType === LINETypes.enums.ContentType.LOCATION &&
			typeof data === "object"
		) {
			return this.encryptE2EELocationMessage(
				senderKeyId,
				receiverKeyId,
				Buffer.from(keyData),
				specVersion,
				data as Location,
				to,
				_from,
			);
		} else if (typeof data === "string" || data instanceof Buffer) {
			return this.encryptE2EETextMessage(
				senderKeyId,
				receiverKeyId,
				Buffer.from(keyData),
				specVersion,
				data,
				to,
				_from,
			);
		} else {
			return this.encryptE2EEMessageByData(
				senderKeyId,
				receiverKeyId,
				Buffer.from(keyData),
				specVersion,
				data,
				to,
				_from,
				contentType,
			);
		}
	}

	public encryptE2EETextMessage(
		senderKeyId: number,
		receiverKeyId: number,
		keyData: Buffer,
		specVersion: number,
		text: string | Buffer,
		to: string,
		_from: string,
	): Buffer[] {
		const salt = crypto.randomBytes(16);
		const gcmKey = this.getSHA256Sum(keyData, salt, Buffer.from("Key"));
		const aad = this.generateAAD(
			to,
			_from,
			senderKeyId,
			receiverKeyId,
			specVersion,
			0,
		);
		const sign = crypto.randomBytes(12);
		const data = Buffer.from(JSON.stringify({ text: text.toString() }));
		const encData = this.encryptE2EEMessageV2(data, gcmKey, sign, aad);

		const bSenderKeyId = Buffer.from(this.getIntBytes(senderKeyId));
		const bReceiverKeyId = Buffer.from(this.getIntBytes(receiverKeyId));

		this.e2eeLog(
			"encryptE2EETextMessageSenderKeyId",
			`${senderKeyId} (${bSenderKeyId.toString("hex")})`,
		);
		this.e2eeLog(
			"encryptE2EETextMessageReceiverKeyId",
			`${receiverKeyId} (${bReceiverKeyId.toString("hex")})`,
		);

		return [salt, encData, sign, bSenderKeyId, bReceiverKeyId];
	}

	public encryptE2EEMessageByData(
		senderKeyId: number,
		receiverKeyId: number,
		keyData: Buffer,
		specVersion: number,
		rawdata: Record<string, LooseType>,
		to: string,
		_from: string,
		contentType: number,
	): Buffer[] {
		const salt = crypto.randomBytes(16);
		const gcmKey = this.getSHA256Sum(keyData, salt, Buffer.from("Key"));
		const aad = this.generateAAD(
			to,
			_from,
			senderKeyId,
			receiverKeyId,
			specVersion,
			contentType,
		);
		const sign = crypto.randomBytes(12);
		const data = Buffer.from(JSON.stringify(rawdata));
		const encData = this.encryptE2EEMessageV2(data, gcmKey, sign, aad);

		const bSenderKeyId = Buffer.from(this.getIntBytes(senderKeyId));
		const bReceiverKeyId = Buffer.from(this.getIntBytes(receiverKeyId));

		this.e2eeLog(
			"encryptE2EEDataMessageSenderKeyId",
			`${senderKeyId} (${bSenderKeyId.toString("hex")})`,
		);
		this.e2eeLog(
			"encryptE2EEDataMessageReceiverKeyId",
			`${receiverKeyId} (${bReceiverKeyId.toString("hex")})`,
		);

		return [salt, encData, sign, bSenderKeyId, bReceiverKeyId];
	}

	public encryptE2EELocationMessage(
		senderKeyId: number,
		receiverKeyId: number,
		keyData: Buffer,
		specVersion: number,
		location: Location,
		to: string,
		_from: string,
	): Buffer[] {
		const salt = crypto.randomBytes(16);
		const gcmKey = this.getSHA256Sum(keyData, salt, Buffer.from("Key"));
		const aad = this.generateAAD(
			to,
			_from,
			senderKeyId,
			receiverKeyId,
			specVersion,
			15,
		);
		const sign = crypto.randomBytes(12);
		const data = Buffer.from(JSON.stringify({ location: location }));
		const encData = this.encryptE2EEMessageV2(data, gcmKey, sign, aad);

		const bSenderKeyId = Buffer.from(this.getIntBytes(senderKeyId));
		const bReceiverKeyId = Buffer.from(this.getIntBytes(receiverKeyId));

		this.e2eeLog(
			"encryptE2EELocationMessageSenderKeyId",
			`${senderKeyId} (${bSenderKeyId.toString("hex")})`,
		);
		this.e2eeLog(
			"encryptE2EELocationMessageReceiverKeyId",
			`${receiverKeyId} (${bReceiverKeyId.toString("hex")})`,
		);

		return [salt, encData, sign, bSenderKeyId, bReceiverKeyId];
	}

	public encryptE2EEMessageV2(
		data: Buffer,
		gcmKey: Buffer,
		nonce: Buffer,
		aad: Buffer,
	): Buffer {
		this.e2eeLog("createCipheriv", { data, gcmKey, nonce, aad });
		const cipher = crypto.createCipheriv("aes-256-gcm", gcmKey, nonce);
		cipher.setAAD(aad);
		const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
		const tag = cipher.getAuthTag();
		return Buffer.concat([encrypted, tag]);
	}

	public async decryptE2EEMessage(messageObj: Message): Promise<Message> {
		if (
			(messageObj.contentType === "NONE" ||
				messageObj.contentType === LINETypes.enums.ContentType.NONE) &&
			messageObj.chunks
		) {
			const [text, meta] = await this.decryptE2EETextMessage(messageObj);
			messageObj.text = text;
			messageObj.contentMetadata = {
				...messageObj.contentMetadata,
				...meta,
			};
		} else if (
			(messageObj.contentType === "LOCATION" ||
				messageObj.contentType ===
					LINETypes.enums.ContentType.LOCATION) &&
			messageObj.chunks
		) {
			messageObj.location = await this.decryptE2EELocationMessage(
				messageObj,
			);
		}

		return messageObj;
	}

	public async decryptE2EETextMessage(
		messageObj: Message,
		isSelf = false,
	): Promise<[string, Record<string, string>]> {
		const _from = messageObj.from;
		const to = messageObj.to;
		if (_from === this.client.profile?.mid) {
			isSelf = true;
		}
		const toType = messageObj.toType;
		const metadata = messageObj.contentMetadata;
		const specVersion = metadata.e2eeVersion || "2";
		const contentType = messageObj.contentType;
		const chunks = messageObj.chunks.map((chunk) =>
			typeof chunk === "string" ? Buffer.from(chunk, "utf-8") : chunk
		);
		const senderKeyId = byte2int(chunks[3]);
		const receiverKeyId = byte2int(chunks[4]);
		this.e2eeLog("decryptE2EETextMessageSenderKeyId", senderKeyId);
		this.e2eeLog("decryptE2EETextMessageReceiverKeyId", receiverKeyId);

		const isUserMsg = toType === LINETypes.enums.MIDType.USER || toType === "USER";

		// USER (1-on-1): use keyId-based lookup — privKey is used directly in ECDH
		//   and historical messages may have a different keyId than current.
		// GROUP: use mid-based lookup — selfKey.privKey is NOT used in ECDH
		//   (overridden by groupKey); selfKey.pubKey must match the sender's
		//   mid-based key used during encryption.
		let selfKey: LooseType;
		if (isUserMsg) {
			const myKeyId = isSelf ? senderKeyId : receiverKeyId;
			selfKey = await this.getE2EESelfKeyDataByKeyId(myKeyId);
			if (!selfKey) {
				console.error(`[e2ee] decryptE2EETextMessage: e2eeKeys:${myKeyId} not found (isSelf=${isSelf} senderKeyId=${senderKeyId} receiverKeyId=${receiverKeyId})`);
				throw new InternalError(
					"NoE2EEKey",
					`E2EE self key not found for keyId ${myKeyId} (isSelf=${isSelf} senderKeyId=${senderKeyId} receiverKeyId=${receiverKeyId})`,
				);
			}
		} else {
			selfKey = await this.getE2EESelfKeyData(this.client.profile!.mid);
		}
		let privK = Buffer.from(selfKey.privKey, "base64");
		let pubK: LooseType;

		if (isUserMsg) {
			pubK = await this.getE2EELocalPublicKey(
				isSelf ? to : _from,
				isSelf ? receiverKeyId : senderKeyId,
			);
		} else {
			const groupK = await this.getE2EELocalPublicKey(
				to,
				receiverKeyId,
			) as GroupKey;
			privK = Buffer.from(groupK.privKey, "base64");
			pubK = Buffer.from(selfKey.pubKey, "base64");
			if (_from !== this.client.profile?.mid) {
				pubK = await this.getE2EELocalPublicKey(_from, senderKeyId);
				console.log(`[e2ee-diag] GROUP DECRYPT: senderPubKey mid=${_from} keyId=${senderKeyId} pub=${Buffer.from(pubK as Buffer).toString("base64")} groupKeyId=${groupK.keyId} groupKey=${groupK.privKey.slice(0, 16)}...`);
			} else {
				console.log(`[e2ee-diag] GROUP DECRYPT SELF: selfPubKey keyId=${selfKey.keyId} pub=${selfKey.pubKey} groupKeyId=${groupK.keyId}`);
			}
		}

		let decrypted;
		if (specVersion === "2") {
			decrypted = this.decryptE2EEMessageV2(
				to,
				_from,
				chunks,
				privK,
				pubK,
				parseInt(specVersion),
				contentType as number,
			);
		} else {
			decrypted = this.decryptE2EEMessageV1(chunks, privK, pubK);
		}
		const text = decrypted.text || "";
		const meta: Record<string, string> = {};
		for (const key in decrypted) {
			if (key === "text") {
				continue;
			}
			if (Object.prototype.hasOwnProperty.call(decrypted, key)) {
				const val = decrypted[key];
				if (typeof val === "string") {
					meta[key] = val;
				} else {
					meta[key] = JSON.stringify(val);
				}
			}
		}
		return [text, meta];
	}
	public async decryptE2EELocationMessage(
		messageObj: Message,
		isSelf = true,
	): Promise<Location> {
		const _from = messageObj.from;
		const to = messageObj.to;
		if (_from === this.client.profile?.mid) {
			isSelf = true;
		} else {
			isSelf = false;
		}
		const toType = messageObj.toType;
		const metadata = messageObj.contentMetadata;
		const specVersion = metadata.e2eeVersion || "2";
		const contentType = messageObj.contentType;
		const chunks = messageObj.chunks.map((chunk) =>
			typeof chunk === "string" ? Buffer.from(chunk, "utf-8") : chunk
		);

		const senderKeyId = byte2int(chunks[3]);
		const receiverKeyId = byte2int(chunks[4]);
		this.e2eeLog("decryptE2EELocationMessageSenderKeyId", senderKeyId);
		this.e2eeLog("decryptE2EELocationMessageReceiverKeyId", receiverKeyId);

		const isUserMsg = toType === LINETypes.enums.MIDType.USER || toType === "USER";

		let selfKey: LooseType;
		if (isUserMsg) {
			const myKeyId = isSelf ? senderKeyId : receiverKeyId;
			selfKey = await this.getE2EESelfKeyDataByKeyId(myKeyId);
			if (!selfKey) {
				console.error(`[e2ee] decryptE2EELocationMessage: e2eeKeys:${myKeyId} not found (isSelf=${isSelf} senderKeyId=${senderKeyId} receiverKeyId=${receiverKeyId})`);
				throw new InternalError(
					"NoE2EEKey",
					`E2EE self key not found for keyId ${myKeyId} (isSelf=${isSelf} senderKeyId=${senderKeyId} receiverKeyId=${receiverKeyId})`,
				);
			}
		} else {
			selfKey = await this.getE2EESelfKeyData(this.client.profile!.mid);
		}
		let privK = Buffer.from(selfKey.privKey, "base64");
		let pubK: LooseType;

		if (isUserMsg) {
			pubK = await this.getE2EELocalPublicKey(
				to,
				isSelf ? receiverKeyId : senderKeyId,
			);
		} else {
			const groupK = await this.getE2EELocalPublicKey(
				to,
				receiverKeyId,
			) as GroupKey;
			privK = Buffer.from(groupK.privKey, "base64");
			pubK = Buffer.from(selfKey.pubKey, "base64");
			if (_from !== this.client.profile?.mid) {
				pubK = await this.getE2EELocalPublicKey(_from, senderKeyId);
			}
		}

		let decrypted;
		if (specVersion === "2") {
			decrypted = this.decryptE2EEMessageV2(
				to,
				_from,
				chunks,
				privK,
				pubK,
				parseInt(specVersion),
				contentType as number,
			);
		} else {
			decrypted = this.decryptE2EEMessageV1(chunks, privK, pubK);
		}

		return decrypted.location || undefined;
	}
	public async decryptE2EEDataMessage(
		messageObj: Message,
		isSelf = true,
	): Promise<Record<string, LooseType>> {
		const _from = messageObj.from;
		const to = messageObj.to;
		if (_from === this.client.profile?.mid) {
			isSelf = true;
		} else {
			isSelf = false;
		}
		const toType = messageObj.toType;
		const metadata = messageObj.contentMetadata;
		const specVersion = metadata.e2eeVersion || "2";
		const contentType = typeof messageObj.contentType === "string"
			? LINETypes.enums.ContentType[messageObj.contentType]
			: messageObj.contentType;
		const chunks = messageObj.chunks.map((chunk) =>
			typeof chunk === "string" ? Buffer.from(chunk, "utf-8") : chunk
		);

		const senderKeyId = byte2int(chunks[3]);
		const receiverKeyId = byte2int(chunks[4]);
		this.e2eeLog("decryptE2EEDataMessageSenderKeyId", senderKeyId);
		this.e2eeLog("decryptE2EEDataMessageReceiverKeyId", receiverKeyId);

		const isUserMsg = toType === LINETypes.enums.MIDType.USER || toType === "USER";

		let selfKey: LooseType;
		if (isUserMsg) {
			const myKeyId = isSelf ? senderKeyId : receiverKeyId;
			selfKey = await this.getE2EESelfKeyDataByKeyId(myKeyId);
			if (!selfKey) {
				console.error(`[e2ee] decryptE2EEDataMessage: e2eeKeys:${myKeyId} not found (isSelf=${isSelf} senderKeyId=${senderKeyId} receiverKeyId=${receiverKeyId})`);
				throw new InternalError(
					"NoE2EEKey",
					`E2EE self key not found for keyId ${myKeyId} (isSelf=${isSelf} senderKeyId=${senderKeyId} receiverKeyId=${receiverKeyId})`,
				);
			}
		} else {
			selfKey = await this.getE2EESelfKeyData(this.client.profile!.mid);
		}
		let privK = Buffer.from(selfKey.privKey, "base64");
		let pubK: LooseType;

		if (isUserMsg) {
			pubK = await this.getE2EELocalPublicKey(
				to,
				isSelf ? receiverKeyId : senderKeyId,
			);
		} else {
			const groupK = await this.getE2EELocalPublicKey(
				to,
				receiverKeyId,
			) as GroupKey;
			privK = Buffer.from(groupK.privKey, "base64");
			pubK = Buffer.from(selfKey.pubKey, "base64");
			if (_from !== this.client.profile?.mid) {
				pubK = await this.getE2EELocalPublicKey(_from, senderKeyId);
			}
		}

		let decrypted;
		if (specVersion === "2") {
			decrypted = this.decryptE2EEMessageV2(
				to,
				_from,
				chunks,
				privK,
				pubK,
				parseInt(specVersion),
				contentType as number,
			);
		} else {
			decrypted = this.decryptE2EEMessageV1(chunks, privK, pubK);
		}

		console.log(`[e2ee-decrypt-data] contentType=${contentType} isSelf=${isSelf} payload=${JSON.stringify(decrypted).slice(0, 200)}`);
		return decrypted || {};
	}

	public decryptE2EEMessageV1(
		chunks: Buffer[],
		privK: Buffer,
		pubK: Buffer,
	): LooseType {
		this.e2eeLog("decryptE2EEMessageV1_arg", {
			chunks,
			privK,
			pubK,
		});
		const salt = chunks[0];
		const message = chunks[1];
		const _sign = chunks[2];
		const aesKey = this.generateSharedSecret(privK, pubK);
		const aes_key = this.getSHA256Sum(Buffer.from(aesKey), salt, "Key");
		const aes_iv = this.xor(
			this.getSHA256Sum(Buffer.from(aesKey), salt, "IV"),
		);
		this.e2eeLog("decryptE2EEMessageV1", {
			aes_key,
			aes_iv,
			message,
		});

		let decrypted: Buffer | undefined;

		// 最初の試行
		try {
			const decipher = crypto.createDecipheriv(
				"aes-256-cbc",
				aes_key,
				aes_iv,
			);
			decrypted = Buffer.concat([
				decipher.update(message),
				decipher.final(),
			]);
		} catch (_error) {
			// エラー時は新しい decipher オブジェクトを作成
			const decipher2 = crypto.createDecipheriv(
				"aes-256-cbc",
				aes_key,
				aes_iv,
			);
			decipher2.setAutoPadding(false);
			decrypted = Buffer.concat([
				decipher2.update(message),
				decipher2.final(),
			]);
		}

		this.e2eeLog(
			"decryptE2EEMessageV1DecryptedMessage",
			decrypted.toString("utf-8"),
		);
		return JSON.parse(decrypted.toString("utf-8"));
	}

	public decryptE2EEMessageV2(
		to: string,
		_from: string,
		chunks: Buffer[],
		privK: Buffer,
		pubK: Buffer,
		specVersion = 2,
		contentType = 0,
	): LooseType {
		const salt = chunks[0];
		const message = chunks[1];
		const ciphertext = message.subarray(0, -16);
		const tag = message.subarray(-16);
		const sign = chunks[2];
		const senderKeyId = byte2int(chunks[3]);
		const receiverKeyId = byte2int(chunks[4]);
		const aesKey = this.generateSharedSecret(privK, pubK);
		const gcmKey = this.getSHA256Sum(Buffer.from(aesKey), salt, "Key");
		const aad = this.generateAAD(
			to,
			_from,
			senderKeyId,
			receiverKeyId,
			specVersion,
			contentType,
		);

		let decrypted;

		this.e2eeLog("decryptE2EEMessageV2Info", {
			iv: sign.length,
			key: gcmKey.length,
			tag: tag.length,
			aad: aad.length,
			encrypted: ciphertext.length,
		});

		// 最初の試行
		try {
			const decipher = crypto.createDecipheriv(
				"aes-256-gcm",
				gcmKey,
				sign,
			);
			decipher.setAuthTag(tag);
			decipher.setAAD(aad);
			decrypted = Buffer.concat([
				decipher.update(ciphertext),
				decipher.final(),
			]);
		} catch (error) {
			if (error instanceof Error) {
				this.e2eeLog(
					"decryptE2EEMessageV2DecryptionFailed",
					error.message,
				);
			}
			// エラー時は新しい decipher オブジェクトを作成
			try {
				const decipher2 = crypto.createDecipheriv(
					"aes-256-gcm",
					gcmKey,
					sign,
				);
				decipher2.setAuthTag(tag);
				decipher2.setAAD(aad);
				decipher2.setAutoPadding(false);
				decrypted = Buffer.concat([
					decipher2.update(ciphertext),
					decipher2.final(),
				]);
			} catch (retryError) {
				if (retryError instanceof Error) {
					this.e2eeLog(
						"decryptE2EEMessageV2DecryptionFailed",
						retryError.message,
					);
				}
				throw retryError;
			}
		}

		this.e2eeLog("decryptE2EEMessageV2DecryptedMessage", decrypted);
		return JSON.parse(decrypted.toString());
	}

	private e2eeLog(type: string, message: LooseType) {
		this.client.log("e2ee", { type, message });
	}

	public createSqrSecret(
		base64Only: boolean = false,
	): [Uint8Array, string] {
		const { secretKey, publicKey } = nacl.box.keyPair();
		const secret = encodeURIComponent(
			Buffer.from(publicKey).toString("base64"),
		);
		const version = 1;
		console.log(`[e2ee-qr] createSqrSecret: secretKey(privKey)=${Buffer.from(secretKey).toString("base64").slice(0, 20)}... publicKey=${Buffer.from(publicKey).toString("base64").slice(0, 20)}... e2eeVersion=${version}`);

		if (base64Only) {
			return [
				Buffer.from(secretKey),
				Buffer.from(publicKey).toString("base64"),
			];
		}
		return [
			Buffer.from(secretKey),
			`?secret=${secret}&e2eeVersion=${version}`,
		];
	}

	// for e2ee next

	_encryptAESCTR(aesKey: Buffer, nonce: Buffer, data: Buffer): Buffer {
		// deno not support ctr !
		const cipher = crypto.createCipheriv("aes-256-ctr", aesKey, nonce);
		const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
		return encrypted;
	}

	async __encryptAESCTR(
		aesKey: Buffer,
		nonce: Buffer,
		data: Buffer,
	): Promise<Buffer> {
		const aesKeyArrayBuffer = aesKey.buffer.slice(aesKey.byteOffset, aesKey.byteOffset + aesKey.byteLength);
		const dataArrayBuffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
		
		return Buffer.from(
			await globalThis.crypto.subtle.encrypt(
				{
					name: "AES-CTR",
					// @ts-expect-error: will fix cuz typescript version change
					counter: nonce,
					length: 32,
				},
				await globalThis.crypto.subtle.importKey(
					"raw",
					new Uint8Array(aesKeyArrayBuffer as ArrayBuffer),
					"AES-CTR",
					false,
					["encrypt"],
				),
				new Uint8Array(dataArrayBuffer as ArrayBuffer),
			),
		);
	}

	___encryptAESCTR(aesKey: Buffer, nonce: Buffer, data: Buffer): Buffer {
		// Convert Buffer to WordArray
		const key = CryptoJS.lib.WordArray.create(aesKey);
		const iv = CryptoJS.lib.WordArray.create(nonce);
		const plaintext = CryptoJS.lib.WordArray.create(data);

		// Encrypt using AES-CTR
		const encrypted = CryptoJS.AES.encrypt(plaintext, key, {
			iv: iv,
			mode: CryptoJS.mode.CTR,
			padding: CryptoJS.pad.NoPadding, // No padding for AES-CTR
		});

		// Convert WordArray ciphertext back to Buffer
		const ciphertext = Buffer.from(
			encrypted.ciphertext.toString(CryptoJS.enc.Hex),
			"hex",
		);

		return ciphertext;
	}

	_decryptAESCTR(aesKey: Buffer, nonce: Buffer, data: Buffer): Buffer {
		const decipher = crypto.createDecipheriv("aes-256-ctr", aesKey, nonce);
		const decrypted = Buffer.concat([
			decipher.update(data),
			decipher.final(),
		]);
		return decrypted;
	}

	async ___decryptAESCTR(
		aesKey: Buffer,
		nonce: Buffer,
		data: Buffer,
	): Promise<Buffer> {
		return Buffer.from(
			await globalThis.crypto.subtle.decrypt(
				{
					name: "AES-CTR",
					// @ts-expect-error: will fix cuz typescript version change
					counter: nonce,
					length: 32,
				},
				// @ts-expect-error: will fix cuz typescript version change
				await globalThis.crypto.subtle.importKey(
					"raw",
					aesKey,
					"AES-CTR",
					false,
					["decrypt"],
				),
				data,
			),
		);
	}

	__decryptAESCTR(aesKey: Buffer, nonce: Buffer, data: Buffer): Buffer {
		const keyWordArray = CryptoJS.lib.WordArray.create(aesKey);
		const nonceWordArray = CryptoJS.lib.WordArray.create(nonce);

		const encryptedData = CryptoJS.lib.WordArray.create(data);

		const decrypted = CryptoJS.AES.decrypt(
			{
				ciphertext: encryptedData,
			},
			keyWordArray,
			{
				mode: CryptoJS.mode.CTR,
				iv: nonceWordArray,
				padding: CryptoJS.pad.NoPadding, // No padding
			},
		);

		return Buffer.from(decrypted.toString(CryptoJS.enc.Hex), "hex");
	}

	signData(data: Buffer, key: Buffer): Buffer {
		const hmac = crypto.createHmac("sha256", key);
		hmac.update(data);
		return hmac.digest();
	}

	async deriveKeyMaterial(
		keyMaterial: Buffer,
	): Promise<{ encKey: Buffer; macKey: Buffer; nonce: Buffer }> {
		const derived = await new Promise<Buffer>((resolve, reject) => {
			// ???
			crypto.hkdf(
				"sha256",
				keyMaterial,
				new Uint8Array(0),
				"FileEncryption",
				76,
				(err, derivedKey) => {
					if (err) {
						reject(err);
					}
					resolve(Buffer.from(derivedKey));
				},
			);
		});
		return {
			encKey: derived.slice(0, 32),
			macKey: derived.slice(32, 64),
			// ???
			nonce: Buffer.concat([derived.slice(64, 76), new Uint8Array(4)]),
		};
	}

	async encryptByKeyMaterial(
		rawData: Buffer,
		keyMaterial?: Buffer,
	): Promise<{ keyMaterial: string; encryptedData: Buffer }> {
		// Encrypt file for E2EE Next
		if (!keyMaterial) {
			keyMaterial = crypto.randomBytes(32);
		}
		const keys = await this.deriveKeyMaterial(keyMaterial);
		const encData = await this.__encryptAESCTR(
			keys.encKey,
			keys.nonce,
			rawData,
		);
		const sign = this.signData(encData, keys.macKey);

		return {
			keyMaterial: keyMaterial.toString("base64"),
			encryptedData: Buffer.concat([encData, sign]),
		};
	}

	async decryptByKeyMaterial(
		rawData: Buffer,
		keyMaterial: Buffer | string,
	): Promise<Buffer> {
		// Decrypt file for E2EE Next
		if (typeof keyMaterial === "string") {
			keyMaterial = Buffer.from(keyMaterial, "base64");
		}
		const keys = await this.deriveKeyMaterial(keyMaterial);
		return (await this.___decryptAESCTR(keys.encKey, keys.nonce, rawData))
			.slice(
				0,
				-32,
			);
	}
}

export default E2EE;

function byte2int(t: Buffer) {
	let e = 0;
	const s = t.length;
	for (let i = 0; i < s; i++) {
		e = 256 * e + t[i];
	}
	return e;
}

function _bin2bytes(k: string) {
	const e: number[] = [];
	for (let i = 0; i < k.length / 2; i++) {
		const _i = parseInt(k.substring(i * 2, i * 2 + 2), 16);
		e.push(_i);
	}
	return new Uint8Array(e);
}
