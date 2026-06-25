/**
 * Password hashing untuk akun admin.
 *
 * Menggunakan `crypto.scrypt` bawaan Node.js — modul native, sudah teraudit,
 * tidak butuh dependency tambahan. Format hash yang disimpan:
 *
 *   scrypt$<N>$<r>$<p>$<saltHex>$<hashHex>
 *
 * Ini sengaja dibuat self-describing (parameter ikut disimpan) supaya kalau
 * suatu saat parameter cost dinaikkan, hash lama tetap bisa diverifikasi.
 */
import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from "crypto";
import { promisify } from "util";

const scrypt = promisify(scryptCallback);

const SCRYPT_N = 16384; // cost factor
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LEN = 64;

export async function hashPassword(plainPassword: string): Promise<string> {
  const salt = randomBytes(16);
  const derivedKey = (await scrypt(plainPassword, salt, KEY_LEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
  })) as Buffer;

  return [
    "scrypt",
    SCRYPT_N,
    SCRYPT_R,
    SCRYPT_P,
    salt.toString("hex"),
    derivedKey.toString("hex"),
  ].join("$");
}

export async function verifyPassword(
  plainPassword: string,
  storedHash: string
): Promise<boolean> {
  try {
    const [scheme, nStr, rStr, pStr, saltHex, hashHex] = storedHash.split("$");
    if (scheme !== "scrypt") return false;

    const salt = Buffer.from(saltHex, "hex");
    const expected = Buffer.from(hashHex, "hex");

    const derivedKey = (await scrypt(plainPassword, salt, expected.length, {
      N: Number(nStr),
      r: Number(rStr),
      p: Number(pStr),
    })) as Buffer;

    return timingSafeEqual(derivedKey, expected);
  } catch {
    return false;
  }
}
