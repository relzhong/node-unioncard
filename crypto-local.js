const crypto = require('crypto');
const xor = require('buffer-xor');

const cryptoLocal = {
  /**
   * 3DES-ECB加密
   * @param {String} req 入参
   * @param {Buffer} key 密钥
   * @return {Buffer} res
   */
  encrypt3DESECB(req, key) {
    key = Buffer.concat([ key, key.slice(0, 8) ]);
    const iv = Buffer.alloc(0);
    if (req.length % 8 !== 0) {
      throw new Error('encrypt false');
    }
    const cipher = crypto.createCipheriv('des-ede3', key, iv);
    cipher.setAutoPadding(false); // default true
    let ciph = cipher.update(req, 'hex');
    ciph = Buffer.concat([ ciph, cipher.final() ]);
    return ciph;
  },
  /**
   * DES-ECB加密
   * @param {String} req 入参
   * @param {Buffer} key 密钥
   * @return {Buffer} res
   */
  encryptDESECB(req, key) {
    const iv = Buffer.alloc(0);
    if (req.length % 8 !== 0) {
      throw new Error('encrypt false');
    }
    const cipher = crypto.createCipheriv('des-ecb', key, iv);
    cipher.setAutoPadding(false); // default true
    let ciph = cipher.update(req, 'hex');
    ciph = Buffer.concat([ ciph, cipher.final() ]);
    return ciph;
  },
  /**
   * DES-ECB解密
   * @param {String} req 入参
   * @param {Buffer} key 密钥
   * @return {Buffer} res
   */
  decryptDESECB(req, key) {
    const iv = Buffer.alloc(0);
    if (req.length % 8 !== 0) {
      throw new Error('encrypt false');
    }
    const cipher = crypto.createDecipheriv('des-ecb', key, iv);
    cipher.setAutoPadding(false); // default true
    let ciph = cipher.update(req, 'hex');
    ciph = Buffer.concat([ ciph, cipher.final() ]);
    return ciph;
  },
  /**
   * 3DES-ECB解密
   * @param {String} req 入参
   * @param {Buffer} key 密钥
   * @return {Buffer} res
   */
  decrypt3DESECB(req, key) {
    key = Buffer.concat([ key, key.slice(0, 8) ]);
    const iv = Buffer.alloc(0);
    if (req.length % 8 !== 0) {
      throw new Error('encrypt false');
    }
    const cipher = crypto.createDecipheriv('des-ede3', key, iv);
    cipher.setAutoPadding(false); // default true
    let ciph = cipher.update(req, 'hex');
    ciph = Buffer.concat([ ciph, cipher.final() ]);
    return ciph;
  },
  /**
     * 计算MAC
     * @param {Buffer} req 请求Buffer
     * @param {Buffer} key 密钥
     * @return {Buffer} mac
     */
  calcMac(req, key) {
    let res = Buffer.alloc(8);
    req = Buffer.concat([ req ], req.length % 8 ? req.length + 8 - req.length % 8 : req.length);
    for (let i = 0; i < req.length / 8; i++) {
      res = xor(res, req.slice(i * 8, (i + 1) * 8));
      res = cryptoLocal.encryptDESECB(res, key);
    }
    return res;
  },
};

module.exports = cryptoLocal;
