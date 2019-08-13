const crypto = require('crypto');
module.exports = {
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
};
