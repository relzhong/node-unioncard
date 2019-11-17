const axios = require('axios');

module.exports = cryptoProxyHost => {
  const cryptoProxy = {
    cryptoProxyHost,
    /**
     * register
     * @param {String} req 入参
     * @return {Buffer} res
     */
    async register(req) {
      const res = await axios.post(cryptoProxy.cryptoProxyHost + '/register', { data: req });
      if (res.data.error) throw new Error('cryptoProxy: register fail!');
      return res.data.data;
    },
    /**
     * 3DES-ECB加密
     * @param {String} req 入参
     * @return {Buffer} res
     */
    async encrypt3DESECB(req) {
      const res = await axios.post(cryptoProxy.cryptoProxyHost + '/encrypt/3desecb', { data: req });
      if (res.data.error) throw new Error('cryptoProxy: encrypt3DESECB fail!');
      return Buffer.from(res.data.data, 'hex');
    },
    /**
     * DES-ECB加密
     * @param {String} req 入参
     * @param {Buffer} key 密钥
     * @return {Buffer} res
     */
    async encryptDESECB(req) {
      const res = await axios.post(cryptoProxy.cryptoProxyHost + '/encrypt/desecb', { data: req });
      if (res.data.error) throw new Error('cryptoProxy: encryptDESECB fail!');
      return Buffer.from(res.data.data, 'hex');
    },
    /**
     * DES-ECB解密
     * @param {String} req 入参
     * @param {Buffer} key 密钥
     * @return {Buffer} res
     */
    async decryptDESECB(req) {
      const res = await axios.post(cryptoProxy.cryptoProxyHost + '/decrypt/desecb', { data: req });
      if (res.data.error) throw new Error('cryptoProxy: decryptDESECB fail!');
      return Buffer.from(res.data.data, 'hex');
    },
    /**
     * 3DES-ECB解密
     * @param {String} req 入参
     * @param {Buffer} key 密钥
     * @return {Buffer} res
     */
    async decrypt3DESECB(req) {
      const res = await axios.post(cryptoProxy.cryptoProxyHost + '/decrypt/3desecb', { data: req });
      if (res.data.error) throw new Error('cryptoProxy: decrypt3DESECB fail!');
      return Buffer.from(res.data.data, 'hex');
    },
    /**
     * 计算MAC
     * @param {Buffer} req 请求Buffer
     * @param {Buffer} key 密钥
     * @return {Buffer} mac
     */
    async calcMac(req) {
      req = req.toString('hex');
      const res = await axios.post(cryptoProxy.cryptoProxyHost + '/calcMac', { data: req });
      if (res.data.error) throw new Error('cryptoProxy: calcMac fail!');
      return Buffer.from(res.data.data, 'hex');
    },
  };

  return cryptoProxy;
};
