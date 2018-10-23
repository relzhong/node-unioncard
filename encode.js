const crypto = require('crypto');
const R = require('ramda');
const Decimal = require('decimal.js');
module.exports = {
  md5(text, encoding) {
    return crypto.createHash('md5').update(this.bufferStr(text), 'utf8').digest(encoding || 'hex');
  },

  bufferStr(value) {
    return Buffer.isBuffer(value) ? value : this.toStr(value);
  },

  toStr(value) {
    return (value || value === 0) ? (value + '') : '';
  },

  Trim(val) { // 去除两边空格
    return val ? val.replace(/(^\s*)|(\s*$)/g, '') : '';
  },

  /**
   * 数字转字符串
   * @param {Number} num 数字
   * @param {Number} length 长度, 自动补长
   * @return {String} res
   */
  num2Str(num, length) {
    const surplusNum = length - ('' + num).length;
    const surplus = R.reduce(R.concat, '', R.repeat('0', surplusNum));
    return surplus + num;
  },

  /**
   * 字符串转Buffer
   * @param {String} req 字符
   * @param {Number} length 长度, 自动补长
   * @return {Buffer} res
   */
  str2Buf(req, length) {
    if (!length) length = req.length;
    return Buffer.concat([ Buffer.from(req) ], length);
  },

  /**
   * 字符串转Hex Buffer
   * @param {String} req 字符 { 0 ~ F }
   * @param {Number} length 长度, 自动补长
   * @param {Number} type 拼接方式 { 0: 右边补0, 1: 左边补0 }
   * @return {Buffer} res
   */
  str2Hex(req, length, type) {
    if (length) {
      if (type) {
        // 左边补0
        if (req.length % 2) {
          req = '0' + req;
        }
        const surplusNum = length * 2 - req.length;
        const surplus = R.reduce(R.concat, '', R.repeat('0', surplusNum));
        req = R.splitEvery(2, surplus + req);

      } else {
        // 默认右边补0
        if (req.length % 2) {
          req = req + '0';
        }
        const surplusNum = length * 2 - req.length;
        const surplus = R.reduce(R.concat, '', R.repeat('0', surplusNum));
        req = R.splitEvery(2, req + surplus);
      }
    } else {
      if (req.length % 2) {
        req = req + '0';
      }
      req = R.splitEvery(2, req);
    }

    let buf = Buffer.from('');
    req.forEach(i => { buf = Buffer.concat([ buf, Buffer.alloc(1, new Decimal('0x' + i).toNumber()) ]); });
    return buf;
  },

  /**
   * Hex Buffer转字符串
   * @param {Buffer} req 字符
   * @return {String} res
   */
  hex2Str(req) {
    let dec = '';
    for (let i = 0; i < req.length; i++) {
      let d = new Decimal(req.readUIntBE(i, 1)).toHex().slice(2, 4)
        .toUpperCase();
      d = d.length % 2 ? '0' + d : '' + d;
      dec = dec + d;
    }
    return dec;
  },

  isJSON(body) {
    if (!body) return false;
    if (typeof body === 'string') return false;
    if (typeof body.pipe === 'function') return false;
    if (Buffer.isBuffer(body)) return false;
    return true;
  },

  calcLLVar(str) {
    const len = '' + str.length;
    const surplusNum = 2 - len.length;
    const surplus = R.reduce(R.concat, '', R.repeat('0', surplusNum));
    return surplus + len;
  },

  calcLLLVar(str) {
    const len = '' + str.length;
    const surplusNum = 4 - len.length;
    const surplus = R.reduce(R.concat, '', R.repeat('0', surplusNum));
    return surplus + len;
  },
};
