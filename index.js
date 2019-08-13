const EventEmitter = require('events');
const R = require('ramda');
const net = require('net');
const Decimal = require('decimal.js');
const crypto = require('./crypto');
const encode = require('./encode');
const xor = require('buffer-xor');
const TlvFactory = require('ber-tlv').TlvFactory;
const { num2Str, str2Hex } = require('./encode');
const https = require('https');
const axios = require('axios');
const url = require('url');

class UniTaskEmitter extends EventEmitter {}

function createRequest(emitter) {
  const client = new net.Socket();
  client.eventEmitter = emitter;
  let buf = Buffer.alloc(0);
  let bufSize = 0;

  client.on('data', function(data) {
    buf = Buffer.concat([ buf, data ]);
    bufSize = bufSize + data.length;
    if (bufSize > 2) {
      const length = buf.readUIntBE(0, 2);
      if (bufSize === length + 2) {
        if (client.eventEmitter) {
          client.eventEmitter.emit('finish', buf);
          client.end();
        }
      }
    }
  });

  client.on('error', client.end);

  client.doSend = function() {
    if (!client.connecting && !client.destroyed) {
      if (client.eventEmitter) {
        client.write(client.eventEmitter.req);
      }
    } else {
      throw new Error('lost connection');
    }
  };

  client.on('connect', function() {
    client.doSend();
  });

  client.connect(this.port, this.host);
}

function createRequestHttps(emitter) {
  const requestUrl = url.format({
    protocol: 'https',
    pathname: '/mjc/webtrans/VPB_lb',
    hostname: this.host,
    port: this.port,
  });
  axios.request({
    url: requestUrl,
    method: 'post',
    headers: { 'Content-Type': 'x-ISO-TPDU/x-auth',
      Accept: '*/*',
      'Cache-Control': 'no-cache' },
    data: emitter.req,
    responseType: 'arraybuffer',
    httpsAgent: new https.Agent({ ca: this.ca, rejectUnauthorized: false }),
  }).then(res => emitter.emit('finish', res.data));
}


class UnionCardPay {
  constructor(host, port, tpdu, posId, deviceId, batchNo, primaryKey, deviceNo, logger = console, timeout = 15000, https = false, ca = '') {
    Object.assign(this, {
      host, port, tpdu, posId, deviceId, batchNo, primaryKey, deviceNo, timeout, logger, ca,
    });
    if (https) {
      this.createRequest = createRequestHttps.bind(this);
    } else {
      this.createRequest = createRequest.bind(this);
    }
  }

  /**
   * 签到
   * @return {Object} res { pKey, mKey, batchNo }
   */
  async register() {
    const { str2Hex, hex2Str, str2Buf } = encode;
    const { parseRegister, selectBit } = UnionCardPay;
    const decrypt3DESECB = crypto.decrypt3DESECB;
    const reqParams = [];
    reqParams.push(str2Hex(this.tpdu)); // tpdu
    reqParams.push(str2Hex('603100310208')); // 报文头
    reqParams.push(str2Hex('0800')); // 消息类型
    reqParams.push(str2Hex('0020000000C00012')); // 位图
    reqParams.push(str2Hex('000001')); // 受卡方系统跟踪号
    reqParams.push(str2Buf(this.deviceId)); // 受卡机终端标识码
    reqParams.push(str2Buf(this.posId)); // 受卡方标识码(商户代码)
    reqParams.push(str2Hex('001100' + this.batchNo + '0030')); // 批次号
    reqParams.push(str2Hex('0003303132')); // 自定义域

    let req = Buffer.concat(reqParams);
    const head = Buffer.alloc(2);
    head.writeUIntBE(req.length, 0, 2);
    req = Buffer.concat([ head, req ]);
    this.logger.info('[unipay - register send]', parseRegister(hex2Str(req)));
    const result = await new Promise((resolve, reject) => {
      const emitter = new UniTaskEmitter();
      emitter.req = req;
      this.createRequest(emitter);
      const timeout = setTimeout(() => { reject(new Error('time out')); }, this.timeout);
      emitter.on('finish', res => {
        res = hex2Str(res);
        const result = parseRegister(res);
        this.logger.info('[unipay - register receive]', result);
        clearTimeout(timeout);
        resolve(result);
      });
    });

    const res = {};
    res.status = selectBit(39, result);
    if (selectBit(39, result) === '3030') {
      const keys = selectBit(62, result);
      if (keys && keys.length === 64) {
        res.pKey = hex2Str(decrypt3DESECB(keys.slice(0, 32), str2Hex(this.primaryKey)));
        res.mKey = hex2Str(decrypt3DESECB(keys.slice(40, 56), str2Hex(this.primaryKey)));
      }
    }
    if (selectBit(60, result)) {
      res.batchNo = selectBit(60, result).slice(2, 8);
    }
    Object.assign(this, res);
    return res;
  }

  /**
   * 交易
   * @param {*} serialNo 受卡方系统跟踪号: 同原交易取值
   * @param {*} track2 2磁
   * @param {*} track3 3磁
   * @param {*} password 密码
   * @param {*} price 金额
   * @return {Object} res
   */
  async trade(serialNo, track2, track3, password, price) {
    const { calcLLLVar, calcLLVar, str2Hex, hex2Str, str2Buf } = encode;
    const { parseRegister, calcMac, selectBit } = UnionCardPay;
    const { encrypt3DESECB } = crypto;
    const reqParams = [];
    reqParams.push(str2Hex(this.tpdu)); // tpdu
    reqParams.push(str2Hex('603100310208')); // 报文头
    reqParams.push(str2Hex('0200')); // 消息类型
    track3 ? reqParams.push(str2Hex('302004C030C09811')) : reqParams.push(str2Hex('302004C020C09811')); // 位图
    reqParams.push(str2Hex('190000')); // 交易处理码
    reqParams.push(str2Hex('' + price, 6, 1)); // 交易金额
    reqParams.push(str2Hex(serialNo)); // 受卡方系统跟踪号
    reqParams.push(str2Hex('0210')); // 服务点输入方式码
    reqParams.push(str2Hex('82')); // 服务点条件码
    reqParams.push(str2Hex('06')); // 服务点PIN获取码
    reqParams.push(str2Hex(calcLLVar(track2) + track2)); // 2磁道数据
    if (track3) reqParams.push(str2Hex(calcLLLVar(track3) + track3)); // 3磁道数据
    reqParams.push(str2Buf(this.deviceId)); // 受卡机终端标识码
    reqParams.push(str2Buf(this.posId)); // 受卡方标识码(商户代码)
    reqParams.push(str2Buf('156')); // 交易货币代码
    reqParams.push(encrypt3DESECB(password, str2Hex(this.pKey))); // 个人标识码数据
    reqParams.push(str2Hex('1600000000000000')); // 安全控制信息
    reqParams.push(str2Hex('001622' + this.batchNo + '00000052')); // 自定义域

    let req = Buffer.concat(reqParams);
    const mac = calcMac(req.slice(11), str2Hex(this.mKey));
    req = Buffer.concat([ req, mac ]);
    const head = Buffer.alloc(2);
    head.writeUIntBE(req.length, 0, 2);
    req = Buffer.concat([ head, req ]);
    this.logger.info('[unipay - trade send]', parseRegister(hex2Str(req)));
    const result = await new Promise((resolve, reject) => {
      const emitter = new UniTaskEmitter();
      emitter.req = req;
      this.createRequest(emitter);
      const timeout = setTimeout(() => { reject(new Error('time out')); }, this.timeout);
      emitter.on('finish', res => {
        res = hex2Str(res);
        const result = parseRegister(res);
        this.logger.info('[unipay - trade receive]', result);
        clearTimeout(timeout);
        resolve(result);
      });
    });
    const res = {};
    res.status = selectBit(39, result);
    if (selectBit(39, result) === '3030') {
      res.retrievalNo = str2Hex(selectBit(37, result)).toString();
      res.tradeTime = selectBit(12, result);
      res.tradeDate = selectBit(13, result);
    }
    return res;
  }

  /**
     * 交易IC
     * @param {*} serialNo 受卡方系统跟踪号
     * @param {*} icCardNo ic卡卡号
     * @param {*} icTags ic卡Tags
     * @param {*} track2 2磁
     * @param {*} track3 3磁
     * @param {*} password Pin
     * @param {*} price 金额
     * @param {*} csn 卡序列号
     * @return {Object} res
     */
  async tradeIC(serialNo, icCardNo, icTags, track2, track3, password, price, csn) {
    const { calcLLVar, calcLLLVar, str2Hex, hex2Str, str2Buf } = encode;
    const { parseRegister, calcMac, selectBit, prepareARQCTags } = UnionCardPay;
    const { encrypt3DESECB } = crypto;
    const reqParams = [];
    reqParams.push(str2Hex(this.tpdu)); // tpdu
    reqParams.push(str2Hex('603100310208')); // 报文头
    reqParams.push(str2Hex('0200')); // 消息类型
    track3 ? reqParams.push(str2Hex('702006C030C09A11')) : reqParams.push(str2Hex('702006C020C09A11')); // 位图
    reqParams.push(str2Hex(calcLLVar(icCardNo) + icCardNo)); // 银行卡号
    reqParams.push(str2Hex('190000')); // 交易处理码
    reqParams.push(str2Hex('' + price, 6, 1)); // 交易金额
    reqParams.push(str2Hex(serialNo)); // 受卡方系统跟踪号
    reqParams.push(str2Hex('0510')); // 服务点输入方式码
    reqParams.push(str2Hex(csn + '0')); // 卡序列号
    reqParams.push(str2Hex('82')); // 服务点条件码
    reqParams.push(str2Hex('06')); // 服务点PIN获取码
    reqParams.push(str2Hex(calcLLVar(track2) + track2)); // 2磁道数据
    if (track3) reqParams.push(str2Hex(calcLLLVar(track3) + track3)); // 3磁道数据
    reqParams.push(str2Buf(this.deviceId)); // 受卡机终端标识码
    reqParams.push(str2Buf(this.posId)); // 受卡方标识码(商户代码)
    // reqParams.push(str2Hex('003150414432303632302020202020202020202020202020202030303030303023')); // 48
    reqParams.push(str2Buf('156')); // 交易货币代码
    reqParams.push(encrypt3DESECB(password, str2Hex(this.pKey))); // 个人标识码数据
    reqParams.push(str2Hex('1600000000000000')); // 安全控制信息
    reqParams.push(prepareARQCTags(icTags.secret, icTags.issuerInfo, icTags.unPredictCode, icTags.counter, icTags.tradeDate, price, str2Buf(this.deviceNo), str2Hex(serialNo, 4, 1))); // IC卡数据域
    reqParams.push(str2Hex('001622' + this.batchNo + '00000050')); // 自定义域
    let req = Buffer.concat(reqParams);
    const mac = calcMac(req.slice(11), str2Hex(this.mKey));
    req = Buffer.concat([ req, mac ]);
    const head = Buffer.alloc(2);
    head.writeUIntBE(req.length, 0, 2);
    req = Buffer.concat([ head, req ]);
    this.logger.info('[unipay - tradeIC send]', parseRegister(hex2Str(req)));
    const result = await new Promise((resolve, reject) => {
      const emitter = new UniTaskEmitter();
      emitter.req = req;
      this.createRequest(emitter);
      const timeout = setTimeout(() => { reject(new Error('time out')); }, this.timeout);
      emitter.on('finish', res => {
        res = hex2Str(res);
        const result = parseRegister(res);
        this.logger.info('[unipay - tradeIC receive]', result);
        clearTimeout(timeout);
        resolve(result);
      });
    });
    const res = {};
    res.status = selectBit(39, result);
    if (selectBit(39, result) === '3030') {
      res.retrievalNo = str2Hex(selectBit(37, result)).toString();
      res.tradeTime = selectBit(12, result);
      res.tradeDate = selectBit(13, result);
      const tlv = TlvFactory.parse(selectBit(55, result));
      const arpc = R.prop('value', R.filter(R.propEq('tag', '91'), tlv)[0]);
      if (arpc) res.arpc = hex2Str(arpc);
      const scriptItems = R.filter(R.propEq('tag', '72'), tlv)[0];
      if (scriptItems) {
        const scripts = scriptItems.items;
        const scriptValues = R.map(R.prop('value'), R.filter(R.propEq('tag', '86'), scripts));
        res.scripts = R.transduce(R.map(val => hex2Str(val) + ','), R.concat, '', scriptValues).slice(0, -1);
      }
      const scriptId = R.prop('value', R.filter(R.propEq('tag', '9F36'), tlv)[0]);
      if (scriptId) res.scriptId = hex2Str(scriptId);
    }
    return res;
  }

  /**
     * IC卡冲正
     * @param {*} preSerialNo 受卡方系统跟踪号: 同原交易取值
     * @param {*} icTags ic卡Tags
     * @param {*} track2 2磁
     * @param {*} track3 3磁
     * @param {*} price 金额
     * @param {*} csn 卡序列号
     * @param {*} preTradeDate 交易日期, 同原交易取值
     * @param {*} preBatchNo 60.2批次号
     * @return {Object} res
     */
  async reversalIC(preSerialNo, icTags, track2, track3, price, csn, preTradeDate, preBatchNo) {
    const { str2Hex, hex2Str, str2Buf, calcLLVar, calcLLLVar } = encode;
    const { parseRegister, calcMac, selectBit, prepareReversalTags } = UnionCardPay;
    const reqParams = [];
    reqParams.push(str2Hex(this.tpdu)); // tpdu
    reqParams.push(str2Hex('603100310208')); // 报文头
    reqParams.push(str2Hex('0400')); // 消息类型
    track3 ? reqParams.push(str2Hex('3020068032C08219')) : reqParams.push(str2Hex('3020068022C08219')); // 位图
    reqParams.push(str2Hex('190000')); // 交易处理码
    reqParams.push(str2Hex('' + price, 6, 1)); // 交易金额
    reqParams.push(str2Hex(preSerialNo)); // 受卡方系统跟踪号
    reqParams.push(str2Hex('0510')); // 服务点输入方式码
    reqParams.push(str2Hex(csn + '0')); // 卡序列号
    reqParams.push(str2Hex('82')); // 服务点条件码
    reqParams.push(str2Hex(calcLLVar(track2) + track2)); // 2磁道数据
    if (track3) reqParams.push(str2Hex(calcLLLVar(track3) + track3)); // 3磁道数据
    reqParams.push(str2Hex('3936')); // 检索参考号
    reqParams.push(str2Buf(this.deviceId)); // 受卡机终端标识码
    reqParams.push(str2Buf(this.posId)); // 受卡方标识码(商户代码)
    reqParams.push(str2Buf('156')); // 交易货币代码
    reqParams.push(prepareReversalTags(icTags.issuerInfo, icTags.counter)); // IC卡数据域
    reqParams.push(str2Hex('001622' + preBatchNo + '00000050')); // 自定义域
    reqParams.push(str2Hex('0029'), str2Buf(preBatchNo + preSerialNo + preTradeDate + '0000000000000', 29)); // 61自定义域

    let req = Buffer.concat(reqParams);
    const mac = calcMac(req.slice(11), str2Hex(this.mKey));
    req = Buffer.concat([ req, mac ]);
    const head = Buffer.alloc(2);
    head.writeUIntBE(req.length, 0, 2);
    req = Buffer.concat([ head, req ]);
    this.logger.info('[unipay - reversalIC send]', parseRegister(hex2Str(req)));
    const result = await new Promise((resolve, reject) => {
      const emitter = new UniTaskEmitter();
      emitter.req = req;
      this.createRequest(emitter);
      const timeout = setTimeout(() => { reject(new Error('time out')); }, 5000);
      emitter.on('finish', res => {
        res = hex2Str(res);
        const result = parseRegister(res);
        this.logger.info('[unipay - reversalIC receive]', result);
        clearTimeout(timeout);
        resolve(result);
      });
    });
    const res = {};
    res.status = selectBit(39, result);
    return res;
  }

  /**
   * IC卡退货
   * @param {*} serialNo 受卡方系统跟踪号
   * @param {*} icCardNo ic卡卡号
   * @param {*} track2 2磁
   * @param {*} track3 3磁
   * @param {*} price 退货金额
   * @param {*} csn 卡序列号
   * @param {*} preTradeDate 交易日期: 同原交易取值
   * @param {*} retrievalNo 先前交易37域
   * @param {*} preSerialNo 受卡方系统跟踪号: 同原交易取值
   * @param {*} preBatchNo 60.2批次号: 同原交易取值
   * @return {Object} res
   */
  async refundIC(serialNo, icCardNo, track2, track3, price, csn, preTradeDate, retrievalNo, preSerialNo, preBatchNo) {
    const { str2Hex, hex2Str, str2Buf, calcLLVar, calcLLLVar } = encode;
    const { parseRegister, calcMac, selectBit } = UnionCardPay;
    const reqParams = [];
    reqParams.push(str2Hex(this.tpdu)); // tpdu
    reqParams.push(str2Hex('603100310208')); // 报文头
    reqParams.push(str2Hex('0220')); // 消息类型
    track3 ? reqParams.push(str2Hex('7020068038C08019')) : reqParams.push(str2Hex('7020068028C08019')); // 位图
    reqParams.push(str2Hex(calcLLVar(icCardNo) + icCardNo)); // 银行卡号
    reqParams.push(str2Hex('200000')); // 交易处理码
    reqParams.push(str2Hex('' + price, 6, 1)); // 交易金额
    reqParams.push(str2Hex(serialNo)); // 受卡方系统跟踪号
    reqParams.push(str2Hex('0510')); // 服务点输入方式码
    reqParams.push(str2Hex(csn + '0')); // 卡序列号
    reqParams.push(str2Hex('82')); // 服务点条件码
    reqParams.push(str2Hex(calcLLVar(track2) + track2)); // 2磁道数据
    if (track3) reqParams.push(str2Hex(calcLLLVar(track3) + track3)); // 3磁道数据
    reqParams.push(str2Buf(retrievalNo, 12)); // 系统检索参考号
    reqParams.push(str2Buf(this.deviceId)); // 受卡机终端标识码
    reqParams.push(str2Buf(this.posId)); // 受卡方标识码(商户代码)
    reqParams.push(str2Buf('156')); // 交易货币代码
    reqParams.push(str2Hex('001625' + this.batchNo + '00000050')); // 自定义域
    reqParams.push(str2Hex('0029'), str2Buf(preBatchNo + preSerialNo + preTradeDate + '0000000000000', 29)); // 61自定义域

    let req = Buffer.concat(reqParams);
    const mac = calcMac(req.slice(11), str2Hex(this.mKey));
    req = Buffer.concat([ req, mac ]);
    const head = Buffer.alloc(2);
    head.writeUIntBE(req.length, 0, 2);
    req = Buffer.concat([ head, req ]);
    this.logger.info('[unipay - refundIC send]', parseRegister(hex2Str(req)));
    const result = await new Promise((resolve, reject) => {
      const emitter = new UniTaskEmitter();
      emitter.req = req;
      this.createRequest(emitter);
      const timeout = setTimeout(() => { reject(new Error('time out')); }, 5000);
      emitter.on('finish', res => {
        res = hex2Str(res);
        const result = parseRegister(res);
        this.logger.info('[unipay - refundIC receive]', result);
        clearTimeout(timeout);
        resolve(result);
      });
    });
    const res = {};
    res.status = selectBit(39, result);
    return res;
  }

  /**
   * IC卡TC上送
   * @param {*} serialNo 受卡方系统跟踪号: 同原交易取值
   * @param {*} icCardNo ic卡卡号
   * @param {*} icTags ic卡Tags
   * @param {*} price 金额
   * @param {*} csn 卡序列号
   * @param {*} preTradeDate 交易日期: 同原交易取值
   * @param {*} preTradeTime 交易时间: 同原交易取值
   * @param {*} preBatchNo 60.2批次号: 同原交易取值
   * @return {Object} res
   */
  async tradeTCUpload(serialNo, icCardNo, icTags, price, csn, preTradeDate, preTradeTime, preBatchNo) {
    const { calcLLVar, str2Hex, hex2Str, str2Buf, num2Str } = encode;
    const { parseRegister, selectBit, prepareTCTags } = UnionCardPay;
    const reqParams = [];
    reqParams.push(str2Hex(this.tpdu)); // tpdu
    reqParams.push(str2Hex('603100310208')); // 报文头
    reqParams.push(str2Hex('0320')); // 消息类型
    reqParams.push(str2Hex('5038060000C08212')); // 位图
    reqParams.push(str2Hex(calcLLVar(icCardNo) + icCardNo)); // 银行卡号
    reqParams.push(str2Hex('' + price, 6, 1)); // 交易金额
    reqParams.push(str2Hex(serialNo)); // 受卡方系统跟踪号
    reqParams.push(str2Hex(preTradeTime)); // 受卡方所在地时间
    reqParams.push(str2Hex(preTradeDate)); // 受卡方所在地日期
    reqParams.push(str2Hex('0510')); // 服务点输入方式码
    reqParams.push(str2Hex(csn + '0')); // 卡序列号
    reqParams.push(str2Buf(this.deviceId)); // 受卡机终端标识码
    reqParams.push(str2Buf(this.posId)); // 受卡方标识码(商户代码)
    reqParams.push(str2Buf('156')); // 交易货币代码
    reqParams.push(prepareTCTags(icTags.secret, icTags.issuerInfo, icTags.unPredictCode, icTags.counter, icTags.tradeDate, price, str2Buf(this.deviceNo), str2Hex(serialNo, 4, 1))); // IC卡数据域
    reqParams.push(str2Hex('001622' + preBatchNo + '20300050')); // 自定义域
    reqParams.push(str2Hex('0021'), str2Buf('610000' + num2Str(price, 12) + '156', 23));
    let req = Buffer.concat(reqParams);
    const head = Buffer.alloc(2);
    head.writeUIntBE(req.length, 0, 2);
    req = Buffer.concat([ head, req ]);
    this.logger.info('[unipay - tradeTCUpload send]', parseRegister(hex2Str(req)));
    const result = await new Promise((resolve, reject) => {
      const emitter = new UniTaskEmitter();
      emitter.req = req;
      this.createRequest(emitter);
      const timeout = setTimeout(() => { reject(new Error('time out')); }, this.timeout);
      emitter.on('finish', res => {
        res = hex2Str(res);
        const result = parseRegister(res);
        this.logger.info('[unipay - tradeTCUpload receive]', result);
        clearTimeout(timeout);
        resolve(result);
      });
    });
    const res = {};
    res.status = selectBit(39, result);
    return res;
  }

  /**
   * script结果上送
   * @param {*} serialNo 受卡方系统跟踪号
   * @param {*} icCardNo ic卡卡号
   * @param {*} icTags ic卡Tags
   * @param {*} price 金额
   * @param {*} csn 卡序列号
   * @param {*} preTradeDate 原交易日期
   * @param {*} retrievalNo 先前交易37域
   * @param {*} preSerialNo 受卡方系统跟踪号: 同原交易取值
   * @param {*} preBatchNo 60.2批次号: 同原交易取值
   * @return {Object} res
   */
  async scriptNotify(serialNo, icCardNo, icTags, price, csn, preTradeDate, retrievalNo, preSerialNo, preBatchNo) {
    const { calcLLVar, str2Hex, hex2Str, str2Buf } = encode;
    const { parseRegister, calcMac, selectBit, prepareScriptNotifyTags } = UnionCardPay;
    const reqParams = [];
    reqParams.push(str2Hex(this.tpdu)); // tpdu
    reqParams.push(str2Hex('603100310208')); // 报文头
    reqParams.push(str2Hex('0620')); // 消息类型
    reqParams.push(str2Hex('7020068008C08219')); // 位图
    reqParams.push(str2Hex(calcLLVar(icCardNo) + icCardNo)); // 银行卡号
    reqParams.push(str2Hex('190000')); // 交易处理码
    reqParams.push(str2Hex('' + price, 6, 1)); // 交易金额
    reqParams.push(str2Hex(serialNo)); // 受卡方系统跟踪号
    reqParams.push(str2Hex('0510')); // 服务点输入方式码
    reqParams.push(str2Hex(csn + '0')); // 卡序列号
    reqParams.push(str2Hex('82')); // 服务点条件码
    reqParams.push(str2Buf(retrievalNo, 12)); // 系统检索参考号
    reqParams.push(str2Buf(this.deviceId)); // 受卡机终端标识码
    reqParams.push(str2Buf(this.posId)); // 受卡方标识码(商户代码)
    reqParams.push(str2Buf('156')); // 交易货币代码
    reqParams.push(prepareScriptNotifyTags(icTags.secret, icTags.issuerInfo, icTags.unPredictCode, icTags.counter, icTags.tradeDate, icTags.scriptStatus)); // IC卡数据域
    reqParams.push(str2Hex('001622' + preBatchNo + '95100050')); // 自定义域
    reqParams.push(str2Hex('0029'), str2Buf(preBatchNo + preSerialNo + preTradeDate + '0000000000000', 29));
    let req = Buffer.concat(reqParams);
    const mac = calcMac(req.slice(11), str2Hex(this.mKey));
    req = Buffer.concat([ req, mac ]);
    const head = Buffer.alloc(2);
    head.writeUIntBE(req.length, 0, 2);
    req = Buffer.concat([ head, req ]);
    this.logger.info('[unipay - scriptNotify send]', parseRegister(hex2Str(req)));
    const result = await new Promise((resolve, reject) => {
      const emitter = new UniTaskEmitter();
      emitter.req = req;
      this.createRequest(emitter);
      const timeout = setTimeout(() => { reject(new Error('time out')); }, this.timeout);
      emitter.on('finish', res => {
        res = hex2Str(res);
        const result = parseRegister(res);
        this.logger.info('[unipay - scriptNotify receive]', result);
        clearTimeout(timeout);
        resolve(result);
      });
    });
    const res = {};
    res.status = selectBit(39, result);
    return res;
  }

  /**
     * 解析bitmap 数组
     * @param {String} req bitmap字符串
     * @return {Number[]} bitmap 数组
     */
  /* eslint no-bitwise: 0*/
  static parseBitMap(req) {
    const res = [];
    for (let i = 0; i < req.length; i++) {
      const num = new Decimal('0x' + req[i]).toNumber();
      if (num & 8) {
        res.push(i * 4 + 1);
      }
      if (num & 4) {
        res.push(i * 4 + 2);
      }
      if (num & 2) {
        res.push(i * 4 + 3);
      }
      if (num & 1) {
        res.push(i * 4 + 4);
      }
    }
    return res;
  }

  /**
     * 解析bitmap 对应长度
     * @param {String|Number} index 位
     * @param {String} res 可变长位字符， 用于LLVar, LLLVar解析
     * @return {Number[]} bitmap 数组
     */
  static registerTable(index, res) {
    switch (parseInt(index)) {
      case 2: return [ parseInt(res.slice(0, 2)) + parseInt(res.slice(0, 2)) % 2 + 2, parseInt(res.slice(0, 2)) + parseInt(res.slice(0, 2)) % 2 ];
      case 3: return 6;
      case 4: return 12;
      case 11: return 6;
      case 12: return 6;
      case 13: return 4;
      case 14: return 4;
      case 15: return 4;
      case 22: return 4;
      case 23: return 4;
      case 25: return 2;
      case 26: return 2;
      case 32: return [ parseInt(res.slice(0, 2)) + parseInt(res.slice(0, 2)) % 2 + 2, parseInt(res.slice(0, 2)) + parseInt(res.slice(0, 2)) % 2 ];
      case 35: return [ parseInt(res.slice(0, 2)) + parseInt(res.slice(0, 2)) % 2 + 2, parseInt(res.slice(0, 2)) + parseInt(res.slice(0, 2)) % 2 ];
      case 36: return [ parseInt(res.slice(0, 4)) + parseInt(res.slice(0, 4)) % 2 + 4, parseInt(res.slice(0, 4)) + parseInt(res.slice(0, 4)) % 2 ];
      case 37: return 24;
      case 38: return 12;
      case 39: return 4;
      case 41: return 16;
      case 42: return 30;
      case 44: return [ parseInt(res.slice(0, 4)) * 2 + 4, parseInt(res.slice(0, 4)) * 2 ];
      case 48: return [ parseInt(res.slice(0, 4)) + parseInt(res.slice(0, 4)) + 4, parseInt(res.slice(0, 4)) + parseInt(res.slice(0, 4)) ];
      case 49: return 6;
      case 52: return 16;
      case 53: return 16;
      case 54: return [ parseInt(res.slice(0, 4)) * 2 + 4, parseInt(res.slice(0, 4)) * 2 ];
      case 55: return [ parseInt(res.slice(0, 4)) * 2 + 4, parseInt(res.slice(0, 4)) * 2 ];
      case 60: return [ parseInt(res.slice(0, 4)) + parseInt(res.slice(0, 4)) % 2 + 4, parseInt(res.slice(0, 4)) + parseInt(res.slice(0, 4)) % 2 ];
      case 61: return [ parseInt(res.slice(0, 4)) * 2 + 4, parseInt(res.slice(0, 4)) * 2 ];
      case 62: return [ parseInt(res.slice(0, 4)) * 2 + 4, parseInt(res.slice(0, 4)) * 2 ];
      case 63: return [ parseInt(res.slice(0, 4)) * 2 + 4, parseInt(res.slice(0, 4)) * 2 ];
      case 64: return 16;
      default: throw new Error('error res');
    }
  }

  /**
     * 解析报文
     * @param {String} req 报文字符
     * @return {Object} 报文对象{bit: 位, data: 位数据}
     */
  static parseRegister(req) {
    const result = [];
    req = req.slice(30);
    const bitMap = UnionCardPay.parseBitMap(req.slice(0, 16));
    req = req.slice(16);
    bitMap.forEach(bit => {
      const len = UnionCardPay.registerTable(bit, req);
      if (len instanceof Array) {
        req = req.slice(len[0] - len[1]);
        result.push({ bit, data: req.slice(0, len[1]) });
        req = req.slice(len[1]);
      } else {
        result.push({ bit, data: req.slice(0, len) });
        req = req.slice(len);
      }
    });
    return result;
  }

  /**
     * 选择报文对象对于位
     * @param {String} bit 报文位
     * @param {String} req 报文对象
     * @return {String} data
     */
  static selectBit(bit, req) {
    return R.prop('data', R.filter(R.propEq('bit', bit), req)[0]);
  }

  /**
     * 计算MAC
     * @param {Buffer} req 请求Buffer
     * @param {Buffer} key 密钥
     * @return {Buffer} mac
     */
  static calcMac(req, key) {
    let res = Buffer.alloc(8);
    req = Buffer.concat([ req ], req.length % 8 ? req.length + 8 - req.length % 8 : req.length);
    for (let i = 0; i < req.length / 8; i++) {
      res = xor(res, req.slice(i * 8, (i + 1) * 8));
      res = crypto.encryptDESECB(res, key);
    }
    return res;
  }

  /**
   * 准备ARQC标签
   * @param {*} secret 应用密文
   * @param {*} issuerInfo 发卡行应用数据
   * @param {*} unPredictCode 不可预知数
   * @param {*} counter 应用交易计数器
   * @param {*} tradeDate 交易日期
   * @param {*} price 金额
   * @param {*} deviceNo 设备编号
   * @param {*} serialNo 受卡方系统跟踪号
   * @return {*} tags
   */
  static prepareARQCTags(secret, issuerInfo, unPredictCode, counter, tradeDate, price, deviceNo, serialNo) {
    const tags = [];
    let tag;
    let tagValue;
    tag = '9F26'; // 应用密文
    tagValue = secret;
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F27'; // 密文信息数据
    tagValue = '80';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F10'; // 发卡行应用数据
    tagValue = issuerInfo;
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F37'; // 不可预知数
    tagValue = unPredictCode;
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F36'; // 应用交易计数器
    tagValue = counter;
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '95'; // 终端验证结果
    tagValue = '008004E000';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9A'; // 交易日期
    tagValue = tradeDate;
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9C'; // 交易类型
    tagValue = '00';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F02'; // 授权金额
    tagValue = num2Str(price, 12);
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '5F2A'; // 交易货币代码
    tagValue = '0156';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '82'; // 应用交互特征
    tagValue = '7C00';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F1A'; // 终端国家代码
    tagValue = '0156';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F03'; // 其它金额
    tagValue = '000000000000';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F33'; // 终端性能
    tagValue = 'E0E9C8';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F34'; // 持卡人验证结果
    tagValue = '020300';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F35'; // 终端类型
    tagValue = '22';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F1E'; // 接口设备序列号
    tagValue = deviceNo;
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '84'; // 专用文件名称
    tagValue = '315041592E5359532E4444463031';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F41'; // 交易序列计数器
    tagValue = serialNo;
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    const icTagsInfo = TlvFactory.serialize(tags);
    const icTags = Buffer.concat([ str2Hex('' + icTagsInfo.length, 2, 1), icTagsInfo ]);
    return icTags;
  }

  /**
   * 准备TC标签
   * @param {*} secret 应用密文
   * @param {*} issuerInfo 发卡行应用数据
   * @param {*} unPredictCode 不可预知数
   * @param {*} counter 应用交易计数器
   * @param {*} tradeDate 交易日期
   * @param {*} price 金额
   * @param {*} deviceNo 设备编号
   * @param {*} serialNo 受卡方系统跟踪号
   * @return {*} tags
   */
  static prepareTCTags(secret, issuerInfo, unPredictCode, counter, tradeDate, price, deviceNo, serialNo) {
    const tags = [];
    let tag;
    let tagValue;
    tag = '9F26'; // 应用密文
    tagValue = secret;
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F27'; // 密文信息数据
    tagValue = '40';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F10'; // 发卡行应用数据
    tagValue = issuerInfo;
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F37'; // 不可预知数
    tagValue = unPredictCode;
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F36'; // 应用交易计数器
    tagValue = counter;
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '95'; // 终端验证结果
    tagValue = '008004E000';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9A'; // 交易日期
    tagValue = tradeDate;
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9C'; // 交易类型
    tagValue = '00';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F02'; // 授权金额
    tagValue = num2Str(price, 12);
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '5F2A'; // 交易货币代码
    tagValue = '0156';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '82'; // 应用交互特征
    tagValue = '7C00';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F1A'; // 终端国家代码
    tagValue = '0156';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F03'; // 其它金额
    tagValue = '000000000000';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F33'; // 终端性能
    tagValue = 'E0E9C8';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F34'; // 持卡人验证结果
    tagValue = '020300';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F35'; // 终端类型
    tagValue = '22';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F1E'; // 接口设备序列号
    tagValue = deviceNo;
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '84'; // 专用文件名称
    tagValue = '315041592E5359532E4444463031';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F41'; // 交易序列计数器
    tagValue = serialNo;
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    const icTagsInfo = TlvFactory.serialize(tags);
    const icTags = Buffer.concat([ str2Hex('' + icTagsInfo.length, 2, 1), icTagsInfo ]);
    return icTags;
  }

  /**
   * 准备ScriptNotify标签
   * @param {*} secret 应用密文
   * @param {*} issuerInfo 发卡行应用数据
   * @param {*} unPredictCode 不可预知数
   * @param {*} counter 应用交易计数器
   * @param {*} tradeDate 交易日期
   * @param {*} scriptStatus 发卡行脚本结果
   * @return {*} tags
   */
  static prepareScriptNotifyTags(secret, issuerInfo, unPredictCode, counter, tradeDate, scriptStatus) {
    const tags = [];
    let tag;
    let tagValue;
    tag = '9F33'; // 终端性能
    tagValue = 'E0E9C8';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '95'; // 终端验证结果
    tagValue = '008004E000';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F37'; // 不可预知数
    tagValue = unPredictCode;
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F10'; // 发卡行应用数据
    tagValue = issuerInfo;
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F26'; // 应用密文
    tagValue = secret;
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F36'; // 应用交易计数器
    tagValue = counter;
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '82'; // 应用交互特征
    tagValue = '7C00';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = 'DF31'; // 发卡行脚本结果
    tagValue = scriptStatus;
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F1A'; // 终端国家代码
    tagValue = '0156';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9A'; // 交易日期
    tagValue = tradeDate;
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    const icTagsInfo = TlvFactory.serialize(tags);
    const icTags = Buffer.concat([ str2Hex('' + icTagsInfo.length, 2, 1), icTagsInfo ]);
    return icTags;
  }

  /**
   * 准备Reversal标签
   * @param {*} issuerInfo 发卡行应用数据
   * @param {*} counter 应用交易计数器
   * @return {*} tags
   */
  static prepareReversalTags(issuerInfo, counter) {
    const tags = [];
    let tag;
    let tagValue;
    tag = '95'; // 终端验证结果
    tagValue = '008004E000';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F10'; // 发卡行应用数据
    tagValue = issuerInfo;
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = '9F36'; // 应用交易计数器
    tagValue = counter;
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    tag = 'DF31'; // 发卡行脚本结果
    tagValue = '0000000000';
    tags.push(TlvFactory.primitiveTlv(tag, tagValue));
    const icTagsInfo = TlvFactory.serialize(tags);
    const icTags = Buffer.concat([ str2Hex('' + icTagsInfo.length, 2, 1), icTagsInfo ]);
    return icTags;
  }
}

module.exports = UnionCardPay;

