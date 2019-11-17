const UnionCardPay = require('..');
const { socket, https, cardInfo } = require('./config');

let unioncardClientSocket;
let unioncardClientHttps;
let tradeSerial;
beforeAll(() => {
  unioncardClientSocket = new UnionCardPay(socket.host, socket.port, socket.tpdu, socket.posId,
    socket.deviceId, socket.batchNo, socket.primaryKey, socket.deviceNo);
  unioncardClientHttps = new UnionCardPay(https.host, https.port, https.tpdu, https.posId,
    https.deviceId, https.batchNo, https.primaryKey, https.deviceNo, console, 15000, true, https.ca, https.cryptoProxyHost);
});

beforeEach(() => {
  tradeSerial = '' + Math.floor(Math.random() * (1000000 - 100000) + 100000);
});

test('UnionCardPay socket register', async () => {
  const res = await unioncardClientSocket.register();
  expect(res.batchNo).toBeTruthy();
});


test('UnionCardPay socket trade', async () => {
  const res = await unioncardClientSocket.trade(tradeSerial, cardInfo.track2, cardInfo.track3, cardInfo.password, 1);
  expect(res.status).toBe('3030');
});

test('UnionCardPay https register', async () => {
  const res = await unioncardClientHttps.register();
  expect(res.batchNo).toBeTruthy();
});

test('UnionCardPay https trade', async () => {
  const res = await unioncardClientHttps.trade(tradeSerial, cardInfo.track2, cardInfo.track3, cardInfo.password, 1);
  expect(res.status).toBe('3030');
});
