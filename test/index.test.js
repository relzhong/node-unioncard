const UnionCardPay = require('..');
const { socket, https } = require('./config');

let unioncardClientSocket;
let unioncardClientHttps;
beforeEach(() => {
  unioncardClientSocket = new UnionCardPay(socket.host, socket.port, socket.tpdu, socket.posId,
    socket.deviceId, socket.batchNo, socket.primaryKey, socket.deviceNo);
  unioncardClientHttps = new UnionCardPay(https.host, https.port, https.tpdu, https.posId,
    https.deviceId, https.batchNo, https.primaryKey, https.deviceNo, console, 15000, true, https.ca);
});

test('UnionCardPay socket register', async () => {
  const res = await unioncardClientSocket.register();
  expect(res.pKey).toBeTruthy();
});

test('UnionCardPay https register', async () => {
  const res = await unioncardClientHttps.register();
  expect(res.pKey).toBeTruthy();
});
