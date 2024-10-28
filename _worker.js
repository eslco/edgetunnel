// <!--GAMFC-->version base on commit 43fad05dcdae3b723c53c226f8181fc5bd47223e, time is 2023-06-22 15:20:05 UTC<!--GAMFC-END-->.
// @ts-ignore
import { connect } from 'cloudflare:sockets';

// How to generate your own UUID:
// [Windows] Press "Win + R", input cmd and run:  Powershell -NoExit -Command "[guid]::NewGuid()"
let userID = 'c8eaa0df-eafb-482c-8e88-d2d1623481ee';

let proxyIP = '';// 小白勿动'cdn.xn--b6gac.eu.org, cdn-all.xn--b6gac.eu.org, workers.cloudflare.cyou'

let sub = '';// VLESS.fxxk.dedyn.io
let subconverter = 'SUBAPI.fxxk.dedyn.io';// sub.d1.mk
let subconfig = "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_Full_MultiMode.ini"; //
let subProtocol = 'https';
// The user name and password do not contain special characters
// Setting the address will ignore proxyIP
// Example:  user:pass@host:port  or  host:port
let socks5Address = '';

if (!isValidUUID(userID)) {
	throw new Error('uuid is not valid');
}

let parsedSocks5Address = {}; 
let enableSocks = false;

// 
let fakeUserID ;
let fakeHostName ;
let noTLS = 'false'; 
const expire = 4102329600;//2099-12-31
let proxyIPs;
let socks5s;
let go2Socks5s = [
	'*ttvnw.net',
	'*tapecontent.net',
	'*cloudatacdn.com',
	'*.loadshare.org',
];
let addresses = [
	//当sub为空时启用本地优选域名/优选IP，若不带端口号 TLS默认端口为443，#号后为备注别名
	/*
	'cf.059527.xyz:8443#t.me',
	'visa.cn:8443',
	'www.visa.com:8443',
	'cis.visa.com:2053',
	'africa.visa.com:2083',
	'www.visa.com.sg:2087',
	'www.visaeurope.at:2096',
	'www.visa.com.mt:8443',
	'qa.visamiddleeast.com',
	'time.is',
	'www.wto.org:8443',
	'chatgpt.com:2087',
	'icook.hk',
	'104.17.0.0#IPv4',
	'[2606:4700::]#IPv6'
	*/
];
let addressesapi = [];
let addressesnotls = [
	//当sub为空且域名带有"worker"字样时启用本地优选域名/优选IP，若不带端口号 noTLS默认端口为80，#号后为备注别名
	/*
	'usa.visa.com',
	'myanmar.visa.com:8080',
	'www.visa.com.tw:8880',
	'www.visaeurope.ch:2052',
	'www.visa.com.br:2082',
	'www.visasoutheasteurope.com:2086',
	'[2606:4700::1]:2095#IPv6'
	*/
];
let addressesnotlsapi = [];
let addressescsv = [];
let DLS = 8;
let FileName = 'edgetunnel';
let BotToken ='';
let ChatID =''; 
let proxyhosts = [];//local proxy hosts
let proxyhostsURL = 'https://raw.githubusercontent.com/cmliu/CFcdnVmess2sub/main/proxyhosts';//在线代理域名池URL
let RproxyIP = 'false';
let httpsPorts = ["2053","2083","2087","2096","8443"];
let effectiveTime = 7;//有效时间 单位:天
let updateTime = 3;//更新时间
let userIDLow;
let userIDTime = "";
export default {
	/**
	 * @param {import("@cloudflare/workers-types").Request} request
	 * @param {{UUID: string, PROXYIP: string}} env
	 * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
	 * @returns {Promise<Response>}
	 */
	async fetch(request, env, ctx) {
		try {
			const UA = request.headers.get('User-Agent') || 'null';
			const userAgent = UA.toLowerCase();
			userID = (env.UUID || userID).toLowerCase();

			const currentDate = new Date();
			currentDate.setHours(0, 0, 0, 0); 
			const timestamp = Math.ceil(currentDate.getTime() / 1000);
			const fakeUserIDMD5 = await MD5MD5(`${userID}${timestamp}`);
			fakeUserID = fakeUserIDMD5.slice(0, 8) + "-" + fakeUserIDMD5.slice(8, 12) + "-" + fakeUserIDMD5.slice(12, 16) + "-" + fakeUserIDMD5.slice(16, 20) + "-" + fakeUserIDMD5.slice(20);
			fakeHostName = fakeUserIDMD5.slice(6, 9) + "." + fakeUserIDMD5.slice(13, 19);
			//console.log(`虚假UUID: ${fakeUserID}`); // 打印fakeID
			if (env.KEY) {
				const userIDs = await generateDynamicUUID(env.KEY);
				userID = userIDs[0];
				userIDLow = userIDs[1];
				userIDTime = userIDs[2];
				//console.log(`启用动态UUID\n秘钥KEY: ${env.KEY}\nUUIDNow: ${userID}\nUUIDLow: ${userIDLow}`);
				effectiveTime = env.TIME || effectiveTime;
				updateTime = env.UPTIME || updateTime;
			}
			proxyIP = env.PROXYIP || proxyIP;
			proxyIPs = await ADD(proxyIP);
			proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
			//console.log(proxyIP);
			socks5Address = env.SOCKS5 || socks5Address;
			socks5s = await ADD(socks5Address);
			socks5Address = socks5s[Math.floor(Math.random() * socks5s.length)];
			socks5Address = socks5Address.split('//')[1] || socks5Address;
			if (env.CFPORTS) httpsPorts = await ADD(env.CFPORTS);
			sub = env.SUB || sub;
			subconverter = env.SUBAPI || subconverter;
			if( subconverter.includes("http://") ){
				subconverter = subconverter.split("//")[1];
				subProtocol = 'http';
			} else {
				subconverter = subconverter.split("//")[1] || subconverter;
			}
			subconfig = env.SUBCONFIG || subconfig;
			if (socks5Address) {
				try {
					parsedSocks5Address = socks5AddressParser(socks5Address);
					RproxyIP = env.RPROXYIP || 'false';
					enableSocks = true;
				} catch (err) {
  					/** @type {Error} */ 
					let e = err;
					console.log(e.toString());
					RproxyIP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
					enableSocks = false;
				}
			} else {
				RproxyIP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
			}
			if (env.ADD) addresses = await ADD(env.ADD);
			if (env.ADDAPI) addressesapi = await ADD(env.ADDAPI);
			if (env.ADDNOTLS) addressesnotls = await ADD(env.ADDNOTLS);
			if (env.ADDNOTLSAPI) addressesnotlsapi = await ADD(env.ADDNOTLSAPI);
			if (env.ADDCSV) addressescsv = await ADD(env.ADDCSV);
			DLS = env.DLS || DLS;
			BotToken = env.TGTOKEN || BotToken;
			ChatID = env.TGID || ChatID; 
			if(env.GO2SOCKS5) go2Socks5s = await ADD(env.GO2SOCKS5);
			const upgradeHeader = request.headers.get('Upgrade');
			const url = new URL(request.url);
			if (url.searchParams.has('sub') && url.searchParams.get('sub') !== '') sub = url.searchParams.get('sub');
			FileName = env.SUBNAME || FileName;
			if (url.searchParams.has('notls')) noTLS = 'true';
			if (!upgradeHeader || upgradeHeader !== 'websocket') {
				const 路径 = url.pathname.toLowerCase();
				if (路径 == '/') {
					if (env.URL302) return Response.redirect(env.URL302, 302);
					else if (env.URL) return await proxyURL(env.URL, url);
					else return new Response(JSON.stringify(request.cf, null, 4), {
						status: 200,
						headers: {
							'content-type': 'application/json',
						},
					});
				} else if (路径 == `/${fakeUserID}`) {
					const fakeConfig = await getVLESSConfig(userID, request.headers.get('Host'), sub, 'CF-Workers-SUB', RproxyIP, url, env);
					return new Response(`${fakeConfig}`, { status: 200 });
				} else if (路径 == `/${env.KEY}` || 路径 == `/${userID}`) {
					await sendMessage(`#获取订阅 ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${UA}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`);
					const vlessConfig = await getVLESSConfig(userID, request.headers.get('Host'), sub, UA, RproxyIP, url, env);
					const now = Date.now();
					//const timestamp = Math.floor(now / 1000);
					const today = new Date(now);
					today.setHours(0, 0, 0, 0);
					const UD = Math.floor(((now - today.getTime())/86400000) * 24 * 1099511627776 / 2);
					let pagesSum = UD;
					let workersSum = UD;
					let total = 24 * 1099511627776 ;
					if (env.CFEMAIL && env.CFKEY){
						const email = env.CFEMAIL;
						const key = env.CFKEY;
						const accountIndex = env.CFID || 0;
						const accountId = await getAccountId(email, key);
						if (accountId){
							const now = new Date()
							now.setUTCHours(0, 0, 0, 0)
							const startDate = now.toISOString()
							const endDate = new Date().toISOString();
							const Sum = await getSum(accountId, accountIndex, email, key, startDate, endDate);
							pagesSum = Sum[0];
							workersSum = Sum[1];
							total = 102400 ;
						}
					}
					//console.log(`pagesSum: ${pagesSum}\nworkersSum: ${workersSum}\ntotal: ${total}`);
					if (userAgent && userAgent.includes('mozilla')){
						return new Response(`${vlessConfig}`, {
							status: 200,
							headers: {
								"Content-Type": "text/plain;charset=utf-8",
								"Profile-Update-Interval": "6",
								"Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
							}
						});
					} else {
						return new Response(`${vlessConfig}`, {
							status: 200,
							headers: {
								"Content-Disposition": `attachment; filename=${FileName}; filename*=utf-8''${encodeURIComponent(FileName)}`,
								"Content-Type": "text/plain;charset=utf-8",
								"Profile-Update-Interval": "6",
								"Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
							}
						});
					}
				} else {
					if (env.URL302) return Response.redirect(env.URL302, 302);
					else if (env.URL) return await proxyURL(env.URL, url);
					else return new Response('Not found', { status: 404 });
				}
			} else {
				proxyIP = url.searchParams.get('proxyip') || proxyIP;
				if (new RegExp('/proxyip=', 'i').test(url.pathname)) proxyIP = url.pathname.toLowerCase().split('/proxyip=')[1];
				else if (new RegExp('/proxyip.', 'i').test(url.pathname)) proxyIP = `proxyip.${url.pathname.toLowerCase().split("/proxyip.")[1]}`;
				
				socks5Address = url.searchParams.get('socks5') || socks5Address;
				if (new RegExp('/socks5=', 'i').test(url.pathname)) socks5Address = url.pathname.split('5=')[1];
				else if (new RegExp('/socks://', 'i').test(url.pathname) || new RegExp('/socks5://', 'i').test(url.pathname)) {
					socks5Address = url.pathname.split('://')[1].split('#')[0];
					if (socks5Address.includes('@')){
						let userPassword = socks5Address.split('@')[0];
						const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
						if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);
						socks5Address = `${userPassword}@${socks5Address.split('@')[1]}`;
					}
				}
				if (socks5Address) {
					try {
						parsedSocks5Address = socks5AddressParser(socks5Address);
						enableSocks = true;
					} catch (err) {
						/** @type {Error} */ 
						let e = err;
						console.log(e.toString());
						enableSocks = false;
					}
				} else {
					enableSocks = false;
				}
				return await vlessOverWSHandler(request);
			}
		} catch (err) {
			/** @type {Error} */ let e = err;
			return new Response(e.toString());
		}
	},
};

/**
 * 
 * @param {import("@cloudflare/workers-types").Request} request
 */
async function vlessOverWSHandler(request) {

	/** @type {import("@cloudflare/workers-types").WebSocket[]} */
	// @ts-ignore
	const webSocketPair = new WebSocketPair();
	const [client, webSocket] = Object.values(webSocketPair);

	// WS
	webSocket.accept();

	let address = '';
	let portWithRandomLog = '';
	// 日志
	const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
		console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
	};
	// 
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

	// 
	const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

	/** @type {{ value: import("@cloudflare/workers-types").Socket | null}}*/
	// 
	let remoteSocketWapper = {
		value: null,
	};
	// 
	let isDns = false;

	// WS
	readableWebSocketStream.pipeTo(new WritableStream({
		async write(chunk, controller) {
			if (isDns) {
				// 
				return await handleDNSQuery(chunk, webSocket, null, log);
			}
			if (remoteSocketWapper.value) {
				// 
				const writer = remoteSocketWapper.value.writable.getWriter()
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}

			// 
			const {
				hasError,
				message,
				addressType,
				portRemote = 443,
				addressRemote = '',
				rawDataIndex,
				vlessVersion = new Uint8Array([0, 0]),
				isUDP,
			} = processVlessHeader(chunk, userID);
			// 
			address = addressRemote;
			portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '} `;
			if (hasError) {
				// 
				throw new Error(message);
				return;
			}
			// 
			if (isUDP) {
				if (portRemote === 53) {
					isDns = true;
				} else {
					throw new Error('UDP 代理仅对 DNS（53 端口）启用');
					return;
				}
			}
			// 
			const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
			// 
			const rawClientData = chunk.slice(rawDataIndex);

			if (isDns) {
				// 
				return handleDNSQuery(rawClientData, webSocket, vlessResponseHeader, log);
			}
			// 处理 TCP 出站连接
			log(`处理 TCP 出站连接 ${addressRemote}:${portRemote}`);
			handleTCPOutBound(remoteSocketWapper, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log);
		},
		close() {
			log(`readableWebSocketStream 已关闭`);
		},
		abort(reason) {
			log(`readableWebSocketStream 已中止`, JSON.stringify(reason));
		},
	})).catch((err) => {
		log('readableWebSocketStream 管道错误', err);
	});

	// 
	return new Response(null, {
		status: 101,
		// @ts-ignore
		webSocket: client,
	});
}

/**
 * 处理 TCP
 *
 * @param {any} remoteSocket 
 * @param {number} addressType 
 * @param {string} addressRemote 
 * @param {number} portRemote 
 * @param {Uint8Array} rawClientData 
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket 用于传递 Socket  WS
 * @param {Uint8Array} vlessResponseHeader 
 * @param {function} log 日志
 * @returns {Promise<void>} 异步操作的 Promise
 */
async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log,) {
	async function useSocks5Pattern(address) {
		if ( go2Socks5s.includes(atob('YWxsIGlu')) || go2Socks5s.includes(atob('Kg==')) ) return true;
		return go2Socks5s.some(pattern => {
			let regexPattern = pattern.replace(/\*/g, '.*');
			let regex = new RegExp(`^${regexPattern}$`, 'i');
			return regex.test(address);
		});
	}
	/**
	 * 
	 * @param {string} address 
	 * @param {number} port 
	 * @param {boolean} socks 
	 * @returns {Promise<import("@cloudflare/workers-types").Socket>} 连接后的 TCP Socket
	 */
	async function connectAndWrite(address, port, socks = false) {
		/** @type {import("@cloudflare/workers-types").Socket} */
		log(`connected to ${address}:${port}`);
		if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(address)) address = `${atob('d3d3Lg==')}${address}${atob('LmlwLjA5MDIyNy54eXo=')}`;
		// 
		const tcpSocket = socks ? await socks5Connect(addressType, address, port, log)
			: connect({
				hostname: address,
				port: port,
			});
		remoteSocket.value = tcpSocket;
		//log(`connected to ${address}:${port}`);
		const writer = tcpSocket.writable.getWriter();
		//
		await writer.write(rawClientData);
		writer.releaseLock();
		return tcpSocket;
	}

	/**
	 * 重试函数
	 */
	async function retry() {
		if (enableSocks) {
			// 
			tcpSocket = await connectAndWrite(addressRemote, portRemote, true);
		} else {
			// 否则，尝试使用预设的代理 IP（如果有）或原始地址重试连接
			if (!proxyIP || proxyIP == '') {
				proxyIP = atob('cHJveHlpcC50cDEuY21saXVzc3NzLmNvbQ==');
			} else if (proxyIP.includes(']:')) {
				portRemote = proxyIP.split(']:')[1] || portRemote;
				proxyIP = proxyIP.split(']:')[0] || proxyIP;
			} else if (proxyIP.split(':').length === 2) {
				portRemote = proxyIP.split(':')[1] || portRemote;
				proxyIP = proxyIP.split(':')[0] || proxyIP;
			}
			if (proxyIP.includes('.tp')) portRemote = proxyIP.split('.tp')[1].split('.')[0] || portRemote;
			tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote);
		}
		// 
		tcpSocket.closed.catch(error => {
			console.log('retry tcpSocket closed error', error);
		}).finally(() => {
			safeCloseWebSocket(webSocket);
		})
		// 
		remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
	}

	let useSocks = false;
	if( go2Socks5s.length > 0 && enableSocks ) useSocks = await useSocks5Pattern(addressRemote);
	// 首次尝试连接远程服务器
	let tcpSocket = await connectAndWrite(addressRemote, portRemote, useSocks);

	// 
	// 
	//
	remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
}

/**
 * 将 WebSocket 转换为可读流（ReadableStream）
 * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer 
 * @param {string} earlyDataHeader WebSocket 0-RTT
 * @param {(info: string)=> void} log 日志用于记录 WebSocket 0-RTT 相关信息
 * @returns {ReadableStream}
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	// 
	let readableStreamCancel = false;

	// 
	const stream = new ReadableStream({
		// 
		start(controller) {
			// 
			webSocketServer.addEventListener('message', (event) => {
				//
				if (readableStreamCancel) {
					return;
				}
				const message = event.data;
				//
				controller.enqueue(message);
			});

			//
			// 
			// 
			// 
			webSocketServer.addEventListener('close', () => {
				// 
				safeCloseWebSocket(webSocketServer);
				// 
				if (readableStreamCancel) {
					return;
				}
				controller.close();
			});

			// WS
			webSocketServer.addEventListener('error', (err) => {
				log('WebSocket 服务器发生错误');
				// 
				controller.error(err);
			});

			// 处理 WebSocket 0-RTT
			// 0-RTT 
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				// 
				controller.error(error);
			} else if (earlyData) {
				// 
				controller.enqueue(earlyData);
			}
		},

		// 
		pull(controller) {
			// 这里可反压机制
			// 如果 WS 可以在流满时停止读取，我们就可以实现反压
			// 参考：https://streams.spec.whatwg.org/#example-rs-push-backpressure
		},

		//
		cancel(reason) {
			// 流被取消的几种情况
			// 1. 
			// 2. 
			// 3. 
			if (readableStreamCancel) {
				return;
			}
			log(`可读流被取消，原因是 ${reason}`);
			readableStreamCancel = true;
			// 安全地关闭 WebSocket
			safeCloseWebSocket(webSocketServer);
		}
	});

	return stream;
}

// https://xtls.github.io/development/protocols/vless.html
// https://github.com/zizifn/excalidraw-backup/blob/main/v2ray-protocol.excalidraw

/**
 * 解析 VLESS 协议的头部
 * @param { ArrayBuffer} vlessBuffer
 * @param {string} userID 
 * @returns {Object} 
 */
function processVlessHeader(vlessBuffer, userID) {
	// 
	if (vlessBuffer.byteLength < 24) {
		return {
			hasError: true,
			message: 'invalid data',
		};
	}

	// 
	const version = new Uint8Array(vlessBuffer.slice(0, 1));

	let isValidUser = false;
	let isUDP = false;

	// 验证用户 ID（接下来的 16 个字节）
	function isUserIDValid(userID, userIDLow, buffer) {
		const userIDArray = new Uint8Array(buffer.slice(1, 17));
		const userIDString = stringify(userIDArray);
		return userIDString === userID || userIDString === userIDLow;
	}

	// 使用函数验证
	isValidUser = isUserIDValid(userID, userIDLow, vlessBuffer);

	// 如果用户 ID 无效，返回错误
	if (!isValidUser) {
		return {
			hasError: true,
			message: `invalid user ${(new Uint8Array(vlessBuffer.slice(1, 17)))}`,
		};
	}

	// 
	const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
	// 

	// 
	// 0x01: TCP, 0x02: UDP, 0x03: MUX
	const command = new Uint8Array(
		vlessBuffer.slice(18 + optLength, 18 + optLength + 1)
	)[0];

	// 0x01 TCP
	// 0x02 UDP
	// 0x03 MUX
	if (command === 1) {
		// 
	} else if (command === 2) {
		// UDP 命令
		isUDP = true;
	} else {
		// 
		return {
			hasError: true,
			message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
		};
	}

	// 
	const portIndex = 18 + optLength + 1;
	const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
	// port is big-Endian in raw data etc 80 == 0x005d
	const portRemote = new DataView(portBuffer).getUint16(0);

	// 
	let addressIndex = portIndex + 2;
	const addressBuffer = new Uint8Array(
		vlessBuffer.slice(addressIndex, addressIndex + 1)
	);

	// 
	const addressType = addressBuffer[0];
	let addressLength = 0;
	let addressValueIndex = addressIndex + 1;
	let addressValue = '';

	switch (addressType) {
		case 1:
			// 
			addressLength = 4;
			// 
			addressValue = new Uint8Array(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			).join('.');
			break;
		case 2:
			// 
			// 
			addressLength = new Uint8Array(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + 1)
			)[0];
			addressValueIndex += 1;
			// 
			addressValue = new TextDecoder().decode(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			break;
		case 3:
			// 
			addressLength = 16;
			const dataView = new DataView(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			// 
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				ipv6.push(dataView.getUint16(i * 2).toString(16));
			}
			addressValue = ipv6.join(':');
			// seems no need add [] for ipv6
			break;
		default:
			// 
			return {
				hasError: true,
				message: `invild addressType is ${addressType}`,
			};
	}

	// 
	if (!addressValue) {
		return {
			hasError: true,
			message: `addressValue is empty, addressType is ${addressType}`,
		};
	}

	// 
	return {
		hasError: false,
		addressRemote: addressValue,  // 
		addressType,                 // 
		portRemote,                 // 
		rawDataIndex: addressValueIndex + addressLength,  // 
		vlessVersion: version,      // 
		isUDP,                     // 
	};
}


/**
 * 将远程 Socket 的数据转发到 WebSocket
 * 
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket 
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket 
 * @param {ArrayBuffer} vlessResponseHeader 
 * @param {(() => Promise<void>) | null} retry 
 * @param {*} log 
 */
async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
	// 
	let remoteChunkCount = 0;
	let chunks = [];
	/** @type {ArrayBuffer | null} */
	let vlessHeader = vlessResponseHeader;
	let hasIncomingData = false; // 

	// 
	await remoteSocket.readable
		.pipeTo(
			new WritableStream({
				start() {
					// 
				},
				/**
				 * handle data blocks
				 * @param {Uint8Array} chunk 
				 * @param {*} controller 
				 */
				async write(chunk, controller) {
					hasIncomingData = true; // 
					// remoteChunkCount++; // 

					// 检查 WS
					if (webSocket.readyState !== WS_READY_STATE_OPEN) {
						controller.error(
							'webSocket.readyState is not open, maybe close'
						);
					}

					if (vlessHeader) {
						// 
						webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
						vlessHeader = null; // 
					} else {
						// 
						// 
						// 但现在 Cloudflare 似乎已经修复了这个问题
						// if (remoteChunkCount > 20000) {
						// 	// cf one package is 4096 byte(4kb),  4096 * 20000 = 80M
						// 	await delay(1);
						// }
						webSocket.send(chunk);
					}
				},
				close() {
					// 
					log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
					// 
					// 
					// 
				},
				abort(reason) {
					// 
					console.error(`remoteConnection!.readable abort`, reason);
				},
			})
		)
		.catch((error) => {
			// 
			console.error(
				`remoteSocketToWS has exception `,
				error.stack || error
			);
			// 发生错误时安全地关闭 WS
			safeCloseWebSocket(webSocket);
		});

	// handle Cloudflare Socket 
	// 1. Socket.closed 
	// 2. Socket.readable 
	if (hasIncomingData === false && retry) {
		log(`retry`);
		retry(); // 
	}
}

/**
 * 将 Base64 ArrayBuffer
 * 
 * @param {string} base64Str Base64 
 * @returns {{ earlyData: ArrayBuffer | undefined, error: Error | null }} ArrayBuffer
 */
function base64ToArrayBuffer(base64Str) {
	// 
	if (!base64Str) {
		return { error: null };
	}
	try {
		// Go 语言使用了 URL 安全的 Base64 （RFC 4648）
		// 这种变体使用 '-' 和 '_' 来代替标准 Base64 中的 '+' 和 '/'
		// JavaScript's atob is not supported with this method
		base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
		
		// 
		// 
		const decode = atob(base64Str);
		
		// 
		// 
		const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
		
		// 
		// 
		return { earlyData: arryBuffer.buffer, error: null };
	} catch (error) {
		// 
		return { error };
	}
}

/**
 * 
 * @param {string} uuid 
 * @returns {boolean} 
 */
function isValidUUID(uuid) {
	// UUID
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	
	// 使用正则表达式测试 UUID 字符串
	return uuidRegex.test(uuid);
}

// WS most important functions
const WS_READY_STATE_OPEN = 1;     // WS opening
const WS_READY_STATE_CLOSING = 2;  // WS closing

/**
 * Close WS
 * WS try-catch
 * @param {import("@cloudflare/workers-types").WebSocket} socket WS
 */
function safeCloseWebSocket(socket) {
	try {
		// WS close()
		// close()
		if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
			socket.close();
		}
	} catch (error) {
		// 
		console.error('safeCloseWebSocket error', error);
	}
}

// 
const byteToHex = [];
for (let i = 0; i < 256; ++i) {
	// (i + 256).toString(16)
	// .slice(1) 
	byteToHex.push((i + 256).toString(16).slice(1));
}

/**
 * 
 * 
 * @param {Uint8Array} arr 
 * @param {number} offset 
 * @returns {string} 
 */
function unsafeStringify(arr, offset = 0) {
	// 
	// 8-4-4-4-12
	// 
	return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" +
		byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" +
		byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" +
		byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" +
		byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] +
		byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

/**
 * 
 * 
 * @param {Uint8Array} arr 
 * @param {number} offset 
 * @returns {string} 
 * @throws {TypeError} 
 */
function stringify(arr, offset = 0) {
	// 
	const uuid = unsafeStringify(arr, offset);
	// 
	if (!isValidUUID(uuid)) {
		// 原：throw TypeError("Stringified UUID is invalid");
		throw TypeError(`Invalid 非法 UUID ${uuid}`); 
		//uuid = userID;
	}
	return uuid;
}

/**
 * Handle DNS
 * @param {ArrayBuffer} udpChunk - DNS
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket - WS
 * @param {ArrayBuffer} vlessResponseHeader - 
 * @param {(string)=> void} log - 日志
 */
async function handleDNSQuery(udpChunk, webSocket, vlessResponseHeader, log) {
    // 
    // 因为有些 DNS 服务器不支持 DNS over TCP
    try {
        // 选用 Google 的 DNS 服务器（注：后续可能会改为 Cloudflare 的 1.1.1.1）
        const dnsServer = '8.8.4.4'; // Cloudflare 修复连接自身 IP 的 bug 后，将改为 1.1.1.1
        const dnsPort = 53; // DNS

        /** @type {ArrayBuffer | null} */
        let vlessHeader = vlessResponseHeader; // 

        /** @type {import("@cloudflare/workers-types").Socket} */
        // DNS TCP
        const tcpSocket = connect({
            hostname: dnsServer,
            port: dnsPort,
        });

        log(`connect to ${dnsServer}:${dnsPort}`); // 
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk); // 
        writer.releaseLock(); // 

        // 
        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState === WS_READY_STATE_OPEN) {
                    if (vlessHeader) {
                        // 
                        webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
                        vlessHeader = null; // header was sent once . null means ...
                    } else {
                        // 
                        webSocket.send(chunk);
                    }
                }
            },
            close() {
                log(`DNS 服务器(${dnsServer}) TCP 连接已关闭`); // 
            },
            abort(reason) {
                console.error(`DNS 服务器(${dnsServer}) TCP 连接异常中断`, reason); // 
            },
        }));
    } catch (error) {
        // 
        console.error(
            `handleDNSQuery 函数发生异常，错误信息: ${error.message}`
        );
    }
}

/**
 * SOCKS5 
 * @param {number} addressType 
 * @param {string} addressRemote 
 * @param {number} portRemote 
 * @param {function} log 
 */
async function socks5Connect(addressType, addressRemote, portRemote, log) {
	const { username, password, hostname, port } = parsedSocks5Address;
	// 连接到 SOCKS5 代理服务器
	const socket = connect({
		hostname, // SOCKS5 服务器的主机名
		port,    // SOCKS5 服务器的端口
	});

	// 请求头格式（Worker -> SOCKS5 服务器）:
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+

	// https://en.wikipedia.org/wiki/SOCKS#SOCKS5
	// METHODS 字段的含义:
	// 0x00 不需要认证
	// 0x02 用户名/密码认证 https://datatracker.ietf.org/doc/html/rfc1929
	const socksGreeting = new Uint8Array([5, 2, 0, 2]);
	// 5: S5, 2: 支持的认证方法数, 0和2: 

	const writer = socket.writable.getWriter();

	await writer.write(socksGreeting);
	log('已发送 SOCKS5 问候消息');

	const reader = socket.readable.getReader();
	const encoder = new TextEncoder();
	let res = (await reader.read()).value;
	// 响应格式（SOCKS5 服务器 -> Worker）:
	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+
	if (res[0] !== 0x05) {
		log(`SOCKS5 服务器版本错误: 收到 ${res[0]}，期望是 5`);
		return;
	}
	if (res[1] === 0xff) {
		log("服务器不接受任何认证方法");
		return;
	}

	// 如果返回 0x0502，表示需要用户名/密码认证
	if (res[1] === 0x02) {
		log("SOCKS5 服务器需要认证");
		if (!username || !password) {
			log("请提供用户名和密码");
			return;
		}
		// 认证请求格式:
		// +----+------+----------+------+----------+
		// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		// +----+------+----------+------+----------+
		// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		// +----+------+----------+------+----------+
		const authRequest = new Uint8Array([
			1,                   // 认证子协议版本
			username.length,    // 用户名长度
			...encoder.encode(username), // 用户名
			password.length,    // 密码长度
			...encoder.encode(password)  // 密码
		]);
		await writer.write(authRequest);
		res = (await reader.read()).value;
		// 期望返回 0x0100 表示认证成功
		if (res[0] !== 0x01 || res[1] !== 0x00) {
			log("SOCKS5 服务器认证失败");
			return;
		}
	}

	// 请求数据格式（Worker -> SOCKS5 服务器）:
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	// ATYP: 地址类型
	// 0x01: IPv4 地址
	// 0x03: 域名
	// 0x04: IPv6 地址
	// DST.ADDR: 目标地址
	// DST.PORT: 目标端口（网络字节序）

	// addressType
	// 1 --> IPv4  地址长度 = 4
	// 2 --> 域名
	// 3 --> IPv6  地址长度 = 16
	let DSTADDR;	// DSTADDR = ATYP + DST.ADDR
	switch (addressType) {
		case 1: // IPv4
			DSTADDR = new Uint8Array(
				[1, ...addressRemote.split('.').map(Number)]
			);
			break;
		case 2: // 域名
			DSTADDR = new Uint8Array(
				[3, addressRemote.length, ...encoder.encode(addressRemote)]
			);
			break;
		case 3: // IPv6
			DSTADDR = new Uint8Array(
				[4, ...addressRemote.split(':').flatMap(x => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]
			);
			break;
		default:
			log(`无效的地址类型: ${addressType}`);
			return;
	}
	const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
	// 5: SOCKS5版本, 1: 表示CONNECT请求, 0: 保留字段
	// ...DSTADDR: 目标地址, portRemote >> 8 和 & 0xff: 将端口转为网络字节序
	await writer.write(socksRequest);
	log('已发送 SOCKS5 请求');

	res = (await reader.read()).value;
	// 响应格式（SOCKS5 服务器 -> Worker）:
	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	if (res[1] === 0x00) {
		log("SOCKS5 连接已建立");
	} else {
		log("SOCKS5 连接建立失败");
		return;
	}
	writer.releaseLock();
	reader.releaseLock();
	return socket;
}


/**
 * 
 * 
 * 
 * @param {string} address SOCKS5 For:
 *   - "username:password@hostname:port" 
 *   - "hostname:port"
 *   - "username:password@[ipv6]:port" 
 */
function socks5AddressParser(address) {
	// 
	// reverse() 
	let [latter, former] = address.split("@").reverse();
	let username, password, hostname, port;

	// 
	if (former) {
		const formers = former.split(":");
		if (formers.length !== 2) {
			throw new Error('无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');
		}
		[username, password] = formers;
	}

	// 
	const latters = latter.split(":");
	// 
	port = Number(latters.pop());
	if (isNaN(port)) {
		throw new Error('SOCKS5 端口号必须是数字! Invalid port number in SCOCK5');
	}

	// 
	hostname = latters.join(":");

	// IPv6
	const regex = /^\[.*\]$/;
	if (hostname.includes(":") && !regex.test(hostname)) {
		throw new Error(' invalid SOCKS 地址格式:IPv6 地址必须用方括号括起来，如 [2001:db8::1]');
	}
	if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(hostname)) hostname = `${atob('d3d3Lg==')}${hostname}${atob('LmlwLjA5MDIyNy54eXo=')}`;
	// 
	return {
		username,  // 
		password,  // 
		hostname,  // 
		port,     // 
	}
}

/**
 * 恢复信息
 * 
 * 
 * @param {string} content 
 * @param {string} userID 
 * @param {string} hostName 
 * @param {boolean} isBase64 
 * @returns {string} 
 */
function revertFakeInfo(content, userID, hostName, isBase64) {
	if (isBase64) content = atob(content);  // Base64 Decode
	
	// 
	// 
	content = content.replace(new RegExp(fakeUserID, 'g'), userID)
	               .replace(new RegExp(fakeHostName, 'g'), hostName);
	
	if (isBase64) content = btoa(content);  //
	
	return content;
}

/**
 * 双重MD5哈希
 * 这个函数对输入文本进行两次MD5哈希
 * 第二次哈希
 * 
 * @param {string} text 要哈希的文本
 * @returns {Promise<string>} 双重哈希后的DEX String
 */
async function MD5MD5(text) {
	const encoder = new TextEncoder();
  
	// 第一次MD5哈希
	const firstPass = await crypto.subtle.digest('MD5', encoder.encode(text));
	const firstPassArray = Array.from(new Uint8Array(firstPass));
	const firstHex = firstPassArray.map(b => b.toString(16).padStart(2, '0')).join('');

	// 第二次MD5哈希
	const secondPass = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
	const secondPassArray = Array.from(new Uint8Array(secondPass));
	const secondHex = secondPassArray.map(b => b.toString(16).padStart(2, '0')).join('');
  
	return secondHex.toLowerCase();  // 
}

/**
 * 
 * 
 * 
 * 
 * @param {string} envadd 
 * @returns {Promise<string[]>} 
 */
async function ADD(envadd) {
	// 
	// 
	var addtext = envadd.replace(/[	|"'\r\n]+/g, ',').replace(/,+/g, ',');
	
	// 
	if (addtext.charAt(0) == ',') addtext = addtext.slice(1);
	if (addtext.charAt(addtext.length - 1) == ',') addtext = addtext.slice(0, addtext.length - 1);
	
	// 
	const add = addtext.split(',');
	
	return add;
}

async function proxyURL(proxyURL, url) {
	const URLs = await ADD(proxyURL);
	const fullURL = URLs[Math.floor(Math.random() * URLs.length)];

	// 解析目标 URL
	let parsedURL = new URL(fullURL);
	console.log(parsedURL);
	// 提取并可能修改 URL 组件
	let URLProtocol = parsedURL.protocol.slice(0, -1) || 'https';
	let URLHostname = parsedURL.hostname;
	let URLPathname = parsedURL.pathname;
	let URLSearch = parsedURL.search;

	// 处理 pathname
	if (URLPathname.charAt(URLPathname.length - 1) == '/') {
		URLPathname = URLPathname.slice(0, -1);
	}
	URLPathname += url.pathname;

	// 构建新的 URL
	let newURL = `${URLProtocol}://${URLHostname}${URLPathname}${URLSearch}`;

	// 反向代理请求
	let response = await fetch(newURL);

	// 创建新的响应
	let newResponse = new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers: response.headers
	});

	// 添加自定义头部，包含 URL 信息
	//newResponse.headers.set('X-Proxied-By', 'Cloudflare Worker');
	//newResponse.headers.set('X-Original-URL', fullURL);
	newResponse.headers.set('X-New-URL', newURL);

	return newResponse;
}

function checkSUB(host) {
	if ((!sub || sub == '') && (addresses.length + addressesapi.length + addressesnotls.length + addressesnotlsapi.length + addressescsv.length) == 0){
		addresses = [
			'cdn.cf.059527.xyz#t.me/tg_idc',
			'127.0.0.1:1234#CFnat',
			'visa.cn:443',
			'singapore.com:8443',
			'japan.com:2053',
			'brazil.com:2083',
			'russia.com:2087',
			'www.gov.ua:2096',
			'www.gco.gov.qa:8443',
			'www.gov.se',
			'time.is',
			'www.wto.org:8443',
			'fbi.gov:2087',
			'icook.hk',
			//'104.17.0.0#IPv4',
			'[2606:4700::]#IPv6'
		];
		if (host.includes(".workers.dev")) addressesnotls = [
			'usa.visa.com:2095',
			'myanmar.visa.com:8080',
			'dynadot.com:8880',
			'www.visaeurope.ch:2052',
			'shopify.com:2082',
			'www.visasoutheasteurope.com:2086'
		];
	}
}

const 蛤 = 'dmxlc3M=';
function 配置信息(UUID, 域名地址) {
	const 协议类型 = atob(蛤);
	
	const 别名 = FileName;
	let 地址 = 域名地址;
	let 端口 = 443;

	const 用户ID = UUID;
	const 加密方式 = 'none';
	
	const 传输层协议 = 'ws';
	const 伪装域名 = 域名地址;
	const 路径 = '/?ed=2560';
	
	let 传输层安全 = ['tls',true];
	const SNI = 域名地址;
	const 指纹 = 'randomized';

	if (域名地址.includes('.workers.dev')){
		地址 = 'www.reliablesite.net';
		端口 = 80 ;
		传输层安全 = ['',false];
	}

	const v2ray = `${协议类型}://${用户ID}@${地址}:${端口}?encryption=${加密方式}&security=${传输层安全[0]}&sni=${SNI}&fp=${指纹}&type=${传输层协议}&host=${伪装域名}&path=${encodeURIComponent(路径)}#${encodeURIComponent(别名)}`;
	const clash = `- type: ${协议类型}
  name: ${FileName}
  server: ${地址}
  port: ${端口}
  uuid: ${用户ID}
  network: ${传输层协议}
  tls: ${传输层安全[1]}
  udp: false
  sni: ${SNI}
  client-fingerprint: ${指纹}
  ws-opts:
    path: "${路径}"
    headers:
      host: ${伪装域名}`;
	return [v2ray,clash];
}

let subParams = ['sub','base64','b64','clash','singbox','sb'];

/**
 * @param {string} userID
 * @param {string | null} hostName
 * @param {string} sub
 * @param {string} UA
 * @returns {Promise<string>}
 */
async function getVLESSConfig(userID, hostName, sub, UA, RproxyIP, _url, env) {
	const uuid = (_url.pathname == `/${env.KEY}`) ? env.KEY : userID;
	checkSUB(hostName);
	const userAgent = UA.toLowerCase();
	const Config = 配置信息(userID , hostName);
	const v2ray = Config[0];
	const clash = Config[1];
	let proxyhost = "";
	if(hostName.includes(".workers.dev") || hostName.includes(".pages.dev")){
		if ( proxyhostsURL && (!proxyhosts || proxyhosts.length == 0)) {
			try {
				const response = await fetch(proxyhostsURL); 
			
				if (!response.ok) {
					console.error('获取地址时出错:', response.status, response.statusText);
					return; // 
				}
			
				const text = await response.text();
				const lines = text.split('\n');
				// 
				const nonEmptyLines = lines.filter(line => line.trim() !== '');
			
				proxyhosts = proxyhosts.concat(nonEmptyLines);
			} catch (error) {
				//console.error
			}
		} 
		if (proxyhosts.length != 0) proxyhost = proxyhosts[Math.floor(Math.random() * proxyhosts.length)] + "/";
	}

	if ( userAgent.includes('mozilla') && !subParams.some(_searchParams => _url.searchParams.has(_searchParams))) {
		const newSocks5s = socks5s.map(socks5Address => {
			if (socks5Address.includes('@')) return socks5Address.split('@')[1];
			else if (socks5Address.includes('//')) return socks5Address.split('//')[1];
			else return socks5Address;
		});

		let socks5List = '';
		if( go2Socks5s.length > 0 && enableSocks ) {
			socks5List = `${decodeURIComponent('SOCKS5%EF%BC%88%E7%99%BD%E5%90%8D%E5%8D%95%EF%BC%89%3A%20')}`;
			if (go2Socks5s.includes(atob('YWxsIGlu'))||go2Socks5s.includes(atob('Kg=='))) socks5List += `${decodeURIComponent('%E6%89%80%E6%9C%89%E6%B5%81%E9%87%8F')}\n`;
			else socks5List += `\n  ${go2Socks5s.join('\n  ')}\n`;
		}

		let 订阅器 = '\n';
		if (!sub || sub == '') {
			if (enableSocks) 订阅器 += `CFCDN（访问方式）: Socks5\n  ${newSocks5s.join('\n  ')}\n${socks5List}`;
			else if (proxyIP && proxyIP != '') 订阅器 += `CFCDN（访问方式）: ProxyIP\n  ${proxyIPs.join('\n  ')}\n`;
			else 订阅器 += `CFCDN（访问方式）: 无法访问, 需要您设置 proxyIP/PROXYIP ！！！\n`;
			订阅器 += `\n您的订阅内容由 内置 addresses/ADD* 参数变量提供\n`;
			if (addresses.length > 0) 订阅器 += `ADD（TLS优选域名&IP）: \n  ${addresses.join('\n  ')}\n`;
			if (addressesnotls.length > 0) 订阅器 += `ADDNOTLS（noTLS优选域名&IP）: \n  ${addressesnotls.join('\n  ')}\n`;
			if (addressesapi.length > 0) 订阅器 += `ADDAPI（TLS优选域名&IP 的 API）: \n  ${addressesapi.join('\n  ')}\n`;
			if (addressesnotlsapi.length > 0) 订阅器 += `ADDNOTLSAPI（noTLS优选域名&IP 的 API）: \n  ${addressesnotlsapi.join('\n  ')}\n`;
			if (addressescsv.length > 0) 订阅器 += `ADDCSV（IPTest测速csv文件 限速 ${DLS} ）: \n  ${addressescsv.join('\n  ')}\n`;
			} else {
			if (enableSocks) 订阅器 += `CFCDN: Socks5\n  ${newSocks5s.join('\n  ')}\n${socks5List}`;
			else if (proxyIP && proxyIP != '') 订阅器 += `CFCDN（访问方式）: ProxyIP\n  ${proxyIPs.join('\n  ')}\n`;
			else if (RproxyIP == 'true') 订阅器 += `CFCDN（访问方式）: 自动获取ProxyIP\n`;
			else 订阅器 += `CFCDN : 无法访问, 需要您设置 proxyIP/PROXYIP ！！！\n`
			订阅器 += `\nSUB : ${sub}`;
		}

		if (env.KEY && _url.pathname !== `/${env.KEY}`) 订阅器 = '';
		else 订阅器 += `\nSUBAPI（订阅转换后端）: ${subProtocol}://${subconverter}\nSUBCONFIG（订阅转换配置文件）: ${subconfig}`;
		const 动态UUID = (uuid != userID) ? `TOKEN: ${uuid}\nUUIDNow: ${userID}\nUUIDLow: ${userIDLow}\n${userIDTime}TIME（动态UUID有效时间）: ${effectiveTime} 天\nUPTIME（动态UUID更新时间）: ${updateTime} 时（北京时间）\n\n` : `${userIDTime}`;
		return `
################################################################
Subscribe / sub URL, Supports Base64、clash-meta、sing-box format
---------------------------------------------------------------
Quick Check:
https://${proxyhost}${hostName}/${uuid}
https://${proxyhost}${hostName}/${uuid}?sub

Base64 Sub URL:
https://${proxyhost}${hostName}/${uuid}?b64
https://${proxyhost}${hostName}/${uuid}?base64

${FileName} 
---------------------------------------------------------------
HOST: ${hostName}
UUID: ${userID}
FKID: ${fakeUserID}
UA: ${UA}

${订阅器}
SUBAPI: ${subProtocol}://${subconverter}
SUBCONFIG: ${subconfig}
`;
	} else {
		if (typeof fetch != 'function') {
			return 'Error: fetch is not available in this environment.';
		}

		let newAddressesapi = [];
		let newAddressescsv = [];
		let newAddressesnotlsapi = [];
		let newAddressesnotlscsv = [];

		// 
		if (hostName.includes(".workers.dev")){
			noTLS = 'true';
			fakeHostName = `${fakeHostName}.workers.dev`;
			newAddressesnotlsapi = await getAddressesapi(addressesnotlsapi);
			newAddressesnotlscsv = await getAddressescsv('FALSE');
		} else if (hostName.includes(".pages.dev")){
			fakeHostName = `${fakeHostName}.pages.dev`;
		} else if (hostName.includes("worker") || hostName.includes("notls") || noTLS == 'true'){
			noTLS = 'true';
			fakeHostName = `notls${fakeHostName}.net`;
			newAddressesnotlsapi = await getAddressesapi(addressesnotlsapi);
			newAddressesnotlscsv = await getAddressescsv('FALSE');
		} else {
			fakeHostName = `${fakeHostName}.xyz`
		}
		console.log(`虚假HOST: ${fakeHostName}`);
		let url = `${subProtocol}://${sub}/sub?host=${fakeHostName}&uuid=${fakeUserID}&edgetunnel=cmliu&proxyip=${RproxyIP}`;
		let isBase64 = true;

		if (!sub || sub == ""){
			if(hostName.includes('workers.dev') || hostName.includes('pages.dev')) {
				if (proxyhostsURL && (!proxyhosts || proxyhosts.length == 0)) {
					try {
						const response = await fetch(proxyhostsURL); 
					
						if (!response.ok) {
							console.error('获取地址时出错:', response.status, response.statusText);
							return; // 
						}
					
						const text = await response.text();
						const lines = text.split('\n');
						// 
						const nonEmptyLines = lines.filter(line => line.trim() !== '');
					
						proxyhosts = proxyhosts.concat(nonEmptyLines);
					} catch (error) {
						console.error('获取地址时出错:', error);
					}
				}
				// Set
				proxyhosts = [...new Set(proxyhosts)];
			}
	
			newAddressesapi = await getAddressesapi(addressesapi);
			newAddressescsv = await getAddressescsv('TRUE');
			url = `https://${hostName}/${fakeUserID}`;
			if (hostName.includes("worker") || hostName.includes("notls") || noTLS == 'true') url += '?notls';
			console.log(`虚假订阅: ${url}`);
		} 

		if (!userAgent.includes(('CF-Workers-SUB').toLowerCase())){
			if ((userAgent.includes('clash') && !userAgent.includes('nekobox')) || ( _url.searchParams.has('clash') && !userAgent.includes('subconverter'))) {
				url = `${subProtocol}://${subconverter}/sub?target=clash&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subconfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
				isBase64 = false;
			} else if (userAgent.includes('sing-box') || userAgent.includes('singbox') || (( _url.searchParams.has('singbox') || _url.searchParams.has('sb')) && !userAgent.includes('subconverter'))) {
				url = `${subProtocol}://${subconverter}/sub?target=singbox&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subconfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
				isBase64 = false;
			}
		}
		
		try {
			let content;
			if ((!sub || sub == "") && isBase64 == true) {
				content = await subAddresses(fakeHostName,fakeUserID,noTLS,newAddressesapi,newAddressescsv,newAddressesnotlsapi,newAddressesnotlscsv);
			} else {
				const response = await fetch(url ,{
					headers: {
						'User-Agent': `${UA} CF-Workers-edgetunnel/cmliu`
					}});
				content = await response.text();
			}

			if (_url.pathname == `/${fakeUserID}`) return content;

			return revertFakeInfo(content, userID, hostName, isBase64);

		} catch (error) {
			console.error('Error fetching content:', error);
			return `Error fetching content: ${error.message}`;
		}

	}
}

async function getAccountId(email, key) {
	try {
		const url = 'https://api.cloudflare.com/client/v4/accounts';
		const headers = new Headers({
			'X-AUTH-EMAIL': email,
			'X-AUTH-KEY': key
		});
		const response = await fetch(url, { headers });
		const data = await response.json();
		return data.result[0].id; // 假设我们需要第一个账号ID
	} catch (error) {
		return false ;
	}
}

async function getSum(accountId, accountIndex, email, key, startDate, endDate) {
	try {
		const startDateISO = new Date(startDate).toISOString();
		const endDateISO = new Date(endDate).toISOString();
	
		const query = JSON.stringify({
			query: `query getBillingMetrics($accountId: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
				viewer {
					accounts(filter: {accountTag: $accountId}) {
						pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) {
							sum {
								requests
							}
						}
						workersInvocationsAdaptive(limit: 10000, filter: $filter) {
							sum {
								requests
							}
						}
					}
				}
			}`,
			variables: {
				accountId,
				filter: { datetime_geq: startDateISO, datetime_leq: endDateISO }
			},
		});
	
		const headers = new Headers({
			'Content-Type': 'application/json',
			'X-AUTH-EMAIL': email,
			'X-AUTH-KEY': key,
		});
	
		const response = await fetch(`https://api.cloudflare.com/client/v4/graphql`, {
			method: 'POST',
			headers: headers,
			body: query
		});
	
		if (!response.ok) {
			throw new Error(`HTTP error! status: ${response.status}`);
		}
	
		const res = await response.json();
	
		const pagesFunctionsInvocationsAdaptiveGroups = res?.data?.viewer?.accounts?.[accountIndex]?.pagesFunctionsInvocationsAdaptiveGroups;
		const workersInvocationsAdaptive = res?.data?.viewer?.accounts?.[accountIndex]?.workersInvocationsAdaptive;
	
		if (!pagesFunctionsInvocationsAdaptiveGroups && !workersInvocationsAdaptive) {
			throw new Error('找不到数据');
		}
	
		const pagesSum = pagesFunctionsInvocationsAdaptiveGroups.reduce((a, b) => a + b?.sum.requests, 0);
		const workersSum = workersInvocationsAdaptive.reduce((a, b) => a + b?.sum.requests, 0);
	
		//console.log(`范围: ${startDateISO} ~ ${endDateISO}\n默认取第 ${accountIndex} 项`);
	
		return [pagesSum, workersSum ];
	} catch (error) {
		return [ 0,0 ];
	}
}
let proxyIPPool = [];
async function getAddressesapi(api) {
	if (!api || api.length === 0) return [];

	let newapi = "";

	// AbortController
	const controller = new AbortController();

	const timeout = setTimeout(() => {
		controller.abort(); // 取消所有请求
	}, 2000); // 2秒后触发

	try {
		// Promise.allSettled
		// api
		const responses = await Promise.allSettled(api.map(apiUrl => fetch(apiUrl, {
			method: 'get', 
			headers: {
				'Accept': 'text/html,application/xhtml+xml,application/xml;',
				'User-Agent': 'CF-Workers-edgetunnel/cmliu'
			},
			signal: controller.signal // 将AbortController的信号量添加到fetch请求中，以便于需要时可以取消请求
		}).then(response => response.ok ? response.text() : Promise.reject())));

		// 遍历
		for (const [index, response] of responses.entries()) {
			// 
			if (response.status === 'fulfilled') {
				// 
				const content = await response.value;

				// 验证当前apiUrl是否带有'proxyip=true'
				if (api[index].includes('proxyip=true')) {
					// 如果URL带有'proxyip=true'，则将内容添加到proxyIPPool
					proxyIPPool = proxyIPPool.concat((await ADD(content)).map(item => {
						const baseItem = item.split('#')[0] || item;
						if (baseItem.includes(':')) {
							const port = baseItem.split(':')[1];
							if (!httpsPorts.includes(port)) {
								return baseItem;
							}
						} else {
							return `${baseItem}:443`;
						}
						return null; // 不符合条件时返回 null
					}).filter(Boolean)); // 过滤掉 null 值
				}
				// 将内容添加到newapi中
				newapi += content + '\n';
			}
		}
	} catch (error) {
		console.error(error);
	} finally {
		// 
		clearTimeout(timeout);
	}

	const newAddressesapi = await ADD(newapi);

	// 
	return newAddressesapi;
}

async function getAddressescsv(tls) {
	if (!addressescsv || addressescsv.length === 0) {
		return [];
	}
	
	let newAddressescsv = [];
	
	for (const csvUrl of addressescsv) {
		try {
			const response = await fetch(csvUrl);
		
			if (!response.ok) {
				console.error('获取CSV地址时出错:', response.status, response.statusText);
				continue;
			}
		
			const text = await response.text();// 
			let lines;
			if (text.includes('\r\n')){
				lines = text.split('\r\n');
			} else {
				lines = text.split('\n');
			}
		
			// CSV
			const header = lines[0].split(',');
			const tlsIndex = header.indexOf('TLS');
		
			const ipAddressIndex = 0;// IP CSV 
			const portIndex = 1;// CSV
			const dataCenterIndex = tlsIndex + 1; // TLS
		
			if (tlsIndex === -1) {
				console.error('CSV文件缺少必需的字段');
				continue;
			}
		
			// 从第二行遍历CSV
			for (let i = 1; i < lines.length; i++) {
				const columns = lines[i].split(',');
				const speedIndex = columns.length - 1; // 最后一个字段
				// 检查TLS是否为"TRUE"且速度大于DLS
				if (columns[tlsIndex].toUpperCase() === tls && parseFloat(columns[speedIndex]) > DLS) {
					const ipAddress = columns[ipAddressIndex];
					const port = columns[portIndex];
					const dataCenter = columns[dataCenterIndex];
			
					const formattedAddress = `${ipAddress}:${port}#${dataCenter}`;
					newAddressescsv.push(formattedAddress);
					if (csvUrl.includes('proxyip=true') && columns[tlsIndex].toUpperCase() == 'true' && !httpsPorts.includes(port)) {
						// 如果URL带有'proxyip=true'，则将内容添加到proxyIPPool
						proxyIPPool.push(`${ipAddress}:${port}`);
					}
				}
			}
		} catch (error) {
			console.error('获取CSV地址时出错:', error);
			continue;
		}
	}
	
	return newAddressescsv;
}

function subAddresses(host,UUID,noTLS,newAddressesapi,newAddressescsv,newAddressesnotlsapi,newAddressesnotlscsv) {
	const regex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[.*\]):?(\d+)?#?(.*)?$/;
	addresses = addresses.concat(newAddressesapi);
	addresses = addresses.concat(newAddressescsv);
	let notlsresponseBody ;
	if (noTLS == 'true'){
		addressesnotls = addressesnotls.concat(newAddressesnotlsapi);
		addressesnotls = addressesnotls.concat(newAddressesnotlscsv);
		const uniqueAddressesnotls = [...new Set(addressesnotls)];

		notlsresponseBody = uniqueAddressesnotls.map(address => {
			let port = "-1";
			let addressid = address;
		
			const match = addressid.match(regex);
			if (!match) {
				if (address.includes(':') && address.includes('#')) {
					const parts = address.split(':');
					address = parts[0];
					const subParts = parts[1].split('#');
					port = subParts[0];
					addressid = subParts[1];
				} else if (address.includes(':')) {
					const parts = address.split(':');
					address = parts[0];
					port = parts[1];
				} else if (address.includes('#')) {
					const parts = address.split('#');
					address = parts[0];
					addressid = parts[1];
				}
			
				if (addressid.includes(':')) {
					addressid = addressid.split(':')[0];
				}
			} else {
				address = match[1];
				port = match[2] || port;
				addressid = match[3] || address;
			}

			const httpPorts = ["8080","8880","2052","2082","2086","2095"];
			if (!isValidIPv4(address) && port == "-1") {
				for (let httpPort of httpPorts) {
					if (address.includes(httpPort)) {
						port = httpPort;
						break;
					}
				}
			}
			if (port == "-1") port = "80";

			let 伪装域名 = host ;
			let 最终路径 = '/?ed=2560' ;
			let 节点备注 = '';
			const 协议类型 = atob(蛤);
			
			const vlessLink = `${协议类型}://${UUID}@${address}:${port}?encryption=none&security=&type=ws&host=${伪装域名}&path=${encodeURIComponent(最终路径)}#${encodeURIComponent(addressid + 节点备注)}`;
	
			return vlessLink;

		}).join('\n');

	}

	// 使用Set对象去重
	const uniqueAddresses = [...new Set(addresses)];

	const responseBody = uniqueAddresses.map(address => {
		let port = "-1";
		let addressid = address;

		const match = addressid.match(regex);
		if (!match) {
			if (address.includes(':') && address.includes('#')) {
				const parts = address.split(':');
				address = parts[0];
				const subParts = parts[1].split('#');
				port = subParts[0];
				addressid = subParts[1];
			} else if (address.includes(':')) {
				const parts = address.split(':');
				address = parts[0];
				port = parts[1];
			} else if (address.includes('#')) {
				const parts = address.split('#');
				address = parts[0];
				addressid = parts[1];
			}
		
			if (addressid.includes(':')) {
				addressid = addressid.split(':')[0];
			}
		} else {
			address = match[1];
			port = match[2] || port;
			addressid = match[3] || address;
		}

		if (!isValidIPv4(address) && port == "-1") {
			for (let httpsPort of httpsPorts) {
				if (address.includes(httpsPort)) {
					port = httpsPort;
					break;
				}
			}
		}
		if (port == "-1") port = "443";
		
		let 伪装域名 = host ;
		let 最终路径 = '/?ed=2560' ;
		let 节点备注 = '';
		const matchingProxyIP = proxyIPPool.find(proxyIP => proxyIP.includes(address));
		if (matchingProxyIP) 最终路径 += `&proxyip=${matchingProxyIP}`;
		
		if(proxyhosts.length > 0 && (伪装域名.includes('.workers.dev') || 伪装域名.includes('pages.dev'))) {
			最终路径 = `/${伪装域名}${最终路径}`;
			伪装域名 = proxyhosts[Math.floor(Math.random() * proxyhosts.length)];
			节点备注 = ` 已启用临时域名! Now temporary domain activated!`;
		}
		
		const 协议类型 = atob(蛤);
		const vlessLink = `${协议类型}://${UUID}@${address}:${port}?encryption=none&security=tls&sni=${伪装域名}&fp=random&type=ws&host=${伪装域名}&path=${encodeURIComponent(最终路径)}#${encodeURIComponent(addressid + 节点备注)}`;
			
		return vlessLink;
	}).join('\n');

	let base64Response = responseBody; // 重新进行 Base64 编码
	if(noTLS == 'true') base64Response += `\n${notlsresponseBody}`;
	return btoa(base64Response);
}

async function sendMessage(type, ip, add_data = "") {
	if ( BotToken !== '' && ChatID !== ''){
		let msg = "";
		const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);
		if (response.status == 200) {
			const ipInfo = await response.json();
			msg = `${type}\nIP: ${ip}\n国家: ${ipInfo.country}\n<tg-spoiler>城市: ${ipInfo.city}\n组织: ${ipInfo.org}\nASN: ${ipInfo.as}\n${add_data}`;
		} else {
			msg = `${type}\nIP: ${ip}\n<tg-spoiler>${add_data}`;
		}
	
		let url = "https://api.telegram.org/bot"+ BotToken +"/sendMessage?chat_id=" + ChatID + "&parse_mode=HTML&text=" + encodeURIComponent(msg);
		return fetch(url, {
			method: 'get',
			headers: {
				'Accept': 'text/html,application/xhtml+xml,application/xml;',
				'Accept-Encoding': 'gzip, deflate, br',
				'User-Agent': 'Mozilla/5.0 Chrome/90.0.4430.72'
			}
		});
	}
}

function isValidIPv4(address) {
	const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
	return ipv4Regex.test(address);
}

function generateDynamicUUID(key) {
    function getWeekOfYear() {
        const now = new Date();
        const timezoneOffset = 8; // 北京时间相对于UTC的时区偏移+8小时
        const adjustedNow = new Date(now.getTime() + timezoneOffset * 60 * 60 * 1000);
        const start = new Date(2007, 6, 7, updateTime, 0, 0); // 固定起始日期为2007年7月7日的凌晨3点
        const diff = adjustedNow - start;
        const oneWeek = 1000 * 60 * 60 * 24 * effectiveTime;
        return Math.ceil(diff / oneWeek);
    }
    
    const passwdTime = getWeekOfYear(); // 获取当前周数
    const endTime = new Date(2007, 6, 7, updateTime, 0, 0); // 固定起始日期
    endTime.setMilliseconds(endTime.getMilliseconds() + passwdTime * 1000 * 60 * 60 * 24 * effectiveTime);

    // 生成 UUID 的辅助函数
    function generateUUID(baseString) {
        const hashBuffer = new TextEncoder().encode(baseString);
        return crypto.subtle.digest('SHA-256', hashBuffer).then((hash) => {
            const hashArray = Array.from(new Uint8Array(hash));
            const hexHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            let uuid = hexHash.substr(0, 8) + '-' + hexHash.substr(8, 4) + '-4' + hexHash.substr(13, 3) + '-' + (parseInt(hexHash.substr(16, 2), 16) & 0x3f | 0x80).toString(16) + hexHash.substr(18, 2) + '-' + hexHash.substr(20, 12);
            return uuid;
        });
    }
    
    // 生成两个 UUID
    const currentUUIDPromise = generateUUID(key + passwdTime);
    const previousUUIDPromise = generateUUID(key + (passwdTime - 1));

    // 格式化到期时间
    const expirationDateUTC = new Date(endTime.getTime() - 8 * 60 * 60 * 1000); // UTC时间
    const expirationDateString = `到期时间(UTC): ${expirationDateUTC.toISOString().slice(0, 19).replace('T', ' ')} (UTC+8): ${endTime.toISOString().slice(0, 19).replace('T', ' ')}\n`;

    return Promise.all([currentUUIDPromise, previousUUIDPromise, expirationDateString]);
}