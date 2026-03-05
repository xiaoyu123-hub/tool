import { connect } from 'cloudflare:sockets';

// ==================== 配置常量（建议根据需求修改） ====================
const CONFIG = {
  // 授权密钥（UUID格式）
  AUTH_UUID: "ae15a15c-cbcc-4dd6-ab51-5b70cc0a62a8",
  // 反代功能总开关
  PROXY_ENABLED: true,
  // 默认反代IP/域名（支持带端口，如：ts.hpc.tw:443）
  PROXY_IP: '',
  // NAT64配置
  NAT64_ENABLED: false,
  NAT64_GLOBAL: false,
  NAT64_ADDRESS: '[2602:fc59:b0:64::]',
  // DOH DNS配置
  DOH_ENABLED: false,
  PREFER_IPV6: false,
  STRICT_TTL_CACHE: true,
  DOH_SERVERS: [
    "https://dns.google/resolve",       // Google DNS
    // "https://dns.alidns.com/resolve",   // 阿里DNS
    // "https://doh.pub/dns-query",        // 腾讯DNS
  ],
  // 流控配置
  FLOW_CONTROL_ENABLED: false,
  FLOW_CONTROL_CHUNK_SIZE: 64 // 字节
};

// ==================== 全局缓存 ====================
const DNS_CACHE = globalThis.DNS_CACHE || new Map();
globalThis.DNS_CACHE = DNS_CACHE;

// ==================== 工具函数 ====================
/**
 * 格式化字节大小
 * @param {number} bytes - 字节数
 * @param {number} precision - 保留小数位数
 * @returns {string} 格式化后的字符串
 */
function formatBytes(bytes, precision = 2) {
  if (bytes === 0) return '0 B';
  
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, exponent);
  
  return `${value.toFixed(precision)} ${units[exponent]}`;
}

/**
 * 格式化毫秒为时分秒
 * @param {number} ms - 毫秒数
 * @returns {string} 格式化后的时间字符串
 */
function formatTime(ms) {
  const totalMs = Math.floor(ms);
  const hours = String(Math.floor(totalMs / 3600000)).padStart(2, '0');
  const minutes = String(Math.floor((totalMs % 3600000) / 60000)).padStart(2, '0');
  const seconds = String(Math.floor((totalMs % 60000) / 1000)).padStart(2, '0');
  const milliseconds = String(totalMs % 1000).padStart(3, '0');
  
  return `${hours}:${minutes}:${seconds}.${milliseconds}`;
}

/**
 * 解析地址（支持IPv4/IPv6/域名，带端口）
 * @param {string} address - 待解析的地址
 * @returns {{type: string, address: string, port: number}} 解析结果
 */
function parseAddress(address) {
  if (!address) return { type: 'domain', address: '', port: 443 };
  
  const match = address.match(
    /^(?:\[(?<ipv6>[0-9a-fA-F:]+)\]|(?<ipv6>[0-9a-fA-F:]+)|(?<ipv4>\d{1,3}(?:\.\d{1,3}){3})|(?<domain>[a-zA-Z0-9.-]+))(?::(?<port>\d+))?$/
  );
  
  if (!match) return { type: 'domain', address, port: 443 };
  
  const { ipv6, ipv4, domain, port } = match.groups;
  return {
    type: ipv6 ? 'ipv6' : ipv4 ? 'ipv4' : 'domain',
    address: ipv6 || ipv4 || domain,
    port: port ? Number(port) : 443
  };
}

/**
 * 验证UUID密钥
 * @param {Uint8Array} buffer - 二进制数据
 * @param {number} offset - 起始偏移量
 * @returns {string} 格式化后的UUID
 */
function validateUUID(buffer, offset = 0) {
  const uuidBytes = buffer.slice(offset, offset + 16);
  const uuidStr = Array.from(uuidBytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
  
  return uuidStr;
}

/**
 * 构建NAT64地址
 * @param {string} nat64Prefix - NAT64前缀
 * @param {string} ipv4 - 目标IPv4地址
 * @returns {string} 构建后的NAT64地址
 */
function buildNAT64Address(nat64Prefix, ipv4) {
  const parsedPrefix = parseAddress(nat64Prefix);
  const ipv4Parts = ipv4.split('.').map(n => (+n).toString(16).padStart(2, '0'));
  const ipv6Suffix = ipv4Parts.join('').replace(/(.{4})/, '$1:');
  
  return `[${parsedPrefix.address}${ipv6Suffix}]`;
}

// ==================== DNS相关函数 ====================
/**
 * 查询最快的IP地址（带缓存）
 * @param {string} domain - 域名
 * @returns {Promise<string>} 解析后的IP地址
 */
async function queryFastestIP(domain) {
  // 初始化缓存存活时间
  if (!DNS_CACHE.get('cache_life')) {
    DNS_CACHE.set('cache_life', { timestamp: Date.now() });
  }
  
  const now = Date.now();
  const cacheEntry = DNS_CACHE.get(domain);
  
  // 检查缓存是否有效
  if (cacheEntry) {
    const isCacheValid = !CONFIG.STRICT_TTL_CACHE || now < cacheEntry.ttlExpires;
    if (isCacheValid) {
      console.log(`[DNS] 缓存命中: ${domain} -> ${cacheEntry.ip}`);
      return cacheEntry.ip;
    }
  }
  
  const abortControllers = [];
  let dnsResult, dnsTTL, dohServer;
  
  // 构建DOH请求
  const buildDohRequests = (recordType) => {
    return CONFIG.DOH_SERVERS.map(server => {
      const controller = new AbortController();
      abortControllers.push(controller);
      
      return fetch(`${server}?name=${domain}&type=${recordType}`, {
        method: 'POST',
        headers: { 'Accept': 'application/dns-json' },
        signal: controller.signal,
        cf: { cacheTtl: 60 }
      })
        .then(res => res.json())
        .then(json => {
          const answer = json.Answer?.filter(r => 
            r.type === (recordType === 'A' ? 1 : 28)
          ).pop();
          
          if (answer?.data) {
            return [answer.data, answer.TTL || 120, server];
          }
          throw new Error(`No ${recordType} record`);
        });
    });
  };
  
  try {
    // 优先查询IPv6或IPv4
    if (CONFIG.PREFER_IPV6) {
      try {
        [dnsResult, dnsTTL, dohServer] = await Promise.any(buildDohRequests('AAAA'));
        const parsed = parseAddress(dnsResult);
        if (parsed.type !== 'ipv6') throw new Error('IPv6解析失败');
      } catch (e) {
        console.log(`[DNS] IPv6解析失败，降级到IPv4: ${domain}`);
        [dnsResult, dnsTTL, dohServer] = await Promise.any(buildDohRequests('A'));
      }
    } else {
      [dnsResult, dnsTTL, dohServer] = await Promise.any(buildDohRequests('A'));
    }
    
    // 验证IP类型
    const parsedResult = parseAddress(dnsResult);
    if (parsedResult.type !== 'ipv4') {
      throw new Error(`无效的IP地址类型: ${parsedResult.type}`);
    }
    
    console.log(`[DNS] 解析成功: ${domain} -> ${dnsResult} (${dohServer})`);
    
    // 更新缓存
    const ttlExpires = now + dnsTTL * 1000;
    const updateTime = new Date(now + 8 * 3600 * 1000)
      .toLocaleString('zh-CN', { hour12: false })
      .replace(/\//g, '-');
    
    DNS_CACHE.set(domain, {
      domain,
      ip: dnsResult,
      updateTime,
      ttl: dnsTTL,
      ttlUpdated: now,
      ttlExpires,
      cachedAt: now
    });
    
    return dnsResult;
  } catch (e) {
    console.error(`[DNS] 解析失败: ${domain} - ${e.message}`);
    return domain; // 回退到原始域名
  } finally {
    // 取消所有未完成的请求
    abortControllers.forEach(controller => controller.abort());
  }
}

// ==================== 核心传输逻辑 ====================
/**
 * 处理WebSocket消息并建立TCP连接
 * @param {WebSocket} ws - WebSocket实例
 * @param {object} runtimeConfig - 运行时配置
 */
async function handleTransport(ws, runtimeConfig) {
  let tcpSocket;
  let addressType;
  let targetAddress;
  let targetPort;
  let firstPacketProcessed = false;
  let txBytes = 0;
  let rxBytes = 0;
  let startTime = performance.now();
  let writeQueue = Promise.resolve();
  
  // 获取读写器
  const getSocketReadWriter = (socket) => {
    return {
      writer: socket.writable.getWriter(),
      reader: socket.readable.getReader()
    };
  };
  
  // 处理首包数据
  const processFirstPacket = async (data) => {
    const buffer = new Uint8Array(data);
    
    // 1. 验证授权密钥
    const uuid = validateUUID(buffer, 1);
    if (uuid !== CONFIG.AUTH_UUID) {
      throw new Error('UUID验证失败');
    }
    
    // 2. 解析目标地址和端口
    const addrLen = buffer[17];
    const portOffset = 18 + addrLen + 1;
    targetPort = new DataView(buffer.buffer, portOffset, 2).getUint16(0);
    
    // 处理DNS查询特殊情况 (端口53)
    if (targetPort === 53) {
      const dnsQuery = buffer.slice(portOffset + 9);
      const dohResponse = await fetch('https://dns.google/dns-query', {
        method: 'POST',
        headers: { 'content-type': 'application/dns-message' },
        body: dnsQuery
      });
      
      const dnsAnswer = await dohResponse.arrayBuffer();
      const lengthHeader = new Uint8Array([
        (dnsAnswer.byteLength >> 8) & 0xff,
        dnsAnswer.byteLength & 0xff
      ]);
      
      ws.send(await new Blob([lengthHeader, dnsAnswer]).arrayBuffer());
      throw new Error('DNS查询完成');
    }
    
    // 3. 解析目标地址
    const addrOffset = portOffset + 2;
    addressType = buffer[addrOffset];
    let addrInfoOffset = addrOffset + 1;
    let addrLength;
    
    switch (addressType) {
      case 1: // IPv4
        addrLength = 4;
        targetAddress = buffer.slice(addrInfoOffset, addrInfoOffset + addrLength).join('.');
        break;
        
      case 2: // 域名
        addrLength = buffer[addrInfoOffset];
        addrInfoOffset += 1;
        targetAddress = new TextDecoder().decode(
          buffer.slice(addrInfoOffset, addrInfoOffset + addrLength)
        );
        
        // 使用DOH解析域名
        if (runtimeConfig.DOH_ENABLED) {
          targetAddress = await queryFastestIP(targetAddress);
          const parsed = parseAddress(targetAddress);
          addressType = parsed.type === 'ipv6' ? 3 : 1;
        }
        break;
        
      case 3: // IPv6
        addrLength = 16;
        const ipv6View = new DataView(buffer.buffer, addrInfoOffset, 16);
        const ipv6Parts = [];
        for (let i = 0; i < 8; i++) {
          ipv6Parts.push(ipv6View.getUint16(i * 2).toString(16));
        }
        targetAddress = ipv6Parts.join(':');
        break;
        
      default:
        throw new Error(`无效的地址类型: ${addressType}`);
    }
    
    // 4. 建立TCP连接
    await createTcpConnection(buffer, addrInfoOffset + addrLength);
    
    // 5. 发送连接成功响应
    ws.send(new Uint8Array([buffer[0], 0]));
    
    return true;
  };
  
  // 建立TCP连接
  const createTcpConnection = async (buffer, dataOffset) => {
    // 全局NAT64反代
    if (runtimeConfig.PROXY_ENABLED && runtimeConfig.NAT64_ENABLED && 
        runtimeConfig.NAT64_GLOBAL && addressType === 1) {
      const nat64Address = buildNAT64Address(runtimeConfig.NAT64_ADDRESS, targetAddress);
      const parsedNat64 = parseAddress(nat64Address);
      
      tcpSocket = connect({
        hostname: parsedNat64.address,
        port: parsedNat64.port
      });
    } else {
      // 尝试直接连接
      try {
        const connectOptions = {
          hostname: addressType === 3 ? `[${targetAddress}]` : targetAddress,
          port: targetPort
        };
        
        tcpSocket = connect(connectOptions);
        await tcpSocket.opened;
      } catch (directErr) {
        // 直接连接失败，使用反代
        if (runtimeConfig.PROXY_ENABLED) {
          if (runtimeConfig.NAT64_ENABLED && addressType === 1) {
            // NAT64反代
            const nat64Address = buildNAT64Address(runtimeConfig.NAT64_ADDRESS, targetAddress);
            const parsedNat64 = parseAddress(nat64Address);
            
            tcpSocket = connect({
              hostname: parsedNat64.address,
              port: parsedNat64.port
            });
          } else {
            // 基础IP反代
            const parsedProxy = parseAddress(runtimeConfig.PROXY_IP);
            
            tcpSocket = connect({
              hostname: parsedProxy.address,
              port: parsedProxy.port || targetPort
            });
          }
        } else {
          throw directErr;
        }
      }
    }
    
    await tcpSocket.opened;
    console.log(`[TCP] 连接成功: ${targetAddress}:${targetPort} (类型: ${addressType})`);
    
    // 获取读写器
    const { writer, reader } = getSocketReadWriter(tcpSocket);
    
    // 发送初始数据
    const initialData = buffer.slice(dataOffset);
    if (initialData.length > 0) {
      await writer.write(initialData);
      txBytes += initialData.length;
    }
    
    // 启动数据回传
    startDataRelay(writer, reader);
  };
  
  // 启动数据回传
  const startDataRelay = async (writer, reader) => {
    try {
      while (true) {
        await writeQueue;
        const { done, value } = await reader.read();
        
        if (done) break;
        if (value && value.length > 0) {
          rxBytes += value.length;
          
          // 流控处理
          if (runtimeConfig.FLOW_CONTROL_ENABLED) {
            let offset = 0;
            const chunkSize = runtimeConfig.FLOW_CONTROL_CHUNK_SIZE;
            
            while (offset < value.length) {
              const chunk = value.slice(offset, offset + chunkSize);
              writeQueue = writeQueue.then(() => ws.send(chunk));
              offset += chunkSize;
            }
          } else {
            writeQueue = writeQueue.then(() => ws.send(value));
          }
        }
      }
    } catch (e) {
      console.error(`[RELAY] 数据回传错误: ${e.message}`);
    } finally {
      writer.releaseLock();
      reader.releaseLock();
      throw new Error('传输完成');
    }
  };
  
  // 主消息处理逻辑
  try {
    ws.addEventListener('message', async (event) => {
      try {
        if (!firstPacketProcessed) {
          firstPacketProcessed = true;
          await processFirstPacket(event.data);
          txBytes += event.data.length;
        } else {
          await writeQueue;
          const { writer } = getSocketReadWriter(tcpSocket);
          await writer.write(event.data);
          txBytes += event.data.length;
        }
      } catch (e) {
        console.error(`[MESSAGE] 处理错误: ${e.message}`);
        ws.close(1011, e.message);
        tcpSocket?.close();
      }
    });
    
    // 错误处理
    ws.addEventListener('error', (error) => {
      console.error(`[WS] 错误: ${error.message}`);
      tcpSocket?.close();
    });
    
    // 关闭处理
    ws.addEventListener('close', () => {
      console.log(`[WS] 连接关闭，总传输: 发送 ${formatBytes(txBytes)}, 接收 ${formatBytes(rxBytes)}, 耗时 ${formatTime(performance.now() - startTime)}`);
      tcpSocket?.close();
    });
  } catch (e) {
    console.error(`[TRANSPORT] 核心错误: ${e.message}`);
    tcpSocket?.close();
    ws.close(1011, e.message);
  }
}

// ==================== 主入口 ====================
export default {
  async fetch(request) {
    try {
      // 处理WebSocket升级请求
      if (request.headers.get('Upgrade') === 'websocket') {
        const url = new URL(request.url);
        const path = decodeURIComponent(url.pathname);
        
        // 合并配置（默认配置 + URL参数）
        const runtimeConfig = {
          ...CONFIG,
          FLOW_CONTROL_ENABLED: url.searchParams.get('kongliu-open') === 'true' || CONFIG.FLOW_CONTROL_ENABLED,
          FLOW_CONTROL_CHUNK_SIZE: Number(url.searchParams.get('kongliu-size')) || CONFIG.FLOW_CONTROL_CHUNK_SIZE,
          PROXY_IP: url.searchParams.get('proxyip') || CONFIG.PROXY_IP,
          NAT64_ADDRESS: url.searchParams.get('nat64') || CONFIG.NAT64_ADDRESS,
          NAT64_ENABLED: url.searchParams.get('nat64-open') === 'true' || CONFIG.NAT64_ENABLED,
          NAT64_GLOBAL: url.searchParams.get('nat64-global') === 'true' || CONFIG.NAT64_GLOBAL
        };
        
        // 创建WebSocket对
        const [client, server] = Object.values(new WebSocketPair());
        server.accept();
        
        // 启动传输逻辑
        handleTransport(server, runtimeConfig);
        
        // 返回WebSocket响应
        return new Response(null, {
          status: 101,
          webSocket: client,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Upgrade, Connection, Authorization'
          }
        });
      }
      
      // 处理普通HTTP请求
      return new Response('Cloudflare Proxy Worker is running', {
        status: 200,
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'Access-Control-Allow-Origin': '*'
        }
      });
    } catch (e) {
      console.error(`[MAIN] 处理请求错误: ${e.message}`);
      return new Response(`Server Error: ${e.message}`, { status: 500 });
    }
  }
};
