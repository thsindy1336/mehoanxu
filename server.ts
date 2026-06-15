import express from 'express';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { createServer as createViteServer } from 'vite';

const app = express();
const PORT = 3000;

app.use(express.json());

// File lưu trữ bí mật TikTok mã hóa ở server-side
const SECRETS_FILE = path.join(process.cwd(), 'tiktok_secrets.json');

// Khóa băm mã hóa duy nhất của máy chủ để bảo vệ API Key
const SECRET_SALT = process.env.TIKTOK_SECRET_SALT || 'tthuy_coquette_rio_hub_salt_2026_secrecy';
const ENCRYPTION_KEY = crypto.createHash('sha256').update(SECRET_SALT).digest();
const IV_LENGTH = 16;

function encrypt(text: string): string {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(text, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text: string): string {
  try {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift()!, 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString('utf8');
  } catch (e) {
    return 'Decryption_Error';
  }
}

// Đọc và ghi danh sách TikTok config mã hóa
function getTikTokConfigs(): Record<string, { creator_username: string, encrypted_api_key: string }> {
  if (!fs.existsSync(SECRETS_FILE)) {
    return {};
  }
  try {
    const data = fs.readFileSync(SECRETS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (e) {
    return {};
  }
}

function saveTikTokConfigs(configs: any) {
  try {
    fs.writeFileSync(SECRETS_FILE, JSON.stringify(configs, null, 2), 'utf8');
  } catch (e) {
    console.error('Error saving SECRETS_FILE:', e);
  }
}

// File lưu trữ Signing Secret webhook TikTok Shop
const SIGNING_SECRET_FILE = path.join(process.cwd(), 'tiktok_webhook_signing_secret.txt');

function getSigningSecret(): string {
  if (!fs.existsSync(SIGNING_SECRET_FILE)) {
    return '';
  }
  try {
    return fs.readFileSync(SIGNING_SECRET_FILE, 'utf8').trim();
  } catch (e) {
    return '';
  }
}

function saveSigningSecret(secret: string) {
  try {
    fs.writeFileSync(SIGNING_SECRET_FILE, secret.trim(), 'utf8');
  } catch (e) {
    console.error('Error saving SIGNING_SECRET_FILE:', e);
  }
}

interface DiagnosticLog {
  id: string;
  time: string;
  username: string;
  url: string;
  method: string;
  params: any;
  status: number;
  body: any;
}

let diagnosticLogs: DiagnosticLog[] = [];

function addDiagnosticLog(username: string, url: string, method: string, params: any, status: number, body: any) {
  diagnosticLogs.unshift({
    id: 'dl_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
    time: new Date().toISOString(),
    username,
    url,
    method,
    params,
    status,
    body
  });
  if (diagnosticLogs.length > 50) {
    diagnosticLogs = diagnosticLogs.slice(0, 50);
  }
}

// API lấy toàn bộ log request/response để admin chẩn đoán
app.get('/api/tiktok/diagnostic-logs', (req, res) => {
  res.json(diagnosticLogs);
});

// API get config của từng tài khoản (không bao giờ lộ API key gốc ra client!)
app.get('/api/tiktok/config/:username', (req, res) => {
  const { username } = req.params;
  const configs = getTikTokConfigs();
  const userConfig = configs[username];
  
  if (!userConfig) {
    return res.json({ creator_username: '', has_key: false, masked_key: '', webhook_url: 'https://cashback.thuydeal.site/api/riohub/webhook' });
  }

  const rawKey = decrypt(userConfig.encrypted_api_key);
  // Hiển thị ở định dạng che bớt ký tự dạng rhk_xxxxxxxxxxxxxx1234
  const masked_key = rawKey.length > 8 
    ? `${rawKey.slice(0, 4)}xxxxxxxxxxxxxx${rawKey.slice(-4)}` 
    : 'rhk_xxxxxxxxxxxxxx1234';

  res.json({
    creator_username: userConfig.creator_username,
    has_key: true,
    masked_key: masked_key,
    webhook_url: (userConfig as any).webhook_url || 'https://cashback.thuydeal.site/api/riohub/webhook'
  });
});

// API lưu config TikTok của user
app.post('/api/tiktok/config/:username', (req, res) => {
  const { username } = req.params;
  const { creator_username, api_key, webhook_url } = req.body;

  if (!creator_username) {
    return res.status(400).json({ error: 'Creator username không được để trống.' });
  }

  const configs = getTikTokConfigs();
  const existingConfig = configs[username] || { creator_username: '', encrypted_api_key: '', webhook_url: '' };

  let encrypted_api_key = existingConfig.encrypted_api_key;
  if (api_key) {
    // Nếu có truyền key mới thì mã hóa rồi lưu
    encrypted_api_key = encrypt(api_key);
  }

  configs[username] = {
    creator_username: creator_username.trim(),
    encrypted_api_key: encrypted_api_key,
    webhook_url: webhook_url ? webhook_url.trim() : ((existingConfig as any).webhook_url || 'https://cashback.thuydeal.site/api/riohub/webhook')
  } as any;

  saveTikTokConfigs(configs);

  res.json({ success: true, message: 'Đã lưu cấu hình TikTok Shop server-side thành công 🌸' });
});

// File lưu trữ nâng cao cho TikTok orders và Webhook stats
const TIKTOK_ORDERS_FILE = path.join(process.cwd(), 'tiktok_orders.json');
const WEBHOOK_STATS_FILE = path.join(process.cwd(), 'tiktok_webhook_stats.json');

// Danh sách các đơn hàng giả lập ban đầu để làm hạt giống (seed) nếu chưa có dữ liệu thực tế
const INITIAL_SIMULATED_ORDERS: any[] = [
  {
    order_id: '123456',
    product_name: 'Nước Hoa Coquette Bloom Blossom 🌸 (TikTok Shop)',
    sub_id: 'thuy',
    commission: 100000,
    status: 'completed',
    time: new Date(Date.now() - 3600000 * 2).toISOString()
  },
  {
    order_id: '123457',
    product_name: 'Lắc Tay Bạc Đính Đá Phong Cách Thụy Sĩ ✨ (TikTok Shop)',
    sub_id: 'nam',
    commission: 50000,
    status: 'completed',
    time: new Date(Date.now() - 3600000 * 3).toISOString()
  },
  {
    order_id: 'TikTok-938210398',
    product_name: 'Son Kem Romand Glasting Water Tint Căng Bóng 🌸',
    sub_id: 'web',
    commission: 12000,
    status: 'completed',
    time: new Date(Date.now() - 3600000 * 2).toISOString()
  },
  {
    order_id: 'TikTok-938210450',
    product_name: 'Váy Nơ Coquette Thiết Kế Thụy Deal Pastel 👗',
    sub_id: 'web',
    commission: 45000,
    status: 'pending',
    time: new Date(Date.now() - 3600000 * 5).toISOString()
  },
  {
    order_id: 'TikTok-123498762',
    product_name: 'Váy Nơ Coquette Hồng Đào Thụy Sĩ 🩰',
    sub_id: 'thuy',
    commission: 65000,
    status: 'cancelled',
    time: new Date(Date.now() - 3600000 * 36).toISOString()
  }
];

// Lấy danh sách đơn hàng từ tệp JSON
function getTikTokWebOrders(): any[] {
  if (!fs.existsSync(TIKTOK_ORDERS_FILE)) {
    try {
      fs.writeFileSync(TIKTOK_ORDERS_FILE, JSON.stringify(INITIAL_SIMULATED_ORDERS, null, 2), 'utf8');
    } catch (e) {
      console.error('Lỗi khởi tạo file tiktok_orders.json:', e);
    }
    return INITIAL_SIMULATED_ORDERS;
  }
  try {
    const data = fs.readFileSync(TIKTOK_ORDERS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (e) {
    return INITIAL_SIMULATED_ORDERS;
  }
}

// Lưu danh sách đơn hàng vào tệp JSON
function saveTikTokWebOrders(orders: any[]) {
  try {
    fs.writeFileSync(TIKTOK_ORDERS_FILE, JSON.stringify(orders, null, 2), 'utf8');
  } catch (e) {
    console.error('Lỗi khi lưu file tiktok_orders.json:', e);
  }
}

// Lấy thống kê Webhook từ tệp JSON
function getWebhookStats(): { lastReceivedAt: string; receivedCount: number; status: string; logs: any[] } {
  const defaultStats = {
    lastReceivedAt: '',
    receivedCount: 0,
    status: 'Active 🟢',
    logs: []
  };
  if (!fs.existsSync(WEBHOOK_STATS_FILE)) {
    try {
      fs.writeFileSync(WEBHOOK_STATS_FILE, JSON.stringify(defaultStats, null, 2), 'utf8');
    } catch (e) {
      console.error('Lỗi khởi tạo file tiktok_webhook_stats.json:', e);
    }
    return defaultStats;
  }
  try {
    const data = fs.readFileSync(WEBHOOK_STATS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (e) {
    return defaultStats;
  }
}

// Lưu thống kê Webhook vào tệp JSON Real database
function saveWebhookStats(stats: any) {
  try {
    fs.writeFileSync(WEBHOOK_STATS_FILE, JSON.stringify(stats, null, 2), 'utf8');
  } catch (e) {
    console.error('Lỗi khi lưu file tiktok_webhook_stats.json:', e);
  }
}

// Giả lập lịch sử tạo link TikTok Shop
const SIMULATED_LINKS: any[] = [
  {
    original_link: 'https://www.tiktok.com/view/product/17234567890123',
    affiliate_link: 'https://vt.tiktok.com/ZS23aBcDe/',
    product_id: '17234567890123',
    sub_id: 'web',
    created_at: new Date(Date.now() - 3600000 * 24).toISOString(),
    orders_count: 12,
    estimated_commission: 240000,
    approved_commission: 180000
  },
  {
    original_link: 'https://vt.tiktok.com/ZS2aB1c2D3/',
    affiliate_link: 'https://vt.tiktok.com/ZS2aB1c2D3/aff',
    product_id: '17234567899999',
    sub_id: 'tiktok_live',
    created_at: new Date(Date.now() - 3600000 * 12).toISOString(),
    orders_count: 5,
    estimated_commission: 85000,
    approved_commission: 50000
  }
];

// WEBHOOK ENDPOINT: Nhận đơn hàng TikTok Shop từ RioHub
app.post('/api/riohub/webhook', (req, res) => {
  const startTime = Date.now();
  try {
    const signingSecret = getSigningSecret();
    if (signingSecret) {
      // Đọc chữ ký từ Header
      const signature = req.headers['x-riohub-signature'] || req.headers['x-signature'] || req.headers['signature'];
      if (!signature) {
        console.warn('[RioHub Webhook] Blocked: Thiếu chữ ký xác thực trong header.');
        return res.status(401).json({
          error: true,
          message: 'Webhook authentication failed: Missing signature header'
        });
      }

      // Xác thực chữ ký đối sánh linh hoạt với Signing Secret đã lưu
      const isDirectMatch = signature === signingSecret;
      const parsedBodyStr = JSON.stringify(req.body);
      const hmac256Hex = crypto.createHmac('sha256', signingSecret).update(parsedBodyStr).digest('hex');
      const hmac256Base64 = crypto.createHmac('sha256', signingSecret).update(parsedBodyStr).digest('base64');
      const hmac1Hex = crypto.createHmac('sha1', signingSecret).update(parsedBodyStr).digest('hex');

      const isValid = isDirectMatch || 
                      signature === hmac256Hex || 
                      signature === hmac256Hex.toUpperCase() || 
                      signature === hmac256Base64 || 
                      signature === hmac1Hex;

      if (!isValid) {
        console.warn(`[RioHub Webhook] Blocked: Chữ ký không khớp. Signature=[${signature}]`);
        return res.status(401).json({
          error: true,
          message: 'Webhook authentication failed: Signature verification failed'
        });
      }
      console.log('[RioHub Webhook] Xác thực chữ ký webhook thành công 🟢');
    }

    const payload = req.body || {};
    console.log('[RioHub Webhook] Nhận request payload:', JSON.stringify(payload, null, 2));

    // Lấy thông tin sự kiện
    const event = String(payload.event || payload.action || 'order.updated').trim();

    // Dữ liệu đơn hàng có thể được lồng trong trường 'data' hoặc trực tiếp ở payload
    const data = payload.data || payload.order || payload;

    // 4. Trích xuất các trường thông tin theo yêu cầu
    const order_id = String(data.order_id || data.orderId || data.id || '').trim();
    const product_id = String(data.product_id || data.productId || '').trim();
    const creator_username = String(data.creator_username || data.creatorUsername || '').trim();
    const commission = Number(data.commission !== undefined ? data.commission : (data.est_commission || data.rawCommission || 0));
    const sub_id = String(data.sub_id || data.subId || '').trim(); // 5. sub_id = username người dùng

    if (!order_id) {
      console.warn('[RioHub Webhook Warning] Không tìm thấy Order ID trong payload.');
      return res.status(400).json({ error: true, message: 'Thiếu thông tin Order ID (order_id)' });
    }

    // Ánh xạ trạng thái đơn hàng của TikTok Shop/RioHub sang hệ thống
    // Trạng thái: 'completed' / 'cancelled' / 'pending'
    let rawStatus = String(data.status || data.order_status || data.state || '').toLowerCase().trim();
    
    if (event === 'order.refunded' || rawStatus.includes('refund') || rawStatus.includes('return')) {
      rawStatus = 'cancelled';
    } else if (event === 'order.created' && !rawStatus) {
      rawStatus = 'pending';
    }

    let status = 'pending';
    if (rawStatus === 'completed' || rawStatus === 'approved' || rawStatus === 'delivered' || rawStatus === 'paid' || rawStatus === 'success') {
      status = 'completed';
    } else if (rawStatus === 'cancelled' || rawStatus === 'refunded' || rawStatus === 'returned' || rawStatus === 'failed') {
      status = 'cancelled';
    }

    const productName = data.product_name || data.productName || 'Sản phẩm TikTok Webhook';
    const orderTime = data.time || data.created_at || data.createdAt || new Date().toISOString();

    // 6. Tự động lưu đơn hàng vào cơ sở dữ liệu
    const orders = getTikTokWebOrders();
    const existingIndex = orders.findIndex(o => o.order_id === order_id);

    const orderObj = {
      order_id,
      product_name: productName,
      product_id,
      creator_username,
      sub_id,
      commission,
      status,
      time: orderTime
    };

    if (existingIndex >= 0) {
      // 7. Nếu Order ID đã tồn tại: Cập nhật trạng thái và không tạo bản ghi mới
      orders[existingIndex] = {
        ...orders[existingIndex],
        ...orderObj,
        time: orders[existingIndex].time || orderTime // giữ nguyên thời gian tạo ban đầu
      };
      console.log(`[RioHub Webhook] Cập nhật thành công đơn hàng #${order_id} chuyển trạng thái sang [${status}]`);
    } else {
      // Thêm bản ghi mới lên đầu danh sách
      orders.unshift(orderObj);
      console.log(`[RioHub Webhook] Tạo bản ghi mới thành công cho đơn hàng #${order_id}`);
    }

    // Đồng bộ lại tệp cơ sở dữ liệu file JSON
    saveTikTokWebOrders(orders);

    // Cập nhật thống kê webhook
    const stats = getWebhookStats();
    stats.lastReceivedAt = new Date().toISOString();
    stats.receivedCount = (stats.receivedCount || 0) + 1;
    stats.status = 'Active 🟢';
    
    // Lưu tối đa 10 log lịch sử webhook gần nhất để admin kiểm tra tiện lợi
    const newLogItem = {
      id: 'log_' + Date.now() + '_' + Math.floor(Math.random() * 100),
      timestamp: new Date().toISOString(),
      event,
      order_id,
      sub_id,
      status,
      commission,
      product_id,
      elapsedMs: Date.now() - startTime
    };
    stats.logs = [newLogItem, ...(stats.logs || [])].slice(0, 10);
    saveWebhookStats(stats);

    // 8. Trả về thành công và phản hồi trong thời gian dưới 5 giây
    return res.status(200).json({
      success: true,
      message: 'TikTok Shop order received and stored successfully via Webhook 🟢',
      order: orderObj
    });

  } catch (error: any) {
    console.error('[RioHub Webhook Error]:', error);
    return res.status(500).json({
      error: true,
      message: 'Internal server error: ' + (error.message || 'Lỗi xử lý webhook')
    });
  }
});

// GET /api/riohub/webhook/stats: Lấy thống kê Webhook cho trang kiểm soát Admin
app.get('/api/riohub/webhook/stats', (req, res) => {
  const stats = getWebhookStats();
  const orders = getTikTokWebOrders();
  
  // Tổng hợp số đơn hàng đã lưu trong DB TikTok thực sự
  const totalCount = orders.length;

  res.json({
    success: true,
    webhookUrl: 'https://cashback.thuydeal.site/api/riohub/webhook',
    lastReceivedAt: stats.lastReceivedAt,
    receivedCount: stats.receivedCount,
    status: stats.status || 'Active 🟢',
    totalOrdersStored: totalCount,
    hasSigningSecret: !!getSigningSecret(),
    logs: stats.logs || []
  });
});

// API lấy Signing Secret (chỉ Super Admin 'admin' được xem)
app.get('/api/riohub/signing-secret', (req, res) => {
  const { username } = req.query;
  if (username !== 'admin') {
    return res.status(403).json({ error: 'Chỉ Super Admin mới được xem cấu hình này 🔒' });
  }
  const secret = getSigningSecret();
  res.json({ success: true, signingSecret: secret });
});

// API lưu Signing Secret (chỉ Super Admin 'admin' được sửa)
app.post('/api/riohub/signing-secret', (req, res) => {
  const { username, signingSecret } = req.body;
  if (username !== 'admin') {
    return res.status(403).json({ error: 'Chỉ Super Admin mới được sửa cấu hình này 🔒' });
  }
  saveSigningSecret(signingSecret || '');
  res.json({ success: true, message: 'Đã lưu Signing Secret thành công 💾' });
});

// Helper function to resolve shortened links on the server
async function resolveUrl(inputUrl: string): Promise<string> {
  const lowercase = inputUrl.toLowerCase();
  if (!lowercase.includes('shope.ee') && !lowercase.includes('s.shopee.vn') && !lowercase.includes('shopee.vn/universal-link')) {
    return inputUrl;
  }
  try {
    const res = await fetch(inputUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'
      },
      redirect: 'follow'
    });
    return res.url || inputUrl;
  } catch (e) {
    console.warn(`[Resolve URL Failed]:`, e);
    return inputUrl;
  }
}

// Helper to extract shopId and itemId from any Shopee URL
function extractShopAndItem(targetUrl: string): { shopId: string; itemId: string } {
  let shopId = '';
  let itemId = '';

  // Pattern 1: i.1234.5678 or similar
  const regexI = /i\.(\d+)\.(\d+)/i;
  const matchI = targetUrl.match(regexI);
  if (matchI) {
    shopId = matchI[1];
    itemId = matchI[2];
    return { shopId, itemId };
  }

  // Pattern 2: product/1234/5678
  const regexProduct = /product\/(\d+)\/(\d+)/i;
  const matchProduct = targetUrl.match(regexProduct);
  if (matchProduct) {
    shopId = matchProduct[1];
    itemId = matchProduct[2];
    return { shopId, itemId };
  }

  // Pattern 3: query parameters
  try {
    const parsed = new URL(targetUrl);
    const qItemId = parsed.searchParams.get('item_id') || parsed.searchParams.get('itemId');
    const qShopId = parsed.searchParams.get('shop_id') || parsed.searchParams.get('shopId');
    if (qItemId) itemId = qItemId;
    if (qShopId) shopId = qShopId;
  } catch (e) {
    // ignore
  }

  return { shopId, itemId };
}

// Proxy gọi API AddLiveTag để lấy thông tin sản phẩm Shopee chống lỗi CORS ở Client
app.get('/api/addlivetag/product', async (req, res) => {
  const { item_id, url, username } = req.query;
  const logUser = (username as string) || 'admin';
  
  try {
    let finalItemId = (item_id as string) || '';
    let finalShopId = '';
    let resolvedUrl = (url as string) || '';

    // Nếu truyền url, thực hiện resolve URL và bóc tách item_id
    if (url) {
      const origUrl = url as string;
      const lowerOrig = origUrl.toLowerCase();
      const isShortLink = lowerOrig.includes('shope.ee') || lowerOrig.includes('s.shopee.vn') || lowerOrig.includes('shopee.vn/universal-link');
      
      try {
        resolvedUrl = await resolveUrl(origUrl);
      } catch (err: any) {
        // (1) Lỗi resolve URL thực sự thất bại
        addDiagnosticLog(logUser, origUrl, 'RESOLVE_FAIL', { error: err.message }, 500, null);
        return res.status(400).json({ 
          success: false, 
          message: 'Lỗi quy trình: Quá trình giải quyết (resolve) liên kết rút gọn Shopee thất bại hoặc liên kết không thể truy cập.' 
        });
      }

      // Check if short link didn't resolve to a different URL
      if (isShortLink && (!resolvedUrl || resolvedUrl === origUrl)) {
        addDiagnosticLog(logUser, origUrl, 'RESOLVE_FAIL', { resolvedUrl }, 400, null);
        return res.status(400).json({ 
          success: false, 
          message: 'Lỗi quy trình: Liên kết rút gọn không thể giải quyết sang trang Shopee thực tế.' 
        });
      }

      const extracted = extractShopAndItem(resolvedUrl);
      if (extracted.itemId) {
        finalItemId = extracted.itemId;
        finalShopId = extracted.shopId;
      } else {
        // (2) Lỗi kĩ thuật không trích xuất được item_id
        addDiagnosticLog(logUser, resolvedUrl, 'EXTRACT_FAIL', { originalUrl: origUrl }, 422, null);
        return res.status(422).json({ 
          success: false, 
          message: 'Lỗi kỹ thuật: Hệ thống không thể trích xuất được mã sản phẩm (item_id) từ liên kết Shopee đã giải quyết.' 
        });
      }
    }

    let targetUrl = '';
    if (finalItemId) {
      // Ưu tiên truyền item_id theo yêu cầu: "Bắt buộc trích item_id. Không ưu tiên dùng URL."
      targetUrl = `https://data.addlivetag.com/product-data/product-data.php?item_id=${finalItemId}`;
    } else if (resolvedUrl) {
      // Chỉ dùng URL khi không lấy được item_id
      targetUrl = `https://data.addlivetag.com/product-data/product-data.php?url=${encodeURIComponent(resolvedUrl)}`;
    } else {
      return res.status(400).json({ success: false, message: 'Thiếu item_id hoặc url để tiến hành truy vấn.' });
    }

    console.log(`[AddLiveTag Triggered] item_id: ${finalItemId}, url: ${resolvedUrl} -> Target API: ${targetUrl}`);

    // (3) Thử lại tối đa 2 lần nếu dữ liệu trả về rỗng hoặc lỗi
    let attempts = 0;
    const maxAttempts = 2;
    let data: any = null;
    let responseOk = false;
    let lastErrorMsg = '';
    let responseStatusHttp = 200;

    while (attempts < maxAttempts) {
      attempts++;
      try {
        const response = await fetch(targetUrl);
        responseStatusHttp = response.status;
        
        if (response.ok) {
          const rawText = await response.text();
          try {
            data = JSON.parse(rawText);
          } catch (e: any) {
            lastErrorMsg = `Phản hồi lỗi phân giải JSON: ${rawText.slice(0, 150)}`;
            continue;
          }

          // Kiểm tra xem dữ liệu từ AddLiveTag có hợp lệ không
          const realProduct = data?.productInfo || data?.product_info || data?.data || data || {};
          if (realProduct && typeof realProduct === 'object' && Object.keys(realProduct).length > 0) {
            responseOk = true;
            // Chuẩn hóa và làm phẳng dữ liệu trả về cho client nhận trực tiếp
            data = realProduct;
            break;
          } else {
            lastErrorMsg = 'Dữ liệu nhận diện sản phẩm rỗng hoặc cấu trúc không được nhận diện.';
          }
        } else {
          lastErrorMsg = `HTTP Error Code: ${response.status}`;
        }
      } catch (err: any) {
        lastErrorMsg = `Mạng kết nối lỗi: ${err.message}`;
      }
      
      if (attempts < maxAttempts) {
        await new Promise(r => setTimeout(r, 600)); // nghỉ nhẹ trước lần gọi sau
      }
    }

    // Ghi nhận log chi tiết bắt buộc trong Admin/Máy chủ cho từng lượt dán link của người dùng
    addDiagnosticLog(
      logUser,
      targetUrl,
      'ADDLIVETAG_FETCH',
      { 
        originalUrl: url || '', 
        resolvedUrl, 
        itemId: finalItemId, 
        shopId: finalShopId,
        attemptsNeeded: attempts
      },
      responseOk ? 200 : responseStatusHttp,
      data || { error: lastErrorMsg }
    );

    if (!responseOk) {
      return res.status(422).json({ 
        success: false, 
        message: `Lỗi nguồn kết nối: Dữ liệu trả về từ AddLiveTag không khả dụng hoặc lỗi sau khi đã thử lại: ${lastErrorMsg}` 
      });
    }

    return res.json({ 
      success: true, 
      itemId: finalItemId || undefined,
      shopId: finalShopId || undefined,
      resolvedUrl,
      data 
    });
  } catch (e: any) {
    console.error('[AddLiveTag Proxy Error]:', e.message);
    addDiagnosticLog(logUser, (url as string) || '', 'ADDLIVETAG_CRASH', { error: e.message }, 500, null);
    return res.status(500).json({ success: false, message: e.message || 'Lỗi khi lấy dữ liệu AddLiveTag' });
  }
});


// Hàm hỗ trợ gọi API ngoài kèm xử lý lỗi của hệ thống RioHub
async function callRioHubApi(endpoint: string, method: string, apiKey: string, body?: any): Promise<any> {
  const url = `https://riohub.vn${endpoint}`;
  
  // Tỷ lệ retry-after tối đa 2 lần đối với lỗi 429
  let attempts = 0;
  const maxAttempts = 3;
  
  while (attempts < maxAttempts) {
    try {
      attempts++;
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
        'X-Api-Key': apiKey,
        'X-RioHub-Api-Key': apiKey
      };

      const response = await fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined
      });

      if (response.status === 429) {
        const retryAfter = parseInt(response.headers.get('Retry-After') || '2', 10);
        console.warn(`[RioHub API] 429 Rate limited. Retrying after ${retryAfter}s... (Attempt ${attempts}/${maxAttempts})`);
        
        if (attempts < maxAttempts) {
          await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
          continue;
        }
      }

      if (!response.ok) {
        let responseBody = '';
        try {
          responseBody = await response.text();
        } catch (_) {}

        return {
          error: true,
          status: response.status,
          statusText: response.statusText,
          body: responseBody
        };
      }

      return await response.json();
    } catch (err: any) {
      if (attempts >= maxAttempts) {
        return {
          error: true,
          status: 500,
          message: err.message || 'Kết nối mạng máy chủ thất bại.'
        };
      }
    }
  }
}

// API POST /api/v1/partner/tiktok/affiliate/links
app.post('/api/v1/partner/tiktok/affiliate/links', async (req, res) => {
  const { creator_username, product_url, sub_id, username } = req.body;

  if (!creator_username || !product_url) {
    return res.status(400).json({ error: 'Thiếu creator_username hoặc product_url' });
  }

  // Khôi phục hoặc tìm API key được lưu tại server
  const configs = getTikTokConfigs();
  // Khớp theo username truyền lên, hoặc dò theo creator_username
  let apiConfig = username ? configs[username] : null;
  if (!apiConfig) {
    // Thử dò theo creator_username
    const foundUser = Object.keys(configs).find(u => configs[u].creator_username === creator_username);
    if (foundUser) {
      apiConfig = configs[foundUser];
    }
  }

  // Trường hợp không có API key hoặc là API key mẫu nháp
  const isMock = !apiConfig || !apiConfig.encrypted_api_key || decrypt(apiConfig.encrypted_api_key).startsWith('rhk_xxxx');
  
  if (isMock) {
    console.log('[RioHub SIMULATION] Sinh link TikTok Shop tự động bảo mật');
    const affLink = `https://vt.tiktok.com/ZS${Math.random().toString(36).substring(2, 9).toUpperCase()}/`;
    const prodId = 'PN-' + Math.floor(100000000 + Math.random() * 900000000);
    
    const newLink = {
      original_link: product_url,
      affiliate_link: affLink,
      product_id: prodId,
      sub_id: sub_id || 'web',
      created_at: new Date().toISOString(),
      orders_count: 0,
      estimated_commission: 0,
      approved_commission: 0
    };

    SIMULATED_LINKS.unshift(newLink);

    return res.json({
      affiliate_link: affLink,
      product_id: prodId,
      sub_id: sub_id || 'web'
    });
  }

  const rawApiKey = decrypt(apiConfig!.encrypted_api_key);

  // Tiến hành gọi API RioHub thực tế
  const result = await callRioHubApi('/api/v1/partner/tiktok/affiliate/links', 'POST', rawApiKey, {
    creator_username,
    product_url,
    sub_id
  });

  if (result.error) {
    return handleRioHubError(result, res);
  }

  // Lưu lịch sử để phục vụ hiển thị
  SIMULATED_LINKS.unshift({
    original_link: product_url,
    affiliate_link: result.affiliate_link || result.link || '',
    product_id: result.product_id || '',
    sub_id: sub_id || 'web',
    created_at: new Date().toISOString(),
    orders_count: 0,
    estimated_commission: 0,
    approved_commission: 0
  });

  return res.json({
    affiliate_link: result.affiliate_link || result.link || '',
    product_id: result.product_id || '',
    sub_id: result.sub_id || sub_id || 'web'
  });
});

// API GET /api/v1/partner/tiktok/affiliate/links
app.get('/api/v1/partner/tiktok/affiliate/links', async (req, res) => {
  const { creator_username, username } = req.query;

  const configs = getTikTokConfigs();
  let apiConfig = username ? configs[username as string] : null;
  if (!apiConfig && creator_username) {
    const foundUser = Object.keys(configs).find(u => configs[u].creator_username === creator_username);
    if (foundUser) {
      apiConfig = configs[foundUser];
    }
  }

  const isMock = !apiConfig || !apiConfig.encrypted_api_key || decrypt(apiConfig.encrypted_api_key).startsWith('rhk_xxxx');

  if (isMock) {
    // Trả về danh sách links giả lập
    return res.json(SIMULATED_LINKS);
  }

  const rawApiKey = decrypt(apiConfig.encrypted_api_key);
  const result = await callRioHubApi('/api/v1/partner/tiktok/affiliate/links', 'GET', rawApiKey);

  if (result.error) {
    return handleRioHubError(result, res);
  }

  // Nếu API RioHub thật trả về, ta map kết quả hoặc trả về trực tiếp
  return res.json(result);
});

// API GET /api/v1/partner/tiktok/affiliate/orders
app.get('/api/v1/partner/tiktok/affiliate/orders', async (req, res) => {
  const { creator_username, username, sub_id, start_time, end_time, page, limit, page_size } = req.query;

  const configs = getTikTokConfigs();
  let apiConfig = username ? configs[username as string] : null;
  if (!apiConfig && creator_username) {
    const foundUser = Object.keys(configs).find(u => configs[u].creator_username === creator_username);
    if (foundUser) {
      apiConfig = configs[foundUser];
    }
  }
  
  // Fallback to admin if not found
  if (!apiConfig && configs['admin']) {
    apiConfig = configs['admin'];
  }
  
  // Final fallback to the first saved config
  if (!apiConfig && Object.keys(configs).length > 0) {
    apiConfig = configs[Object.keys(configs)[0]];
  }

  const isMock = !apiConfig || !apiConfig.encrypted_api_key || decrypt(apiConfig.encrypted_api_key).startsWith('rhk_xxxx');

  if (isMock) {
    // Giả lập tính năng lọc thời gian, sub_id và phân trang dựa trên file DB JSON thực tế
    let filtered = getTikTokWebOrders();
    
    if (sub_id) {
      filtered = filtered.filter(o => o.sub_id === sub_id);
    }
    
    // Phân trang
    const p = parseInt(page as string, 10) || 1;
    const l = parseInt((page_size || limit) as string, 10) || 10;
    const startIdx = (p - 1) * l;
    const paginated = filtered.slice(startIdx, startIdx + l);

    const responseBody = {
      orders: paginated,
      total: filtered.length,
      page: p,
      limit: l
    };
    addDiagnosticLog((creator_username || username || 'admin') as string, `https://riohub.vn/api/v1/partner/tiktok/affiliate/orders?creator_username=${creator_username || ''}&sub_id=${sub_id || ''}`, 'GET', req.query, 200, responseBody);
    return res.json(responseBody);
  }

  const rawApiKey = decrypt(apiConfig.encrypted_api_key);
  
  // Xây dựng query params gọi sang RioHub
  const queryParams = new URLSearchParams();
  if (creator_username) queryParams.append('creator_username', creator_username as string);
  if (sub_id) queryParams.append('sub_id', sub_id as string);
  if (start_time) queryParams.append('start_time', start_time as string);
  if (end_time) queryParams.append('end_time', end_time as string);
  if (page) queryParams.append('page', page as string);
  
  // Ưu tiên page_size hơn limit để chuẩn hóa theo yêu cầu RioHub
  const sizeParam = page_size || limit || '100';
  queryParams.append('page_size', sizeParam as string);

  const result = await callRioHubApi(`/api/v1/partner/tiktok/affiliate/orders?${queryParams.toString()}`, 'GET', rawApiKey);

  if (result.error) {
    addDiagnosticLog((creator_username || username || 'admin') as string, `https://riohub.vn/api/v1/partner/tiktok/affiliate/orders?${queryParams.toString()}`, 'GET', req.query, result.status || 500, result);
    return handleRioHubError(result, res);
  }

  addDiagnosticLog((creator_username || username || 'admin') as string, `https://riohub.vn/api/v1/partner/tiktok/affiliate/orders?${queryParams.toString()}`, 'GET', req.query, 200, result);
  return res.json(result);
});

// API Kiểm tra kết nối TikTok Shop của Admin
app.get('/api/tiktok/test-connection', async (req, res) => {
  const { creator_username, api_key, username } = req.query;

  if (!creator_username || !api_key) {
    return res.status(400).json({ error: true, message: '🔴 Thiếu thông tin Creator Username hoặc API Key' });
  }

  let apiKeyStr = (api_key as string).trim();
  const usernameStr = (creator_username as string).trim();
  const sysUser = (username as string || 'admin').trim();

  // Khôi phục API Key đã lưu nếu nhận placeholder hoặc key bị che/rỗng
  if (!apiKeyStr || apiKeyStr === 'rhk_placeholder_saved' || apiKeyStr === 'rhk_placeholder_existing' || apiKeyStr === 'mock_use_saved_key_or_placeholder' || apiKeyStr.includes('xxx')) {
    const configs = getTikTokConfigs();
    const apiConfig = configs[sysUser];
    if (apiConfig && apiConfig.encrypted_api_key) {
      apiKeyStr = decrypt(apiConfig.encrypted_api_key);
    }
  }

  const isMock = apiKeyStr.startsWith('rhk_xxxx') || apiKeyStr === 'rhk_placeholder' || apiKeyStr.toLowerCase().includes('mock') || !apiKeyStr;

  if (isMock) {
    // Giả lập kết nối theo đầu vào
    if (usernameStr.toLowerCase() === 'error401') {
      return res.status(401).json({ error: true, status: 401, message: '🔴 API Key không hợp lệ' });
    }
    if (usernameStr.toLowerCase() === 'error403') {
      return res.status(403).json({ error: true, status: 403, message: '🔴 Creator Username không thuộc API Key này' });
    }
    if (usernameStr.toLowerCase() === 'error404') {
      return res.status(404).json({ error: true, status: 404, message: '🔴 Creator chưa được kết nối trên RioHub' });
    }

    return res.json({
      success: true,
      creator_username: usernameStr,
      message: '🟢 Kết nối thành công',
      details: {
        creator: usernameStr,
        apiKey: 'Hợp lệ',
        rioHubApi: 'Hoạt động'
      }
    });
  }

  const url = `https://riohub.vn/api/v1/partner/tiktok/affiliate/links?creator_username=${encodeURIComponent(usernameStr)}&page=1&page_size=1`;
  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKeyStr}`,
      'X-Api-Key': apiKeyStr,
      'X-RioHub-Api-Key': apiKeyStr
    };
    const response = await fetch(url, {
      method: 'GET',
      headers
    });

    if (response.ok) {
      return res.json({
        success: true,
        creator_username: usernameStr,
        message: '🟢 Kết nối thành công',
        details: {
          creator: usernameStr,
          apiKey: 'Hợp lệ',
          rioHubApi: 'Hoạt động'
        }
      });
    }

    const status = response.status;
    let errMessage = '🔴 Đã xảy ra sự cố kết nối tới RioHub.';
    let responseBody = '';
    try {
      responseBody = await response.text();
    } catch (_) {}

    if (status === 401) {
      errMessage = '❌ API Key không hợp lệ';
    } else if (status === 403) {
      errMessage = '❌ Creator không thuộc API Key hiện tại';
    } else if (status === 404) {
      errMessage = '❌ Creator chưa được kết nối RioHub';
    } else if (status === 422) {
      errMessage = '⚠️ RioHub từ chối yêu cầu do dữ liệu gửi lên không hợp lệ hoặc sản phẩm không đủ điều kiện affiliate. (HTTP 422)';
    } else if (status === 429) {
      errMessage = '⚠️ Quá giới hạn API RioHub. Vui lòng xếp hàng thử lại sau.';
    } else {
      errMessage = `🔴 Lỗi kết nối RioHub (Mã lỗi: ${status})`;
    }

    return res.status(status).json({
      error: true,
      status,
      message: errMessage,
      body: responseBody
    });
  } catch (err: any) {
    return res.status(500).json({
      error: true,
      status: 500,
      message: `🔴 Lỗi kết nối mạng máy chủ: ${err.message || 'Không thể truy cập'}`
    });
  }
});

// API "Kiểm tra API Orders" độc lập gọi đến endpoint GET /partner/tiktok/affiliate/orders của RioHub
app.get('/api/tiktok/test-orders-api', async (req, res) => {
  const { creator_username, api_key, username } = req.query;

  if (!creator_username) {
    return res.status(400).json({ error: true, message: '🔴 Thiếu thông tin Creator Username' });
  }

  let apiKeyStr = (api_key as string || '').trim();
  const usernameStr = (creator_username as string).trim();
  const sysUser = (username as string || 'admin').trim();

  // Khôi phục API Key đã lưu nếu nhận placeholder hoặc rỗng
  if (!apiKeyStr || apiKeyStr === 'rhk_placeholder_saved' || apiKeyStr === 'rhk_placeholder_existing' || apiKeyStr === 'mock_use_saved_key_or_placeholder' || apiKeyStr.includes('xxx')) {
    const configs = getTikTokConfigs();
    const apiConfig = configs[sysUser];
    if (apiConfig && apiConfig.encrypted_api_key) {
      apiKeyStr = decrypt(apiConfig.encrypted_api_key);
    }
  }

  const isMock = !apiKeyStr || apiKeyStr.startsWith('rhk_xxxx') || apiKeyStr === 'rhk_placeholder' || apiKeyStr.toLowerCase().includes('mock');
  const url = `https://riohub.vn/api/v1/partner/tiktok/affiliate/orders?creator_username=${encodeURIComponent(usernameStr)}&page=1&limit=2`;

  if (isMock) {
    const mockResponseBody = {
      orders: [
        {
          order_id: "TKT-995818",
          sub_id: "testmember",
          commission: 45000,
          status: "pending_approve",
          product_name: "Áo Cardigan Nữ Coquette Style Màu Hồng Pastel Ôm Dáng Thủy Tiên",
          time: new Date().toISOString()
        }
      ],
      total: 1,
      page: 1,
      limit: 2
    };

    addDiagnosticLog(
      sysUser,
      url,
      'GET',
      { creator_username: usernameStr, page: 1, limit: 2 },
      200,
      mockResponseBody
    );

    return res.json({
      success: true,
      status: 200,
      message: '🟢 Kiểm tra API Orders thành công (giả lập)',
      body: mockResponseBody
    });
  }

  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKeyStr}`,
      'X-Api-Key': apiKeyStr,
      'X-RioHub-Api-Key': apiKeyStr
    };

    const response = await fetch(url, {
      method: 'GET',
      headers
    });

    const status = response.status;
    let resBody: any = null;
    try {
      resBody = await response.json();
    } catch (e) {
      resBody = { message: 'Không thể parse JSON response.' };
    }

    addDiagnosticLog(
      sysUser,
      url,
      'GET',
      { creator_username: usernameStr, page: 1, limit: 2 },
      status,
      resBody
    );

    if (response.ok) {
      return res.json({
        success: true,
        status,
        message: '🟢 Kiểm tra API Orders thành công',
        body: resBody
      });
    }

    return res.status(status).json({
      error: true,
      status,
      message: `🔴 Kiểm tra API Orders thất bại (Mã phản hồi: ${status})`,
      body: resBody
    });
  } catch (err: any) {
    const errorBody = { message: err.message || 'Mất kết nối máy chủ.' };
    addDiagnosticLog(
      sysUser,
      url,
      'GET',
      { creator_username: usernameStr, page: 1, limit: 2 },
      500,
      errorBody
    );

    return res.status(500).json({
      error: true,
      status: 500,
      message: `🔴 Lỗi kết nối máy chủ hoặc mạng: ${err.message}`,
      body: errorBody
    });
  }
});

// API Kiểm tra tạo link thực tế từ Admin
app.get('/api/tiktok/test-link', async (req, res) => {
  const { creator_username, api_key, product_url, username } = req.query;

  if (!creator_username || !api_key || !product_url) {
    return res.status(400).json({ error: true, message: '🔴 Thiếu Creator Username, API Key hoặc Link sản phẩm' });
  }

  let apiKeyStr = (api_key as string).trim();
  const usernameStr = (creator_username as string).trim();
  const productUrlStr = (product_url as string).trim();
  const sysUser = (username as string || 'admin').trim();

  // Khôi phục API Key đã lưu nếu nhận placeholder
  if (apiKeyStr === 'rhk_placeholder_saved' || apiKeyStr === 'rhk_placeholder_existing' || apiKeyStr === 'mock_test_link') {
    const configs = getTikTokConfigs();
    const apiConfig = configs[sysUser];
    if (apiConfig && apiConfig.encrypted_api_key) {
      apiKeyStr = decrypt(apiConfig.encrypted_api_key);
    }
  }

  const isMock = apiKeyStr.startsWith('rhk_xxxx') || apiKeyStr === 'rhk_placeholder' || apiKeyStr.toLowerCase().includes('mock') || !apiKeyStr;

  if (isMock) {
    const affLink = `https://vt.tiktok.com/ZS${Math.random().toString(36).substring(2, 9).toUpperCase()}/`;
    return res.json({
      success: true,
      affiliate_link: affLink,
      message: '🟢 Tạo link thành công'
    });
  }

  const url = `https://riohub.vn/api/v1/partner/tiktok/affiliate/links`;
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKeyStr}`,
        'X-Api-Key': apiKeyStr,
        'X-RioHub-Api-Key': apiKeyStr
      },
      body: JSON.stringify({
        creator_username: usernameStr,
        product_url: productUrlStr,
        sub_id: 'test_admin'
      })
    });

    const data = await response.json();
    if (response.ok && (data.affiliate_link || data.link)) {
      return res.json({
        success: true,
        affiliate_link: data.affiliate_link || data.link,
        message: '🟢 Tạo link thành công'
      });
    }

    const status = response.status;
    let errMessage = '🔴 Tạo link không thành công. Lỗi hệ thống.';
    if (status === 401) {
      errMessage = '🔴 API Key không hợp lệ';
    } else if (status === 403) {
      errMessage = '🔴 Creator Username không thuộc API Key này';
    } else if (status === 404) {
      errMessage = '🔴 Creator chưa được kết nối trên RioHub';
    } else if (status === 422) {
      errMessage = '🔴 Sản phẩm không hợp lệ hoặc chưa tham gia tiếp thị liên kết TikTok Shop';
    }

    return res.status(status).json({
      error: true,
      status,
      message: errMessage
    });
  } catch (err: any) {
    return res.status(500).json({
      error: true,
      status: 500,
      message: `🔴 Lỗi mạng máy chủ: ${err.message || 'Kiểm tra link thất bại'}`
    });
  }
});

// Hàm dịch mã phản hồi lỗi RioHub thành Tiếng Việt bảo mật, dễ chịu cho khách hàng
function handleRioHubError(apiError: any, res: any) {
  const status = apiError.status || 500;
  
  let formattedError = 'Đã xảy ra sự cố từ RioHub.';
  if (status === 401) {
    formattedError = '❌ API Key không hợp lệ';
  } else if (status === 403) {
    formattedError = '❌ Creator không thuộc API Key hiện tại';
  } else if (status === 404) {
    formattedError = '❌ Creator chưa được kết nối RioHub';
  } else if (status === 422) {
    formattedError = '⚠️ RioHub từ chối yêu cầu đồng bộ đơn hàng do dữ liệu gửi lên không hợp lệ. Vui lòng kiểm tra endpoint, creator_username và tham số truy vấn.';
  } else if (status === 429) {
    formattedError = '⚠️ 429 Quá giới hạn API RioHub. Vui lòng thử lại sau giây lát.';
  }

  return res.status(status).json({
    error: true,
    message: formattedError,
    status,
    body: apiError.body || apiError.statusText || ''
  });
}

// Tích hợp Vite middleware để chạy trơn tru trong môi trường sandbox & production
const startServer = async () => {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Full-Stack Server] Đang hoạt động ổn định tài port ${PORT}`);
  });
};

startServer();
